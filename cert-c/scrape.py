import re
import json
import time
import argparse
from typing import Dict, Any, List, Optional, Tuple, Iterator
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup, NavigableString, Tag
from requests.adapters import HTTPAdapter, Retry
from tqdm import tqdm


class CertCScraper:
    """
    Scrape CERT-C pages with a 3-step crawl:
      1) Start page (SEI CERT C Coding Standard)
      2) Category pages for both Rules and Recommendations
      3) Specific rules/recommendations (e.g., PRE30-C. ...)
    Extracts per page:
      rule_id, title, url, description,
      examples: [
        {
          "noncompliant": {
            "heading": str,
            "pre_code_commentary": str|None,
            "code": str|None,
            "explanation_after": str|None
          }|None,
          "compliant": {
            "heading": str,
            "pre_code_commentary": str|None,
            "code": str|None,
            "explanation_after": str|None
          }|None
        }, ...
      ]
      risk_assessment: {
        "explanation": str|None,
        "metrics": { severity, likelihood, detectable, repairable, priority, level }
      }
    """
    RULE_ID_RE = re.compile(r"\b([A-Z]{3}\d{2}-C)\b")
    RULE_CATEGORY_TEXT_RE = re.compile(r"\b(?:Rule|Rec\.)\s+0?\d+\.\s+.*\(([A-Z]{3})\)", re.I)
    SPEC_RULE_URL_RE = re.compile(r"(?:/display/c/|/pages/viewpage\.action\?pageId=\d+|/x/)", re.I)

    NONCOMPL_RE = re.compile(r"\bNon[- ]?compliant\b", re.I)
    COMPL_RE = re.compile(r"\bCompliant\b", re.I)

    def __init__(
        self,
        base_page: str,
        domain: str,
        request_timeout: int = 15,
        sleep_between_requests: float = 0.2,
        user_agent: str = "CERTC-RAG-Scraper/1.6",
        retries: int = 3,
        backoff_factor: float = 0.6,
    ):
        self.base_page = base_page
        self.domain = domain
        self.request_timeout = request_timeout
        self.sleep_between_requests = sleep_between_requests
        self.session = self._make_session(user_agent, retries, backoff_factor)

    # ----------------- HTTP / HTML utils -----------------
    def _make_session(self, user_agent: str, retries: int, backoff_factor: float) -> requests.Session:
        s = requests.Session()
        s.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        })
        retry = Retry(
            total=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET"]),
        )
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
        return s

    def _get_soup(self, url: str) -> Optional[BeautifulSoup]:
        try:
            r = self.session.get(url, timeout=self.request_timeout)
            ctype = r.headers.get("Content-Type", "")
            if r.status_code != 200 or "text/html" not in ctype:
                return None
            return BeautifulSoup(r.text, "html.parser")
        except Exception:
            return None

    def _clean_link(self, base: str, href: str) -> Optional[str]:
        if not href or href.startswith(("mailto:", "javascript:", "#")):
            return None
        abs_url = urljoin(base, href)
        abs_url, _ = urldefrag(abs_url)
        p = urlparse(abs_url)
        if self.domain not in p.netloc:
            return None
        return abs_url

    @staticmethod
    def _text_or_none(el) -> Optional[str]:
        return el.get_text(" ", strip=True) if el else None

    def _find_main_content(self, soup: BeautifulSoup):
        el = soup.find("div", {"id": "main-content"}) or soup.find("div", {"id": "content"})
        if el:
            return el
        for sel in [
            ('div', {'class': re.compile(r'(^|\b)(wiki-content|content-body|ak-renderer-document)\b', re.I)}),
            ('main', {}),
            ('article', {}),
            ('div', {'role': 'main'}),
        ]:
            el = soup.find(*sel)
            if el:
                return el
        return soup.body or soup

    # ----------------- Step 1 → 2: discover category pages ----------
    def find_rule_categories(self) -> List[str]:
        to_visit = {self.base_page}
        base_parsed = urlparse(self.base_page)
        root = f"{base_parsed.scheme}://{base_parsed.netloc}"
        two_rules = urljoin(root, "/confluence/display/c/2%2BRules")
        three_recs = urljoin(root, "/confluence/display/c/3%2BRecommendations")
        to_visit.update([two_rules, three_recs])

        links = set()
        for page in to_visit:
            sp = self._get_soup(page)
            if not sp:
                continue

            for a in sp.find_all("a", href=True):
                txt = self._text_or_none(a) or ""
                if self.RULE_CATEGORY_TEXT_RE.search(txt):
                    u = self._clean_link(page, a["href"])
                    if u:
                        links.add(u)

            for a in sp.select("div.plugin_pagetree_children_content a[href]"):
                txt = self._text_or_none(a) or ""
                if self.RULE_CATEGORY_TEXT_RE.search(txt):
                    u = self._clean_link(page, a["href"])
                    if u:
                        links.add(u)

        return sorted(links)

    # ----------------- Step 2 → 3: discover specific rule pages -------------
    def find_specific_rules(self, category_url: str) -> List[str]:
        sp = self._get_soup(category_url)
        if not sp:
            return []
        found = set()

        def consider(href: str):
            u = self._clean_link(category_url, href)
            if not u:
                return
            if self.SPEC_RULE_URL_RE.search(urlparse(u).path + ("?" + urlparse(u).query if urlparse(u).query else "")):
                found.add(u)

        for a in sp.find_all("a", href=True):
            consider(a["href"])
        for a in sp.select("div.plugin_pagetree_children_content a[href]"):
            consider(a["href"])

        return sorted(found)

    # ----------------- Parsing helpers -----------------
    def _parse_rule_header(self, soup: BeautifulSoup) -> Tuple[Optional[str], Optional[str]]:
        h1 = soup.find("h1")
        h1_text = self._text_or_none(h1) or ""
        m = self.RULE_ID_RE.search(h1_text) or self.RULE_ID_RE.search((soup.title.get_text(" ", strip=True) if soup.title else ""))
        rule_id = m.group(1) if m else None

        title = h1_text.strip() or None
        if title and rule_id:
            if ". " in title:
                rid_prefix, rest = title.split(". ", 1)
                if self.RULE_ID_RE.fullmatch(rid_prefix):
                    title = rest.strip()
            else:
                title = title.replace(rule_id, "").lstrip(" .-—").strip() or title
        return rule_id, title

    # ---------- Description (intro) ----------
    def _intro_text(self, body: Tag, stop_heads: List[str]) -> Optional[str]:
        """
        Return ALL content that appears before the first TOP-LEVEL <h2> in the main content.
        - Includes paragraphs, lists, tables, etc. as plain text.
        - Includes <pre>/<code> blocks verbatim (preserving newlines).
        - No filtering/deduping.
        """
        # keep the arg for compatibility, even if unused
        _ = stop_heads

        if not body:
            return None

        parts: List[str] = []

        # Find the first top-level H2 (section boundary)
        first_h2 = None
        for child in body.find_all("h2", recursive=False):
            first_h2 = child
            break

        # Iterate top-level nodes until the first H2
        for child in body.children:
            if isinstance(child, Tag):
                if first_h2 is not None and child is first_h2:
                    break

                name = (child.name or "").lower()
                if name in {"script", "style"}:
                    continue

                # 1) If it's a direct code block, include verbatim
                if name in {"pre", "code"}:
                    txt = child.get_text("\n", strip=False)
                    if txt and txt.strip():
                        parts.append(txt.replace("\r", "\n").rstrip("\n"))
                    continue

                # 2) For any other block: include its non-code text in a readable way
                txt = child.get_text(" ", strip=True)
                if txt:
                    parts.append(txt)

                # 3) Also include any nested <pre>/<code> verbatim
                for pre in child.find_all("pre"):
                    t = pre.get_text("\n", strip=False)
                    if t and t.strip():
                        parts.append(t.replace("\r", "\n").rstrip("\n"))

                for code in child.find_all("code"):
                    # avoid duplicating code already covered via <pre>
                    if code.find_parent("pre"):
                        continue
                    t = code.get_text("\n", strip=False)
                    if t and t.strip():
                        parts.append(t.replace("\r", "\n").rstrip("\n"))

            elif isinstance(child, NavigableString):
                s = str(child).strip()
                if s:
                    parts.append(s)

        out = "\n\n".join(p for p in parts if p and p.strip())
        return out or None


    # ---------- H2 sections ----------
    def _iter_h2_sections(self, body: Tag) -> Iterator[Tuple[Tag, str, List]]:
        if not body:
            return
        for h2 in body.find_all("h2"):
            heading_text = h2.get_text(" ", strip=True)
            nodes = []
            sib = h2.next_sibling
            while sib and not (isinstance(sib, Tag) and sib.name == "h2"):
                nodes.append(sib)
                sib = sib.next_sibling
            yield h2, heading_text, nodes

    # ---------- Content flattening into blocks ----------
    def _is_block_code(self, node: Tag) -> bool:
        if not isinstance(node, Tag):
            return False
        if node.name == "pre":
            return True
        classes = " ".join(node.get("class", [])).lower()
        if "ak-renderer-codeblock" in classes or "code" in classes or "panel" in classes:
            if node.find("pre") or node.find("code"):
                return True
        return False

    def _extract_code_text(self, node: Tag) -> Optional[str]:
        if node.name == "pre":
            txt = node.get_text("\n", strip=False)
            return txt if txt and txt.strip() else None
        pre = node.find("pre")
        if pre:
            txt = pre.get_text("\n", strip=False)
            return txt if txt and txt.strip() else None
        code = node.find("code")
        if code:
            txt = code.get_text("\n", strip=False)
            return txt if txt and txt.strip() else None
        return None

    def _iter_section_blocks(self, nodes: List) -> List[Tuple[str, str]]:
        BLOCK_LIKE = {"p", "ul", "ol", "blockquote"}
        blocks: List[Tuple[str, str]] = []
        seen_text_norm = set()

        def add_text(txt: str):
            txt = (txt or "").strip()
            if not txt:
                return
            norm = re.sub(r"\s+", " ", txt).lower()
            if norm in seen_text_norm:
                return
            seen_text_norm.add(norm)
            blocks.append(("text", txt))

        for n in nodes:
            if isinstance(n, Tag):
                if self._is_block_code(n):
                    code_txt = self._extract_code_text(n)
                    if code_txt:
                        blocks.append(("code", code_txt))
                    continue

                if n.name in BLOCK_LIKE:
                    t = n.get_text(" ", strip=True)
                    if t:
                        add_text(t)
                else:
                    for d in n.descendants:
                        if isinstance(d, Tag):
                            if d.name in {"pre", "code", "table", "script", "style"}:
                                continue
                            if d.name in BLOCK_LIKE:
                                t = d.get_text(" ", strip=True)
                                if t:
                                    add_text(t)
        return blocks

    def _split_blocks(self, blocks: List[Tuple[str, str]]) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        first_code_idx = next((i for i, (k, _) in enumerate(blocks) if k == "code"), None)
        if first_code_idx is None:
            pre = "\n\n".join(v for k, v in blocks if k == "text").strip() or None
            return pre, None, None
        pre = "\n\n".join(v for k, v in blocks[:first_code_idx] if k == "text").strip() or None
        code = blocks[first_code_idx][1] or None
        post = "\n\n".join(v for k, v in blocks[first_code_idx + 1:] if k == "text").strip() or None
        return pre, code, post

    def _extract_sections(self, body: Tag):
        ordered: List[Tuple[str, Dict[str, Any]]] = []
        if not body:
            return ordered

        for _, heading, nodes in self._iter_h2_sections(body):
            lower = heading.lower()
            if not (self.NONCOMPL_RE.search(lower) or self.COMPL_RE.search(lower)):
                ordered.append(("other", {"heading": heading}))
                continue

            kind = "noncompliant" if self.NONCOMPL_RE.search(lower) else "compliant"
            blocks = self._iter_section_blocks(nodes)
            pre, code, post = self._split_blocks(blocks)
            ordered.append((
                kind,
                {
                    "heading": heading,
                    "pre_code_commentary": pre,
                    "code": code,
                    "explanation_after": post,
                },
            ))
        return ordered

    # ---------- Pairing & de-dup ----------
    def _pair_examples(self, body: Tag) -> List[Dict[str, Any]]:
        """
        Pair noncompliant with subsequent compliant(s). If a noncompliant is
        followed by at least one compliant, do NOT emit it again single-sided.
        """
        ordered = self._extract_sections(body)
        examples: List[Dict[str, Any]] = []

        current_non: Optional[Dict[str, Any]] = None
        paired_count = 0

        for kind, sec in ordered:
            if kind == "noncompliant":
                if current_non is not None and paired_count == 0:
                    examples.append({"noncompliant": current_non, "compliant": None})
                current_non = sec
                paired_count = 0
                continue

            if kind == "compliant":
                if current_non is not None:
                    examples.append({"noncompliant": current_non, "compliant": sec})
                    paired_count += 1
                else:
                    examples.append({"noncompliant": None, "compliant": sec})
                continue

            # "other" closes any open unpaired noncompliant
            if current_non is not None and paired_count == 0:
                examples.append({"noncompliant": current_non, "compliant": None})
            current_non = None
            paired_count = 0

        if current_non is not None and paired_count == 0:
            examples.append({"noncompliant": current_non, "compliant": None})

        return self._dedup_examples(examples)

    def _dedup_examples(self, examples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove exact duplicate pairs caused by page quirks.
        """
        seen = set()
        out = []

        def norm(s: Optional[str]) -> str:
            if s is None:
                return ""
            return re.sub(r"\s+", " ", s).strip()

        for ex in examples:
            n = ex.get("noncompliant") or {}
            c = ex.get("compliant") or {}
            key = (
                norm(n.get("heading")),
                norm(n.get("code")),
                norm(n.get("pre_code_commentary")),
                norm(c.get("heading")),
                norm(c.get("code")),
                norm(c.get("pre_code_commentary")),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(ex)
        return out

    # ----------------- Risk assessment (explanation + metrics) -----------------
    def _extract_risk_assessment(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """
        Risk Assessment:
        - explanation: all text after the 'Risk Assessment' heading up to (but not including)
            the metrics table. The table may be wrapped (e.g., <div class="table-wrap"><table>…)
        - metrics: parsed via _extract_risk_table (unchanged)
        """
        metrics = self._extract_risk_table(soup)

        body = self._find_main_content(soup)
        if not body:
            return {"explanation": None, "metrics": metrics}

        # Find the 'Risk Assessment' heading
        heading = None
        for h in body.find_all(re.compile(r"^h[1-6]$")):
            if re.search(r"\bRisk\s+Assessment\b", h.get_text(" ", strip=True), re.I):
                heading = h
                break
        if not heading:
            return {"explanation": None, "metrics": metrics}

        parts: List[str] = []
        for sib in heading.next_siblings:
            if not isinstance(sib, Tag):
                # ignore stray whitespace/text nodes
                continue

            name = (sib.name or "").lower()

            # Stop at the metrics table OR its wrapper
            if name == "table" or sib.find("table") is not None:
                break

            if name in {"script", "style"}:
                continue

            txt = sib.get_text(" ", strip=True)
            if txt:
                parts.append(txt)

        explanation = "\n\n".join(parts).strip() or None
        return {"explanation": explanation, "metrics": metrics}



    # ----------------- Risk table (metrics-only helper) -----------------
    def _extract_risk_table(self, soup: BeautifulSoup) -> Dict[str, Any]:
        keys = ["severity", "likelihood", "detectable", "repairable", "priority", "level"]
        out = {k: None for k in keys}

        body = self._find_main_content(soup)
        if not body:
            return out

        # find Risk Assessment heading
        heading = None
        for h in body.find_all(re.compile(r"^h[1-6]$")):
            if re.search(r"\bRisk\s+Assessment\b", h.get_text(" ", strip=True), re.I):
                heading = h
                break

        risk_table = None
        if heading:
            for sib in heading.next_siblings:
                if isinstance(sib, Tag) and sib.name == "table":
                    risk_table = sib
                    break
                if isinstance(sib, Tag) and sib.name in {"h2", "h3", "h4"}:
                    break
        if not risk_table:
            # fallback: any table that looks like risk metrics
            for tbl in body.find_all("table"):
                txt = tbl.get_text(" ", strip=True).lower()
                if all(k in txt for k in ["severity", "likelihood"]) and ("priority" in txt or "level" in txt):
                    risk_table = tbl
                    break
        if not risk_table:
            return out

        def norm(x: str) -> str:
            return (x or "").strip().lower()

        rows = risk_table.find_all("tr")
        headers = [norm(th.get_text(" ", strip=True)) for th in rows[0].find_all(["th", "td"])] if rows else []

        label_map = {
            "severity": ["severity"],
            "likelihood": ["likelihood"],
            "detectable": ["detectable", "automated detection", "detection"],
            "repairable": ["repairable", "automated repair", "repair", "remediation"],
            "priority": ["priority"],
            "level": ["level"],
        }

        def get_cell(label_variants: List[str]) -> Optional[str]:
            # style A: two-column label|value rows
            if rows and len(headers) <= 2:
                for tr in rows:
                    cells = tr.find_all(["th", "td"])
                    if len(cells) >= 2:
                        key = norm(cells[0].get_text(" ", strip=True))
                        val = (cells[1].get_text(" ", strip=True) or "").strip()
                        if any(lv in key for lv in label_variants):
                            return val or None
            # style B: header columns
            if headers:
                for i, h in enumerate(headers):
                    if any(lv in h for lv in label_variants):
                        if len(rows) > 1:
                            first_data = rows[1].find_all(["td", "th"])
                            if i < len(first_data):
                                return (first_data[i].get_text(" ", strip=True) or "").strip() or None
            return None

        out["severity"]   = get_cell(label_map["severity"])   # e.g., "Medium"
        out["likelihood"] = get_cell(label_map["likelihood"]) # e.g., "Unlikely"
        out["detectable"] = get_cell(label_map["detectable"]) # e.g., "No" / "Yes"
        out["repairable"] = get_cell(label_map["repairable"]) # e.g., "No"
        out["priority"]   = get_cell(label_map["priority"])   # e.g., "P2"
        out["level"]      = get_cell(label_map["level"])      # e.g., "L3"

        return out

    # ----------------- Page extraction (Step 3) -----------------
    def extract_rule_page(self, url: str) -> Optional[Dict[str, Any]]:
        sp = self._get_soup(url)
        if not sp:
            return None
        body = self._find_main_content(sp)
        rule_id, title = self._parse_rule_header(sp)

        description = None
        if body:
            description = self._intro_text(
                body,
                stop_heads=[
                    "noncompliant", "compliant", "risk assessment", "exceptions",
                    "automated detection", "related guidelines", "implementation details"
                ],
            )

        examples = self._pair_examples(body)
        ra = self._extract_risk_assessment(sp)

        if self.sleep_between_requests:
            time.sleep(self.sleep_between_requests)

        return {
            "rule_id": rule_id,
            "title": title,
            "url": url,
            "description": description,
            "examples": examples or None,
            "risk_assessment": {
                "explanation": ra.get("explanation"),
                "metrics": ra.get("metrics", {k: None for k in ["severity","likelihood","detectable","repairable","priority","level"]}),
            },
        }

    # ----------------- Orchestration -----------------
    def run(self) -> List[Dict[str, Any]]:
        cats = self.find_rule_categories()
        print(f"Discovered {len(cats)} rule/recommendation categories.")

        specific: List[str] = []
        for c in tqdm(cats, desc="Finding specific pages"):
            specific.extend(self.find_specific_rules(c))
            if self.sleep_between_requests:
                time.sleep(self.sleep_between_requests)
        specific = sorted(set(specific))
        print(f"Discovered {len(specific)} specific pages.")

        results: List[Dict[str, Any]] = []
        for u in tqdm(specific, desc="Scraping pages"):
            rec = self.extract_rule_page(u)
            if not rec:
                continue
            if not rec.get("rule_id") or not rec.get("title"):
                continue
            results.append(rec)
        print(f"Extracted {len(results)} pages.")
        return results


def main():
    ap = argparse.ArgumentParser(description="Scrape SEI CERT-C rules & recommendations into JSON/JSONL.")
    ap.add_argument("--base-page", default="https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard")
    ap.add_argument("--domain", default="wiki.sei.cmu.edu")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--sleep", type=float, default=0.2, help="Seconds between requests")
    ap.add_argument("--out-json", default="cert-c/certc_rules.json")
    ap.add_argument("--out-jsonl", default="cert-c/certc_rules.jsonl")
    args = ap.parse_args()

    scraper = CertCScraper(
        base_page=args.base_page,
        domain=args.domain,
        request_timeout=args.timeout,
        sleep_between_requests=args.sleep,
    )

    results = scraper.run()

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    with open(args.out_jsonl, "w", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print("Saved:")
    print(f" - JSON : {args.out_json}")
    print(f" - JSONL: {args.out_jsonl}")


if __name__ == "__main__":
    main()
