# CERT-C Scraper (SEI CERT C Coding Standard → JSON)

A small Python crawler that walks the SEI CERT C Coding Standard wiki and converts each rule/recommendation page into clean, machine-readable JSON (and JSONL). It captures the page intro (including any inline code blocks), pairs *Noncompliant* and *Compliant* examples, and extracts a structured **risk\_assessment** (free-text explanation + metrics table).

---

## Features

* **Three-step crawl**

  1. Start page → 2) category pages (Rules & Recommendations) → 3) individual rule pages (e.g., `API00-C`, `ARR01-C`).

* **Robust content parsing**

  * `rule_id`, `title`, canonical `url`
  * `description` (intro text **plus any code blocks** that appear before the first section heading, emitted as plain text)
  * `examples` list with paired `noncompliant`/`compliant` entries:

    * `heading`, `pre_code_commentary`, `code`, `explanation_after`
    * Duplicate examples are de-duplicated.
  * `risk_assessment` object with:

    * `explanation` (text under “Risk Assessment” heading prior to the metrics table)
    * `metrics` (severity, likelihood, detectable, repairable, priority, level)

* **Resilient HTTP**
  Retries with backoff, request throttling, and domain-scoped link resolution.

---

## Output schema (per page)

```json
{
  "rule_id": "API00-C",
  "title": "Functions should validate their parameters",
  "url": "https://wiki.sei.cmu.edu/confluence/display/c/API00-C.+Functions+should+validate+their+parameters",
  "description": "Introductory paragraphs...\n\n<code from intro if present>\n...\n",
  "examples": [
    {
      "noncompliant": {
        "heading": "Noncompliant Code Example",
        "pre_code_commentary": "Context…",
        "code": "/* raw code */",
        "explanation_after": "Why this is bad…"
      },
      "compliant": {
        "heading": "Compliant Solution",
        "pre_code_commentary": "Context…",
        "code": "/* raw code */",
        "explanation_after": "Why this is better…"
      }
    }
  ],
  "risk_assessment": {
    "explanation": "Narrative explaining the risk…",
    "metrics": {
      "severity": "Medium",
      "likelihood": "Unlikely",
      "detectable": "No",
      "repairable": "No",
      "priority": "P2",
      "level": "L3"
    }
  }
}
```

> **Note:** The scraper intentionally **does not** repeat the risk metrics outside the `risk_assessment.metrics` object.

---

## Installation

```bash
conda activate mqp
pip install -r requirements.txt
```

---

## Usage

```bash
python certc_scraper.py \
  --base-page "https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard" \
  --domain "wiki.sei.cmu.edu" \
  --timeout 15 \
  --sleep 0.2 \
  --out-json certc_rules.json \
  --out-jsonl certc_rules.jsonl
```

### CLI options

* `--base-page` (str)
  Entry page for the crawl. Defaults to the SEI CERT C start page.
* `--domain` (str)
  Only URLs under this domain will be visited (safety guard).
* `--timeout` (int, seconds)
  Per-request timeout. Default: `15`.
* `--sleep` (float, seconds)
  Throttle between requests. Default: `0.2` (be polite).
* `--out-json` (path)
  Full dataset as a single JSON file.
* `--out-jsonl` (path)
  Line-delimited JSON (one object per page).

---

## How it works (brief)

1. **Discover categories** from the start page (Rules & Recommendations trees).
2. **Collect rule URLs** from each category page (both pretty URLs and pageId forms).
3. **Parse each rule page**:

   * Header → `rule_id`, `title`
   * Intro section → `description` (includes paragraphs and **any `<pre>`/`code` blocks** that appear before the first major heading; code is added as plain text)
   * H2 sections → pair *Noncompliant* and *Compliant* examples; de-duplicate exact repeats
   * “Risk Assessment” → explanation + structured metrics table (with fallbacks)

