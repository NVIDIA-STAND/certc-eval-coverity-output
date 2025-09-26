"""Evaluation and similarity logic for the CERT-C evaluator UI."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from utilities import SEVERITY_ORDER, join_nonempty, normalize

_HAS_BERTSCORE = False
_HAS_ST = False
_HAS_SK = False

try:
    from bert_score import score as bert_score  # type: ignore

    _HAS_BERTSCORE = True
except Exception:
    _HAS_BERTSCORE = False

try:
    from sentence_transformers import SentenceTransformer  # type: ignore
    import numpy as np  # type: ignore

    _HAS_ST = True
except Exception:
    _HAS_ST = False
    SentenceTransformer = None  # type: ignore
    np = None  # type: ignore

try:
    from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore
    from sklearn.metrics.pairwise import cosine_similarity  # type: ignore

    _HAS_SK = True
except Exception:
    _HAS_SK = False

__all__ = [
    "_HAS_BERTSCORE",
    "_HAS_SK",
    "_HAS_ST",
    "evaluate_ai_explanation",
    "evaluate_fix",
    "evaluate_issue_match",
    "evaluate_priority",
    "evaluate_severity",
    "jaccard",
    "supporting_citations",
]

_ID_RE = None
_ST_MODEL = None


def severity_distance(pred: str, gold: str) -> Optional[int]:
    """Ordinal distance (0 = exact). Return None if unknown."""
    if not pred or not gold:
        return None
    pred_n = normalize(pred).title()
    gold_n = normalize(gold).title()
    if pred_n not in SEVERITY_ORDER or gold_n not in SEVERITY_ORDER:
        return None
    return abs(SEVERITY_ORDER.index(pred_n) - SEVERITY_ORDER.index(gold_n))


def _id_re():
    global _ID_RE
    if _ID_RE is None:
        import re

        _ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    return _ID_RE


def code_tokens(source: str) -> List[str]:
    """Lightweight code tokenizer: identifiers only (language-agnostic)."""
    source = source or ""
    return _id_re().findall(source)


def token_set(source: str) -> Set[str]:
    return {token.lower() for token in code_tokens(source)}


def jaccard(left: Set[str], right: Set[str]) -> float:
    if not left or not right:
        return 0.0
    inter = len(left & right)
    union = len(left | right)
    return inter / float(union) if union else 0.0


def _maybe_load_st_model():
    global _ST_MODEL
    if _HAS_ST and _ST_MODEL is None and SentenceTransformer is not None:
        _ST_MODEL = SentenceTransformer("all-MiniLM-L6-v2")
    return _ST_MODEL


def sim_text(hypothesis: str, reference: str) -> float:
    """Text similarity in [0,1] with graceful degradation over backends."""
    hyp = normalize(hypothesis)
    ref = normalize(reference)
    if not hyp or not ref:
        return 0.0

    if _HAS_BERTSCORE:
        try:
            precision, recall, f1 = bert_score([hyp], [ref], lang="en", verbose=False)
            return float(f1.mean().item())
        except Exception:
            pass

    if _HAS_ST and np is not None:
        try:
            model = _maybe_load_st_model()
            if model is not None:
                hyp_vec, ref_vec = model.encode([hyp, ref], convert_to_numpy=True)
                denom = (np.linalg.norm(hyp_vec) * np.linalg.norm(ref_vec)) or 1.0
                return float((hyp_vec @ ref_vec) / denom)
        except Exception:
            pass

    if _HAS_SK:
        try:
            vectorizer = TfidfVectorizer(min_df=1, stop_words="english")
            matrix = vectorizer.fit_transform([hyp, ref])
            cosine = cosine_similarity(matrix[0:1], matrix[1:2])[0][0]
            return float(cosine)
        except Exception:
            pass

    hyp_tokens = set(hyp.lower().split())
    ref_tokens = set(ref.lower().split())
    if not hyp_tokens or not ref_tokens:
        return 0.0
    return len(hyp_tokens & ref_tokens) / float(len(hyp_tokens | ref_tokens))


def sim_code(hyp_code: str, ref_code: str) -> float:
    """Code similarity using TF-IDF char n-grams with token fallback."""
    hyp_src = hyp_code or ""
    ref_src = ref_code or ""
    if not hyp_src.strip() or not ref_src.strip():
        return 0.0

    if _HAS_SK:
        try:
            vectorizer = TfidfVectorizer(min_df=1, analyzer="char_wb", ngram_range=(3, 5))
            matrix = vectorizer.fit_transform([hyp_src, ref_src])
            cosine = cosine_similarity(matrix[0:1], matrix[1:2])[0][0]
            return float(cosine)
        except Exception:
            pass

    return jaccard(token_set(hyp_src), token_set(ref_src))


def _extract_ground_context(rule: Dict[str, Any]) -> Tuple[str, str, List[str], List[str], str]:
    intro = normalize(rule.get("description"))
    compliant_blobs: List[str] = []
    compliant_codes: List[str] = []
    noncompliant_codes: List[str] = []

    for ex in (rule.get("examples") or []):
        compliant = ex.get("compliant") if ex else None
        noncompliant = ex.get("noncompliant") if ex else None
        if compliant:
            compliant_blobs.append(
                join_nonempty(
                    [
                        normalize(compliant.get("heading")),
                        normalize(compliant.get("pre_code_commentary")),
                        normalize(compliant.get("code")),
                        normalize(compliant.get("explanation_after")),
                    ]
                )
            )
            if compliant.get("code"):
                compliant_codes.append(normalize(compliant.get("code")))
        if noncompliant and noncompliant.get("code"):
            noncompliant_codes.append(normalize(noncompliant.get("code")))

    risk_assessment = (rule.get("risk_assessment") or {}).get("explanation")
    return (
        intro,
        join_nonempty(compliant_blobs),
        compliant_codes,
        noncompliant_codes,
        normalize(risk_assessment),
    )


def _extract_noncompliant_blob(rule: Dict[str, Any]) -> str:
    parts = []
    for ex in (rule.get("examples") or []):
        noncompliant = ex.get("noncompliant") if ex else None
        if not noncompliant:
            continue
        blob = join_nonempty(
            [
                normalize(noncompliant.get("heading")),
                normalize(noncompliant.get("pre_code_commentary")),
                normalize(noncompliant.get("code")),
                normalize(noncompliant.get("explanation_after")),
            ]
        )
        if blob:
            parts.append(blob)
    return join_nonempty(parts)


def evaluate_severity(predicted: str, gold_metrics: Dict[str, Any]) -> Dict[str, Any]:
    gold = (gold_metrics or {}).get("severity")
    dist = severity_distance(predicted, gold)
    if dist is None:
        verdict = "Unknown"
    elif dist == 0:
        verdict = "Exact match"
    elif dist == 1:
        verdict = "Close (off by one)"
    else:
        verdict = f"Off by {dist}"
    return {
        "predicted": predicted or "",
        "gold": gold or "",
        "distance": dist,
        "verdict": verdict,
    }


def evaluate_priority(pred_priority: str, gold_priority: str) -> Dict[str, Any]:
    pred_clean = (pred_priority or "").strip().upper()
    gold_clean = (gold_priority or "").strip().upper()
    if not pred_clean or not gold_clean:
        verdict = "Unknown"
    elif pred_clean == gold_clean:
        verdict = "Exact match"
    else:
        verdict = "Mismatch"
    return {
        "predicted": pred_clean,
        "gold": gold_clean,
        "verdict": verdict,
    }


def _top_k_terms_from_codes(codes: List[str], k: int = 12) -> List[str]:
    from collections import Counter

    counter = Counter()
    for code in codes:
        counter.update(code_tokens(code))

    stop = {
        "int",
        "char",
        "size_t",
        "const",
        "return",
        "if",
        "else",
        "for",
        "while",
        "void",
        "struct",
        "static",
        "include",
        "define",
        "null",
        "errno",
        "file",
        "fd",
        "fp",
    }
    filtered = [(token, count) for token, count in counter.items() if token not in stop]
    filtered.sort(key=lambda item: (-item[1], item[0]))
    tokens = [token for token, _ in filtered]

    critical = {
        "open",
        "fopen",
        "close",
        "fclose",
        "fileno",
        "fstat",
        "stat",
        "fseek",
        "fflush",
        "fsync",
        "st_dev",
        "st_ino",
        "getuid",
        "getgid",
        "lseek",
    }
    prefixed = [token for token in critical if token in counter] + [token for token in tokens if token not in critical]
    seen: Set[str] = set()
    result: List[str] = []
    for token in prefixed:
        if token not in seen:
            result.append(token)
            seen.add(token)
    return result[:k]


def evaluate_issue_match(issue_text: str, issue_code: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    intro, _, _, noncompliant_codes, _ = _extract_ground_context(rule)
    noncompliant_blob = _extract_noncompliant_blob(rule)

    text_intro = sim_text(issue_text, intro)
    text_noncompliant = sim_text(issue_text, noncompliant_blob)
    code_noncompliant = (
        max([sim_code(issue_code, code) for code in noncompliant_codes], default=0.0)
        if issue_code.strip()
        else 0.0
    )

    signal = max(text_noncompliant, text_intro, code_noncompliant)
    if signal >= 0.60:
        verdict = "Likely true positive"
    elif signal >= 0.35:
        verdict = "Unclear (needs human review)"
    else:
        verdict = "Possibly spurious"

    return {
        "text_similarity_to_noncompliant": round(text_noncompliant, 3),
        "text_similarity_to_intro": round(text_intro, 3),
        "code_similarity_to_noncompliant_max": round(code_noncompliant, 3),
        "verdict": verdict,
    }


def evaluate_ai_explanation(ai_expl_text: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    intro, compliant_blob, _, _, risk_expl = _extract_ground_context(rule)
    noncompliant_blob = _extract_noncompliant_blob(rule)

    sim_risk = sim_text(ai_expl_text, risk_expl)
    sim_compliant = sim_text(ai_expl_text, compliant_blob)
    sim_intro = sim_text(ai_expl_text, intro)
    sim_noncompliant = sim_text(ai_expl_text, noncompliant_blob)

    best_positive = max(sim_risk, sim_compliant, sim_intro)
    gap_text = best_positive - sim_noncompliant

    if best_positive >= 0.65 and gap_text >= 0.20:
        label = "Explanation OK"
    elif best_positive >= 0.40 and gap_text >= 0.10:
        label = "Explanation Partial"
    else:
        label = "Explanation Misguided"

    return {
        "similarity": {
            "to_risk_explanation": round(sim_risk, 3),
            "to_compliant_text": round(sim_compliant, 3),
            "to_intro": round(sim_intro, 3),
            "to_noncompliant_text": round(sim_noncompliant, 3),
            "gap_good_minus_noncompliant": round(gap_text, 3),
        },
        "categorization": label,
    }


def evaluate_fix(
    ai_fix_text: str,
    ai_fix_code: str,
    rule: Dict[str, Any],
    issue_code: Optional[str] = None,
) -> Dict[str, Any]:
    intro, compliant_blob, compliant_codes, noncompliant_codes, risk_expl = _extract_ground_context(rule)
    noncompliant_blob = _extract_noncompliant_blob(rule)

    sim_comp_text = sim_text(ai_fix_text, compliant_blob)
    sim_intro_text = sim_text(ai_fix_text, intro)
    sim_risk_text = sim_text(ai_fix_text, risk_expl)
    sim_non_text = sim_text(ai_fix_text, noncompliant_blob) if noncompliant_blob else 0.0

    comp_code_scores = [sim_code(ai_fix_code, code) for code in compliant_codes] if compliant_codes else [0.0]
    sim_comp_code_max = max(comp_code_scores) if comp_code_scores else 0.0

    non_code_scores = [sim_code(ai_fix_code, code) for code in noncompliant_codes] if noncompliant_codes else [0.0]
    sim_non_code_max = max(non_code_scores) if non_code_scores else 0.0

    gap_text = sim_comp_text - sim_non_text
    gap_code = sim_comp_code_max - sim_non_code_max

    combined_ai_text = " ".join([ai_fix_text or "", ai_fix_code or ""])
    ai_identifiers = token_set(combined_ai_text)
    compliant_identifiers = token_set(" ".join(compliant_codes)) if compliant_codes else set()
    noncompliant_identifiers = token_set(" ".join(noncompliant_codes)) if noncompliant_codes else set()

    key_terms = _top_k_terms_from_codes(compliant_codes, k=12)
    present_keys = [token for token in key_terms if token.lower() in ai_identifiers]
    missing_keys = [token for token in key_terms if token.lower() not in ai_identifiers]
    suspicious_noncomp = sorted(list((ai_identifiers & noncompliant_identifiers) - set(present_keys)))[:12]

    comp_signal = max(sim_comp_text, sim_comp_code_max, sim_intro_text, sim_risk_text)
    penalty_noncomp = max(sim_non_text, sim_non_code_max)
    missing_penalty = 0.10 if missing_keys else 0.0
    score = comp_signal - 0.5 * penalty_noncomp - missing_penalty

    if score >= 0.60 and gap_code >= 0.15 and gap_text >= 0.10:
        label = "OK"
    elif score >= 0.35:
        label = "Partial"
    else:
        label = "Misguided"

    issue_alignment = sim_code(ai_fix_code or "", issue_code or "") if issue_code else None

    return {
        "similarity": {
            "text_to_compliant": round(sim_comp_text, 3),
            "text_to_intro": round(sim_intro_text, 3),
            "text_to_risk_explanation": round(sim_risk_text, 3),
            "text_to_noncompliant": round(sim_non_text, 3),
            "code_to_compliant_max": round(sim_comp_code_max, 3),
            "code_to_noncompliant_max": round(sim_non_code_max, 3),
            "gap_text": round(gap_text, 3),
            "gap_code": round(gap_code, 3),
            "issue_code_alignment": None if issue_alignment is None else round(issue_alignment, 3),
        },
        "identifier_analysis": {
            "key_terms_from_compliant": key_terms,
            "present_in_ai_fix": present_keys,
            "missing_from_ai_fix": missing_keys,
            "suspicious_noncompliant_terms_in_ai_fix": suspicious_noncomp,
            "ai_fix_identifier_count": len(ai_identifiers),
        },
        "categorization": label,
    }


def supporting_citations(rule: Dict[str, Any]) -> List[Dict[str, str]]:
    citations = []
    base_url = normalize(rule.get("url"))
    if base_url:
        citations.append({"title": f"{rule.get('rule_id')}. {rule.get('title')}", "url": base_url})
    for example in (rule.get("examples") or []):
        for side in ("noncompliant", "compliant"):
            section = example.get(side)
            if section and section.get("heading"):
                citations.append({"title": f"{rule.get('rule_id')} – {section.get('heading')}", "url": base_url})
    return citations
