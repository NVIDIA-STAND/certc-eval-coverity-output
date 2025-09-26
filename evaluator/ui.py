"""Streamlit UI for the CERT-C evaluator."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import streamlit as st

from analysis import (
    _HAS_BERTSCORE,
    _HAS_SK,
    _HAS_ST,
    evaluate_ai_explanation,
    evaluate_fix,
    evaluate_issue_match,
    evaluate_priority,
    evaluate_severity,
    supporting_citations,
)
from utilities import (
    CERT_C_RULES_PATH,
    COVERITY_EXAMPLES_PATH,
    PRIORITY_OPTIONS,
    RUBRIC_PATH,
    SEVERITY_ORDER,
    join_nonempty,
    load_examples,
    load_rubric,
    load_rules,
    rule_index_by_id,
)

__all__ = ["main"]


def _apply_example_to_state(example: Dict[str, Any]) -> None:
    """Populate Streamlit inputs from a saved example payload."""
    coverity = (example.get("coverity") or {}) if isinstance(example, dict) else {}
    ai = (example.get("ai") or {}) if isinstance(example, dict) else {}

    rule_id = coverity.get("rule_id")
    if rule_id:
        st.session_state.sel_rule_id = rule_id

    st.session_state.coverity_sev = coverity.get("severity", st.session_state.get("coverity_sev", "Medium"))
    st.session_state.coverity_pri = coverity.get("priority", st.session_state.get("coverity_pri", "P1"))
    st.session_state.issue_text = coverity.get("message", "")
    st.session_state.issue_code = coverity.get("code", "")

    st.session_state.ai_sev = ai.get("identified_severity", "")
    st.session_state.ai_pri = ai.get("identified_priority", "")
    st.session_state.ai_expl = ai.get("explanation", "")
    st.session_state.ai_fix_text = ai.get("fix_narrative", "")
    st.session_state.ai_fix_code = ai.get("patch", "")


def _escape_table_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|")


def _rubric_metrics_table(metrics: Iterable[Dict[str, Any]]) -> str:
    columns: List[str] = ["Metric", "Description", "Evaluation Method", "Weight"]
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join(["---"] * len(columns)) + " |",
    ]
    for metric in metrics:
        entries = [
            _escape_table_cell(metric.get("metric")),
            _escape_table_cell(metric.get("description")),
            _escape_table_cell(metric.get("evaluation_method")),
            _escape_table_cell(metric.get("weight")),
        ]
        lines.append("| " + " | ".join(entries) + " |")
    return "\n".join(lines)


def _ensure_data_loaded() -> None:
    if "rules" not in st.session_state:
        try:
            rules = load_rules(CERT_C_RULES_PATH)
            st.session_state.rules = rules
            st.session_state.rules_by_id = rule_index_by_id(rules)
            st.session_state.rules_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.rules = []
            st.session_state.rules_by_id = {}
            st.session_state.rules_error = str(exc)

    if "examples" not in st.session_state:
        try:
            st.session_state.examples = load_examples(COVERITY_EXAMPLES_PATH)
            st.session_state.examples_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.examples = []
            st.session_state.examples_error = str(exc)

    if "rubric" not in st.session_state:
        try:
            st.session_state.rubric = load_rubric(RUBRIC_PATH)
            st.session_state.rubric_error = None
        except Exception as exc:  # noqa: BLE001
            st.session_state.rubric = None
            st.session_state.rubric_error = str(exc)


def _render_rubric_panel() -> None:
    with st.expander("Evaluation rubric", expanded=False):
        rubric = st.session_state.get("rubric")
        rubric_error = st.session_state.get("rubric_error")
        if rubric:
            metrics = rubric.get("metrics") or []
            if metrics:
                st.markdown(_rubric_metrics_table(metrics))
            else:
                st.info("Rubric does not define any metrics.")
            notes = rubric.get("notes") or {}
            if notes:
                st.markdown("**Notes**")
                for key, value in notes.items():
                    st.markdown(f"- **{key}**: {value}")
        elif rubric_error:
            st.error(f"Failed to load rubric from `{RUBRIC_PATH}`.\n\n{rubric_error}")
        else:
            st.info("No rubric available.")


def _render_backend_status(container: Any) -> None:
    backend_box = container.expander("Backends", expanded=False)
    backend_box.write(f"BERTScore available: `{_HAS_BERTSCORE}`")
    backend_box.write(f"SentenceTransformers available: `{_HAS_ST}`")
    backend_box.write(f"scikit-learn TF-IDF available: `{_HAS_SK}`")


def _render_example_selector(
    examples: List[Dict[str, Any]],
    examples_error: Optional[str],
    container: Any,
) -> bool:
    if examples:
        options = ["(none)"] + [f"example{i + 1}" for i in range(len(examples))]
        loaded_label = st.session_state.get("loaded_example_label")
        default_label = loaded_label if loaded_label in options else "(none)"
        selection = container.selectbox(
            "Choose example",
            options=options,
            index=options.index(default_label),
            key="example_selector",
        )
        if selection == "(none)":
            st.session_state.loaded_example_label = None
        elif selection != loaded_label:
            example_idx = options.index(selection) - 1
            _apply_example_to_state(examples[example_idx])
            st.session_state.example_idx = example_idx
            st.session_state.loaded_example_label = selection
        if st.session_state.get("loaded_example_label"):
            container.caption(f"Loaded {st.session_state['loaded_example_label']}")
        else:
            container.caption(f"{len(examples)} examples available")
    elif examples_error:
        container.error(f"Failed to load examples from `{COVERITY_EXAMPLES_PATH}`.\n\n{examples_error}")
    else:
        container.info("No examples available.")

    return container.button("Calculate evaluation", key="calculate_evaluation")


def _render_sidebar_controls(examples: List[Dict[str, Any]], examples_error: Optional[str]) -> bool:
    controls = st.sidebar.expander("Evaluator Controls", expanded=False)
    _render_backend_status(controls)
    return _render_example_selector(examples, examples_error, controls)


def _render_coverity_inputs(
    rules: List[Dict[str, Any]],
    rule_labels: List[str],
    default_index: int,
) -> Tuple[Dict[str, Any], str, str, str, str]:
    with st.expander("Coverity finding", expanded=False):
        selected_idx = st.selectbox(
            "Select CERT-C rule",
            options=range(len(rules)),
            format_func=lambda idx: rule_labels[idx],
            index=default_index,
            key="rule_selector",
        )
        rule = rules[selected_idx]
        st.session_state.sel_rule_id = rule.get("rule_id")

        coverity_sev = st.selectbox("Reported severity", options=SEVERITY_ORDER, key="coverity_sev")
        coverity_pri = st.selectbox("Reported priority", options=PRIORITY_OPTIONS, key="coverity_pri")
        issue_text = st.text_area("Finding description", height=190, key="issue_text")
        issue_code = st.text_area("Finding source code", height=220, key="issue_code")

    return rule, coverity_sev, coverity_pri, issue_text, issue_code


def _render_example_with_code(label: str, section: Dict[str, Any]) -> None:
    body = join_nonempty(
        [
            section.get("heading"),
            section.get("pre_code_commentary"),
            section.get("explanation_after"),
        ]
    )
    if body:
        st.markdown(f"**{label}**")
        st.write(body)
    code = section.get("code")
    if code:
        st.code(code, language="c")


def _render_json_sections(sections: Sequence[Tuple[str, Dict[str, Any]]]) -> None:
    for title, payload in sections:
        if not payload:
            continue
        st.markdown(f"**{title}**")
        st.json(payload)


def _render_rule_details(rule: Dict[str, Any]) -> None:
    with st.expander("CERT-C Rule Details", expanded=False):
        rule_id = rule.get("rule_id")
        rule_title = rule.get("title")
        rule_url = rule.get("url")
        if rule_id and rule_title and rule_url:
            st.markdown(f"[**{rule_id} — {rule_title}**]({rule_url})")
        else:
            st.markdown(f"**{rule_id or '—'} — {rule_title or '—'}**")

        risk_assessment = rule.get("risk_assessment") or {}
        metrics = risk_assessment.get("metrics") or {}
        with st.expander("Description", expanded=False):
            st.write(rule.get("description") or "—")

        with st.expander("Risk Assessment", expanded=False):
            st.markdown("**Explanation**")
            st.write((risk_assessment.get("explanation") or "").strip() or "—")
            st.markdown("**Metrics**")
            st.json(metrics or {})

        with st.expander("Examples", expanded=False):
            examples = rule.get("examples") or []
            if not examples:
                st.text("—")
            for idx, example in enumerate(examples, 1):
                st.markdown(f"**Example {idx}**")
                noncompliant = example.get("noncompliant") or {}
                compliant = example.get("compliant") or {}
                if noncompliant:
                    _render_example_with_code("Noncompliant", noncompliant)
                if compliant:
                    _render_example_with_code("Compliant", compliant)


def _render_ai_inputs() -> Tuple[str, str, str, str, str]:
    with st.expander("AI Analysis & Proposed Fix", expanded=False):
        ai_sev = st.selectbox("Identified severity", options=[""] + SEVERITY_ORDER, key="ai_sev")
        ai_pri = st.selectbox("Identified priority", options=[""] + PRIORITY_OPTIONS, key="ai_pri")
        ai_expl = st.text_area("Explanation (Why or why not this is a problem)", height=140, key="ai_expl")
        ai_fix_text = st.text_area("Fix description", height=120, key="ai_fix_text")
        ai_fix_code = st.text_area("Fix source code", height=220, key="ai_fix_code")
    return ai_sev, ai_pri, ai_expl, ai_fix_text, ai_fix_code


def _render_fix_summary(fix_eval: Dict[str, Any]) -> None:
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Similarity signals**")
        st.json(fix_eval.get("similarity", {}))
    with col_b:
        st.markdown("**Identifier & action coverage**")
        st.json(fix_eval.get("identifier_analysis", {}))
    st.markdown("**Overall fix categorization**")
    category = fix_eval.get("categorization")
    if category == "OK":
        st.success(category)
    elif category == "Partial":
        st.warning(category)
    elif category:
        st.error(category)
    else:
        st.info("No categorization computed.")


def _render_evaluation_results(
    trigger: bool,
    rule: Dict[str, Any],
    coverity_sev: str,
    coverity_pri: str,
    issue_text: str,
    issue_code: str,
    ai_sev: str,
    ai_pri: str,
    ai_expl: str,
    ai_fix_text: str,
    ai_fix_code: str,
) -> None:
    if not trigger:
        return

    with st.expander("Evaluation", expanded=False):
        gold_metrics = (rule.get("risk_assessment") or {}).get("metrics") or {}

        st.markdown("## 1) Is this really an instance of the rule?")
        issue_verdict = evaluate_issue_match(issue_text, issue_code, rule)
        st.json(issue_verdict)

        st.markdown("## 2) Severity & Priority Checks")
        coverity_vs_gold = evaluate_severity(coverity_sev, gold_metrics)
        ai_vs_gold = evaluate_severity(ai_sev, gold_metrics)
        coverity_vs_ai = evaluate_severity(coverity_sev, {"severity": ai_sev})
        _render_json_sections(
            [
                ("Coverity severity vs CERT gold", coverity_vs_gold),
                ("AI severity vs CERT gold", ai_vs_gold),
                ("Coverity severity vs AI severity", coverity_vs_ai),
            ]
        )

        gold_pri = gold_metrics.get("priority") or ""
        priority_sections: List[Tuple[str, Dict[str, Any]]] = []
        if coverity_pri or gold_pri:
            priority_sections.append(
                ("Coverity priority vs CERT priority", evaluate_priority(coverity_pri, gold_pri))
            )
        if ai_pri or gold_pri:
            priority_sections.append(
                ("AI priority vs CERT priority", evaluate_priority(ai_pri, gold_pri))
            )
        if coverity_pri or ai_pri:
            priority_sections.append(
                ("Coverity priority vs AI priority", evaluate_priority(coverity_pri, ai_pri))
            )
        _render_json_sections(priority_sections)

        st.markdown("## 3) AI Explanation Quality")
        if ai_expl.strip():
            explanation_eval = evaluate_ai_explanation(ai_expl, rule)
            st.json(explanation_eval)
        else:
            st.info("No AI explanation provided.")

        st.markdown("## 4) AI Fix Quality (text + code)")
        fix_eval = evaluate_fix(ai_fix_text, ai_fix_code, rule, issue_code=issue_code)
        _render_fix_summary(fix_eval)

        st.markdown("## 5) Supporting Resources (from CERT)")
        for citation in supporting_citations(rule):
            st.markdown(f"- [{citation['title']}]({citation['url']})")


def main() -> None:
    """Render the evaluator UI."""
    st.set_page_config(page_title="CERT-C Guided Evaluator", layout="wide")
    _ensure_data_loaded()

    st.title("Evaluation of Coverity Findings & AI Fixes")
    _render_rubric_panel()

    if not st.session_state.rules:
        rules_error = st.session_state.get("rules_error")
        if rules_error:
            st.error(f"Failed to load rules from `{CERT_C_RULES_PATH}`.\n\n{rules_error}")
        else:
            st.info("No CERT-C rules available.")
        st.stop()

    examples_error = st.session_state.get("examples_error")

    run_eval = _render_sidebar_controls(st.session_state.examples, examples_error)

    col_left, col_right = st.columns(2)

    with col_left:
        rules = st.session_state.rules
        rule_labels = [f"{rule.get('rule_id', '—')} — {rule.get('title', '—')}" for rule in rules]
        default_index = 0
        if st.session_state.get("sel_rule_id"):
            matching = [idx for idx, itm in enumerate(rules) if itm.get("rule_id") == st.session_state.sel_rule_id]
            if matching:
                default_index = matching[0]

        rule, coverity_sev, coverity_pri, issue_text, issue_code = _render_coverity_inputs(
            rules,
            rule_labels,
            default_index,
        )
        _render_rule_details(rule)

    with col_right:
        ai_sev, ai_pri, ai_expl, ai_fix_text, ai_fix_code = _render_ai_inputs()

    _render_evaluation_results(
        run_eval,
        rule,
        coverity_sev,
        coverity_pri,
        issue_text,
        issue_code,
        ai_sev,
        ai_pri,
        ai_expl,
        ai_fix_text,
        ai_fix_code,
    )


if __name__ == "__main__":
    main()
