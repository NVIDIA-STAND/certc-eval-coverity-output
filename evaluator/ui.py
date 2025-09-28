"""Streamlit UI for the CERT-C evaluator."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import io
import json

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

# Mapping from Coverity checker names to CERT-C rules for auto-suggestion
# Based on semantic analysis of CERT-C rule content
CHECKER_TO_CERT_MAPPING = {
    "TAINTED_STRING": "FIO02-C",  # Best match: "Canonicalize path names originating from tainted sources"
    # Alternative relevant rules for TAINTED_STRING: INT04-C, FIO30-C
    # Add more mappings only when you encounter real Coverity checker names
}

# Semantic keywords that help identify relevant CERT-C rules
TAINTED_DATA_RULES = ["FIO02-C", "INT04-C", "FIO30-C"]  # Rules mentioning "tainted"

# Mapping Coverity checker names to typical Impact levels (since JSON export doesn't include Impact)
CHECKER_TO_IMPACT_MAPPING = {
    "TAINTED_STRING": "High",  # Tainted data issues are typically high impact
    # Add more as you encounter real checker names
}

# Mapping Coverity severity to evaluation pipeline severity
COVERITY_SEVERITY_MAPPING = {
    "Major": "High",
    "Moderate": "Medium",
    "Minor": "Low", 
    "Unspecified": "Unspecified"  # Keep as-is, don't assume Medium
}


def _parse_defect_details(json_str: str) -> Tuple[bool, Dict[str, Any], str]:
    """Parse defectdetails.json content."""
    try:
        data = json.loads(json_str) if json_str.strip() else {}
        return True, data, ""
    except json.JSONDecodeError as e:
        return False, {}, f"Invalid JSON: {str(e)}"


def _parse_defect_triage(json_str: str) -> Tuple[bool, Dict[str, Any], str]:
    """Parse defecttriage.json content."""
    try:
        data = json.loads(json_str) if json_str.strip() else {}
        return True, data, ""
    except json.JSONDecodeError as e:
        return False, {}, f"Invalid JSON: {str(e)}"


def _parse_source_json(json_str: str) -> Tuple[bool, Dict[str, Any], str]:
    """Parse source.json content (required file with Impact data)."""
    if not json_str.strip():
        return False, {}, "source.json content is required"
    try:
        data = json.loads(json_str)
        return True, data, ""
    except json.JSONDecodeError as e:
        return False, {}, f"Invalid JSON: {str(e)}"


def _extract_coverity_values(details_data: Dict[str, Any], triage_data: Dict[str, Any], source_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """Extract key values from raw Coverity JSON data."""
    
    # From defectdetails.json
    checker_name = details_data.get("checkerName", "")
    short_desc = details_data.get("shortDescription", "")
    long_desc = details_data.get("longDescription", "")
    local_effect = details_data.get("localEffect", "")
    cwe_category = details_data.get("cweCategory", "")
    function_name = details_data.get("functionName", "")
    defect_id = details_data.get("defectInstanceId", "")
    
    # Combine descriptions for issue_text
    issue_text = join_nonempty([short_desc, long_desc, local_effect])
    
    # Extract code context from occurrences
    issue_code = _extract_code_context(details_data.get("occurrences", []))
    
    # Extract Impact from source.json if available, otherwise use triage severity
    impact_from_source = None
    if source_data and "defects" in source_data:
        defects = source_data.get("defects", [])
        if defects and len(defects) > 0:
            impact_from_source = defects[0].get("impact")
    
    # Extract triage data first
    triage_severity = "Unspecified"
    classification = "Unclassified"
    action = "Undecided"
    
    attributes = triage_data.get("attributes", [])
    for attr in attributes:
        display_name = attr.get("displayName", "")
        column_value = attr.get("columnValue", "")
        
        if display_name == "Severity":
            triage_severity = COVERITY_SEVERITY_MAPPING.get(column_value, "Unspecified")
        elif display_name == "Classification":
            classification = column_value
        elif display_name == "Action":
            action = column_value
    
    # Prioritize Impact from source.json over triage severity
    severity = impact_from_source if impact_from_source else triage_severity
    
    # Other triage info
    defect_status = triage_data.get("defectStatus", "")
    owner = triage_data.get("ownerDisplayUsername", "")
    
    return {
        "checker_name": checker_name,
        "issue_text": issue_text,
        "issue_code": issue_code,
        "severity": severity,  # Uses Impact from source.json if available, otherwise triage severity
        "impact_note": f"Impact source: {'source.json' if impact_from_source else 'triage data'}",
        "classification": classification,
        "action": action,
        "cwe_category": cwe_category,
        "function_name": function_name,
        "defect_id": defect_id,
        "defect_status": defect_status,
        "owner": owner,
        "short_description": short_desc,
        "long_description": long_desc,
        "local_effect": local_effect
    }


def _extract_code_context(occurrences: List[Dict[str, Any]]) -> str:
    """Extract code context from Coverity occurrences."""
    code_lines = []
    
    for occurrence in occurrences:
        event_sets = occurrence.get("eventSets", [])
        for event_set in event_sets:
            caption = event_set.get("caption", "")
            if caption:
                code_lines.append(f"// {caption}")
            
            event_tree = event_set.get("eventTree", [])
            for event in event_tree:
                filename = event.get("filename", "")
                line_number = event.get("lineNumber", "")
                description = event.get("description", "")
                
                if filename and line_number and description:
                    # Clean up HTML entities
                    clean_desc = description.replace("&quot;", '"').replace("&amp;", "&")
                    code_lines.append(f"// {filename}:{line_number} - {clean_desc}")
    
    return "\n".join(code_lines) if code_lines else "// No code context available"


def _suggest_cert_rule(checker_name: str, rules: List[Dict[str, Any]]) -> Optional[int]:
    """Suggest CERT-C rule index based on checker name."""
    suggested_rule_id = CHECKER_TO_CERT_MAPPING.get(checker_name)
    if suggested_rule_id:
        for idx, rule in enumerate(rules):
            if rule.get("rule_id") == suggested_rule_id:
                return idx
    return None


def _apply_example_to_state(example: Dict[str, Any]) -> None:
    """Populate Streamlit inputs from a saved example payload."""
    coverity = (example.get("coverity") or {}) if isinstance(example, dict) else {}
    triage = (example.get("triage") or {}) if isinstance(example, dict) else {}
    ai = (example.get("ai") or {}) if isinstance(example, dict) else {}

    # Set raw JSON content for Coverity data (separate files)
    st.session_state.defect_details_json = json.dumps(coverity, indent=2)
    st.session_state.defect_triage_json = json.dumps(triage, indent=2)

    # Set AI data (unchanged)
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
    # Hidden - users don't need to see technical backend details
    pass


def _render_example_selector(
    examples: List[Dict[str, Any]],
    examples_error: Optional[str],
    container: Any,
) -> None:
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

    # Button moved to main area - no longer returned from here
    pass


def _render_sidebar_controls(examples: List[Dict[str, Any]], examples_error: Optional[str]) -> None:
    controls = st.sidebar.expander("Example Data", expanded=False)
    _render_example_selector(examples, examples_error, controls)


def _render_coverity_inputs(
    rules: List[Dict[str, Any]],
    rule_labels: List[str],
    default_index: int,
) -> Tuple[Dict[str, Any], Dict[str, Any], bool]:
    with st.expander("Coverity Finding (Raw JSON)", expanded=False):
        st.markdown("**Input Coverity JSON Data:**")
        
        # File upload option
        st.markdown("**Option 1: Upload Files**")
        col_upload1, col_upload2, col_upload3 = st.columns(3)
        
        with col_upload1:
            details_file = st.file_uploader(
                "Upload defectdetails.json",
                type=["json"],
                key="details_file_upload"
            )
        
        with col_upload2:
            triage_file = st.file_uploader(
                "Upload defecttriage.json", 
                type=["json"],
                key="triage_file_upload"
            )
            
        with col_upload3:
            source_file = st.file_uploader(
                "Upload source.json (for Impact)",
                type=["json"],
                key="source_file_upload",
                help="Required: Contains Impact assessment from Coverity UI"
            )
        
        # Get content from files or text areas
        defect_details_json = ""
        defect_triage_json = ""
        source_json = ""
        
        if details_file is not None:
            details_content = details_file.read().decode("utf-8")
            st.session_state.defect_details_json = details_content
            defect_details_json = details_content
        else:
            defect_details_json = st.session_state.get("defect_details_json", "")
        
        if triage_file is not None:
            triage_content = triage_file.read().decode("utf-8")
            st.session_state.defect_triage_json = triage_content
            defect_triage_json = triage_content
        else:
            defect_triage_json = st.session_state.get("defect_triage_json", "")
            
        if source_file is not None:
            source_content = source_file.read().decode("utf-8")
            st.session_state.source_json = source_content
            source_json = source_content
        else:
            source_json = st.session_state.get("source_json", "")
        
        st.markdown("**Option 2: Paste JSON Content**")
        
        # JSON input text areas
        defect_details_json = st.text_area(
            "defectdetails.json content:",
            value=defect_details_json,
            height=300,
            key="defect_details_json",
            placeholder='Paste the contents of defectdetails.json here or upload file above...'
        )
        
        defect_triage_json = st.text_area(
            "defecttriage.json content:",
            value=defect_triage_json,
            height=200, 
            key="defect_triage_json",
            placeholder='Paste the contents of defecttriage.json here or upload file above...'
        )
        
        source_json = st.text_area(
            "source.json content (Required - for Impact):",
            value=source_json,
            height=200,
            key="source_json",
            placeholder='Paste the contents of source.json here or upload file above...',
            help="This file contains the Impact field from Coverity UI"
        )
        
        # Parse JSON and validate
        details_valid, details_data, details_error = _parse_defect_details(defect_details_json)
        triage_valid, triage_data, triage_error = _parse_defect_triage(defect_triage_json)
        source_valid, source_data, source_error = _parse_source_json(source_json)
        
        # Show validation status with detailed errors
        col1, col2, col3 = st.columns(3)
        with col1:
            if defect_details_json.strip():
                if details_valid:
                    st.success("✅ defectdetails.json is valid")
                else:
                    st.error(f"❌ defectdetails.json validation failed:")
                    st.code(details_error, language="text")
            else:
                st.info("📝 Provide defectdetails.json content")
        
        with col2:
            if defect_triage_json.strip():
                if triage_valid:
                    st.success("✅ defecttriage.json is valid")
                else:
                    st.error(f"❌ defecttriage.json validation failed:")
                    st.code(triage_error, language="text")
            else:
                st.info("📝 Provide defecttriage.json content")
                
        with col3:
            if source_json.strip():
                if source_valid:
                    st.success("✅ source.json is valid")
                else:
                    st.error(f"❌ source.json validation failed:")
                    st.code(source_error, language="text")
            else:
                st.info("📝 Provide source.json content")
        
        # Extract and display parsed values only if ALL three files are valid
        extracted_values = {}
        # Require all three files: defectdetails.json, defecttriage.json, and source.json
        json_valid = (details_valid and triage_valid and source_valid and 
                     defect_details_json.strip() and defect_triage_json.strip() and source_json.strip())
        
        if json_valid:
            # Debug: Show what was extracted from source.json (only after all files are processed)
            if source_json.strip():
                if source_valid and source_data and "defects" in source_data:
                    defects = source_data.get("defects", [])
                    if defects and len(defects) > 0:
                        impact_debug = defects[0].get("impact")
                        st.success(f"🔍 Debug: Found Impact '{impact_debug}' in source.json")
                    else:
                        st.warning("🔍 Debug: No defects found in source.json")
                elif source_valid and source_data:
                    st.warning("🔍 Debug: source.json loaded but no 'defects' key found")
                elif not source_valid:
                    st.error("🔍 Debug: source.json is invalid")
            else:
                st.info("🔍 Debug: No source.json data provided - using triage severity")
            
            # Always re-extract values when JSON data changes (don't cache in session state here)
            # This ensures source.json changes are immediately reflected
            extracted_values = _extract_coverity_values(details_data, triage_data, source_data)
            
            # Update session state for the editable form
            if 'extracted_values' not in st.session_state or st.session_state.get('force_refresh', False):
                st.session_state.extracted_values = extracted_values
                st.session_state.force_refresh = False
            else:
                # Use session state values if they exist (user may have edited them)
                extracted_values = st.session_state.extracted_values
            
            # Editable parsed data section
            st.markdown("**📝 Parsed Data (Editable):**")
            st.markdown("*Edit the values below if the JSON export is missing data or incorrect:*")
            
            # Create editable form for parsed data
            with st.form("parsed_data_form"):
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("**From defectdetails.json:**")
                    edited_checker = st.text_input("Checker Name", value=extracted_values['checker_name'])
                    edited_cwe = st.number_input("CWE Category", value=int(extracted_values['cwe_category']) if extracted_values['cwe_category'] else 0, min_value=0)
                    edited_function = st.text_input("Function Name", value=extracted_values['function_name'])
                    edited_defect_id = st.text_input("Defect ID", value=str(extracted_values['defect_id']))
                
                with col2:
                    st.markdown("**From defecttriage.json:**")
                    edited_classification = st.selectbox(
                        "Classification", 
                        options=["Unclassified", "Bug", "Intentional", "False Positive", "Pending"],
                        index=["Unclassified", "Bug", "Intentional", "False Positive", "Pending"].index(extracted_values['classification']) if extracted_values['classification'] in ["Unclassified", "Bug", "Intentional", "False Positive", "Pending"] else 0
                    )
                    edited_action = st.selectbox(
                        "Action", 
                        options=["Undecided", "Fix Required", "Fix Submitted", "Modeling Required", "Ignore", "On Hold"],
                        index=["Undecided", "Fix Required", "Fix Submitted", "Modeling Required", "Ignore", "On Hold"].index(extracted_values['action']) if extracted_values['action'] in ["Undecided", "Fix Required", "Fix Submitted", "Modeling Required", "Ignore", "On Hold"] else 0
                    )
                    edited_status = st.text_input("Defect Status", value=extracted_values['defect_status'])
                    edited_owner = st.text_input("Owner", value=extracted_values['owner'])
                
                with col3:
                    st.markdown("**From source.json:**")
                    edited_severity = st.selectbox(
                        "Severity (Impact from Coverity)", 
                        options=["Unspecified", "Low", "Medium", "High", "Critical"],
                        index=["Unspecified", "Low", "Medium", "High", "Critical"].index(extracted_values['severity']) if extracted_values['severity'] in ["Unspecified", "Low", "Medium", "High", "Critical"] else 0
                    )
                
                # Descriptions span full width
                st.markdown("**Descriptions:**")
                edited_short_desc = st.text_input("Short Description", value=extracted_values['short_description'])
                edited_long_desc = st.text_area("Long Description", value=extracted_values['long_description'], height=120)
                
                st.markdown("**Code Context:**")
                edited_code = st.text_area("Issue Code Context", value=extracted_values['issue_code'], height=150)
                
                # Form submit button
                update_data = st.form_submit_button("🔄 Update Parsed Data")
                
                # Update extracted_values if form is submitted
                if update_data:
                    # Update session state with edited values
                    st.session_state.extracted_values = {
                        "checker_name": edited_checker,
                        "cwe_category": edited_cwe,
                        "function_name": edited_function,
                        "defect_id": edited_defect_id,
                        "short_description": edited_short_desc,
                        "long_description": edited_long_desc,
                        "severity": edited_severity,
                        "classification": edited_classification,
                        "action": edited_action,
                        "defect_status": edited_status,
                        "owner": edited_owner,
                        "issue_code": edited_code,
                        "issue_text": join_nonempty([edited_short_desc, edited_long_desc]),
                        "impact_note": "User edited data"
                    }
                    # Update local variable too
                    extracted_values = st.session_state.extracted_values
                    st.success("✅ Data updated! You can now proceed with evaluation.")
                    st.rerun()  # Force a rerun to update the display
            
            # Show current values summary
            st.markdown("**📋 Current Values for Evaluation:**")
            st.info(
                f"**{extracted_values['checker_name']}** | "
                f"Severity: **{extracted_values['severity']}** | "
                f"CWE: **{extracted_values['cwe_category']}** | "
                f"Function: **{extracted_values['function_name']}**"
            )
            
            # Auto-suggest CERT-C rule
            suggested_idx = _suggest_cert_rule(extracted_values['checker_name'], rules)
            if suggested_idx is not None:
                st.session_state.suggested_rule_idx = suggested_idx
                st.info(f"💡 Suggested CERT-C rule: **{rules[suggested_idx]['rule_id']}** - {rules[suggested_idx]['title']}")
        else:
            # Show message when required files are missing
            st.warning("⏳ **Waiting for required files**: Please upload all three files (defectdetails.json, defecttriage.json, and source.json) to begin parsing.")
        
        # CERT-C rule selection
        st.markdown("**Select CERT-C Rule:**")
        rule_idx = default_index
        if json_valid and 'suggested_rule_idx' in st.session_state:
            rule_idx = st.session_state.suggested_rule_idx
            
        selected_idx = st.selectbox(
            "CERT-C rule to evaluate against:",
            options=range(len(rules)),
            format_func=lambda idx: rule_labels[idx],
            index=rule_idx,
            key="rule_selector",
        )
        rule = rules[selected_idx]
        st.session_state.sel_rule_id = rule.get("rule_id")

    return rule, extracted_values, json_valid


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
        
        st.markdown("### Description")
        st.write(rule.get("description") or "—")

        st.markdown("### Risk Assessment")
        st.markdown("**Explanation**")
        st.write((risk_assessment.get("explanation") or "").strip() or "—")
        st.markdown("**Metrics**")
        st.json(metrics or {})

        st.markdown("### Examples")
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
    extracted_values: Dict[str, Any],
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

        # Extract values from Coverity data
        issue_text = extracted_values.get("issue_text", "")
        issue_code = extracted_values.get("issue_code", "")
        coverity_sev = extracted_values.get("severity", "Medium")
        coverity_classification = extracted_values.get("classification", "Unclassified")

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
        if coverity_classification or gold_pri:
            priority_sections.append(
                ("Coverity classification vs CERT priority", evaluate_priority(coverity_classification, gold_pri))
            )
        if ai_pri or gold_pri:
            priority_sections.append(
                ("AI priority vs CERT priority", evaluate_priority(ai_pri, gold_pri))
            )
        if coverity_classification or ai_pri:
            priority_sections.append(
                ("Coverity classification vs AI priority", evaluate_priority(coverity_classification, ai_pri))
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

    _render_sidebar_controls(st.session_state.examples, examples_error)

    col_left, col_right = st.columns(2)

    with col_left:
        rules = st.session_state.rules
        rule_labels = [f"{rule.get('rule_id', '—')} — {rule.get('title', '—')}" for rule in rules]
        default_index = 0
        if st.session_state.get("sel_rule_id"):
            matching = [idx for idx, itm in enumerate(rules) if itm.get("rule_id") == st.session_state.sel_rule_id]
            if matching:
                default_index = matching[0]

        rule, extracted_values, json_valid = _render_coverity_inputs(
            rules,
            rule_labels,
            default_index,
        )
        _render_rule_details(rule)

    with col_right:
        ai_sev, ai_pri, ai_expl, ai_fix_text, ai_fix_code = _render_ai_inputs()

    # Evaluate button after both columns
    st.markdown("---")
    st.markdown("### 🚀 Ready to Evaluate?")
    
    if json_valid:
        run_eval = st.button(
            "🚀 Calculate Evaluation", 
            type="primary", 
            key="calculate_evaluation",
            help="Compare Coverity findings with AI responses against CERT-C standards"
        )
    else:
        st.button(
            "🚀 Calculate Evaluation", 
            type="primary", 
            disabled=True, 
            key="calculate_evaluation_disabled"
        )
        st.error("❌ Please provide valid JSON for both Coverity files before evaluation")
        run_eval = False

    _render_evaluation_results(
        run_eval,
        rule,
        st.session_state.get('extracted_values', extracted_values),
        ai_sev,
        ai_pri,
        ai_expl,
        ai_fix_text,
        ai_fix_code,
    )


if __name__ == "__main__":
    main()
