"""Evaluation and similarity logic for the CERT-C evaluator UI."""
from __future__ import annotations

from langchain.chat_models import init_chat_model
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from dotenv import load_dotenv
import os

load_dotenv()

def verification(rubric, ai_analysis, coverity_analysis):
    """Evaluate AI analysis against Coverity analysis using the provided rubric."""
    
    # Check if API key is available
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return "Error: GOOGLE_API_KEY environment variable not set. Please add your Google API key to the .env file."
    
    try:
        llm = init_chat_model("google_genai:gemini-2.5-flash",
                              google_api_key=api_key,
                              temperature=0,
                              timeout=30)  # Add timeout
    except Exception as e:
        return f"Error initializing LLM: {str(e)}"

    # Simplify and truncate data to avoid token limits
    def truncate_text(text, max_length=1000):
        if isinstance(text, str) and len(text) > max_length:
            return text[:max_length] + "..."
        return text

    # Prepare simplified data
    coverity_summary = {
        "rule_id": coverity_analysis.get("rule_id", ""),
        "severity": coverity_analysis.get("severity", ""),
        "priority": coverity_analysis.get("priority", ""),
        "issue_description": truncate_text(coverity_analysis.get("issue_description", "")),
        "issue_code": truncate_text(coverity_analysis.get("issue_code", ""))
    }
    
    ai_summary = {
        "identified_severity": ai_analysis.get("identified_severity", ""),
        "identified_priority": ai_analysis.get("identified_priority", ""),
        "explanation": truncate_text(ai_analysis.get("explanation", "")),
        "fix_description": truncate_text(ai_analysis.get("fix_description", "")),
        "fix_code": truncate_text(ai_analysis.get("fix_code", ""))
    }
    
    # Prepare CERT-C rule context
    cert_rule_context = f"""
    Rule ID: {coverity_analysis.get("rule_id", "Unknown")}
    Rule Title: {coverity_analysis.get("rule_title", "Unknown")}
    Rule Description: {truncate_text(coverity_analysis.get("rule_description", ""), 500)}
    Risk Assessment: {truncate_text(coverity_analysis.get("risk_assessment", ""), 300)}
    """

    # Simplified rubric text
    rubric_text = f"Rubric: {rubric.get('name', 'Evaluation Rubric')}\n\n"
    for i, metric in enumerate(rubric.get('metrics', []), 1):  # Evaluate all metrics
        rubric_text += f"{i}. {metric.get('metric', 'Unknown')}: {metric.get('description', 'No description')}\n"

    prompt_template = ChatPromptTemplate(
        [
            ("system",
             """You are an expert code analysis evaluator. Compare AI analysis against Coverity analysis for each rubric metric.

            CERT-C Rule Context:
            {cert_rule_context}
            
            Coverity Analysis:
            {coverity_analysis}
            
            AI Analysis:
            {ai_analysis}
            
            Rubric:
            {rubric}
            
            CRITICAL: You must respond with ONLY a markdown table in this exact format:
            
            | Metric | AI vs Coverity Comparison | Score/Status | Reasoning |
            |--------|---------------------------|--------------|-----------|
            | [Metric Name] | [Brief comparison] | [PASS/FAIL or 0-100] | [Short explanation] |
            
            For each rubric metric:
            1. Compare AI output vs Coverity output
            2. Give PASS/FAIL for hard requirements, or 0-100 score for others
            3. Keep reasoning under 50 words
            4. Do NOT add any text before or after the table
            5. Do NOT add explanations outside the table
            
            Focus comparisons on:
            - Severity alignment
            - Priority alignment  
            - Issue understanding alignment
            - Fix quality alignment"""
             ),
            ("human", "Return ONLY the markdown table comparing AI vs Coverity for each rubric metric.")
        ]
    )

    chain = prompt_template | llm | StrOutputParser()

    try:
        import threading
        
        result = [None]
        error = [None]
        
        def run_evaluation():
            try:
                result[0] = chain.invoke({
                    "cert_rule_context": cert_rule_context,
                    "coverity_analysis": coverity_summary,
                    "ai_analysis": ai_summary,
                    "rubric": rubric_text
                })
            except Exception as e:
                error[0] = e
        
        # Start evaluation in a separate thread
        thread = threading.Thread(target=run_evaluation)
        thread.daemon = True
        thread.start()
        
        # Wait for completion with timeout
        thread.join(timeout=60)
        
        if thread.is_alive():
            return "Error: LLM evaluation timed out after 60 seconds. Please try again."
        
        if error[0]:
            raise error[0]
        
        if result[0] is None:
            return "Error: LLM evaluation failed to complete."
        
        # Clean up the response to ensure it's a proper table
        response = result[0].strip()
        
        # Extract table if LLM added extra text
        if "| Metric |" in response:
            lines = response.split('\n')
            table_start = -1
            table_end = -1
            
            for i, line in enumerate(lines):
                if "| Metric |" in line and "AI vs Coverity" in line:
                    table_start = i
                elif table_start != -1 and line.strip() == "":
                    table_end = i
                    break
            
            if table_start != -1:
                if table_end == -1:
                    table_end = len(lines)
                table_lines = lines[table_start:table_end]
                response = '\n'.join(table_lines)
        
        # Ensure it starts with proper table format
        if not response.startswith('| Metric |'):
            return f"Error: LLM did not return proper table format. Raw response:\n\n{response}"
        
        return response
        
    except Exception as e:
        return f"Error during evaluation: {str(e)}"

