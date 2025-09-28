# CERT-C Evaluator & Tooling

This repository is a small toolkit for evaluating LLM suggested fixes of CERT-C non-compliant code :

- `evaluator/` – a Streamlit app that scores AI-generated analyses and fixes against CERT-C guidance.
- `cert-c/` – scripts for scraping the SEI CERT C Coding Standard into JSON.
- `coverity/` – sample input payloads for the evaluator.

The sections below focus on getting the evaluator running; see `cert-c/README.md` for scraper details.

## Prerequisites

- Python 3.9+ 
- Optional: a virtual environment (recommended).

## Installation

```bash
conda activate mqp    
pip install -r requirements.txt
```

## Required data files

The evaluator uses a set of JSON files alongside the app:

- `certc_rules.json` – structured CERT-C rule data. You can supply your own file or generate one via the scraper under `cert-c/`.
- `example_inputs.json` – optional example payloads that pre-fill the UI. The `coverity/` folder contains sample files.
- `evaluator/rubric.json` – rubric used to summarise evaluation metrics. A default version ships with the repo.

## Understanding the Coverity JSON Files

A key feature of this tool is its ability to process a complete, real-world Coverity finding by combining multiple data files, simulating how an enterprise application would retrieve data from various APIs.

### How the Web UI Works

The Coverity web UI acts as a dynamic client that populates its views by making separate API calls to a central server. This is exactly what you observed in the network tab.

**Main View (The Issues Table):** When a user first navigates to a project, the UI displays a high-level summary of all defects. This data is pulled from an API that returns a list of defects, similar to the data you'd find in `table.json`. This view provides key summary fields like Type, Impact, and a default Status of "New."

**Detail View (The Triage Pane):** When a user clicks on a specific defect in the table, the UI makes a series of new, targeted API calls to retrieve more detailed information:

- It fetches the raw analysis data, which is represented by `defectdetails.json` and `source.json`. This populates the main code view and the event trace pane, showing the bug's flow and the raw technical evidence.
- At the same time, it fetches the triage-specific data, represented by `defecttriage.json`. This populates the Triage pane on the right-hand side, showing the human-assigned Classification, Severity, and Action.

This dynamic process of fetching and displaying data is what makes your prototype so powerful. By ingesting these three files, the evaluator can compare the AI's autonomous judgment against a human's judgment, providing a robust and realistic measure of the AI's performance.

---

## Running the evaluator

```bash
# From the repository root
streamlit run evaluator/ui.py
```