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

---

## Running the evaluator

```bash
# From the repository root
streamlit run evaluator/ui.py
```