# VulnAI Local Prototype — Week 12 build

VulnAI is an authorised-lab cybersecurity capstone prototype. This build aligns the prototype with the latest product-owner feedback: showcase-ready UI, modular reviewed checks, saved logs, red/orange reconnaissance prioritisation, and a consistent 10-key-point reporting workflow.

## What changed
- **Modular checks:** the UI discovers reviewed modules from `attacks/<module>/manifest.json`; modules are not hard-coded into the front end.
- **Three safe demonstration modules:** TCP connectivity, HTTP security-header evidence, and service-banner evidence. They collect lab evidence only and do not exploit targets.
- **Saved evidence:** each module execution writes a JSON log to `data/logs/` and appears in assessment history.
- **Recon prioritisation:** Critical findings are red and High findings are orange, with a dedicated priority panel.
- **Reporting:** the dashboard can generate exactly 10 key points. With `OPENAI_API_KEY`, the configured model is asked for a consistent evidence-only JSON response; otherwise the prototype uses a clearly labelled deterministic fallback.
- **Validation:** ground-truth fields calculate TP/FP/TN/FN, accuracy, precision, recall and F1 instead of inventing an accuracy figure.
- **Health endpoint:** `/health` reports Nmap readiness, module count and whether a report model key is configured.

## Run on Kali
```bash
cd vulnai-local-week12
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt update
sudo apt install -y nmap
python3 app.py
```
Open `http://127.0.0.1:5000`.

## Optional LLM reporting
The prototype works without an API key. To demonstrate model-backed reporting, set a key in the shell before starting VulnAI:
```bash
export OPENAI_API_KEY='YOUR_KEY_HERE'
export VULNAI_REPORT_MODEL='gpt-4.1'
python3 app.py
```
Do not put an API key in source code, screenshots, GitHub, or the submitted report.

## Week 12 demo sequence
1. Start VulnAI and show the **Authorised Lab Mode** banner.
2. Scan your Metasploitable private IP or load known Nmap XML.
3. Show the **red/orange reconnaissance priority** panel.
4. Open a finding and explain confidence, impact and remediation.
5. Run one or more **reviewed modular checks** and open the generated log.
6. Record validation/ground truth for tested cases and show calculated metrics.
7. Generate the **10-key-point summary**.
8. Download the full HTML report.

## Safety / scope
Live scanning and modules are restricted to private or loopback IP addresses that belong to the selected assessment. Scripts are executed without a shell and only reviewed local manifests are exposed in the UI. This build is for an authorised teaching lab, not unauthorised testing.
