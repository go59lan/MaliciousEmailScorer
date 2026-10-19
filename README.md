# Gmail Threat Analyzer Add-on

## Overview
This project is a professional-grade Gmail Add-on designed to perform automated phishing, malware, and social engineering analysis on incoming emails. 

It consists of a lightweight Google Apps Script (Card Service) frontend that extracts email metadata and payloads, and a Python/FastAPI backend that performs deep static analysis, threat intelligence routing, and heuristic evaluations. The UI provides users with actionable security directives based on a worst-case severity tiering model.

*Disclaimer: This project was built as a functional demonstration and prototype. The current architecture (single-instance FastAPI, local `config.json`, in-memory processing) is designed to showcase cybersecurity concepts and product thinking. It is not currently load-balanced or hardened to accept high-concurrency traffic or multi-tenant enterprise deployment.*

## Core Security Capabilities
- **In-Memory Static Analysis:** Extracts and analyzes attachments in RAM buffers without writing to disk or detonating payloads. Identifies encrypted ZIPs, hidden VBA macros inside modern Office documents (`vbaProject.bin`), and JavaScript HTML Smuggling payloads. Immune to decompression (Zip) bombs.
- **Business Email Compromise (BEC) Detection:** Compares `From` and `Reply-To` headers to detect hidden routing mismatches used in impersonation attacks.
- **Heuristic Typosquatting:** Calculates Levenshtein string distances (SequenceMatcher) to detect domains mimicking high-value targets (e.g., `paypaI.com`).
- **Link Spoofing & URL Verification:** Parses DOM structures via BeautifulSoup to detect mismatched display text and target `href` domains. Flags known URL shorteners.
- **Threat Intelligence Integration:** Queries the URLhaus API to identify known malicious domains and infrastructure.

## Architecture & Product Decisions

1. **Tiered "Worst-Case" Scoring over Additive Scoring:**
   Security risk is not additive (e.g., a polite email with a malware attachment is still Critical). The backend uses a high-watermark severity model (Safe, Low, Suspicious, High, Critical). The UI was designed to present an actionable *Debrief* (e.g., "Report to IT") rather than a meaningless numerical score.
2. **Separation of Concerns (Data vs. Logic):**
   Threat indicators (trusted domains, malicious extensions, keywords) are decoupled from the Python execution logic and stored in `config.json`. This mimics a production environment where a SOC team can update threat rules dynamically without requiring engineering to redeploy the microservice.
3. **Failing Transparently:**
   Due to Apps Script memory limits and network latency, deep static analysis is capped at 5MB attachments. If a file exceeds this limit, the system gracefully degrades: it performs the basic extension checks and returns a "Low Risk" flag, explicitly warning the user that deep analysis was bypassed due to size.

## Trade-offs & Out of Scope

* **Email Authentication Headers:** Google Apps Script abstracts away raw RFC-822 headers. In a native environment, I would extract raw headers (Authentication-Results) to validate DKIM signatures and DMARC alignment to catch raw IP spoofing.
* **Archive Formats:** The current implementation performs in-memory analysis on ZIP archives (and Office files, which are ZIP structures). Adding `.rar` or `.7z` support was omitted to avoid introducing OS-level C-library dependencies (like `unrar`) for this demo, but the logic would be identical.
* **Dynamic Sandboxing:** The backend relies purely on static analysis. Executing files in an isolated VM to analyze behavioral memory hooks is out of scope for a lightweight microservice.
* **URL Unrolling:** URL shorteners currently trigger a warning. With more time, I would implement a mechanism to send a `HEAD` request with `allow_redirects=False` to unroll the short link and scan the true destination domain.

## Getting Started

### 1. Backend Setup (FastAPI)
The backend is built with Python 3 and FastAPI. It is recommended to use a virtual environment.

```bash
# Clone the repository and navigate to the backend directory
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start the server
python main.py
```
The server will run locally on `http://0.0.0.0:8000`.

### 2. Exposing the Backend (ngrok)
Google Apps Script requires a public HTTPS endpoint to communicate with external APIs. Since the backend is running locally on your machine, we use `ngrok` to create a secure tunnel to it.

```bash
ngrok http 8000
```
*Note: If you are using the free tier of ngrok, the `https://xxxx.ngrok.app` URL will change every time you restart the ngrok service. You will need to update the Apps Script code with the new URL each time.*

### 3. Frontend Setup (Google Apps Script)
1. Go to [script.google.com](https://script.google.com).
2. Create a new project and paste the contents of `Code.gs`.
3. Update the `BACKEND_URL` variable at the top of `Code.gs` with your current ngrok URL.
4. Update the `appsscript.json` manifest file with the required Gmail scopes.
5. Deploy the script as a "Test Deployment" and install it on your Gmail account.

## Testing the Engine

Modern enterprise email gateways (like Google Workspace) will natively quarantine weaponized documents or exact typosquatted domains before they reach the inbox. To demonstrate the backend's capability against advanced evasion techniques without requiring live malware, a test harness is included.

While the FastAPI server is running, execute:
```bash
python test_payload.py
```
This script dynamically generates weaponized payloads in memory (e.g., Base64 encoded HTML smuggling and Office Macro structures) and fires them at the `/analyze` endpoint, outputting a color-coded security debrief in your terminal.