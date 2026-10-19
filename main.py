from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import requests
from bs4 import BeautifulSoup
import urllib.parse
from email.utils import parseaddr

app = FastAPI(title="Email Analyzer API")

class AnalysisResult(BaseModel):
    score: int
    verdict: str
    reasons: List[str]

class AttachmentMeta(BaseModel):
    name: str
    size: int

class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str  # Now expecting HTML from the Add-on
    attachments: List[AttachmentMeta] = []

def check_urlhaus(url: str) -> bool:
    """
    Queries the free URLhaus API to see if a URL is known malware.
    Returns True if malicious, False otherwise.
    """
    # Quick sanity check to avoid sending mailto: or invalid links
    if not url.startswith(("http://", "https://")):
        return False
        
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {'url': url}
    try:
        response = requests.post(api_url, data=data, timeout=3)
        if response.status_code == 200:
            result = response.json()
            # query_status is 'ok' if the URL is in their database of malware
            if result.get("query_status") == "ok":
                return True
    except requests.exceptions.RequestException as e:
        # If the API times out, we fail open (assume safe) so the Add-on doesn't crash
        print(f"URLhaus API error: {e}")
        
    return False

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_email(email: EmailPayload):
    score = 0
    reasons = []

    # 1. Basic Sender Analysis
    display_name, extracted_email = parseaddr(email.sender)
    sender_lower = extracted_email.lower()
    # A local "Allowlist" is good architecture - fast and saves API calls
    trusted_domains = ("@gmail.com", "@hit.ac.il", "@upwind.comeet-notifications.com")
    if not sender_lower.endswith(trusted_domains):
        print(f"Sender domain is external: {email.sender}")
        score += 20
        reasons.append(f"Sender domain is external to trusted networks.")

    # 2. Subject Line Analysis
    subject_lower = email.subject.lower()
    urgent_keywords = ["urgent", "action required", "suspended", "password", "invoice"]
    if any(keyword in subject_lower for keyword in urgent_keywords):
        score += 15
        reasons.append("Subject contains high-urgency or financial keywords.")

    # 3. Attachment Analysis
    dangerous_extensions = [".exe", ".vbs", ".scr", ".bat", ".js"]
    for att in email.attachments:
        name_lower = att.name.lower()
        if any(name_lower.endswith(ext) for ext in dangerous_extensions):
            score += 50
            reasons.append(f"Highly dangerous attachment type detected: {att.name}")
        
        parts = name_lower.split('.')
        if len(parts) > 2 and parts[-1] in [ext.strip('.') for ext in dangerous_extensions]:
            score += 40
            reasons.append(f"Suspicious double extension detected: {att.name}")

    # 4. Link Extraction and Threat Intelligence Analysis
    if email.body:
        soup = BeautifulSoup(email.body, "html.parser")
        # Find all <a> tags with an href attribute
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        for link in links:
            # Check against URLhaus API
            is_malicious = check_urlhaus(link)
            if is_malicious:
                score += 80 # Known malware gets a massive score increase
                reasons.append(f"Malicious link detected via Threat Intelligence (URLhaus): {link}")
                break # Once we find one malware link, no need to check the rest

    # 5. Verdict Calculation
    if score >= 70:
        verdict = "Critical Risk"
    elif score >= 40:
        verdict = "High Risk"
    elif score >= 15:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return AnalysisResult(
        score=score,
        verdict=verdict,
        reasons=reasons
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)