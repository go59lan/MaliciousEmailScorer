from fastapi import FastAPI
from pydantic import BaseModel
from typing import List
import requests
from bs4 import BeautifulSoup
from email.utils import parseaddr
from urllib.parse import urlparse
from difflib import SequenceMatcher

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
    body: str  # Expecting HTML
    attachments: List[AttachmentMeta] = []

def check_urlhaus(url: str) -> bool:
    """Queries the free URLhaus API to see if a URL is known malware."""
    if "safe-test-malware.com" in url:
        return True
        
    if not url.startswith(("http://", "https://")):
        return False
        
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {'url': url}
    try:
        response = requests.post(api_url, data=data, timeout=3)
        if response.status_code == 200:
            result = response.json()
            if result.get("query_status") == "ok":
                return True
    except requests.exceptions.RequestException as e:
        print(f"URLhaus API error: {e}")
        
    return False

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_email(email: EmailPayload):
    score = 0
    reasons = []

    # 1. Sender Analysis & Typosquatting
    display_name, extracted_email = parseaddr(email.sender)
    sender_lower = extracted_email.lower()
    sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else sender_lower
    
    trusted_domains = ("gmail.com", "hit.ac.il", "upwind.comeet-notifications.com")
    high_value_targets = ["paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com", "bankofamerica.com"]
    
    if sender_domain not in trusted_domains:
        score += 20
        reasons.append(f"Sender domain is external: {sender_lower}")

    # Typosquatting Check: Compare against high-value targets
    for target in high_value_targets:
        similarity = SequenceMatcher(None, sender_domain, target).ratio()
        # If it is between 80% and 99% similar (meaning it's close, but not exactly the real domain)
        if 0.80 <= similarity < 1.0:
            score += 60
            reasons.append(f"Typosquatting detected: '{sender_domain}' is dangerously similar to '{target}'")
            break

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

    # 4. Link Spoofing and Threat Intelligence Analysis
    if email.body:
        soup = BeautifulSoup(email.body, "html.parser")
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            display_text = a_tag.get_text(strip=True).lower()
            
            # Check 4A: Link Spoofing
            # If the visible text looks like a URL (contains a dot, no spaces)
            if "." in display_text and " " not in display_text:
                try:
                    href_domain = urlparse(href).netloc.lower()
                    # Clean up display text to extract just the domain if it has http://
                    text_domain = urlparse(display_text).netloc.lower() if display_text.startswith(('http', 'www')) else display_text
                    
                    # If the display text domain doesn't match the actual destination domain
                    if text_domain and href_domain and text_domain not in href_domain and href_domain not in text_domain:
                        score += 60
                        reasons.append(f"Link spoofing detected: Text shows '{text_domain}' but directs to '{href_domain}'")
                except Exception:
                    pass

            # Check 4B: URLhaus Malware Database
            if check_urlhaus(href):
                score += 80
                reasons.append(f"Malicious link detected via Threat Intelligence (URLhaus): {href}")
                break

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