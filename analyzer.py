import requests
from bs4 import BeautifulSoup
from email.utils import parseaddr
from urllib.parse import urlparse
from difflib import SequenceMatcher
from models import EmailPayload, AnalysisResult

class EmailAnalyzer:
    def __init__(self, email: EmailPayload):
        self.email = email
        self.score = 0
        self.reasons = []

    def analyze(self) -> AnalysisResult:
        """Executes all security checks and returns the final result."""
        self._check_sender()
        self._check_subject()
        self._check_attachments()
        self._check_links()
        return self._calculate_verdict()

    def _check_sender(self):
        display_name, extracted_email = parseaddr(self.email.sender)
        sender_lower = extracted_email.lower()
        sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else sender_lower
        
        trusted_domains = ("gmail.com", "hit.ac.il", "upwind.comeet-notifications.com")
        high_value_targets = ["paypal.com", "amazon.com", "microsoft.com", "apple.com", "google.com", "bankofamerica.com"]
        
        if sender_domain not in trusted_domains:
            self.score += 20
            self.reasons.append(f"Sender domain is external: {sender_lower}")

        for target in high_value_targets:
            similarity = SequenceMatcher(None, sender_domain, target).ratio()
            if 0.80 <= similarity < 1.0:
                self.score += 60
                self.reasons.append(f"Typosquatting detected: '{sender_domain}' is dangerously similar to '{target}'")
                break

    def _check_subject(self):
        subject_lower = self.email.subject.lower()
        urgent_keywords = ["urgent", "action required", "suspended", "password", "invoice"]
        if any(keyword in subject_lower for keyword in urgent_keywords):
            self.score += 15
            self.reasons.append("Subject contains high-urgency or financial keywords.")

    def _check_attachments(self):
        dangerous_extensions = [".exe", ".vbs", ".scr", ".bat", ".js"]
        for att in self.email.attachments:
            name_lower = att.name.lower()
            if any(name_lower.endswith(ext) for ext in dangerous_extensions):
                self.score += 50
                self.reasons.append(f"Highly dangerous attachment type detected: {att.name}")
            
            parts = name_lower.split('.')
            if len(parts) > 2 and parts[-1] in [ext.strip('.') for ext in dangerous_extensions]:
                self.score += 40
                self.reasons.append(f"Suspicious double extension detected: {att.name}")

    def _check_links(self):
        if not self.email.body:
            return

        soup = BeautifulSoup(self.email.body, "html.parser")
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            display_text = a_tag.get_text(strip=True).lower()
            
            # Link Spoofing Check
            if "." in display_text and " " not in display_text:
                try:
                    href_domain = urlparse(href).netloc.lower()
                    text_domain = urlparse(display_text).netloc.lower() if display_text.startswith(('http', 'www')) else display_text
                    
                    if text_domain and href_domain and text_domain not in href_domain and href_domain not in text_domain:
                        self.score += 60
                        self.reasons.append(f"Link spoofing detected: Text shows '{text_domain}' but directs to '{href_domain}'")
                except Exception:
                    pass

            # URLhaus Check
            if self._query_urlhaus(href):
                self.score += 80
                self.reasons.append(f"Malicious link detected via Threat Intelligence: {href}")
                break

    def _query_urlhaus(self, url: str) -> bool:
        if "safe-test-malware.com" in url:
            return True
            
        if not url.startswith(("http://", "https://")):
            return False
            
        try:
            response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': url}, timeout=3)
            if response.status_code == 200 and response.json().get("query_status") == "ok":
                return True
        except requests.exceptions.RequestException as e:
            print(f"URLhaus API error: {e}")
            
        return False

    def _calculate_verdict(self) -> AnalysisResult:
        if self.score >= 70:
            verdict = "Critical Risk"
        elif self.score >= 40:
            verdict = "High Risk"
        elif self.score >= 15:
            verdict = "Suspicious"
        else:
            verdict = "Safe"

        return AnalysisResult(score=self.score, verdict=verdict, reasons=self.reasons)