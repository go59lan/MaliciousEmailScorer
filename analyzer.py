import json
import base64
import io
import zipfile
import requests
from bs4 import BeautifulSoup
from email.utils import parseaddr
from urllib.parse import urlparse
from difflib import SequenceMatcher
from models import EmailPayload, AnalysisResult

try:
    with open("config.json", "r") as f:
        SECURITY_CONFIG = json.load(f)
except FileNotFoundError:
    print("WARNING: config.json not found. Falling back to default empty lists.")
    SECURITY_CONFIG = {
        "trusted_domains": [], "high_value_targets": [], 
        "dangerous_extensions": [], "urgent_keywords": []
    }

class EmailAnalyzer:
    def __init__(self, email: EmailPayload):
        self.email = email
        self.findings = []
        # Severity scale: 0=Safe, 1=Low, 2=Medium, 3=High, 4=Critical
        self.max_severity = 0 

    def analyze(self) -> AnalysisResult:
        self._check_sender()
        self._check_subject()
        self._check_attachments()
        self._check_links()
        return self._calculate_final_result()

    def _add_finding(self, severity: int, description: str):
        self.findings.append(description)
        if severity > self.max_severity:
            self.max_severity = severity

    def _check_sender(self):
        display_name, extracted_email = parseaddr(self.email.sender)
        sender_lower = extracted_email.lower()
        sender_domain = sender_lower.split('@')[-1] if '@' in sender_lower else sender_lower
        
        trusted_domains = SECURITY_CONFIG["trusted_domains"]
        high_value_targets = SECURITY_CONFIG["high_value_targets"]
        
        is_trusted = any(
            sender_domain == trusted or sender_domain.endswith("." + trusted)
            for trusted in trusted_domains
        )
        
        if not is_trusted:
            self._add_finding(1, f"Low: Sender domain is external ({sender_lower})")

        for target in high_value_targets:
            similarity = SequenceMatcher(None, sender_domain, target).ratio()
            if 0.80 <= similarity < 1.0:
                self._add_finding(3, f"High: Typosquatting detected ('{sender_domain}' mimicking '{target}')")
                break

    def _check_subject(self):
        subject_lower = self.email.subject.lower()
        urgent_keywords = SECURITY_CONFIG["urgent_keywords"]
        
        if any(keyword in subject_lower for keyword in urgent_keywords):
            self._add_finding(2, "Medium: Subject contains urgent/financial phishing keywords.")

    def _check_attachments(self):
        dangerous_extensions = SECURITY_CONFIG["dangerous_extensions"]
        
        for att in self.email.attachments:
            name_lower = att.name.lower()
            
            if any(name_lower.endswith(ext) for ext in dangerous_extensions):
                self._add_finding(4, f"Critical: Dangerous attachment type ({att.name})")
                continue
            
            if not att.base64_data:
                if att.size >= 5242880:
                    self._add_finding(1, f"Low: Attachment '{att.name}' is too large for deep static analysis. Standard extension checks were applied, but exercise caution.")
                continue

            try:
                file_bytes = base64.b64decode(att.base64_data)
                
                if name_lower.endswith(".zip"):
                    zip_buffer = io.BytesIO(file_bytes)
                    with zipfile.ZipFile(zip_buffer) as zf:
                        # Bit 0 of the flag_bits header indicates if the file requires a password
                        is_encrypted = any(zinfo.flag_bits & 0x1 for zinfo in zf.infolist())
                        if is_encrypted:
                            self._add_finding(3, f"High: Encrypted ZIP archive detected ({att.name}).")
                
                elif name_lower.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm")):
                    zip_buffer = io.BytesIO(file_bytes)
                    with zipfile.ZipFile(zip_buffer) as zf:
                        # Modern Office files are ZIP archives; vbaproject.bin indicates embedded VBA macros
                        for internal_file in zf.namelist():
                            if "vbaproject.bin" in internal_file.lower():
                                self._add_finding(4, f"Critical: Weaponized Office document detected. Contains hidden VBA Macros ({att.name}).")
                                break
                
                elif name_lower.endswith((".html", ".htm")):
                    html_text = file_bytes.decode('utf-8', errors='ignore').lower()
                    
                    # JavaScript functions commonly used for HTML smuggling to assemble payloads in-browser
                    smuggling_indicators = ["createobjecturl", "blob(", "data:application/octet-stream"]
                    
                    if any(indicator in html_text for indicator in smuggling_indicators):
                        self._add_finding(3, f"High: Potential HTML smuggling detected in attachment ({att.name}). Contains suspicious JavaScript.")

            except zipfile.BadZipFile:
                self._add_finding(2, f"Medium: Corrupted or malformed archive/document ({att.name}).")
            except Exception as e:
                print(f"Error analyzing attachment {att.name}: {e}")

    def _check_links(self):
        if not self.email.body:
            return

        soup = BeautifulSoup(self.email.body, "html.parser")
        for a_tag in soup.find_all('a', href=True):
            href = a_tag.get('href')
            display_text = a_tag.get_text(strip=True).lower()
            
            if "." in display_text and " " not in display_text:
                try:
                    href_domain = urlparse(href).netloc.lower()
                    text_domain = urlparse(display_text).netloc.lower() if display_text.startswith(('http', 'www')) else display_text
                    
                    if text_domain and href_domain and text_domain not in href_domain and href_domain not in text_domain:
                        self._add_finding(3, f"High: Link spoofing detected (Text: '{text_domain}' -> Target: '{href_domain}')")
                except Exception:
                    pass

            if self._query_urlhaus(href):
                self._add_finding(4, f"Critical: Malicious link detected via URLhaus ({href})")
                break

    def _query_urlhaus(self, url: str) -> bool:
        # Mock intercept to safely demonstrate a Critical alert during testing
        if "safe-test-malware.com" in url:
            return True
            
        if not url.startswith(("http://", "https://")):
            return False
            
        try:
            response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': url}, timeout=3)
            if response.status_code == 200 and response.json().get("query_status") == "ok":
                return True
        except requests.exceptions.RequestException:
            pass
            
        return False

    def _calculate_final_result(self) -> AnalysisResult:
        severity_map = {
            0: {
                "verdict": "Safe",
                "debrief": "No immediate threats detected. However, always exercise standard caution. Do not share personal or financial information unless you fully trust the recipient."
            },
            1: {
                "verdict": "Low Risk",
                "debrief": "Minor anomalies detected (e.g., unrecognized external sender). Proceed with standard caution. Verify the sender's identity before sharing sensitive data."
            },
            2: {
                "verdict": "Suspicious",
                "debrief": "Potential phishing indicators found. Do not execute any unexpected attachments or click unrecognized links. Verify the request out-of-band if possible."
            },
            3: {
                "verdict": "High Risk",
                "debrief": "Strong indicators of malicious intent (e.g., link spoofing or typosquatting). Do not interact with links or files. Treat this email as hostile."
            },
            4: {
                "verdict": "Critical",
                "debrief": "Explicit malware or known threats detected. DO NOT click links or download attachments. Block the sender and report this immediately to your IT/Security team."
            }
        }
        
        result_data = severity_map[self.max_severity]
        
        if not self.findings:
            self.findings.append("No suspicious indicators found.")
            
        return AnalysisResult(
            verdict=result_data["verdict"],
            debrief=result_data["debrief"],
            reasons=self.findings
        )