import requests
import base64
import io
import zipfile
import json

# ==========================================
# 1. Dynamic Payload Generators
# ==========================================

def create_weaponized_docx_b64() -> str:
    """Creates a mock .docx (ZIP) containing a hidden VBA macro file in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        # The presence of this specific file triggers the macro detection
        zf.writestr("word/vbaProject.bin", b"mock malicious macro data")
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def create_html_smuggling_b64() -> str:
    """Creates a mock .html file containing JavaScript used for smuggling."""
    html_content = b"<html><body><script>let url = window.URL.createObjectURL(new Blob(['malware']));</script></body></html>"
    return base64.b64encode(html_content).decode('utf-8')

# ==========================================
# 2. The Test Cases
# ==========================================

test_cases = [
    {
        "name": "1. The 'Safe' Email (Score: 0)",
        "payload": {
            "sender": "Admin <admin@gmail.com>",
            "subject": "Lunch tomorrow?",
            "body": "<html>Hey, are we still on for lunch? <a href='https://gmail.com'>Inbox</a></html>",
            "attachments": []
        }
    },
    {
        "name": "2. The 'Low Risk' Email (Unknown sender + Oversized file)",
        "payload": {
            "sender": "Marketing <newsletter@random-startup.io>",
            "subject": "Check out our new catalog",
            "body": "<html>Attached is our new catalog.</html>",
            # Simulating a 10MB file. No base64 data is sent because it exceeds the 5MB limit.
            "attachments": [{"name": "catalog_2026.pdf", "size": 10485760, "base64_data": ""}]
        }
    },
    {
        "name": "3. The 'Suspicious' Email (Urgent Keywords)",
        "payload": {
            "sender": "Billing <noreply@external-vendor.com>",
            "subject": "URGENT: Action Required for unpaid invoice",
            "body": "<html>Please review your account immediately.</html>",
            "attachments": []
        }
    },
    {
        "name": "4. The 'High Risk' Email (Typosquatting & Link Spoofing)",
        "payload": {
            # Notice the capital 'I' instead of 'L' in paypal
            "sender": "Security <support@paypaI.com>", 
            "subject": "Security Alert",
            # The text says paypal.com, but the href points to evil-phishing.com
            "body": "<html>Please update your account: <a href='http://evil-phishing.com/login'>www.paypal.com/login</a></html>",
            "attachments": []
        }
    },
    {
        "name": "5. The 'High Risk' Email (HTML Smuggling Evasion)",
        "payload": {
            "sender": "Partner <partner@vendor.com>",
            "subject": "Secure Document Delivery",
            "body": "<html>Please open the attached secure HTML portal.</html>",
            "attachments": [{"name": "secure_portal.html", "size": 1024, "base64_data": create_html_smuggling_b64()}]
        }
    },
    {
        "name": "6. The 'Critical' Email (Weaponized DOCX Macro)",
        "payload": {
            "sender": "HR <hr@some-company.com>",
            "subject": "Updated Salary Guidelines",
            "body": "<html>Please review the attached Word document and enable macros to view.</html>",
            "attachments": [{"name": "Q3_Salary_Guidelines.docm", "size": 45000, "base64_data": create_weaponized_docx_b64()}]
        }
    },
    {
        "name": "7. The 'Critical' Email (Threat Intel Malware Hit & Double Extension)",
        "payload": {
            "sender": "Hacker <admin@hacker.net>",
            "subject": "Your receipt",
            "body": "<html>Click <a href='http://safe-test-malware.com'>here</a> to download.</html>",
            "attachments": [{"name": "receipt_document.pdf.exe", "size": 1024, "base64_data": ""}]
        }
    }
]

# ==========================================
# 3. Execution Engine
# ==========================================

def run_tests():
    url = "http://localhost:8000/analyze"
    print("\n" + "="*60)
    print("🚀 RUNNING CYBERSECURITY BACKEND TEST SUITE")
    print("="*60 + "\n")

    for idx, test in enumerate(test_cases):
        print(f"Testing: {test['name']}")
        try:
            response = requests.post(url, json=test['payload'])
            
            if response.status_code == 200:
                result = response.json()
                verdict = result['verdict']
                
                # Terminal color formatting
                color = "\033[92m" if verdict == "Safe" else "\033[94m" if verdict == "Low Risk" else "\033[93m" if verdict == "Suspicious" else "\033[95m" if verdict == "High Risk" else "\033[91m"
                reset = "\033[0m"
                
                print(f"  Result:  {color}[{verdict}]{reset}")
                print(f"  Debrief: {result['debrief']}")
                print("  Findings:")
                for reason in result['reasons']:
                    print(f"   - {reason}")
            else:
                print(f"  ❌ Failed with HTTP {response.status_code}: {response.text}")
        except requests.exceptions.ConnectionError:
            print("  ❌ Could not connect to backend. Is FastAPI running on port 8000?")
            break
        print("-" * 60)

if __name__ == "__main__":
    run_tests()