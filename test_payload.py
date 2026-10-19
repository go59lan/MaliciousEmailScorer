import requests

url = "http://localhost:8000/analyze"

payload = {
    "sender": "Amazon Support <billing@ainazon.com>",
    "subject": "URGENT: Your account is suspended",
    "body": "<html>Please <a href='http://safe-test-malware.com'>click here</a> to reset.</html>",
    "attachments": [{"name": "invoice.pdf.exe", "size": 1024}]
}

response = requests.post(url, json=payload)
print(response.json())