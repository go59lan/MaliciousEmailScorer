from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

app = FastAPI(title="Email Analyzer API")

# Define the expected structure of incoming data
class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str

class AnalysisResult(BaseModel):
    score: int
    verdict: str
    reasons: List[str]

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_email(email: EmailPayload):
    score = 0
    reasons = []

    # 1. Basic Sender Analysis
    sender_lower = email.sender.lower()
    if not sender_lower.endswith(("@gmail.com", "@yourcompany.com")):
        score += 20
        reasons.append("Sender domain is external or unrecognized.")

    # 2. Subject Line Analysis
    subject_lower = email.subject.lower()
    urgent_keywords = ["urgent", "action required", "suspended", "password"]
    if any(keyword in subject_lower for keyword in urgent_keywords):
        score += 30
        reasons.append("Subject contains high-urgency keywords often used in phishing.")

    # 3. Verdict Calculation
    if score >= 50:
        verdict = "High Risk"
    elif score >= 20:
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
    # Runs the server locally on port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)