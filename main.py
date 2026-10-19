from fastapi import FastAPI
from models import EmailPayload, AnalysisResult
from analyzer import EmailAnalyzer

app = FastAPI(title="Email Analyzer API")

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_email(email: EmailPayload):
    # Instantiate the analyzer with the incoming payload and run it
    analyzer = EmailAnalyzer(email)
    return analyzer.analyze()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)