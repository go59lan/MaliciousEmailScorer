from pydantic import BaseModel
from typing import List

class AttachmentMeta(BaseModel):
    name: str
    size: int

class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str 
    attachments: List[AttachmentMeta] = []

class AnalysisResult(BaseModel):
    score: int
    verdict: str
    reasons: List[str]