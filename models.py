from pydantic import BaseModel
from typing import List, Optional

class AttachmentMeta(BaseModel):
    name: str
    size: int
    base64_data: Optional[str] = ""

class EmailPayload(BaseModel):
    sender: str
    subject: str
    body: str 
    attachments: List[AttachmentMeta] = []

class AnalysisResult(BaseModel):
    verdict: str
    debrief: str 
    reasons: List[str]