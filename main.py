from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Email Scorer API")


class EmailData(BaseModel):
    sender: str
    subject: str
    bodySnippet: str
    links: Optional[List[str]] = None


@app.post("/analyze")
def analyze_email(email: EmailData):
    score = 0
    reasons = []

    subject_lower = email.subject.lower()
    urgency_keywords = ["urgent", "action required", "locked", "suspended", "alert"]
    if any(word in subject_lower for word in urgency_keywords):
        score += 3
        reasons.append("Subject contains urgent/threatening language.")

    body_lower = email.bodySnippet.lower()
    phishing_keywords = ["verify", "click here", "password", "login", "update"]
    if any(word in body_lower for word in phishing_keywords):
        score += 4
        reasons.append("Body asks for sensitive actions.")

    sender_lower = email.sender.lower()
    suspicious_domains = [".xyz", ".biz", "update", "security-alert"]
    if any(domain in sender_lower for domain in suspicious_domains):
        score += 3
        reasons.append("Sender domain looks suspicious.")

    if email.links:
        for link in email.links:
            link_lower = link.lower()
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
            if any(short in link_lower for short in shorteners):
                score += 3
                reasons.append(f"Suspicious short link detected: {link}")

            if link_lower.startswith("http://"):
                score += 2
                reasons.append(f"Insecure link (HTTP) detected: {link}")

    final_score = min(score, 10)

    if final_score >= 7:
        verdict = "High Risk (Malicious)"
    elif final_score >= 4:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        reasons.append("No obvious signs of phishing detected.")

    return {
        "score": final_score,
        "verdict": verdict,
        "reason": " | ".join(reasons)
    }