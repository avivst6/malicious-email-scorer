from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import re
from urllib.parse import urlparse

app = FastAPI(title="Malicious Email Scorer API", version="2.0")

try:
    vectorizer = joblib.load("vectorizer.pkl")
    model = joblib.load("phishing_model.pkl")
except Exception as e:
    print(f"Error loading model files: {e}")

class EmailRequest(BaseModel):
    content: str

def check_malicious_links(text: str) -> int:
    urls = re.findall(r'https?://[^\s]+', text)
    if not urls:
        return 0
        
    risk_score = 0
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'auth', 'password']
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
    
    for url in urls:
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            risk_score += 40
            
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            if any(shortener in domain for shortener in shorteners):
                risk_score += 25
                
            if any(keyword in domain or keyword in path for keyword in suspicious_keywords):
                risk_score += 20
        except:
            pass
            
    return min(risk_score, 60)

@app.post("/predict")
def predict_email(email: EmailRequest):
    text = email.content
    
    if not text.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")

    X_vec = vectorizer.transform([text])
    probabilities = model.predict_proba(X_vec)[0]
    nlp_score = probabilities[1] * 100 
    
    link_score = check_malicious_links(text)
    final_score = min(round(nlp_score + link_score, 2), 100.0)
    
    is_phishing = final_score > 50.0

    return {
        "email_preview": text[:50] + "...",
        "phishing_probability": final_score,
        "is_phishing": is_phishing,
        "details": {
            "nlp_model_score": round(nlp_score, 2),
            "link_threat_score": link_score
        }
    }