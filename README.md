# Malicious Email Scorer

A FastAPI service that scores email content for phishing risk. It combines a trained NLP classifier with static URL heuristics and returns a 0–100 probability plus a phishing verdict.

## Architecture

Scoring is split into two independent signals that are added together (capped at 100). An email is flagged as phishing when the combined score is greater than 50.

### NLP content analysis (Logistic Regression + TF-IDF)

Email body text is transformed with Scikit-Learn’s `TfidfVectorizer` (`max_features=5000`) and classified by a `LogisticRegression` model trained on `Phishing_Email.csv`. At inference time the model’s phishing class probability (0–1) is scaled to a 0–100 **NLP model score**.

Training artifacts:

- `vectorizer.pkl` — fitted TF-IDF vectorizer
- `phishing_model.pkl` — fitted logistic regression classifier

Retrain with:

```powershell
python train_phishing_model.py
```

### URL threat detection (static regex heuristics)

Links in the email are extracted with a regular expression and inspected without calling any external API. The heuristic layer can add up to 60 points for:

- Raw IP addresses in URLs
- Known URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, and similar)
- Suspicious keywords in the domain or path (`login`, `verify`, `password`, and similar)

The two scores are returned separately under `details.nlp_model_score` and `details.link_threat_score` from `POST /predict`.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python train_phishing_model.py
uvicorn main:app --reload
```

Then send email text to `POST /predict` as JSON: `{ "content": "..." }`.

## Future Enhancements

- **VirusTotal API integration** — replace or complement the static URL heuristics with real-time link threat scanning. Each extracted URL would be submitted to VirusTotal so reputation, malware detections, and newly registered domains can raise the link-threat score instead of relying only on regex patterns.
