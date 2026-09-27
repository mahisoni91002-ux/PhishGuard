from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib

from app.analyzer import analyze_email


app = FastAPI(title="PhishGuard API")


# Allow frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Load trained ML model
model = joblib.load("phishing_model.joblib")
vectorizer = joblib.load("tfidf_vectorizer.joblib")


class EmailRequest(BaseModel):
    text: str


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "message": "PhishGuard backend is running"
    }


@app.post("/api/analyze")
def analyze(request: EmailRequest):

    email_text = request.text.strip()

    if not email_text:
        return {
            "error": "Please provide an email to analyze."
        }

    # Convert email into TF-IDF features
    email_vector = vectorizer.transform([email_text])

    # ML prediction
    prediction = model.predict(email_vector)[0]

    probabilities = model.predict_proba(email_vector)[0]

    # Probability associated with phishing class
    phishing_probability = probabilities[1]

    ml_confidence = round(phishing_probability * 100, 2)

    # Rule-based explainability analysis
    rule_analysis = analyze_email(email_text)

    # Combine ML signal and rule-based indicators
    rule_score = rule_analysis["risk_score"]

    risk_score = round(
        (ml_confidence * 0.6) + (rule_score * 0.4)
    )

    risk_score = min(max(risk_score, 0), 100)

    # Final classification
    if risk_score >= 70:
        risk_level = "High"
        classification = "Phishing"
    elif risk_score >= 40:
        risk_level = "Medium"
        classification = "Suspicious"
    else:
        risk_level = "Low"
        classification = "Likely Legitimate"

    return {
        "classification": classification,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "ml_confidence": ml_confidence,
        "indicators": rule_analysis["indicators"],
        "recommendation": (
            "Do not click links or share sensitive information. "
            "Verify the sender through an official channel."
            if risk_level in ["High", "Medium"]
            else
            "No major phishing indicators were detected, "
            "but always verify unexpected emails."
        )
    }