import re


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "within 24 hours",
    "final warning",
    "action required",
    "as soon as possible",
]

CREDENTIAL_WORDS = [
    "password",
    "otp",
    "verify your account",
    "verification",
    "login credentials",
    "pin",
    "credit card",
    "bank details",
]

FINANCIAL_WORDS = [
    "payment",
    "bank",
    "refund",
    "transaction",
    "money",
    "cash prize",
    "credit card",
]

THREAT_WORDS = [
    "suspended",
    "blocked",
    "closed",
    "deleted",
    "penalty",
    "legal action",
]

REWARD_WORDS = [
    "congratulations",
    "winner",
    "won",
    "free gift",
    "lottery",
    "claim your reward",
]


def analyze_email(text: str):
    """
    Detect common phishing indicators in an email.
    This is an explainability layer and does not replace the ML model.
    """

    text_lower = text.lower()

    indicators = []
    score = 0

    # Urgency
    urgency_found = [
        word for word in URGENCY_WORDS
        if word in text_lower
    ]

    if urgency_found:
        indicators.append({
            "type": "Urgency",
            "message": "The email uses urgent or time-pressure language.",
            "matches": urgency_found
        })
        score += min(len(urgency_found) * 10, 25)

    # Credential requests
    credential_found = [
        word for word in CREDENTIAL_WORDS
        if word in text_lower
    ]

    if credential_found:
        indicators.append({
            "type": "Credential Request",
            "message": "The email appears to request sensitive account information.",
            "matches": credential_found
        })
        score += min(len(credential_found) * 12, 30)

    # Financial language
    financial_found = [
        word for word in FINANCIAL_WORDS
        if word in text_lower
    ]

    if financial_found:
        indicators.append({
            "type": "Financial Language",
            "message": "The email contains payment, banking, or money-related language.",
            "matches": financial_found
        })
        score += min(len(financial_found) * 8, 20)

    # Threat language
    threat_found = [
        word for word in THREAT_WORDS
        if word in text_lower
    ]

    if threat_found:
        indicators.append({
            "type": "Threat Language",
            "message": "The email uses threats or consequences to pressure the recipient.",
            "matches": threat_found
        })
        score += min(len(threat_found) * 10, 20)

    # Reward/scam language
    reward_found = [
        word for word in REWARD_WORDS
        if word in text_lower
    ]

    if reward_found:
        indicators.append({
            "type": "Reward Language",
            "message": "The email contains prize, reward, or unexpected-winner language.",
            "matches": reward_found
        })
        score += min(len(reward_found) * 10, 20)

    # URL detection
    urls = re.findall(
        r"https?://[^\s]+|www\.[^\s]+",
        text_lower
    )

    if urls:
        indicators.append({
            "type": "Link Detected",
            "message": "The email contains one or more web links.",
            "matches": urls
        })
        score += min(len(urls) * 10, 20)

    # Suspicious shortened URLs
    shortened_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
    ]

    shortened_found = [
        domain for domain in shortened_domains
        if domain in text_lower
    ]

    if shortened_found:
        indicators.append({
            "type": "Shortened URL",
            "message": "The email contains a shortened URL that hides the destination.",
            "matches": shortened_found
        })
        score += 15

    # Keep score between 0 and 100
    score = min(score, 100)

    # Risk level
    if score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "indicators": indicators
    }