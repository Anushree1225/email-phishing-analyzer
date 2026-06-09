from fastapi import APIRouter

router = APIRouter()

@router.post("/analyze")
def analyze_email():
    return {
        "risk_score": 87,
        "severity": "High",
        "reasons": [
            {
                "type": "credential_request",
                "message": "Email asks for credentials"
            }
        ],
        "recommended_action": [
            "Do not interact with this email",
            "Report it to the security team"
        ]
    }