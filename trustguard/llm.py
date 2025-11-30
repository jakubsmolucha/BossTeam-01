import os
from typing import Dict, Any, List, Optional

from openai import OpenAI

# Safety: do not hardcode keys; read from env or optional .env
API_KEY_ENV = "OPENAI_API_KEY"
MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "You are a fraud detection assistant for seniors. "
    "Assess messages for social-engineering risk: urgency, threats, credential or payment requests, suspicious URLs, impersonation. "
    "Calibrate to reduce false positives for legitimate notices from major providers (e.g., Google, Microsoft, banks). "
    "Consider sender domain and any allowlisted brands provided by the user. "
    "Return ONLY compact JSON with: score (0-100), verdict (High Risk/Caution/Likely Safe), reasons (array of strings), advice (array of strings), confidence (0-1). "
    "Score reflects risk, NOT annoyance. Legitimate notifications asking NOT to share codes should be lower risk."
)


def llm_assess_message(text: str, sender: Optional[str] = None, allowlist: Optional[List[str]] = None) -> Dict[str, Any]:
    """Call OpenAI to assess message risk. Returns a dict matching our schema.
    If no API key is set, raises RuntimeError.
    """
    # Try environment first, then optional .env file in project root
    api_key = os.getenv(API_KEY_ENV)
    if not api_key:
        # Lazy load dotenv if available
        try:
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv(API_KEY_ENV)
        except Exception:
            pass
    if not api_key:
        raise RuntimeError(
            f"Missing {API_KEY_ENV}. Set it before enabling AI checks.")
    client = OpenAI(api_key=api_key)

    sender_info = sender or "unknown"
    whitelist = ", ".join(allowlist or [])
    user_prompt = (
        "Message:\n" + (text or "") + "\n\n" +
        f"Sender domain or name: {sender_info}\n" +
        (f"User allowlist domains/brands: {whitelist}\n" if whitelist else "") +
        "\nAssess risk. If sender is in allowlist and content matches typical legitimate patterns (e.g., security alerts advising NOT to share codes), lower the score. "
        "Respond ONLY with JSON: {\n  \"score\": <0-100>,\n  \"verdict\": \"High Risk\"|\"Caution\"|\"Likely Safe\",\n  \"reasons\": [""],\n  \"advice\": [""],\n  \"confidence\": <0-1>\n}"
    )

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        content = resp.choices[0].message.content.strip()
    except Exception as e:
        # Fallback conservative response
        return {
            "score": 50,
            "verdict": "Caution",
            "reasons": [f"LLM error: {e}"],
            "advice": [
                "Do not share codes or passwords.",
                "Verify via official channels and trusted contacts."
            ],
        }

    # Attempt to parse JSON
    import json
    try:
        data = json.loads(content)
        score = int(max(0, min(100, data.get("score", 50))))
        verdict = data.get("verdict", "Caution")
        reasons = data.get("reasons", [])
        advice = data.get("advice", [])
        confidence = float(max(0.0, min(1.0, data.get("confidence", 0.6))))
        return {
            "score": score,
            "verdict": verdict,
            "reasons": reasons,
            "advice": advice,
            "confidence": confidence,
        }
    except Exception:
        # Non-JSON response fallback
        return {
            "score": 50,
            "verdict": "Caution",
            "reasons": ["LLM returned non-JSON content."],
            "advice": [
                "Avoid urgency traps; verify independently.",
                "Never share OTPs or passwords."
            ],
            "confidence": 0.5,
        }
