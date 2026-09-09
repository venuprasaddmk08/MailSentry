import os
import json
from groq import Groq
_client = None
def get_client():
    global _client
    if _client is None:
        _client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    return _client
def score_with_ai(subject: str, body: str, from_header: str, spf: str, dkim: str, dmarc: str) -> dict:
    """
    Uses an LLM to assess phishing risk with real reasoning,
    correcting false positives/negatives from rule-based heuristics.
    """
    try:
        client = get_client()
        prompt = f"""You are a phishing detection expert. Analyze this email and assess whether it is a phishing/scam attempt or a legitimate email.
From: {from_header}
Subject: {subject}
Authentication: SPF={spf}, DKIM={dkim}, DMARC={dmarc}
Body (truncated):
{body[:2000]}
Respond ONLY with valid JSON in this exact format, no other text, no markdown:
{{
  "ai_risk_score": <integer 0-100, where 0 is definitely legitimate and 100 is definitely phishing>,
  "verdict": "<one of: legitimate, suspicious, likely_phishing>",
  "reasoning": "<one or two sentences explaining your assessment>",
  "red_flags": ["<specific concerning element>", ...]
}}
Consider: Legitimate companies (Microsoft, Google, game companies, etc.) commonly send account notifications, marketing emails, and use redirect/tracking links � these are NOT inherently suspicious. Focus on genuine social engineering signals: impersonation of a different brand than the actual sender domain, urgent threats combined with unusual requests (wiring money, gift cards, credential harvesting via fake login pages), or content that doesn't match a legitimate business purpose."""
        response = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        text = response.choices[0].message.content.strip()
        text = text.replace("```json", "").replace("```", "").strip()
        result = json.loads(text)
        return {
            "ai_risk_score": result.get("ai_risk_score", 0),
            "verdict": result.get("verdict", "unknown"),
            "reasoning": result.get("reasoning", ""),
            "red_flags": result.get("red_flags", []),
        }
    except Exception as e:
        print(f"AI scoring error: {e}")
        return None
