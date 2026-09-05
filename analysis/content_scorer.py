import re

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "verify your account",
    "suspended", "confirm your identity", "click here", "limited time",
    "your account will be", "unusual activity", "security alert",
    "failure to", "final notice", "expire", "restricted",
]

def score_urgency(subject: str, body: str) -> dict:
    text = f"{subject} {body}".lower()
    matches = [phrase for phrase in URGENCY_PHRASES if phrase in text]
    return {
        "matched_phrases": matches,
        "urgency_score": min(len(matches) * 15, 100),  # cap at 100
    }

def extract_links(body: str) -> list[str]:
    return re.findall(r'https?://[^\s<>"\']+', body)

def score_links(body: str) -> dict:
    links = extract_links(body)
    suspicious = []
    for link in links:
        # crude heuristics: IP-based URL, excessive subdomains, url shorteners
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", link):
            suspicious.append(link)
        elif any(shortener in link for shortener in ["bit.ly", "tinyurl", "t.co", "goo.gl"]):
            suspicious.append(link)
        elif link.count(".") > 4:  # excessive subdomains, e.g. secure.login.paypal.verify.xyz.com
            suspicious.append(link)

    return {
        "total_links": len(links),
        "suspicious_links": suspicious,
        "link_score": min(len(suspicious) * 25, 100),
    }

def score_sender_mismatch(display_name: str, from_email: str) -> dict:
    """Flags cases like: From: "PayPal Security" <random123@gmail.com>"""
    known_brands = ["paypal", "google", "microsoft", "amazon", "apple", "bank", "netflix"]
    display_lower = (display_name or "").lower()
    email_lower = (from_email or "").lower()

    mismatch = False
    for brand in known_brands:
        if brand in display_lower and brand not in email_lower:
            mismatch = True
            break

    return {
        "brand_mismatch": mismatch,
        "mismatch_score": 40 if mismatch else 0,
    }

def calculate_content_score(subject: str, body: str, from_header: str) -> dict:
    # from_header looks like: "Google Play <googleplay-noreply@google.com>"
    match = re.match(r'^"?([^"<]*)"?\s*<(.+)>$', from_header or "")
    display_name = match.group(1).strip() if match else ""
    from_email = match.group(2).strip() if match else (from_header or "")

    urgency = score_urgency(subject, body)
    links = score_links(body)
    mismatch = score_sender_mismatch(display_name, from_email)

    total = min(
        urgency["urgency_score"] * 0.4 +
        links["link_score"] * 0.4 +
        mismatch["mismatch_score"] * 0.2,
        100
    )

    return {
        "urgency": urgency,
        "links": links,
        "sender_mismatch": mismatch,
        "content_risk_score": round(total, 1),
    }

def calculate_risk_score(auth: dict, content: dict) -> dict:
    auth_score = 0
    if auth["spf"] == "fail":
        auth_score += 30
    if auth["dkim"] == "fail":
        auth_score += 30
    if auth["dmarc"] == "fail":
        auth_score += 20

    total = min(auth_score + content["content_risk_score"] * 0.5, 100)

    if total >= 70:
        level = "high"
    elif total >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": round(total, 1),
        "risk_level": level,
    }