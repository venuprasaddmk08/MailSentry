from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from analysis.auth_parser import parse_auth_results
from analysis.geoip_lookup import lookup_ip
from analysis.ip_extractor import extract_ips
from analysis.content_scorer import calculate_content_score, calculate_risk_score
from auth.crypto import decrypt_token, encrypt_token
from auth.oauth import complete_login, start_login
from db.database import get_user, init_db, save_email, save_user
from gmail.client import (
    fetch_email_list,
    fetch_full_message,
    get_body,
    get_gmail_service,
    get_user_email,
    parse_headers,
)

app = FastAPI()
init_db()

@app.get("/auth/login")
def login():
    auth_url = start_login()
    return RedirectResponse(auth_url)

@app.get("/auth/callback")
def callback(request: Request):
    state = request.query_params.get("state")
    creds = complete_login(str(request.url), state)
    if not creds:
        return {"error": "Invalid or expired state — try /auth/login again"}

    creds_dict = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

    service = get_gmail_service(creds_dict)
    user_email = get_user_email(service)

    save_user(
        user_email,
        encrypt_token(creds.refresh_token),
        creds.client_id,
        creds.client_secret,
        creds.scopes,
    )

    return {"status": "authenticated", "user_email": user_email}

@app.get("/emails")
def list_emails(user_email: str):
    user = get_user(user_email)
    if not user:
        return {"error": "User not found — log in first via /auth/login"}

    creds_dict = {
        "token": None,
        "refresh_token": decrypt_token(user["encrypted_refresh_token"]),
        "client_id": user["client_id"],
        "client_secret": user["client_secret"],
        "scopes": user["scopes"],
    }

    service = get_gmail_service(creds_dict)
    messages = fetch_email_list(service, max_results=5, include_spam=True)

    results = []
    for msg in messages:
        full = fetch_full_message(service, msg["id"])
        headers = parse_headers(full)
        body = get_body(full)
        save_email(user_email, msg["id"], headers, body)

        auth = parse_auth_results(headers["authentication_results"])
        ips = extract_ips(headers["received"])
        geo_data = [lookup_ip(ip) for ip in ips]
        content = calculate_content_score(headers["subject"], body, headers["from"])
        risk = calculate_risk_score(auth, content)

        results.append({
            **headers,
            "body_preview": body[:200],
            "spf": auth["spf"],
            "dkim": auth["dkim"],
            "dmarc": auth["dmarc"],
            "sender_ips": ips,
            "geo": geo_data,
            "content": content,
            "risk": risk,
        })

    return results