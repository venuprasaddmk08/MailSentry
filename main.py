from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from auth.oauth import start_login, complete_login
from auth.crypto import encrypt_token, decrypt_token
from gmail.client import (
    get_gmail_service, fetch_email_list, fetch_full_message,
    parse_headers, get_body, get_user_email
)
from db.database import init_db, save_user, get_user, save_email

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
        "token": None,  # will be refreshed automatically using refresh_token
        "refresh_token": decrypt_token(user["encrypted_refresh_token"]),
        "client_id": user["client_id"],
        "client_secret": user["client_secret"],
        "scopes": user["scopes"],
    }

    service = get_gmail_service(creds_dict)
    messages = fetch_email_list(service, max_results=5)

    results = []
    for msg in messages:
        full = fetch_full_message(service, msg["id"])
        headers = parse_headers(full)
        body = get_body(full)
        save_email(user_email, msg["id"], headers, body)
        results.append({**headers, "body_preview": body[:200]})

    return results