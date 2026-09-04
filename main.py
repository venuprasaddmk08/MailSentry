from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from auth.oauth import start_login, complete_login
from gmail.client import get_gmail_service, fetch_email_list, fetch_full_message, parse_headers, get_body

app = FastAPI()

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

    # Temporary: stash creds in memory for testing Gmail calls next.
    # This will move into encrypted SQLite storage in Session 5-6.
    global last_creds
    last_creds = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }
    return {"status": "authenticated", "refresh_token_present": bool(creds.refresh_token)}

@app.get("/emails")
def list_emails():
    service = get_gmail_service(last_creds)
    messages = fetch_email_list(service, max_results=5)

    results = []
    for msg in messages:
        full = fetch_full_message(service, msg["id"])
        headers = parse_headers(full)
        body = get_body(full)
        results.append({**headers, "body_preview": body[:200]})

    return results