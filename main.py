from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, FileResponse

import os
from analysis.auth_parser import parse_auth_results
from analysis.geoip_lookup import lookup_ip
from analysis.ip_extractor import extract_ips
from analysis.content_scorer import calculate_content_score, calculate_risk_score
from auth.crypto import decrypt_token, encrypt_token
from auth.oauth import complete_login, start_login
from googleapiclient.errors import HttpError
from db.database import (
    get_user, init_db, save_email, save_user, get_stats, get_scanned_count,
    get_emails_by_risk, get_scanned_ids, get_emails_by_ids,
    get_cached_exact_count, set_cached_exact_count
)
from gmail.client import (
    fetch_email_list,
    fetch_full_message,
    fetch_full_messages_sequential,
    get_body,
    get_gmail_service,
    get_total_email_count,
    get_exact_email_count,
    get_user_email,
    parse_headers,
)
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
init_db()

app.mount("/static", StaticFiles(directory="static"), name="static")

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

    return RedirectResponse(f"/dashboard?user_email={user_email}")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.get("/dashboard")
def dashboard():
    return FileResponse(os.path.join(BASE_DIR, "static", "dashboard.html"))

@app.get("/emails")
def list_emails(user_email: str, max_results: int = 10, page_token: str = None):
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
    messages, next_page_token = fetch_email_list(
        service, max_results=max_results, include_spam=True, page_token=page_token
    )

    message_ids = [msg["id"] for msg in messages]

    # Skip re-scanning emails already in the database — pull them from cache instead.
    already_scanned = get_scanned_ids(user_email, message_ids)
    cached_lookup = get_emails_by_ids(user_email, list(already_scanned)) if already_scanned else {}
    new_ids = [mid for mid in message_ids if mid not in already_scanned]

    full_messages = fetch_full_messages_sequential(service, new_ids) if new_ids else []
    freshly_scored = {}

    for full in full_messages:
        try:
            headers = parse_headers(full)
            body = get_body(full)

            auth = parse_auth_results(headers["authentication_results"])
            ips = extract_ips(headers["received"])
            geo_data = [lookup_ip(ip) for ip in ips]
            content = calculate_content_score(headers["subject"], body, headers["from"])
            risk = calculate_risk_score(auth, content, headers["subject"], body, headers["from"])
            save_email(
                user_email, full["id"], headers, body,
                spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"],
                sender_ips=ips, risk_score=risk["risk_score"],
                content=content, geo=geo_data
            )

            freshly_scored[full["id"]] = {
                **headers,
                "body_preview": body[:200],
                "spf": auth["spf"],
                "dkim": auth["dkim"],
                "dmarc": auth["dmarc"],
                "sender_ips": ips,
                "geo": geo_data,
                "content": content,
                "risk": risk,
            }
        except Exception as e:
            print(f"ERROR processing email {full.get('id')}: {e}")
            continue

    # Reassemble in the original Gmail-returned order, mixing cached + freshly scored.
    results = []
    for mid in message_ids:
        if mid in freshly_scored:
            results.append(freshly_scored[mid])
        elif mid in cached_lookup:
            results.append(cached_lookup[mid])

    return {"emails": results, "next_page_token": next_page_token}

@app.get("/stats")
def stats(user_email: str):
    counts = get_stats(user_email)
    scanned = get_scanned_count(user_email)

    user = get_user(user_email)
    total = scanned  # fallback if lookup fails
    exact = False

    cached = get_cached_exact_count(user_email)
    if cached:
        total = cached["count"]
        exact = True
    elif user:
        try:
            creds_dict = {
                "token": None,
                "refresh_token": decrypt_token(user["encrypted_refresh_token"]),
                "client_id": user["client_id"],
                "client_secret": user["client_secret"],
                "scopes": user["scopes"],
            }
            service = get_gmail_service(creds_dict)
            total = get_total_email_count(service)
        except HttpError:
            total = scanned  # quota hit — just fall back gracefully, don't crash

    return {**counts, "scanned": scanned, "total": total, "total_is_exact": exact}

@app.get("/refresh_exact_count")
def refresh_exact_count(user_email: str):
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

    try:
        service = get_gmail_service(creds_dict)
        exact_count = get_exact_email_count(service)
        set_cached_exact_count(user_email, exact_count)
        return {"total": exact_count, "total_is_exact": True}
    except HttpError as e:
        if e.resp.status in (429, 403):
            return {"error": "rate_limited", "message": "Gmail API quota exceeded — try again shortly."}
        return {"error": f"Gmail API error: {e}"}

@app.get("/scan_all")
def scan_all(user_email: str, page_token: str = None, batch_size: int = 50):
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

    try:
        messages, next_page_token = fetch_email_list(
            service, max_results=batch_size, include_spam=True, page_token=page_token
        )

        message_ids = [msg["id"] for msg in messages]
        already_scanned = get_scanned_ids(user_email, message_ids)
        new_ids = [mid for mid in message_ids if mid not in already_scanned]
        skipped = len(message_ids) - len(new_ids)
        full_messages = fetch_full_messages_sequential(service, new_ids)
        processed = 0

        for full in full_messages:
            try:
                headers = parse_headers(full)
                body = get_body(full)

                auth = parse_auth_results(headers["authentication_results"])
                ips = extract_ips(headers["received"])
                content = calculate_content_score(headers["subject"], body, headers["from"])
                risk = calculate_risk_score(auth, content, headers["subject"], body, headers["from"])

                ips_for_geo = extract_ips(headers["received"])
                geo_data = [lookup_ip(ip) for ip in ips_for_geo]
                save_email(
                    user_email, full["id"], headers, body,
                    spf=auth["spf"], dkim=auth["dkim"], dmarc=auth["dmarc"],
                    sender_ips=ips, risk_score=risk["risk_score"],
                    content=content, geo=geo_data
                )
                processed += 1
            except Exception as e:
                print(f"ERROR processing email {full.get('id')}: {e}")
                continue

        scanned_so_far = get_scanned_count(user_email)
        total_mailbox = get_total_email_count(service)

        is_done = next_page_token is None or scanned_so_far >= total_mailbox

        return {
            "processed": processed,
            "skipped": skipped,
            "next_page_token": next_page_token,
            "resume_token": page_token,
            "done": is_done,
            "scanned_so_far": scanned_so_far,
            "total_mailbox": total_mailbox,
        }

    except HttpError as e:
        if e.resp.status in (429, 403):
            return {
                "error": "rate_limited",
                "message": "Gmail API quota exceeded — please wait a moment before continuing.",
                "resume_token": page_token,
            }
        return {"error": f"Gmail API error: {e}"}

@app.get("/emails_by_risk")
def emails_by_risk(user_email: str, risk_level: str = None):
    emails = get_emails_by_risk(user_email, risk_level)
    return {"emails": emails}