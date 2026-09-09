import base64
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

def get_gmail_service(creds_dict: dict):
    creds = Credentials(
        token=creds_dict["token"],
        refresh_token=creds_dict["refresh_token"],
        token_uri="https://oauth2.googleapis.com/token",
        client_id=creds_dict["client_id"],
        client_secret=creds_dict["client_secret"],
        scopes=creds_dict["scopes"],
    )
    return build("gmail", "v1", credentials=creds)

def fetch_email_list(service, max_results=20, include_spam=False, page_token=None):
    query = "in:anywhere" if include_spam else ""
    request_params = {"userId": "me", "maxResults": max_results, "q": query}
    if page_token:
        request_params["pageToken"] = page_token

    resp = service.users().messages().list(**request_params).execute()
    return resp.get("messages", []), resp.get("nextPageToken")

def fetch_full_message(service, msg_id):
    return service.users().messages().get(
        userId="me", id=msg_id, format="full"
    ).execute()

def fetch_full_messages_sequential(service, message_ids):
    return [fetch_full_message(service, msg_id) for msg_id in message_ids]

def parse_headers(message: dict) -> dict:
    headers = message["payload"]["headers"]
    header_map = {h["name"]: h["value"] for h in headers}
    return {
        "from": header_map.get("From"),
        "to": header_map.get("To"),
        "subject": header_map.get("Subject"),
        "date": header_map.get("Date"),
        "received": [h["value"] for h in headers if h["name"].lower() == "received"],
        "authentication_results": header_map.get("Authentication-Results"),
    }

def get_body(message: dict) -> str:
    payload = message["payload"]
    parts = payload.get("parts", [payload])
    for part in parts:
        if part.get("mimeType") == "text/plain" and "data" in part.get("body", {}):
            return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8", errors="replace")
    return ""

def get_user_email(service):
    profile = service.users().getProfile(userId="me").execute()
    return profile["emailAddress"]

def get_total_email_count(service, include_spam=True):
    """Fast but approximate — Gmail's own estimate, not exact."""
    query = "in:anywhere" if include_spam else ""
    resp = service.users().messages().list(userId="me", maxResults=1, q=query).execute()
    return resp.get("resultSizeEstimate", 0)

def get_exact_email_count(service, include_spam=True):
    """
    Slower but exact — paginates through all message IDs and counts them.
    Only fetches IDs (not full content), so it's much lighter than a full scan,
    but still makes one API call per 500 messages.
    """
    query = "in:anywhere" if include_spam else ""
    total = 0
    page_token = None

    while True:
        request_params = {
            "userId": "me",
            "maxResults": 500,
            "q": query,
            "fields": "messages/id,nextPageToken",
        }
        if page_token:
            request_params["pageToken"] = page_token

        resp = service.users().messages().list(**request_params).execute()
        messages = resp.get("messages", [])
        total += len(messages)

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return total
