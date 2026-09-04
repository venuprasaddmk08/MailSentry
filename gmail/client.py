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

def fetch_email_list(service, max_results=20):
    resp = service.users().messages().list(
        userId="me", maxResults=max_results
    ).execute()
    return resp.get("messages", [])

def fetch_full_message(service, msg_id):
    return service.users().messages().get(
        userId="me", id=msg_id, format="full"
    ).execute()

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