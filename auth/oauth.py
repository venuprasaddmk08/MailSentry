import os
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # local dev only — remove/condition for production

from google_auth_oauthlib.flow import Flow

CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
REDIRECT_URI = "http://localhost:8000/auth/callback"

# In-memory store keyed by state — fine for local dev, not for production/multi-process
flow_store = {}

def create_flow():
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, redirect_uri=REDIRECT_URI
    )

def start_login():
    flow = create_flow()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    flow_store[state] = flow
    return auth_url

def complete_login(request_url: str, state: str):
    flow = flow_store.get(state)
    if not flow:
        return None
    flow.fetch_token(authorization_response=request_url)
    creds = flow.credentials
    del flow_store[state]
    return creds