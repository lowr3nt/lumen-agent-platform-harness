import base64
import hashlib
import http.server
import json
import os
import secrets
import socketserver
import urllib.parse
import requests

PORT = 8085
REDIRECT_URI = f"http://localhost:{PORT}/callback"

OKTA_ISSUER = os.environ.get("OKTA_ISSUER", "https://integrator-8660722.okta.com/oauth2/default")
OKTA_CLIENT_ID = os.environ.get("OKTA_CLIENT_ID", "0oa1816vjhdPpXWU1698")

if os.path.exists(".env"):
    with open(".env") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip()
    OKTA_ISSUER = os.environ.get("OKTA_ISSUER", OKTA_ISSUER)
    OKTA_CLIENT_ID = os.environ.get("OKTA_CLIENT_ID", OKTA_CLIENT_ID)

auth_code = None

class CallbackHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if "code" in params:
            auth_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>Authentication successful!</h1><p>You can close this tab and return to VS Code.</p>")
        else:
            self.send_response(400)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            err_desc = params.get("error_description", ["Unknown error"])[0]
            self.wfile.write(f"<h1>Authentication failed</h1><p>{err_desc}</p>".encode("utf-8"))

    def log_message(self, format, *args):
        return

def generate_pkce_pair():
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").replace("=", "")
    return verifier, challenge

def main():
    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)

    params = {
        "client_id": OKTA_CLIENT_ID,
        "response_type": "code",
        "scope": "openid profile email",
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "login",  # <-- FORCES OKTA TO SHOW THE LOGIN SCREEN
    }

    auth_url = f"{OKTA_ISSUER}/v1/authorize?{urllib.parse.urlencode(params)}"

    print("\n" + "=" * 80)
    print("COPY AND PASTE THIS URL INTO A FRESH PRIVATE / INCOGNITO WINDOW:")
    print("=" * 80)
    print(auth_url)
    print("=" * 80 + "\n")
    print(f"[*] Waiting for callback on port {PORT}...")

    with socketserver.TCPServer(("", PORT), CallbackHandler) as httpd:
        while auth_code is None:
            httpd.handle_request()

    token_url = f"{OKTA_ISSUER}/v1/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": OKTA_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code": auth_code,
        "code_verifier": verifier
    }

    resp = requests.post(token_url, data=token_data)
    if resp.status_code != 200:
        print(f"\n[!] Failed to exchange token: {resp.text}")
        return

    tokens = resp.json()
    token_to_save = tokens.get("access_token") or tokens.get("id_token")

    with open("token.txt", "w", encoding="utf-8") as f:
        f.write(token_to_save)

    print("\n[+] SUCCESS: Token acquired and saved to token.txt")

if __name__ == "__main__":
    main()