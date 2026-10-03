import json
from jose import jwt

# Shared secret/key for test token synthesis
SECRET_KEY = "lumen-test-secret-key"
ALGORITHM = "HS256"

dana_claims = {
    "sub": "dana.admin@lumenretail.lab",
    "name": "Dana Admin",
    "groups": ["Lumen-Data-Admins"],
    "iss": "https://trial-6804593.okta.com/oauth2/default",
    "aud": "api://default",
}

alex_claims = {
    "sub": "alex.analyst@lumenretail.lab",
    "name": "Alex Analyst",
    "groups": ["Lumen-Marketing-Analysts"],
    "iss": "https://trial-6804593.okta.com/oauth2/default",
    "aud": "api://default",
}

token_dana = jwt.encode(dana_claims, SECRET_KEY, algorithm=ALGORITHM)
token_alex = jwt.encode(alex_claims, SECRET_KEY, algorithm=ALGORITHM)

with open("token_dana.txt", "w") as f:
    f.write(token_dana)

with open("token_alex.txt", "w") as f:
    f.write(token_alex)

print("[+] Successfully generated tokens:")
print(" - token_dana.txt (Lumen-Data-Admins)")
print(" - token_alex.txt (Lumen-Marketing-Analysts)")