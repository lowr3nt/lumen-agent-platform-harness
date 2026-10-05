"""
Mints local HS256 JWTs simulating an enterprise identity provider for lab personas.
"""
import argparse
import os
import time
from jose import jwt

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "lumen-test-secret-key")
ALGORITHM = "HS256"
ISSUER = "lumen-identity-provider"
AUDIENCE = "api://default"

def generate_tokens(handle: str = None):
    now = int(time.time())
    expires = now + (24 * 3600)  # 24-hour validity

    alex_sub = f"alex.analyst+{handle}@lumenretail.lab" if handle else "alex.analyst@lumenretail.lab"
    dana_sub = f"dana.admin+{handle}@lumenretail.lab" if handle else "dana.admin@lumenretail.lab"

    # Alex Analyst (Restricted)
    alex_claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": alex_sub,
        "groups": ["Lumen-Marketing-Analysts"],
        "iat": now,
        "exp": expires,
    }
    token_alex = jwt.encode(alex_claims, SECRET_KEY, algorithm=ALGORITHM)
    with open("token_alex.txt", "w") as f:
        f.write(token_alex)

    # Dana Admin (Privileged)
    dana_claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": dana_sub,
        "groups": ["Lumen-Data-Admins"],
        "iat": now,
        "exp": expires,
    }
    token_dana = jwt.encode(dana_claims, SECRET_KEY, algorithm=ALGORITHM)
    with open("token_dana.txt", "w") as f:
        f.write(token_dana)

    print("[+] Successfully generated tokens:")
    print(f"  - token_dana.txt ({dana_sub} -> Lumen-Data-Admins)")
    print(f"  - token_alex.txt ({alex_sub} -> Lumen-Marketing-Analysts)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mint test persona JWTs.")
    parser.add_argument("--handle", type=str, default=None, help="Per-student unique handle")
    args = parser.parse_args()
    generate_tokens(handle=args.handle)