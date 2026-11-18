"""Creates a .env with a fresh random JWT secret. Never overwrites an existing .env."""
import secrets
from pathlib import Path

env = Path(".env")
if env.exists():
    print(".env already exists, leaving it untouched.")
else:
    env.write_text(f"JWT_SECRET={secrets.token_hex(32)}\nDATABASE_URL=sqlite:///./iam_tool.db\n")
    print("Created .env with a new random JWT_SECRET. Do not commit this file.")
