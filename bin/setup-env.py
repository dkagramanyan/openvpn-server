#!/usr/bin/env python3
"""Generate missing local PostgreSQL secrets without replacing existing settings."""
from pathlib import Path
import os
import re
import secrets
import tempfile

root = Path(__file__).resolve().parents[1]
path = root / ".env"
previous = path.read_text() if path.exists() else ""
text = previous
for key in ("POSTGRES_PASSWORD", "OPENVPN_DB_PASSWORD", "RELAY_POLICY_DB_PASSWORD"):
    match = re.search(r"(?m)^\s*" + key + r"\s*=([^\n]*)$", text)
    if match and match.group(1).strip() not in ("", "''", '\"\"'):
        continue
    line = key + "='" + secrets.token_urlsafe(32) + "'"
    if match: text = text[:match.start()] + line + text[match.end():]
    else: text += ("\n" if text and not text.endswith("\n") else "") + line + "\n"
# Migrate the former default auth URL to the independent evaluator.
text = re.sub(r"(?m)^APPLE_RELAY_AUTH_URL=['\"]?http://127\.0\.0\.1:8080/api/relay/authorize['\"]?\s*$",
              "APPLE_RELAY_AUTH_URL=http://127.0.0.1:8447/api/relay/authorize", text)
fd, name = tempfile.mkstemp(prefix=".env-", dir=root)
try:
    with os.fdopen(fd, "w") as stream: stream.write(text)
    Path(name).replace(path)
finally:
    Path(name).unlink(missing_ok=True)
print("PostgreSQL credentials prepared in .env; values were not printed.")
