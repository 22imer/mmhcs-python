"""
credential_store.py — JSON-based persistent storage for WebAuthn/FIDO2 credentials + TOTP.

Schema per user in credentials.json:
{
  "username": {
    "credentials": [
      {
        "user_id": "...",
        "credential_data": "..."
      }
    ],
    "totp_secret": null   // set to base32 string after TOTP setup
  }
}
"""

import json
import base64
from pathlib import Path


STORE_FILE = Path(__file__).parent / "credentials.json"


def _load_store() -> dict:
    """Load the credential store from disk."""
    if STORE_FILE.exists():
        with open(STORE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save_store(store: dict):
    """Persist the credential store to disk."""
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)


def _ensure_user(store: dict, username: str) -> dict:
    """Ensure a user entry exists with the correct shape."""
    if username not in store:
        store[username] = {"credentials": [], "totp_secret": None}
    # Migrate old flat list format → new dict format
    if isinstance(store[username], list):
        store[username] = {"credentials": store[username], "totp_secret": None}
    if "totp_secret" not in store[username]:
        store[username]["totp_secret"] = None
    return store[username]


# ── Passkey Credentials ───────────────────────────────────────────────


def save_credential(username: str, credential_data_bytes: bytes, user_id: bytes):
    """
    Save a registered credential for a user.
    totp_secret is initialised as null.
    """
    store = _load_store()
    user = _ensure_user(store, username)

    entry = {
        "user_id": base64.urlsafe_b64encode(user_id).decode("ascii"),
        "credential_data": base64.urlsafe_b64encode(credential_data_bytes).decode("ascii"),
    }

    user["credentials"].append(entry)
    _save_store(store)


def get_credentials(username: str) -> list[bytes]:
    """
    Retrieve stored credential data bytes for a user.

    Returns:
        List of raw AttestedCredentialData bytes, or empty list.
    """
    store = _load_store()
    user = _ensure_user(store, username) if username in store else None
    if not user:
        return []
    result = []
    for entry in user["credentials"]:
        raw = base64.urlsafe_b64decode(entry["credential_data"])
        result.append(raw)
    return result


def get_user_id(username: str) -> bytes | None:
    """Get the stored user_id for a username, or None if not registered."""
    store = _load_store()
    user = _ensure_user(store, username) if username in store else None
    if user and user["credentials"]:
        return base64.urlsafe_b64decode(user["credentials"][0]["user_id"])
    return None


def get_all_users() -> list[str]:
    """Return a list of all registered usernames."""
    store = _load_store()
    return list(store.keys())


def delete_credential(username: str) -> bool:
    """Delete all credentials for a user. Returns True if found and deleted."""
    store = _load_store()
    if username in store:
        del store[username]
        _save_store(store)
        return True
    return False


# ── TOTP Secret (stored inside credentials.json) ──────────────────────


def save_totp_secret(username: str, secret: str):
    """Update the totp_secret field for a user (was null, now set)."""
    store = _load_store()
    user = _ensure_user(store, username)
    user["totp_secret"] = secret
    _save_store(store)


def get_totp_secret(username: str) -> str | None:
    """Get the TOTP secret for a user, or None if not yet configured."""
    store = _load_store()
    if username not in store:
        return None
    user = _ensure_user(store, username)
    return user["totp_secret"]


def has_totp(username: str) -> bool:
    """Check if a user has TOTP configured (secret is not null)."""
    return get_totp_secret(username) is not None


def delete_totp(username: str) -> bool:
    """Reset TOTP secret back to null for a user."""
    store = _load_store()
    if username in store:
        user = _ensure_user(store, username)
        user["totp_secret"] = None
        _save_store(store)
        return True
    return False
