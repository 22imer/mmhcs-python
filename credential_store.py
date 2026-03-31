"""
credential_store.py — MongoDB-backed persistent storage for WebAuthn/FIDO2 credentials + TOTP.

Uses the 'auth' collection in the same MongoDB database (chatap) as the Chatify backend.
Validates usernames against the 'users' collection.

Schema per document in the 'auth' collection:
{
  "username": "...",
  "credentials": [
    {
      "user_id": "...",         // base64url-encoded WebAuthn user handle
      "credential_data": "..."  // base64url-encoded AttestedCredentialData
    }
  ],
  "totp_secret": null           // set to base32 string after TOTP setup
}
"""

import os
import base64

from dotenv import load_dotenv
from pathlib import Path
from pymongo import MongoClient

# ── Load environment ──────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / ".env")

_MONGO_URI = os.getenv("MONGO_URI", "")

# ── Database helpers ──────────────────────────────────────────────────

def _get_db():
    """Return a (client, db) tuple. Caller should close client when done."""
    client = MongoClient(_MONGO_URI)
    db = client["chatap"]
    return client, db


def _get_auth_collection():
    """Return (client, auth_collection)."""
    client, db = _get_db()
    return client, db["auth"]


def _get_users_collection():
    """Return (client, users_collection)."""
    client, db = _get_db()
    return client, db["users"]


# ── Username validation against users table ───────────────────────────


def validate_username(username: str) -> bool:
    """
    Check if a username exists in the Chatify 'users' collection.
    Matches against the 'fullName' field in the users table.
    Returns True if the user exists.
    """
    client, users = _get_users_collection()
    try:
        # Match by fullName (username in the desktop app maps to fullName)
        user = users.find_one({
            "$or": [
                {"fullName": username},
                {"email": f"{username}@gmail.com"},
            ]
        })
        return user is not None
    finally:
        client.close()


def get_user_from_users_table(username: str) -> dict | None:
    """
    Look up a user from the Chatify 'users' collection by username.
    Returns the user document or None.
    """
    client, users = _get_users_collection()
    try:
        user = users.find_one({
            "$or": [
                {"fullName": username},
                {"email": f"{username}@gmail.com"},
            ]
        })
        return user
    finally:
        client.close()


# ── Auth document helpers ─────────────────────────────────────────────


def _ensure_auth_doc(username: str) -> dict:
    """
    Ensure an auth document exists for the username.
    Creates one if it doesn't exist. Returns the document.
    """
    client, auth = _get_auth_collection()
    try:
        doc = auth.find_one({"username": username})
        if not doc:
            doc = {
                "username": username,
                "credentials": [],
                "totp_secret": None,
            }
            auth.insert_one(doc)
        # Migrate old format if needed
        if "totp_secret" not in doc:
            auth.update_one(
                {"username": username},
                {"$set": {"totp_secret": None}},
            )
            doc["totp_secret"] = None
        return doc
    finally:
        client.close()


# ── Passkey Credentials ───────────────────────────────────────────────


def save_credential(username: str, credential_data_bytes: bytes, user_id: bytes):
    """
    Save a registered credential for a user in the 'auth' collection.
    """
    client, auth = _get_auth_collection()
    try:
        entry = {
            "user_id": base64.urlsafe_b64encode(user_id).decode("ascii"),
            "credential_data": base64.urlsafe_b64encode(credential_data_bytes).decode("ascii"),
        }

        # Upsert: create doc if missing, push credential
        auth.update_one(
            {"username": username},
            {
                "$push": {"credentials": entry},
                "$setOnInsert": {"totp_secret": None},
            },
            upsert=True,
        )
    finally:
        client.close()


def get_credentials(username: str) -> list[bytes]:
    """
    Retrieve stored credential data bytes for a user from MongoDB.

    Returns:
        List of raw AttestedCredentialData bytes, or empty list.
    """
    client, auth = _get_auth_collection()
    try:
        doc = auth.find_one({"username": username})
        if not doc or not doc.get("credentials"):
            return []
        result = []
        for entry in doc["credentials"]:
            raw = base64.urlsafe_b64decode(entry["credential_data"])
            result.append(raw)
        return result
    finally:
        client.close()


def get_user_id(username: str) -> bytes | None:
    """Get the stored user_id for a username, or None if not registered."""
    client, auth = _get_auth_collection()
    try:
        doc = auth.find_one({"username": username})
        if doc and doc.get("credentials"):
            return base64.urlsafe_b64decode(doc["credentials"][0]["user_id"])
        return None
    finally:
        client.close()


def get_all_users() -> list[str]:
    """Return a list of all registered usernames from the auth collection."""
    client, auth = _get_auth_collection()
    try:
        docs = auth.find({}, {"username": 1})
        return [doc["username"] for doc in docs]
    finally:
        client.close()


def delete_credential(username: str) -> bool:
    """Delete all credentials for a user. Returns True if found and deleted."""
    client, auth = _get_auth_collection()
    try:
        result = auth.delete_one({"username": username})
        return result.deleted_count > 0
    finally:
        client.close()


# ── TOTP Secret ───────────────────────────────────────────────────────


def save_totp_secret(username: str, secret: str):
    """Update the totp_secret field for a user."""
    client, auth = _get_auth_collection()
    try:
        auth.update_one(
            {"username": username},
            {"$set": {"totp_secret": secret}},
            upsert=True,
        )
    finally:
        client.close()


def get_totp_secret(username: str) -> str | None:
    """Get the TOTP secret for a user, or None if not yet configured."""
    client, auth = _get_auth_collection()
    try:
        doc = auth.find_one({"username": username})
        if not doc:
            return None
        return doc.get("totp_secret")
    finally:
        client.close()


def has_totp(username: str) -> bool:
    """Check if a user has TOTP configured (secret is not null)."""
    return get_totp_secret(username) is not None


def delete_totp(username: str) -> bool:
    """Reset TOTP secret back to null for a user."""
    client, auth = _get_auth_collection()
    try:
        result = auth.update_one(
            {"username": username},
            {"$set": {"totp_secret": None}},
        )
        return result.matched_count > 0
    finally:
        client.close()
