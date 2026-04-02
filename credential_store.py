"""
credential_store.py — MongoDB-backed persistent storage for WebAuthn/FIDO2 credentials + TOTP.

Target collection: chatify.users

Existing Chatify users (created by the web app) are looked up for validation only —
their documents are never modified.

New passkey-registered users get their own document inserted into chatify.users
with the following schema:
{
    "email":           "user@gmail.com",
    "fullName":        "username",
    "user_id":         "<base64url WebAuthn user handle>",
    "credential_id":   "<base64url credential ID>",
    "credential_data": "<base64url AttestedCredentialData bytes>",
    "totp_secret":     null,
    "created_at":      <datetime>,
    "updated_at":      <datetime>
}
"""

import os
import base64
from datetime import datetime, timezone

from dotenv import load_dotenv
from pathlib import Path
from pymongo import MongoClient

# ── Load environment ──────────────────────────────────────────────────
load_dotenv(Path(__file__).parent / ".env")

_MONGO_URI = os.getenv("MONGO_URI", "")

# Determine the database name: prefer explicit MONGO_DB_NAME env var,
# otherwise parse it from the URI path (the segment after the last "/"),
# falling back to "chatify" as the default.
def _resolve_db_name() -> str:
    explicit = os.getenv("MONGO_DB_NAME", "").strip()
    if explicit:
        return explicit
    # Parse from URI: mongodb+srv://.../<dbname>?...
    path = _MONGO_URI.split("/")[-1].split("?")[0].strip()
    return path if path else "chatify"

_MONGO_DB_NAME = _resolve_db_name()

# ── Database helpers ──────────────────────────────────────────────────

def _get_db():
    """Return a (client, db) tuple. Caller must close client when done."""
    client = MongoClient(_MONGO_URI)
    db = client[_MONGO_DB_NAME]
    return client, db


def _get_users_collection():
    """Return (client, users_collection)."""
    client, db = _get_db()
    return client, db["users"]


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ── Username validation ───────────────────────────────────────────────


def validate_username(username: str) -> bool:
    """
    Check if a username exists in chatify.users.
    Matches against fullName or email fields.
    Returns True if found.
    """
    client, users = _get_users_collection()
    try:
        doc = users.find_one({
            "$or": [
                {"fullName": username},
                {"email": username},
                {"email": f"{username}@gmail.com"},
            ]
        })
        return doc is not None
    finally:
        client.close()


def get_user_from_users_table(username: str) -> dict | None:
    """
    Look up a user document from chatify.users by fullName or email.
    Returns the raw document or None.
    """
    client, users = _get_users_collection()
    try:
        return users.find_one({
            "$or": [
                {"fullName": username},
                {"email": username},
                {"email": f"{username}@gmail.com"},
            ]
        })
    finally:
        client.close()


# ── Internal: find the passkey doc for a user ─────────────────────────
# A passkey doc is one that has credential_data at top-level (new schema)
# or has a credentials array (old patched schema – handled for backward compat).


def _find_passkey_doc(username: str, users_col) -> dict | None:
    """Return the user's passkey document, or None."""
    return users_col.find_one({
        "$and": [
            {
                "$or": [
                    {"fullName": username},
                    {"email": username},
                    {"email": f"{username}@gmail.com"},
                ]
            },
            {
                "$or": [
                    {"credential_data": {"$exists": True}},  # new schema
                    {"credentials":    {"$exists": True}},   # old schema
                ]
            },
        ]
    })


# ── Passkey Credentials ───────────────────────────────────────────────


def save_credential(username: str, credential_data_bytes: bytes, user_id: bytes):
    """
    Persist a newly registered passkey credential.

    Always inserts a new document into chatify.users with the clean schema.
    A single user may register multiple passkeys — each gets its own document.
    """
    from fido2.webauthn import AttestedCredentialData

    cred = AttestedCredentialData(credential_data_bytes)
    credential_id_b64 = base64.urlsafe_b64encode(bytes(cred.credential_id)).decode("ascii")
    user_id_b64 = base64.urlsafe_b64encode(user_id).decode("ascii")
    cred_data_b64 = base64.urlsafe_b64encode(credential_data_bytes).decode("ascii")

    now = _now()
    doc = {
        "email":           f"{username}@gmail.com" if "@" not in username else username,
        "fullName":        username,
        "user_id":         user_id_b64,
        "credential_id":   credential_id_b64,
        "credential_data": cred_data_b64,
        "totp_secret":     None,
        "created_at":      now,
        "updated_at":      now,
    }

    client, users = _get_users_collection()
    try:
        users.insert_one(doc)
    finally:
        client.close()


def get_credentials(username: str) -> list[bytes]:
    """
    Retrieve all credential_data bytes for a user.

    Handles both new schema (top-level credential_data) and the legacy
    credentials-array schema that may exist from earlier migration.

    Returns a list of raw AttestedCredentialData byte strings.
    """
    client, users = _get_users_collection()
    try:
        # Collect ALL passkey docs for this user (one per registered key)
        docs = list(users.find({
            "$and": [
                {
                    "$or": [
                        {"fullName": username},
                        {"email": username},
                        {"email": f"{username}@gmail.com"},
                    ]
                },
                {
                    "$or": [
                        {"credential_data": {"$exists": True}},
                        {"credentials":    {"$exists": True}},
                    ]
                },
            ]
        }))

        result: list[bytes] = []
        for doc in docs:
            # New schema: single top-level credential_data
            if "credential_data" in doc:
                result.append(base64.urlsafe_b64decode(doc["credential_data"]))
            # Legacy schema: embedded credentials array
            elif "credentials" in doc:
                for entry in doc.get("credentials", []):
                    result.append(base64.urlsafe_b64decode(entry["credential_data"]))

        return result
    finally:
        client.close()


def get_user_id(username: str) -> bytes | None:
    """Return the WebAuthn user_id bytes for a user, or None if unregistered."""
    client, users = _get_users_collection()
    try:
        doc = _find_passkey_doc(username, users)
        if not doc:
            return None
        # New schema
        if "user_id" in doc:
            return base64.urlsafe_b64decode(doc["user_id"])
        # Legacy schema
        creds = doc.get("credentials", [])
        if creds:
            return base64.urlsafe_b64decode(creds[0]["user_id"])
        return None
    finally:
        client.close()


def get_all_users() -> list[str]:
    """Return all usernames that have at least one registered passkey."""
    client, users = _get_users_collection()
    try:
        docs = users.find({
            "$or": [
                {"credential_data": {"$exists": True}},
                {"credentials":    {"$exists": True, "$ne": []}},
            ]
        }, {"fullName": 1})
        seen: set[str] = set()
        result: list[str] = []
        for doc in docs:
            name = doc.get("fullName", "")
            if name and name not in seen:
                seen.add(name)
                result.append(name)
        return result
    finally:
        client.close()


def delete_credential(username: str) -> bool:
    """
    Delete all passkey documents for a user.
    Old Chatify user documents (without credential_data) are left untouched.
    Returns True if at least one document was deleted.
    """
    client, users = _get_users_collection()
    try:
        result = users.delete_many({
            "$and": [
                {
                    "$or": [
                        {"fullName": username},
                        {"email": username},
                        {"email": f"{username}@gmail.com"},
                    ]
                },
                {
                    "$or": [
                        {"credential_data": {"$exists": True}},
                        {"credentials":    {"$exists": True}},
                    ]
                },
            ]
        })
        return result.deleted_count > 0
    finally:
        client.close()


# ── TOTP Secret ───────────────────────────────────────────────────────


def save_totp_secret(username: str, secret: str):
    """Set or update the totp_secret on the user's passkey document(s)."""
    client, users = _get_users_collection()
    try:
        users.update_many(
            {
                "$and": [
                    {
                        "$or": [
                            {"fullName": username},
                            {"email": username},
                            {"email": f"{username}@gmail.com"},
                        ]
                    },
                    {
                        "$or": [
                            {"credential_data": {"$exists": True}},
                            {"credentials":    {"$exists": True}},
                        ]
                    },
                ]
            },
            {"$set": {"totp_secret": secret, "updated_at": _now()}},
        )
    finally:
        client.close()


def get_totp_secret(username: str) -> str | None:
    """Get the TOTP secret from the user's passkey document, or None."""
    client, users = _get_users_collection()
    try:
        doc = _find_passkey_doc(username, users)
        if not doc:
            return None
        return doc.get("totp_secret")
    finally:
        client.close()


def has_totp(username: str) -> bool:
    """Return True if the user has TOTP configured."""
    return get_totp_secret(username) is not None


def delete_totp(username: str) -> bool:
    """Reset totp_secret to null on the user's passkey document(s)."""
    client, users = _get_users_collection()
    try:
        result = users.update_many(
            {
                "$and": [
                    {
                        "$or": [
                            {"fullName": username},
                            {"email": username},
                            {"email": f"{username}@gmail.com"},
                        ]
                    },
                    {
                        "$or": [
                            {"credential_data": {"$exists": True}},
                            {"credentials":    {"$exists": True}},
                        ]
                    },
                ]
            },
            {"$set": {"totp_secret": None, "updated_at": _now()}},
        )
        return result.matched_count > 0
    finally:
        client.close()
