"""
migrate_to_mongo.py — One-time migration script.

Reads existing credentials.json and uploads all passkey credentials + TOTP secrets
into the MongoDB 'users' collection in the 'chatify' database.

Run once:
    python migrate_to_mongo.py
"""

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(Path(__file__).parent / ".env")

STORE_FILE = Path(__file__).parent / "credentials.json"
MONGO_URI = os.getenv("MONGO_URI", "")


def migrate():
    if not STORE_FILE.exists():
        print("No credentials.json found — nothing to migrate.")
        return

    with open(STORE_FILE, "r", encoding="utf-8") as f:
        store = json.load(f)

    if not store:
        print("credentials.json is empty — nothing to migrate.")
        return

    client = MongoClient(MONGO_URI)
    db = client["chatify"]
    users = db["users"]

    migrated = 0
    skipped = 0

    for username, data in store.items():
        # Handle old flat list format
        if isinstance(data, list):
            data = {"credentials": data, "totp_secret": None}

        # Find existing user in the users collection
        existing = users.find_one({
            "$or": [{"fullName": username}, {"email": f"{username}@gmail.com"}]
        })
        if not existing:
            print(f"  ❌  User '{username}' not found in users collection — skipping")
            skipped += 1
            continue

        if existing.get("credentials"):
            print(f"  ⏭  Skipping '{username}' — already has credentials in users collection")
            skipped += 1
            continue

        # Add passkey fields to the existing user document
        users.update_one(
            {"_id": existing["_id"]},
            {"$set": {
                "credentials": data.get("credentials", []),
                "totp_secret": data.get("totp_secret"),
            }},
        )
        cred_count = len(data.get('credentials', []))
        has_totp = 'yes' if data.get('totp_secret') else 'no'
        print(f"  ✅  Migrated '{username}' ({cred_count} credential(s), TOTP: {has_totp})")
        migrated += 1

    client.close()
    print(f"\nDone! Migrated: {migrated}, Skipped: {skipped}")
    print("You can now safely rename credentials.json to credentials.json.bak")


if __name__ == "__main__":
    migrate()
