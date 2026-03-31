"""
migrate_to_mongo.py — One-time migration script.

Reads existing credentials.json and uploads all passkey credentials + TOTP secrets
into the MongoDB 'auth' collection.

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
    db = client["chatap"]
    auth = db["auth"]

    migrated = 0
    skipped = 0

    for username, data in store.items():
        # Handle old flat list format
        if isinstance(data, list):
            data = {"credentials": data, "totp_secret": None}

        existing = auth.find_one({"username": username})
        if existing:
            print(f"  ⏭  Skipping '{username}' — already exists in MongoDB")
            skipped += 1
            continue

        doc = {
            "username": username,
            "credentials": data.get("credentials", []),
            "totp_secret": data.get("totp_secret"),
        }
        auth.insert_one(doc)
        print(f"  ✅  Migrated '{username}' ({len(doc['credentials'])} credential(s), TOTP: {'yes' if doc['totp_secret'] else 'no'})")
        migrated += 1

    client.close()
    print(f"\nDone! Migrated: {migrated}, Skipped: {skipped}")
    print("You can now safely rename credentials.json to credentials.json.bak")


if __name__ == "__main__":
    migrate()
