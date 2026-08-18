"""
Export old scam sessions from MongoDB honeypot database to JSON.

Usage:
    python ml/export_old_sessions.py

Output:
    old_sessions.json  — all 281 session documents
"""
import json
import os

from pymongo import MongoClient

MONGO_URI = os.environ["MONGODB_URI"]

client = MongoClient(MONGO_URI)
col = client["honeypot"]["scam_sessions"]

docs = list(col.find({}))

for doc in docs:
    doc["_id"] = str(doc["_id"])

with open("old_sessions.json", "w", encoding="utf-8") as f:
    json.dump(docs, f, indent=2, default=str)

print(f"Exported {len(docs)} sessions to old_sessions.json")
client.close()
