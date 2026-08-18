"""
Convert exported MongoDB sessions to training CSV for DistilBERT / TF-IDF.

Usage:
    python ml/convert_sessions_to_csv.py

Output:
    data/scam_dataset_enhanced.csv  — appends new rows to existing dataset
    data/sessions_training_only.csv — standalone file with just the new rows

Each conversation turn becomes one row:
    text  = scammer message text
    label = 1 (all sessions are scam — honeypot only engages with scammers)
"""
import json
import csv
import os
from pathlib import Path

INPUT_FILE = "old_sessions.json"
ENHANCED_CSV = "data/scam_dataset_enhanced.csv"
NEW_ROWS_CSV = "data/sessions_training_only.csv"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    sessions = json.load(f)

print(f"Loaded {len(sessions)} sessions")

rows = []

for session in sessions:
    transcript = session.get("conversationTranscript", [])
    scam_detected = session.get("scamDetected", True)
    label = 1 if scam_detected else 0

    for turn in transcript:
        sender = turn.get("sender", "")
        text = turn.get("text", "").strip()

        # Only use scammer messages as training examples
        # (sender != "user" means it came from the scammer side)
        if sender != "user" and text and len(text) >= 10:
            rows.append({"text": text, "label": label})

print(f"Extracted {len(rows)} scammer message rows")

# Write standalone file
os.makedirs("data", exist_ok=True)
with open(NEW_ROWS_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=["text", "label"])
    writer.writeheader()
    writer.writerows(rows)
print(f"Written {len(rows)} rows to {NEW_ROWS_CSV}")

# Append to existing enhanced CSV if it exists
if os.path.exists(ENHANCED_CSV):
    # Read existing to avoid duplicates
    existing_texts = set()
    with open(ENHANCED_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            existing_texts.add(row["text"].strip())

    new_rows = [r for r in rows if r["text"] not in existing_texts]
    print(f"{len(new_rows)} rows are new (not already in {ENHANCED_CSV})")

    with open(ENHANCED_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writerows(new_rows)
    print(f"Appended {len(new_rows)} new rows to {ENHANCED_CSV}")
else:
    with open(ENHANCED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Created {ENHANCED_CSV} with {len(rows)} rows")

print("\nDone. You can now retrain:")
print("  python ml/train_distilbert.py")
print("  python -m ml.train_model --data data/scam_dataset_enhanced.csv")
