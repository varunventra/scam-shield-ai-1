"""
Download free public scam/spam/phishing datasets and merge into
data/scam_dataset_enhanced.csv

Datasets downloaded (no login required):
  1. UCI SMS Spam Collection       (5,574 rows)  — CC BY 4.0
  2. SMS Spam Multilingual HF      (5,570 rows)  — includes Hindi
  3. ealvaradob phishing SMS       (5,971 rows)  — Apache 2.0
  4. zefang-liu phishing emails   (18,650 rows)  — LGPL-3.0
  5. GitHub 138K SMS scam dataset (138,813 rows) — multilingual

Usage:
    pip install datasets requests pandas
    python ml/download_datasets.py
"""
import os
import re
import pandas as pd
import requests

os.makedirs("data", exist_ok=True)

ENHANCED_CSV = "data/scam_dataset_enhanced.csv"

# Load existing dataset
if os.path.exists(ENHANCED_CSV):
    existing = pd.read_csv(ENHANCED_CSV)
    print(f"Existing dataset: {len(existing)} rows")
else:
    existing = pd.DataFrame(columns=["text", "label"])
    print("No existing dataset found — starting fresh")

all_new = []


def clean(text):
    """Basic text cleaning."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    text = re.sub(r'\s+', ' ', text)
    return text if len(text) >= 10 else None


def add_rows(texts, label, source):
    cleaned = [clean(t) for t in texts]
    cleaned = [t for t in cleaned if t]
    rows = [{"text": t, "label": label} for t in cleaned]
    all_new.extend(rows)
    print(f"  [{source}] Added {len(rows)} rows (label={label})")


# =============================================================================
# Dataset 1: UCI SMS Spam via Hugging Face
# =============================================================================
print("\n[1/5] UCI SMS Spam Collection (Hugging Face)...")
try:
    from datasets import load_dataset
    ds = load_dataset("ucirvine/sms_spam", split="train", trust_remote_code=True)
    df = ds.to_pandas()
    # columns: label (0=ham, 1=spam), sms
    spam = df[df["label"] == 1]["sms"].tolist()
    ham  = df[df["label"] == 0]["sms"].tolist()
    add_rows(spam, 1, "UCI-SMS-spam")
    add_rows(ham,  0, "UCI-SMS-ham")
except Exception as e:
    print(f"  FAILED: {e}")


# =============================================================================
# Dataset 2: SMS Spam Multilingual (includes Hindi)
# =============================================================================
print("\n[2/5] SMS Spam Multilingual (Hugging Face)...")
try:
    from datasets import load_dataset
    ds = load_dataset("dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset",
                      split="train", trust_remote_code=True)
    df = ds.to_pandas()
    # columns: labels (ham/spam), text (English), text_hi (Hindi), ...
    label_map = {"spam": 1, "ham": 0}
    for col in ["text", "text_hi"]:
        if col in df.columns:
            for lbl_str, lbl_int in label_map.items():
                subset = df[df["labels"] == lbl_str][col].tolist()
                add_rows(subset, lbl_int, f"Multilingual-{col}-{lbl_str}")
except Exception as e:
    print(f"  FAILED: {e}")


# =============================================================================
# Dataset 3: ealvaradob phishing dataset — SMS subset
# =============================================================================
print("\n[3/5] ealvaradob phishing SMS dataset (Hugging Face)...")
try:
    from datasets import load_dataset
    ds = load_dataset("ealvaradob/phishing-dataset", "sms_dataset",
                      split="train", trust_remote_code=True)
    df = ds.to_pandas()
    # columns: text, label (1=phishing/scam, 0=benign)
    scam = df[df["label"] == 1]["text"].tolist()
    legit = df[df["label"] == 0]["text"].tolist()
    add_rows(scam,  1, "ealvaradob-SMS-phishing")
    add_rows(legit, 0, "ealvaradob-SMS-legit")
except Exception as e:
    print(f"  FAILED: {e}")


# =============================================================================
# Dataset 4: zefang-liu phishing emails
# =============================================================================
print("\n[4/5] zefang-liu phishing email dataset (Hugging Face)...")
try:
    from datasets import load_dataset
    ds = load_dataset("zefang-liu/phishing-email-dataset",
                      split="train", trust_remote_code=True)
    df = ds.to_pandas()
    # columns: Email Text, Email Type (Safe Email / Phishing Email)
    text_col  = "Email Text" if "Email Text" in df.columns else df.columns[0]
    label_col = "Email Type" if "Email Type" in df.columns else df.columns[1]
    phish = df[df[label_col] == "Phishing Email"][text_col].tolist()
    safe  = df[df[label_col] == "Safe Email"][text_col].tolist()
    add_rows(phish, 1, "zefang-phishing-email")
    add_rows(safe,  0, "zefang-safe-email")
except Exception as e:
    print(f"  FAILED: {e}")


# =============================================================================
# Dataset 5: GitHub 138K SMS Scam Dataset (raw CSV download)
# =============================================================================
print("\n[5/5] GitHub 138K multilingual SMS scam dataset...")
try:
    url = (
        "https://raw.githubusercontent.com/vinit9638/SMS-scam-detection-dataset"
        "/main/sms_scam_detection_dataset_merged_with_lang.csv"
    )
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    from io import StringIO
    df = pd.read_csv(StringIO(resp.text))
    # columns: label (ham/spam), text, lang, URL, EMAIL, PHONE
    label_map = {"spam": 1, "ham": 0}
    for lbl_str, lbl_int in label_map.items():
        subset = df[df["label"] == lbl_str]["text"].tolist()
        add_rows(subset, lbl_int, f"GitHub-138K-{lbl_str}")
except Exception as e:
    print(f"  FAILED: {e}")


# =============================================================================
# Merge and deduplicate
# =============================================================================
print(f"\nTotal new rows collected: {len(all_new)}")

new_df = pd.DataFrame(all_new).dropna(subset=["text"])

# Deduplicate against existing
existing_texts = set(existing["text"].str.strip().tolist()) if len(existing) else set()
new_df = new_df[~new_df["text"].str.strip().isin(existing_texts)]
new_df = new_df.drop_duplicates(subset=["text"])

print(f"New unique rows after deduplication: {len(new_df)}")

# Append to enhanced CSV
combined = pd.concat([existing, new_df], ignore_index=True)
combined.to_csv(ENHANCED_CSV, index=False)

print(f"\nFinal dataset size: {len(combined)} rows")
print(f"Label distribution:\n{combined['label'].value_counts().to_string()}")
print(f"\nSaved to {ENHANCED_CSV}")
print("\nNext step — retrain:")
print("  python ml/train_distilbert.py")
print("  python -m ml.train_model --data data/scam_dataset_enhanced.csv")
