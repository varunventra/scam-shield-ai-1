"""
Fine-tune DistilBERT on scam_dataset_enhanced.csv for binary scam classification.

Usage:
    python ml/train_distilbert.py
    python ml/train_distilbert.py --data data/scam_dataset_enhanced.csv --epochs 5

Output:
    ml/models/distilbert/   (tokenizer + model saved here)

Requirements:
    pip install transformers torch datasets scikit-learn
"""
import argparse
import os
import sys

import pandas as pd
from sklearn.model_selection import train_test_split

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(description="Fine-tune DistilBERT for scam detection")
parser.add_argument("--data", default="data/scam_dataset_enhanced.csv", help="Path to CSV dataset")
parser.add_argument("--output", default="ml/models/distilbert", help="Output directory for saved model")
parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
parser.add_argument("--batch-size", type=int, default=16, help="Training batch size")
parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate")
parser.add_argument("--max-length", type=int, default=128, help="Max token length (128 is fast, 512 is thorough)")
args = parser.parse_args()

# ---------------------------------------------------------------------------
# Validate dependencies early
# ---------------------------------------------------------------------------
try:
    import torch
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
    )
    from datasets import Dataset
    import numpy as np
    from sklearn.metrics import accuracy_score, f1_score
except ImportError as e:
    print(f"ERROR: Missing dependency — {e}")
    print("Install with: pip install transformers torch datasets scikit-learn")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
data_path = args.data
if not os.path.exists(data_path):
    print(f"ERROR: Dataset not found at {data_path}")
    sys.exit(1)

df = pd.read_csv(data_path)
print(f"Loaded {len(df)} rows from {data_path}")

# Expect columns: text, label (1=scam, 0=legitimate)
if "text" not in df.columns or "label" not in df.columns:
    print(f"ERROR: CSV must have 'text' and 'label' columns. Found: {list(df.columns)}")
    sys.exit(1)

df = df.dropna(subset=["text", "label"])
df["label"] = df["label"].astype(int)
print(f"Label distribution:\n{df['label'].value_counts().to_string()}")

# ---------------------------------------------------------------------------
# Split
# ---------------------------------------------------------------------------
train_df, eval_df = train_test_split(df, test_size=0.15, random_state=42, stratify=df["label"])
print(f"Train: {len(train_df)}, Eval: {len(eval_df)}")

# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
MODEL_NAME = "distilbert-base-uncased"
print(f"\nLoading tokenizer: {MODEL_NAME}")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)


def tokenize(batch):
    return tokenizer(
        batch["text"],
        truncation=True,
        padding="max_length",
        max_length=args.max_length,
    )


train_dataset = Dataset.from_pandas(train_df[["text", "label"]].reset_index(drop=True))
eval_dataset  = Dataset.from_pandas(eval_df[["text", "label"]].reset_index(drop=True))

train_dataset = train_dataset.map(tokenize, batched=True)
eval_dataset  = eval_dataset.map(tokenize, batched=True)

train_dataset = train_dataset.rename_column("label", "labels")
eval_dataset  = eval_dataset.rename_column("label", "labels")
train_dataset.set_format("torch", columns=["input_ids", "attention_mask", "labels"])
eval_dataset.set_format("torch", columns=["input_ids", "attention_mask", "labels"])

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
print(f"Loading model: {MODEL_NAME}")
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Training device: {device}")
model = model.to(device)

# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    return {
        "accuracy": accuracy_score(labels, preds),
        "f1": f1_score(labels, preds, average="binary"),
    }

# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
os.makedirs(args.output, exist_ok=True)

training_args = TrainingArguments(
    output_dir=args.output,
    num_train_epochs=args.epochs,
    per_device_train_batch_size=args.batch_size,
    per_device_eval_batch_size=args.batch_size,
    learning_rate=args.lr,
    eval_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    logging_steps=20,
    warmup_steps=100,
    weight_decay=0.01,
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    compute_metrics=compute_metrics,
)

print(f"\nStarting training: {args.epochs} epochs, batch_size={args.batch_size}, lr={args.lr}")
trainer.train()

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
print(f"\nSaving model to {args.output}")
trainer.save_model(args.output)
tokenizer.save_pretrained(args.output)

print(f"\n✅ DistilBERT fine-tuning complete. Model saved to: {args.output}")
print("Restart the backend to use the new model.")
