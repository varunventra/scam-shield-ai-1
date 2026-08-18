"""
CYBER-FORENSIC AGENT: Optimized ML Training Script
Standardized for India AI Impact Buildathon Grand Finale.
"""
import argparse
import os
import re
import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

def detect_columns(df):
    cols = {c.lower().strip(): c for c in df.columns}
    label_col = cols.get('label', cols.get('is_scam', cols.get('v1')))
    text_col = cols.get('text', cols.get('scammer_message', cols.get('v2')))
    if not label_col or not text_col:
        raise ValueError(f"Required columns 'text' and 'label' not found. Found: {list(df.columns)}")
    return label_col, text_col

def preprocess_text(text):
    if not isinstance(text, str): return ""
    text = text.lower().strip()
    
    # 1. Forensic Tokenization (Normalization)
    text = re.sub(r'\S+@\S+', ' <upi_id> ', text)
    text = re.sub(r'http\S+|www\S+', ' <link> ', text)
    text = re.sub(r'\d{4,}', ' <number_long> ', text) # Likely OTPs or Bank A/cs
    text = re.sub(r'\d+', ' <num> ', text)
    
    # 2. Noise Removal (Single letters often used in Hinglish typos)
    text = re.sub(r'\b[a-z]\b', '', text)
    
    # 3. Structural Cleaning
    text = re.sub(r'[^\w\s<>]', ' ', text)
    return re.sub(r'\s+', ' ', text)

def train_model(data_path, output_dir="ml/models/"):
    print(f"\n{'='*60}\n TRAINING: HYBRID SCAM DETECTOR v2.0\n{'='*60}")
    
    df = pd.read_csv(data_path, encoding="latin-1")
    label_col, text_col = detect_columns(df)
    
    # Cleaning & Normalization
    df = df.dropna(subset=[text_col, label_col])
    df['clean_text'] = df[text_col].astype(str).apply(preprocess_text)
    
    # Ensure numeric labels
    df['label'] = df[label_col].apply(lambda x: 1 if str(x) in ['1', '1.0', 'scam', 'spam'] else 0)

    # TF-IDF with N-Grams (Crucial for phrases like "Account Blocked")
    vectorizer = TfidfVectorizer(
        max_features=2000, 
        ngram_range=(1,2), 
        stop_words="english"
    )
    
    X = vectorizer.fit_transform(df['clean_text'])
    y = df['label'].values
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Increased Regularization (C=10.0) to penalize misclassifications
    model = LogisticRegression(
        max_iter=2000,           # More iterations for the complex data
        C=1.0,                   # Lower C (standard is 1.0) to prevent overfitting
        class_weight="balanced",
        random_state=42 # Essential for handling the "Friendly" noise
    )
    model.fit(X_train, y_train)

    # Metrics
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, output_dict=True)

    print(f"\nAccuracy: {accuracy:.4f}")
    print(classification_report(y_test, y_pred))

    # Deployment Save
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(vectorizer, os.path.join(output_dir, "vectorizer.pkl"))
    joblib.dump(model, os.path.join(output_dir, "scam_model.pkl"))
    
    return {
        "accuracy": accuracy,
        "precision": report['1']['precision'] if '1' in report else report['1.0']['precision'],
        "recall": report['1']['recall'] if '1' in report else report['1.0']['recall']
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    args = parser.parse_args()
    train_model(args.data)