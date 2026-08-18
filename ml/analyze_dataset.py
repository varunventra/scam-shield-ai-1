"""
Quick dataset analysis script to understand data distribution.
"""
import pandas as pd
import numpy as np
import sys

# Set UTF-8 encoding for stdout
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Load dataset
df = pd.read_csv("data/scam_dataset.csv", encoding="utf-8")

print("=" * 70)
print("DATASET ANALYSIS")
print("=" * 70)
print(f"\nTotal samples: {len(df)}")
print(f"Columns: {list(df.columns)}")

# Check for missing values
print(f"\nMissing values:")
print(df.isnull().sum())

# Class distribution
print(f"\nClass distribution:")
print(df['label'].value_counts())
print(f"\nClass balance:")
scam_count = (df['label'] == 1).sum()
safe_count = (df['label'] == 0).sum()
print(f"  Scam (1): {scam_count} ({scam_count/len(df)*100:.1f}%)")
print(f"  Safe (0): {safe_count} ({safe_count/len(df)*100:.1f}%)")

# Check for duplicates
duplicates = df.duplicated(subset=['text']).sum()
print(f"\nDuplicate messages: {duplicates}")

# Sample messages
print(f"\nSample scam messages:")
scam_samples = df[df['label'] == 1]['text'].head(5)
for i, msg in enumerate(scam_samples, 1):
    print(f"  {i}. {msg[:80]}")

print(f"\nSample safe messages:")
safe_samples = df[df['label'] == 0]['text'].head(5)
for i, msg in enumerate(safe_samples, 1):
    print(f"  {i}. {msg[:80]}")

# Text length analysis
df['text_length'] = df['text'].str.len()
print(f"\nText length statistics:")
print(f"  Mean: {df['text_length'].mean():.1f} characters")
print(f"  Median: {df['text_length'].median():.1f} characters")
print(f"  Min: {df['text_length'].min()} characters")
print(f"  Max: {df['text_length'].max()} characters")

print(f"\nScam vs Safe text length:")
print(f"  Scam mean: {df[df['label']==1]['text_length'].mean():.1f}")
print(f"  Safe mean: {df[df['label']==0]['text_length'].mean():.1f}")

print("=" * 70)
