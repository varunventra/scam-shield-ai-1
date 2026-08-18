"""
OPTIMIZED ML Training Pipeline for Scam Detection
Target: 90%+ accuracy with robust cross-validation

Features:
- Enhanced preprocessing matching production ml_detector.py
- TF-IDF with optimized parameters
- Multiple model comparison
- Hyperparameter tuning
- Cross-validation
- Comprehensive evaluation
"""
import argparse
import os
import re
import pandas as pd
import numpy as np
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import (
    classification_report, accuracy_score, precision_recall_fscore_support,
    confusion_matrix, roc_auc_score
)
import warnings
warnings.filterwarnings('ignore')


def preprocess_text(text):
    """
    Enhanced preprocessing aligned with production patterns.
    Normalizes forensic entities while preserving scam indicators.
    """
    if not isinstance(text, str):
        return ""

    text = text.lower().strip()

    # Forensic Tokenization (Normalization)
    # UPI IDs - critical scam indicator
    text = re.sub(r'\S+@\S+', ' <upi_id> ', text)

    # Links - major phishing indicator
    text = re.sub(r'http\S+|www\S+', ' <link> ', text)

    # Long numbers (OTPs, Account numbers, Phone numbers)
    text = re.sub(r'\d{4,}', ' <number_long> ', text)

    # Currency amounts (preserve the semantic meaning)
    text = re.sub(r'rs\.?\s*\d+|₹\s*\d+', ' <currency> ', text, flags=re.IGNORECASE)

    # Short numbers (keep for context like "1 rupee")
    text = re.sub(r'\d+', ' <num> ', text)

    # Remove single letters (Hinglish noise reduction)
    text = re.sub(r'\b[a-z]\b', '', text)

    # Structural cleaning (keep angle brackets for tokens)
    text = re.sub(r'[^\w\s<>]', ' ', text)

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text).strip()

    return text


def train_and_evaluate_model(X_train, X_test, y_train, y_test, model_name, model, param_grid=None):
    """Train a model with optional hyperparameter tuning and evaluate it."""
    print(f"\n{'='*70}")
    print(f"Training {model_name}")
    print(f"{'='*70}")

    if param_grid:
        print(f"Running GridSearchCV with {len(param_grid)} parameter combinations...")
        grid_search = GridSearchCV(
            model,
            param_grid,
            cv=5,
            scoring='f1',
            n_jobs=-1,
            verbose=0
        )
        grid_search.fit(X_train, y_train)
        best_model = grid_search.best_estimator_
        print(f"Best parameters: {grid_search.best_params_}")
        print(f"Best CV F1 score: {grid_search.best_score_:.4f}")
    else:
        best_model = model
        best_model.fit(X_train, y_train)

    # Cross-validation scores
    cv_scores = cross_val_score(best_model, X_train, y_train, cv=5, scoring='accuracy')
    print(f"\nCross-validation accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Test set evaluation
    y_pred = best_model.predict(X_test)
    y_pred_proba = best_model.predict_proba(X_test)[:, 1] if hasattr(best_model, 'predict_proba') else None

    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')

    print(f"\nTest Set Performance:")
    print(f"  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1-Score:  {f1:.4f}")

    if y_pred_proba is not None:
        auc = roc_auc_score(y_test, y_pred_proba)
        print(f"  ROC AUC:   {auc:.4f}")

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    print(f"\nConfusion Matrix:")
    print(f"  True Negatives:  {tn}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  True Positives:  {tp}")

    print(f"\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Scam']))

    return {
        'model': best_model,
        'model_name': model_name,
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
    }


def train_optimized_model(data_path, output_dir="ml/models/"):
    """Main training pipeline with comprehensive model comparison."""
    print(f"\n{'='*70}")
    print(" OPTIMIZED SCAM DETECTION ML TRAINING PIPELINE")
    print(f"{'='*70}\n")

    # Load data
    print(f"Loading dataset from: {data_path}")
    df = pd.read_csv(data_path, encoding="utf-8")

    # Detect columns
    label_col = 'label'
    text_col = 'text'
    if 'label' not in df.columns or 'text' not in df.columns:
        raise ValueError(f"Expected columns 'text' and 'label'. Found: {list(df.columns)}")

    print(f"Dataset shape: {df.shape}")
    print(f"Class distribution:")
    print(df[label_col].value_counts())

    # Clean data
    df = df.dropna(subset=[text_col, label_col])
    df['clean_text'] = df[text_col].astype(str).apply(preprocess_text)

    # Ensure binary labels
    df['label'] = df[label_col].apply(lambda x: 1 if x == 1 else 0)

    print(f"\nPreprocessing complete. Sample:")
    print(f"Original: {df[text_col].iloc[0]}")
    print(f"Cleaned:  {df['clean_text'].iloc[0]}")

    # Feature extraction with optimized TF-IDF
    print(f"\n{'='*70}")
    print("Feature Extraction: TF-IDF Vectorization")
    print(f"{'='*70}")

    vectorizer = TfidfVectorizer(
        max_features=3000,        # Increased from 2000 for better coverage
        ngram_range=(1, 3),       # Trigrams capture phrases like "send money urgent"
        min_df=2,                 # Ignore terms appearing in < 2 documents
        max_df=0.95,              # Ignore terms appearing in > 95% of documents
        sublinear_tf=True,        # Use log normalization
        stop_words='english',     # Remove common English stop words
        strip_accents='unicode',  # Handle Unicode characters
    )

    X = vectorizer.fit_transform(df['clean_text'])
    y = df['label'].values

    print(f"Feature matrix shape: {X.shape}")
    print(f"Total vocabulary: {len(vectorizer.vocabulary_)}")

    # Train/test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print(f"\nTrain set: {X_train.shape[0]} samples")
    print(f"Test set:  {X_test.shape[0]} samples")

    # Model comparison
    results = []

    # 1. Logistic Regression with extensive hyperparameter tuning
    lr_param_grid = {
        'C': [0.1, 0.5, 1.0, 2.0, 5.0],
        'penalty': ['l2'],
        'max_iter': [2000],
        'class_weight': ['balanced'],
        'solver': ['lbfgs', 'saga']
    }
    lr_model = LogisticRegression(random_state=42)
    lr_result = train_and_evaluate_model(
        X_train, X_test, y_train, y_test,
        "Logistic Regression",
        lr_model,
        lr_param_grid
    )
    results.append(lr_result)

    # 2. Random Forest
    rf_param_grid = {
        'n_estimators': [100, 200],
        'max_depth': [20, 30, None],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'class_weight': ['balanced']
    }
    rf_model = RandomForestClassifier(random_state=42)
    rf_result = train_and_evaluate_model(
        X_train, X_test, y_train, y_test,
        "Random Forest",
        rf_model,
        rf_param_grid
    )
    results.append(rf_result)

    # 3. Gradient Boosting
    gb_param_grid = {
        'n_estimators': [100, 200],
        'learning_rate': [0.05, 0.1, 0.2],
        'max_depth': [3, 5, 7],
        'min_samples_split': [2, 5],
        'subsample': [0.8, 1.0]
    }
    gb_model = GradientBoostingClassifier(random_state=42)
    gb_result = train_and_evaluate_model(
        X_train, X_test, y_train, y_test,
        "Gradient Boosting",
        gb_model,
        gb_param_grid
    )
    results.append(gb_result)

    # Select best model based on F1 score
    best_result = max(results, key=lambda x: x['f1'])

    print(f"\n{'='*70}")
    print(" MODEL COMPARISON SUMMARY")
    print(f"{'='*70}")
    for result in results:
        print(f"\n{result['model_name']}:")
        print(f"  Accuracy:  {result['accuracy']:.4f}")
        print(f"  Precision: {result['precision']:.4f}")
        print(f"  Recall:    {result['recall']:.4f}")
        print(f"  F1-Score:  {result['f1']:.4f}")
        print(f"  CV Score:  {result['cv_mean']:.4f} (+/- {result['cv_std']:.4f})")

    print(f"\n{'='*70}")
    print(f" BEST MODEL: {best_result['model_name']}")
    print(f" Accuracy: {best_result['accuracy']:.4f} ({best_result['accuracy']*100:.2f}%)")
    print(f" F1-Score: {best_result['f1']:.4f}")
    print(f"{'='*70}")

    # Save the best model
    os.makedirs(output_dir, exist_ok=True)
    vectorizer_path = os.path.join(output_dir, "vectorizer.pkl")
    model_path = os.path.join(output_dir, "scam_model.pkl")

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(best_result['model'], model_path)

    print(f"\nModel saved to: {output_dir}")
    print(f"  - vectorizer.pkl")
    print(f"  - scam_model.pkl")

    return best_result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train optimized scam detection model")
    parser.add_argument("--data", default="data/scam_dataset_enhanced.csv", help="Path to training data")
    parser.add_argument("--output", default="ml/models/", help="Output directory for models")
    args = parser.parse_args()

    result = train_optimized_model(args.data, args.output)

    if result['accuracy'] >= 0.90:
        print(f"\n SUCCESS! Achieved {result['accuracy']*100:.2f}% accuracy (target: 90%)")
    else:
        print(f"\n WARNING: Accuracy {result['accuracy']*100:.2f}% below 90% target")
        print("Consider:")
        print("  - Adding more diverse training data")
        print("  - Further hyperparameter tuning")
        print("  - Ensemble methods")
