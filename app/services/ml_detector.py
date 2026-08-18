"""
ML-based scam detection.

Primary:  DistilBERT fine-tuned classifier (ml/models/distilbert/)
Fallback: TF-IDF + Logistic Regression (ml/models/vectorizer.pkl + scam_model.pkl)

Module-level singletons are loaded once at app startup via load_model().
predict_scam_probability(text) returns float in [0.0, 1.0] regardless of which
model is active. Returns None if neither model is available.
"""
import os
import re

from app.core.logging import logger


def preprocess_for_tfidf(text: str) -> str:
    """
    Normalize text exactly as ``ml/train_model.preprocess_text`` does at fit time.

    Kept here (rather than imported from ml/) so the runtime package does not
    depend on the training scripts. Any change to the training function MUST be
    mirrored here or the TF-IDF tier silently degrades: the vocabulary contains
    <upi_id>/<link>/<num> placeholder tokens that raw text can never produce.
    """
    if not isinstance(text, str):
        return ""
    text = text.lower().strip()
    text = re.sub(r"\S+@\S+", " <upi_id> ", text)
    text = re.sub(r"http\S+|www\S+", " <link> ", text)
    text = re.sub(r"\d{4,}", " <number_long> ", text)
    text = re.sub(r"\d+", " <num> ", text)
    text = re.sub(r"\b[a-z]\b", "", text)
    text = re.sub(r"[^\w\s<>]", " ", text)
    return re.sub(r"\s+", " ", text)

# ---------------------------------------------------------------------------
# TF-IDF + Logistic Regression (fallback)
# ---------------------------------------------------------------------------
_vectorizer = None
_model = None
_model_loaded = False

_DEFAULT_MODEL_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "ml", "models",
)

# ---------------------------------------------------------------------------
# DistilBERT (primary)
# ---------------------------------------------------------------------------
_distilbert_model = None
_distilbert_tokenizer = None
_distilbert_loaded = False

_DISTILBERT_MODEL_DIR = os.path.join(_DEFAULT_MODEL_DIR, "distilbert")


def load_distilbert_model(model_dir: str | None = None) -> bool:
    """
    Load fine-tuned DistilBERT classifier from disk.

    Expects the directory to contain a saved HuggingFace model
    (config.json, pytorch_model.bin / model.safetensors, tokenizer files).

    Never raises - logs and returns False on any failure.
    """
    global _distilbert_model, _distilbert_tokenizer, _distilbert_loaded

    if model_dir is None:
        model_dir = _DISTILBERT_MODEL_DIR

    if not os.path.isdir(model_dir):
        # ERROR, not INFO: silently degrading from a fine-tuned transformer to a
        # 2.7KB logistic-regression model is a material loss of detection
        # quality. At LOG_LEVEL=INFO the old message was indistinguishable from
        # routine startup chatter, so every deploy ran degraded unnoticed.
        logger.error(
            f"DistilBERT weights NOT FOUND at {model_dir} - falling back to the "
            "TF-IDF model, which is significantly less accurate. The weights are "
            "gitignored; the deploy must download them. "
            "Run 'python ml/train_distilbert.py' to produce them locally."
        )
        return False

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        _distilbert_tokenizer = AutoTokenizer.from_pretrained(model_dir)
        _distilbert_model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        _distilbert_model.eval()

        # Keep on CPU - GPU optional
        device = "cuda" if torch.cuda.is_available() else "cpu"
        _distilbert_model = _distilbert_model.to(device)

        _distilbert_loaded = True
        logger.info(f"[OK] DistilBERT scam classifier loaded from {model_dir} (device={device})")
        return True

    except ImportError:
        logger.warning("[WARN] transformers / torch not installed - DistilBERT unavailable. Using TF-IDF fallback.")
        return False
    except Exception as exc:
        logger.error(f"Failed to load DistilBERT model: {type(exc).__name__}: {exc}")
        _distilbert_model = _distilbert_tokenizer = None
        _distilbert_loaded = False
        return False


def load_model(model_dir: str | None = None) -> bool:
    """
    Load ML models at application startup.

    Tries DistilBERT first, then TF-IDF + Logistic Regression.
    Returns True if at least one model loads successfully.
    """
    distilbert_ok = load_distilbert_model()
    tfidf_ok = _load_tfidf_model(model_dir)

    if distilbert_ok:
        logger.info("[AI] Active scam classifier: DistilBERT (TF-IDF available as fallback)")
    elif tfidf_ok:
        logger.info("[AI] Active scam classifier: TF-IDF + Logistic Regression")
    else:
        logger.warning("[WARN] No ML model loaded - ML detection disabled")

    return distilbert_ok or tfidf_ok


def _load_tfidf_model(model_dir: str | None = None) -> bool:
    """Load TF-IDF vectorizer + Logistic Regression model."""
    global _vectorizer, _model, _model_loaded

    if model_dir is None:
        model_dir = _DEFAULT_MODEL_DIR

    vectorizer_path = os.path.join(model_dir, "vectorizer.pkl")
    model_path = os.path.join(model_dir, "scam_model.pkl")

    if not os.path.exists(vectorizer_path) or not os.path.exists(model_path):
        logger.warning(
            f"TF-IDF model files not found at {model_dir}. "
            "Run 'python -m ml.train_model --data data/scam_dataset.csv' to train."
        )
        _model_loaded = False
        return False

    try:
        import joblib

        _vectorizer = joblib.load(vectorizer_path)
        _model = joblib.load(model_path)
        _model_loaded = True
        logger.info(f"TF-IDF scam detection model loaded from {model_dir}")
        return True
    except Exception as exc:
        logger.error(f"Failed to load TF-IDF model: {type(exc).__name__}: {exc}")
        _vectorizer = _model = None
        _model_loaded = False
        return False


def is_model_loaded() -> bool:
    """Check if at least one ML model is loaded and ready for inference."""
    return _distilbert_loaded or _model_loaded


def predict_scam_probability(text: str) -> float | None:
    """
    Predict the probability that *text* is a scam message.

    Uses DistilBERT if available, otherwise falls back to TF-IDF + LR.

    Args:
        text: Message text to classify.

    Returns:
        Float in [0.0, 1.0] where 1.0 = definitely scam.
        Returns None if no model is loaded.
    """
    # --- DistilBERT (primary) ---
    if _distilbert_loaded and _distilbert_model is not None and _distilbert_tokenizer is not None:
        try:
            import torch

            inputs = _distilbert_tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            # Move inputs to same device as model
            device = next(_distilbert_model.parameters()).device
            inputs = {k: v.to(device) for k, v in inputs.items()}

            with torch.no_grad():
                logits = _distilbert_model(**inputs).logits

            prob = float(torch.softmax(logits, dim=1)[0][1].item())
            return prob
        except Exception as exc:
            logger.error(f"DistilBERT prediction failed, trying TF-IDF fallback: {type(exc).__name__}: {exc}")

    # --- TF-IDF + LR (fallback) ---
    if _model_loaded and _vectorizer is not None and _model is not None:
        try:
            # MUST match the preprocessing used at fit time. The vectorizer was
            # fitted on text normalized by ml/train_model.preprocess_text, which
            # replaces URLs/emails/digit-runs with <link>/<upi_id>/<num> tokens.
            # Serving raw text meant the discriminative tokens could never fire.
            features = _vectorizer.transform([preprocess_for_tfidf(text)])
            probability = _model.predict_proba(features)[0][1]
            return float(probability)
        except Exception as exc:
            logger.error(f"TF-IDF prediction failed: {type(exc).__name__}: {exc}")

    return None
