"""Train a phishing-email classifier from Phishing_Email.csv."""

from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

DATA_PATH = Path(__file__).resolve().parent / "Phishing_Email.csv"
TEXT_COLUMN = "Email Text"
LABEL_COLUMN = "Email Type"
VECTORIZER_PATH = Path(__file__).resolve().parent / "vectorizer.pkl"
MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.pkl"
PHISHING_LABEL = "Phishing Email"


def load_dataset(path: Path) -> pd.DataFrame:
    print(f"[1/5] Loading dataset from {path.name}...")
    df = pd.read_csv(path, usecols=[TEXT_COLUMN, LABEL_COLUMN])
    print(f"       Loaded {len(df):,} rows.")
    return df


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    print("[2/5] Dropping rows with missing values...")
    before = len(df)
    df = df.dropna(subset=[TEXT_COLUMN, LABEL_COLUMN]).copy()
    df[TEXT_COLUMN] = df[TEXT_COLUMN].astype(str).str.strip()
    df[LABEL_COLUMN] = df[LABEL_COLUMN].astype(str).str.strip().str.replace(r"\s+", " ", regex=True)
    df = df[df[TEXT_COLUMN].str.len() > 0]
    print(f"       Removed {before - len(df):,} rows. {len(df):,} remain.")

    df["label"] = (df[LABEL_COLUMN] == PHISHING_LABEL).astype(int)
    n_safe = int((df["label"] == 0).sum())
    n_phish = int((df["label"] == 1).sum())
    print(f"       Class balance: {n_safe:,} safe, {n_phish:,} phishing.")
    return df


def train_model(df: pd.DataFrame) -> tuple[TfidfVectorizer, LogisticRegression]:
    x_train, x_test, y_train, y_test = train_test_split(
        df[TEXT_COLUMN],
        df["label"],
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    print("[3/5] Fitting TfidfVectorizer (max_features=5000)...")
    vectorizer = TfidfVectorizer(max_features=5000, stop_words="english")
    x_train_tfidf = vectorizer.fit_transform(x_train)
    x_test_tfidf = vectorizer.transform(x_test)
    print(f"       Vocabulary size: {len(vectorizer.get_feature_names_out()):,}")

    print("[4/5] Training LogisticRegression...")
    model = LogisticRegression(max_iter=1000)
    model.fit(x_train_tfidf, y_train)
    accuracy = model.score(x_test_tfidf, y_test)
    print(f"       Hold-out accuracy: {accuracy:.4f}")
    return vectorizer, model


def save_artifacts(vectorizer: TfidfVectorizer, model: LogisticRegression) -> None:
    print("[5/5] Saving model and vectorizer...")
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(model, MODEL_PATH)
    print(f"       Wrote {VECTORIZER_PATH.name} and {MODEL_PATH.name}")


def main() -> None:
    df = load_dataset(DATA_PATH)
    df = clean_dataset(df)
    vectorizer, model = train_model(df)
    save_artifacts(vectorizer, model)
    print("Training complete.")


if __name__ == "__main__":
    main()
