import csv
from pathlib import Path

from preprocess import extract_message_features

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
INPUT_PATH = DATA_DIR / "messages.csv"
OUTPUT_PATH = DATA_DIR / "messages_features.csv"


def build_features_csv(input_path: Path = INPUT_PATH, output_path: Path = OUTPUT_PATH) -> None:
    """Add engineered ML features to the curated message dataset."""
    if not input_path.exists():
        raise FileNotFoundError(f"Dataset not found: {input_path}")

    with input_path.open("r", encoding="utf-8", newline="") as source_file:
        rows = list(csv.DictReader(source_file))

    fieldnames = [
        "text",
        "label",
        "category",
        "length",
        "url_count",
        "urls",
        "email_count",
        "emails",
        "phone_count",
        "phones",
        "suspicious_keywords",
        "repeated_character_count",
        "excessive_punctuation_count",
        "uppercase_ratio",
        "digit_ratio",
        "has_url",
        "has_email",
        "has_phone",
    ]

    output_rows: list[dict[str, object]] = []
    for row in rows:
        features = extract_message_features(row["text"])
        output_rows.append(
            {
                "text": row["text"],
                "label": row["label"],
                "category": row["category"],
                "length": features["length"],
                "url_count": features["url_count"],
                "urls": " | ".join(features["urls"]),
                "email_count": features["email_count"],
                "emails": " | ".join(features["emails"]),
                "phone_count": features["phone_count"],
                "phones": " | ".join(features["phones"]),
                "suspicious_keywords": " | ".join(features["suspicious_keywords"]),
                "repeated_character_count": features["repeated_character_count"],
                "excessive_punctuation_count": features["excessive_punctuation_count"],
                "uppercase_ratio": features["uppercase_ratio"],
                "digit_ratio": features["digit_ratio"],
                "has_url": features["has_url"],
                "has_email": features["has_email"],
                "has_phone": features["has_phone"],
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(output_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Created feature dataset: {output_path} ({len(output_rows)} rows)")


if __name__ == "__main__":
    build_features_csv()
