# SafeShield dataset and data-source documentation

## 1) Starter message dataset for SafeShield

- Dataset name: SafeShield starter message benchmark
- Source: Curated internal benchmark created for hackathon development and reproducible experimentation
- License: Internal research use for this project only; do not redistribute externally without approval
- Number of samples: 30 starter examples
- Classes: benign, spam, phishing, scam, malicious_download, credential_theft, financial_fraud
- Preprocessing: Unicode normalization, whitespace cleanup, URL/email/phone extraction, suspicious keyword tagging, repeated-character detection, uppercase and digit ratios
- Limitations: This is intentionally small and purpose-built for hackathon validation; it is not a production-grade public benchmark and should not be treated as a complete real-world corpus

## 2) Public datasets to consider for production expansion

| Dataset name | Source | License | Approx. size | Classes | Preprocessing | Limitations |
| --- | --- | --- | --- | --- | --- | --- |
| UCI SMS Spam Collection | UCI Machine Learning Repository | Check the dataset page for the exact license before redistribution | ~5,500 SMS messages | spam / ham | lowercasing, token cleanup, basic normalization | Not phishing-specific; limited cybercrime categories |
| Phishing email datasets | Public phishing corpora and benchmark archives | Varies by source | Varies | phishing / legitimate | text normalization and email-header filtering | Many corpora are outdated and not ready for direct production use |
| URL reputation corpora | PhishTank, URLhaus, OpenPhish references | Terms vary by provider | Varies | malicious / benign / unknown | URL feature engineering and label validation | Requires threat-intel API or careful curation |

## 3) Data handling policy

- Do not scrape private messages or personal communications.
- Do not use private WhatsApp, SMS, or user-device content in model training without explicit consent.
- Keep synthetic examples clearly labeled as synthetic data, not real-world evidence.
- Separate public datasets, synthetic data, and user-provided test samples in training and evaluation logs.

## 4) Recommended next expansion path

1. Add a public spam/phishing benchmark to the training corpus.
2. Keep a small synthetic validation set for edge-case regressions.
3. Maintain a separate user-provided test set for local verification.
4. Record model performance by class and monitor false positives carefully.
