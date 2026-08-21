# SafeShield

<<<<<<< HEAD
SafeShield is a cybersecurity assistant designed to help users detect suspicious or risky messaging patterns in WhatsApp content. The project combines a FastAPI backend, a React dashboard, and a Chrome browser extension to flag scam, phishing, and social-engineering indicators before a user engages with a message.

## Overview

SafeShield analyzes incoming message content using a rules-based risk engine and ML-assisted classification. It produces:

- a risk score and risk level
- detected suspicious indicators
- confidence assessment
- recommended next steps
- persistent storage of analyses in MongoDB

## Features

- Message risk analysis via a FastAPI API
- Explainable risk results with reasons and indicators
- React dashboard for monitoring analysis results
- Chrome extension for quick review of WhatsApp messages
- MongoDB-backed historical logging
- ML training and preprocessing pipeline for message classification

## Architecture

- Backend: Python + FastAPI + MongoDB
- Frontend: React + Vite
- Browser extension: Chrome extension (Manifest V3)
- Data science: scikit-learn pipeline and joblib model artifacts

## Project Structure

```text
Safeshield/
├── backend/
│   ├── analyzer/
│   ├── data/
│   ├── ml/
│   ├── .env
│   ├── database.py
│   ├── main.py
│   ├── requirements.txt
│   ├── risk_engine.py
│   └── test_api.py
├── extension/
│   ├── content.js
│   ├── manifest.json
│   ├── popup.css
│   ├── popup.html
│   └── popup.js
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── README.md
├── README.md
└── .gitignore
```

## Prerequisites

Before running the project, make sure you have:

- Python 3.10+
- Node.js 18+
- npm
- MongoDB instance or connection URI
- Google Chrome or Chromium for extension testing

## Backend Setup

1. Open a terminal in the backend folder:

```bash
cd backend
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Configure the environment file in `backend/.env`:

```env
=======
SafeShield is a local-first cyber-risk analysis project for user-initiated inspection of suspicious messages and URLs. It combines deterministic indicators, explainable scoring, and optional machine-learning models behind a FastAPI service, with a React web interface and a Chrome extension prototype.

This repository is a research and development project. Its results should support human review, not replace security, financial, legal, or incident-response decisions.

## Current Scope

Implemented end-to-end:

- Message analysis through the FastAPI backend and React Message Scanner.
- URL analysis through the FastAPI backend and React URL Scanner.
- Explainable risk scores, risk levels, categories, reasons, indicators, confidence, and recommendations.
- Optional MongoDB persistence. The original message is stored as a SHA-256 hash rather than plaintext.
- Offline model training and evaluation utilities for messages and URLs.

Prototype or incomplete:

- The Chrome extension currently displays local hard-coded result templates. It does not call the backend or inspect WhatsApp content.
- Dashboard statistics and recent analyses are static placeholders.
- Image and APK analysis modules exist, but they are not exposed by backend routes or wired into the frontend.
- VirusTotal and Google Safe Browsing are mentioned in older URL-checker documentation, but no active runtime integration is present in the current source.
- No frontend test suite currently exists.

For the detailed system map, contracts, and AI-oriented maintenance notes, read [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository Layout

```text
SafeShield/
├── backend/                 FastAPI service, analyzers, risk engine, message ML
│   ├── analyzer/            Message, URL, APK, and image analyzer modules
│   ├── data/                Message datasets and engineered features
│   ├── ml/                  Message dataset and model training utilities
│   ├── main.py              FastAPI app and HTTP endpoints
│   ├── risk_engine.py       Message scoring, categorization, recommendations
│   ├── database.py          Optional MongoDB setup
│   ├── test_api.py          Backend API tests
│   └── requirements.txt     Python dependencies
├── frontend/                React 18 + Vite web application
│   └── src/
│       ├── api.js           Axios client for the backend
│       └── pages/            Dashboard, message scanner, URL scanner
├── extension/               Chrome Manifest V3 popup prototype
├── url_checker/             URL normalization, features, rules, models, datasets
│   ├── dataset/utils/       URL and text preprocessing helpers
│   ├── model/               Serialized URL model artifacts and calibration metadata
│   ├── scripts/             Rule tests and evaluation scripts
│   └── train_model.py       URL model training entry point
└── .venv/                   Local virtual environment; do not commit or rely on its presence
```

Large or generated files are intentionally summarized rather than listed individually. The URL checker contains raw provider response JSON files under `url_checker/dataset/raw_responses/`.

## Requirements

- Windows, macOS, or Linux.
- Python 3.10 or newer. The checked backend dependencies include FastAPI, Uvicorn, Pydantic 2, PyMongo, python-dotenv, joblib, pandas, scikit-learn, and httpx.
- Node.js 16 or newer and npm for the frontend.
- MongoDB is optional. It is only used when `MONGODB_URI` is configured.

## Setup and Run

From the repository root, create or activate a Python virtual environment and install backend dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r backend\requirements.txt
```

Start the backend in one terminal:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Install and start the frontend in another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The backend OpenAPI UI is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

The frontend API base URL is currently hard-coded to `http://127.0.0.1:8000` in `frontend/src/api.js`. If that changes, update backend CORS origins in `backend/main.py` as well.

## Configuration

Create `backend/.env` only when MongoDB persistence is needed:

```dotenv
>>>>>>> e8739a5 (fixed url to 55%)
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=safeshield
```

<<<<<<< HEAD
5. Start the FastAPI server:

```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

The API will be available at:

- http://127.0.0.1:8000
- Swagger docs: http://127.0.0.1:8000/docs

## Frontend Setup

1. Open a terminal in the frontend folder:

```bash
cd frontend
```

2. Install dependencies:

```bash
npm install
```

3. Start the development server:

```bash
npm run dev
```

The frontend should be available at:

- http://localhost:3000

## Chrome Extension Setup

1. Open Chrome and go to:

```text
chrome://extensions/
```

2. Enable Developer mode.

3. Click Load unpacked.

4. Select the `extension/` folder from this project.

## API Usage

The backend exposes a message analysis endpoint:

```http
POST /analyze/message
```

Example payload:

```json
{
  "message": "URGENT! Your bank account has expired. Click here to verify."
}
```

Example response:

```json
{
  "analysis_id": "SS-123ABC",
  "risk_score": 92,
  "risk_level": "high",
  "category": "phishing",
  "confidence": 91,
  "reasons": ["Urgent language detected", "Bank impersonation pattern"],
  "detected_indicators": ["urgency", "financial_reference"],
  "recommendation": "Do not click the link. Verify through official channels."
}
```

## ML and Risk Engine

The project includes a machine-learning workflow under `backend/ml/` and a rule-based risk engine under `backend/risk_engine.py`.

These components work together to evaluate the message content and generate explainable outputs for users.

## Development Notes

- MongoDB is required for storing analysis records.
- The frontend expects the backend to be running on `http://127.0.0.1:8000`.
- The Chrome extension is intended for browser-based review of WhatsApp content and requires host permissions for WhatsApp Web.

## License

This project is currently for educational and prototype use in a cybersecurity context.

## Contributors

This repository includes backend, frontend, browser extension, and machine-learning components built for the SafeShield project.
=======
Without `MONGODB_URI`, analysis still runs but results are not persisted. When MongoDB is configured but unavailable, the API returns HTTP 503 after analysis cannot be saved.

Do not add API keys, credentials, local datasets containing secrets, or generated virtual-environment files to source control.

## API Quick Reference

`GET /` returns service metadata. `GET /health` returns the service health response.

`POST /analyze/message` accepts:

```json
{"message":"URGENT: your bank account is suspended. Verify your OTP now."}
```

The response includes `analysis_id`, `risk_score`, `risk_level`, `category`, `confidence`, `confidence_level`, `reasons`, `detected_indicators`, `recommendation`, `model_prediction`, `model_confidence`, and `rule_confidence`.

`POST /analyze/url` accepts:

```json
{"url":"https://example.com/login"}
```

The response additionally includes `original_url`, `normalized_url`, `verdict`, and `domain_valid`.

Input limits are 1 to 5000 characters for messages and 1 to 2048 characters for URLs. Extra JSON fields are rejected by the Pydantic request models.

## Tests and Model Commands

Run backend API tests:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe -m unittest test_api.py
```

Run URL rule checks and evaluation:

```powershell
Set-Location url_checker
..\.venv\Scripts\python.exe scripts\test_rule_check.py
..\.venv\Scripts\python.exe scripts\evaluate_url_checker.py
```

Train the message model:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe ml\train_message_model.py
```

Train URL models:

```powershell
Set-Location url_checker
..\.venv\Scripts\python.exe train_model.py
```

The message model is expected at `backend/ml/models/message_model.joblib`. The URL runtime prefers `url_checker/model/url_model_calibrated.pkl` and falls back to `url_checker/model/url_model.pkl`. If a model is missing or cannot be loaded, the analyzers continue with rule-based behavior and report the model as unavailable.

## Development Guidance

- Preserve the public response fields in `backend/main.py` when changing analyzer internals.
- Keep user-facing explanations deterministic and understandable; every score should remain traceable to rules, model output, or both.
- Treat normalization as part of the URL analysis contract: the normalized URL is what feature extraction and model scoring receive.
- Add or update focused backend tests when changing risk rules, response schemas, persistence behavior, or model loading.
- Do not assume a module is production-wired merely because it exists. Check routes and frontend calls before extending a feature.
- Keep sensitive message content out of logs and persistence; the current message persistence design stores only a hash.

## Related Documentation

- [Architecture and AI context](ARCHITECTURE.md)
- [Backend data sources](backend/data_sources.md)
- [Frontend setup](frontend/README.md)
- [URL checker notes](url_checker/README.md)
>>>>>>> e8739a5 (fixed url to 55%)
