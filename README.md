# SafeShield

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
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=safeshield
```

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
