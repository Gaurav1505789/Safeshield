<<<<<<< HEAD
# SafeShield Frontend - Installation & Setup

This frontend connects to the FastAPI backend at http://127.0.0.1:8000, including native URL analysis.

## Prerequisites

- Node.js 16+ and npm/yarn/pnpm
- Backend running on http://127.0.0.1:8000

## Installation Steps

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Start Development Server
```bash
npm run dev
```

The frontend will run at: **http://localhost:3000**

### 3. Build for Production
```bash
npm run build
```

## Backend Requirements

Make sure your FastAPI backend is running:
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

## Testing the Connection

1. Open http://localhost:3000 in your browser
2. You should see "● Connected" in the top-right corner
3. Navigate to "Message Scanner"
4. Test with: "URGENT! Your bank account has expired. Click here to verify."
5. Select **Analyze URL** to open the integrated URL checker.
5. You should see the analysis result from the backend

## File Structure

```
frontend/
├── src/
│   ├── main.jsx           # Entry point
│   ├── App.jsx            # Main app component
│   ├── App.css            # Main styles
│   ├── index.css          # Global styles
│   ├── api.js             # API client (calls backend)
│   └── pages/
│       ├── Dashboard.jsx
│       ├── Dashboard.css
│       ├── MessageScanner.jsx
│       ├── MessageScanner.css
│       ├── URLScanner.jsx
│       └── URLScanner.css
├── index.html
├── package.json
└── vite.config.js
```

## CORS Configuration

The backend is configured to accept requests from:
- http://localhost:3000
- http://127.0.0.1:3000

If you change the frontend port, update the CORS in `backend/main.py`.
=======
# SafeShield

SafeShield is a local-first cyber-risk analysis application for user-initiated inspection of suspicious messages, URLs, and Android APK files. It combines deterministic rules, optional machine-learning models, explainable findings, and a React interface backed by FastAPI.

SafeShield is a research and development project. Its results support human review and do not replace security, financial, legal, or incident-response decisions.

## Current Scope

Implemented end to end:

- Message analysis through the FastAPI backend and React Message Scanner.
- URL normalization, rule analysis, optional model scoring, and React URL Scanner results.
- APK upload and static analysis through the FastAPI backend and React APK Scanner.
- Explainable scores, risk levels or verdicts, categories, reasons, indicators, confidence values, and recommendations.
- Optional MongoDB persistence. Message plaintext is not stored; message records contain a SHA-256 hash.
- Offline training and evaluation utilities for message and URL models.

Prototype or incomplete:

- The Chrome extension currently displays local hard-coded result templates. It does not call the backend or inspect WhatsApp content.
- Dashboard statistics and recent analyses are static placeholders.
- Image analysis code exists but is not exposed by an API route or frontend page.
- Image Scanner, Analysis History, and Reports navigation items are disabled in the React app.
- URL-checker documentation may mention external reputation providers, but the current runtime does not make live VirusTotal or Google Safe Browsing requests.
- No frontend test suite currently exists.

For the detailed system map and maintenance guidance, read [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository Layout

```text
SafeShield/
|- backend/                 FastAPI service and Python analyzers
|  |- analyzer/            Message, URL, APK, and image analyzers
|  |- data/                Message datasets
|  |- ml/                  Message preprocessing and training
|  |- main.py              API app, models, routes, and persistence calls
|  |- risk_engine.py       Message scoring and categorization
|  |- database.py          Optional MongoDB setup
|  |- requirements.txt     Backend dependencies
|  `- test_*.py            Backend tests
|- frontend/                React 18 and Vite web application
|  `- src/                 App shell, API client, pages, and styles
|- extension/               Chrome Manifest V3 popup prototype
|- url_checker/             URL rules, features, models, datasets, and scripts
|- ARCHITECTURE.md          System design and AI maintenance context
`- README.md                Project setup and usage guide
```

Large or generated files are summarized rather than listed individually. The URL checker contains model artifacts, datasets, scan logs, and raw provider-response snapshots under `url_checker/dataset/`.

## Requirements

- Windows, macOS, or Linux.
- Python 3.10 or newer.
- Node.js 16 or newer and npm.
- MongoDB only when persistence is required.
- Java/Android tooling is not required for the current APK analysis implementation; APK files are parsed statically with Androguard.

The backend dependencies are pinned or constrained in [backend/requirements.txt](backend/requirements.txt). APK uploads also require the FastAPI multipart form dependency available in the active environment.

## Setup and Run

From the repository root, create or activate a virtual environment and install backend dependencies:

```powershell
py -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
py -m pip install -r backend\\requirements.txt
```

Start the backend in one terminal:

```powershell
.\\.venv\\Scripts\\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Install and start the frontend in another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The backend OpenAPI UI is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

The frontend API base URL is currently hard-coded to `http://127.0.0.1:8000` in `frontend/src/api.js`. If it changes, update the backend CORS configuration in `backend/main.py` as well.

## Configuration

MongoDB is optional. Create `backend/.env` only when persistence is needed:

```dotenv
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=safeshield
```

Without `MONGODB_URI`, analysis still runs and results are returned without being saved. When MongoDB is configured but insertion fails, the message and URL endpoints return HTTP 503 after analysis.

Do not commit API keys, credentials, private datasets, generated virtual environments, or sensitive provider responses.

## API Quick Reference

| Method | Route | Request | Purpose |
|---|---|---|---|
| GET | `/` | none | Service metadata and documentation links |
| GET | `/health` | none | Health response |
| POST | `/analyze/message` | `{ "message": "..." }` | Analyze message risk |
| POST | `/analyze/url` | `{ "url": "..." }` | Analyze URL risk |
| POST | `/analyze/apk` | `multipart/form-data` field `file` | Analyze an APK upload |

Message requests accept 1-5000 characters. URL requests accept 1-2048 characters. Unknown JSON fields are rejected, and blank values are rejected after trimming.

Message and URL responses include an `SS-XXXXXXXXXX` analysis ID, `risk_score`, `risk_level`, `category`, `confidence`, `reasons`, `detected_indicators`, `recommendation`, `model_prediction`, `model_confidence`, and `rule_confidence`. URL responses additionally include `original_url`, `normalized_url`, `verdict`, and `domain_valid`.

Message risk levels are `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` at score thresholds 25, 50, and 75. URL verdicts are `SAFE` or `FRAUD`; URL verdict and numeric score are related but not identical because suspicious rule findings can force a fraud verdict below the high-score threshold.

APK responses include file metadata, SHA-256, package and version information, permissions, suspicious permissions, API findings, component counts, a score from 0 to 100, and a verdict of `low_risk`, `suspicious`, or `dangerous`.

## Analysis Behavior

### Messages

The message analyzer normalizes whitespace and checks word-boundary patterns for urgency, banking, credentials, financial rewards, downloads, links, threats, and sensitive information. Requests for credentials or sensitive information receive additional indicators. The risk engine combines rule points with an optional `backend/ml/models/message_model.joblib` prediction and caps non-suspicious messages below 25.

### URLs

The URL analyzer normalizes the URL, removes selected tracking parameters, extracts structural features, evaluates URL rules, and optionally loads `url_checker/model/url_model_calibrated.pkl` or `url_model.pkl`. Model probability contributes 60% and rule probability 40%. The analyzer also handles malformed hosts, IP addresses, punycode, and suspicious URL structures.

### APKs

The APK analyzer parses the uploaded package with Androguard, calculates a SHA-256 hash, reads package metadata and permissions, searches DEX content for suspicious APIs, counts components, and adds risk points for high-risk capabilities. It does not execute the APK and should not be treated as a full malware verdict.

## Tests and Model Commands

Run backend API tests from the repository root:

```powershell
.\\.venv\\Scripts\\python.exe -m unittest discover -s backend -p "test_*.py"
```

Run URL rule checks and evaluation:

```powershell
Set-Location url_checker
..\\.venv\\Scripts\\python.exe scripts\\test_rule_check.py
..\\.venv\\Scripts\\python.exe scripts\\evaluate_url_checker.py
```

Train the message model:

```powershell
Set-Location backend
..\\.venv\\Scripts\\python.exe ml\\train_message_model.py
```

Train URL models:

```powershell
Set-Location url_checker
..\\.venv\\Scripts\\python.exe train_model.py
```

The analyzers continue with rules when model artifacts are missing or incompatible and report the model as unavailable.

## Browser Extension

The extension is a Manifest V3 popup prototype. To load it in Chrome, open `chrome://extensions/`, enable Developer mode, choose **Load unpacked**, and select the `extension/` directory. Its current behavior is local-only and stores its last result under `safeShieldLastResult`; backend integration is not implemented.

## Development Guidance

- Preserve public response fields when changing analyzer internals.
- Keep user-facing explanations deterministic and understandable.
- Treat URL normalization as part of the scoring contract.
- Keep message plaintext out of logs and persistence.
- Add focused backend tests when changing rules, thresholds, schemas, persistence, or model loading.
- Update [ARCHITECTURE.md](ARCHITECTURE.md) whenever a route, integration, model path, or implementation status changes.

## License

This project is currently intended for educational and prototype use in a cybersecurity context.
>>>>>>> 77cc4f6aaa2cb99b5d850849d631016dc9ab77fa
