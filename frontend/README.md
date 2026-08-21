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
