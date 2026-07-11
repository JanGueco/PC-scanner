# NullScan

Personal on-demand file scanner desktop app built with Tauri, React, and Python FastAPI.

## Stack

- **Frontend:** Tauri v2, React, Vite, Tailwind CSS, shadcn/ui
- **Backend:** Python FastAPI sidecar on `http://127.0.0.1:8787`

## Development

1. Install frontend dependencies:

```bash
npm install
```

2. Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

3. Copy environment file (optional):

```bash
copy backend\.env.example backend\.env
```

4. Run the app:

```bash
npm run tauri:dev
```

This starts the FastAPI backend and Tauri dev window together.

## Production Build

```bash
npm run tauri:build
```

Builds the PyInstaller sidecar and packages the Tauri app.

## MalwareBazaar Auth-Key

Get a free key at https://auth.abuse.ch/ and add it in Settings or set `MALWAREBAZAAR_AUTH_KEY` in `backend/.env`.
