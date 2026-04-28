# Getting Started

## One-Click Startup

From the project root:

```powershell
.\start-dev.ps1
```

This opens separate PowerShell windows for the backend and frontend dev servers.

## Backend

```powershell
cd backend
uv venv --python 3.12
.\.venv\Scripts\activate
uv sync
uv run uvicorn app.main:app --reload
```

Open:

- API root: `http://127.0.0.1:8000/`
- Swagger UI: `http://127.0.0.1:8000/docs`

## Frontend

```powershell
cd frontend
pnpm install
pnpm dev
```

Open:

- Dashboard: `http://127.0.0.1:5173/`

## Environment Variables

Copy root `.env.example` to `.env` when API keys or custom ports are needed.
