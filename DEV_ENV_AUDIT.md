# Development Environment Audit

## Prepared On

- Date: 2026-04-14
- Workspace: `D:\Codex\LLM Penetration Testing System`

## Installed or Confirmed

### Core Development Tools

- Git: `2.53.0.windows.2`
- Node.js LTS: `v24.14.1`
- npm: `11.11.0`
- pnpm: `10.33.0`
- Python: existing `3.14.4`
- Python 3.12: installed as stable project runtime target
- uv: installed
- ripgrep: installed

### Python Development Tools

Installed for `Python 3.12`:

- `pip`
- `pytest`
- `ruff`

## Recommended Runtime Choice

For this project, prefer:

- backend runtime: `Python 3.12`
- frontend runtime: `Node.js LTS`

Avoid using Python `3.14` as the default project interpreter unless we verify package compatibility first.

## Suggested Commands

### Python 3.12

```powershell
py -3.12 --version
py -3.12 -m pip --version
```

### Node and pnpm

```powershell
node --version
npm --version
pnpm --version
```

### Git

```powershell
git --version
```

### uv

```powershell
uv --version
```

## Notes

- Some newly installed tools may require a new terminal session before they are available on PATH everywhere.
- Current system PATH already includes Git and Node.js machine-wide locations.
- Current user PATH already includes Python 3.12, uv, and ripgrep.
- PowerShell execution policy for the current user was set to `RemoteSigned` so `npm` and `pnpm` can run normally in PowerShell.

## Not Installed Yet

### Docker Desktop

Not installed in this pass.

Reason:

- current machine check did not show a ready WSL/Hypervisor setup for a clean Docker Desktop workflow

If containerized local deployment is needed later, we should prepare:

1. WSL2 availability
2. virtualization support
3. Docker Desktop installation and verification

## Next Recommended Setup Step

The next practical step is to initialize the project skeleton with:

1. backend folder
2. frontend folder
3. Python 3.12 virtual environment via `uv`
4. FastAPI and React/Vite base scaffolding
