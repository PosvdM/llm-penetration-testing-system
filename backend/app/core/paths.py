from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_OUTPUT_DIR = DATA_DIR / "raw"
REPORT_OUTPUT_DIR = DATA_DIR / "reports"
TASK_STORAGE_DIR = DATA_DIR / "tasks"


def ensure_data_dirs() -> None:
    RAW_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    TASK_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
