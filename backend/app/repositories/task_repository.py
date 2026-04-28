from collections.abc import Iterable
from pathlib import Path

from app.core.paths import TASK_STORAGE_DIR, ensure_data_dirs
from app.schemas.task import TaskDetail


class TaskRepository:
    def __init__(self, storage_dir: Path | None = None) -> None:
        ensure_data_dirs()
        self.storage_dir = storage_dir or TASK_STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._tasks: dict[str, TaskDetail] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        for task_file in sorted(self.storage_dir.glob("*.json")):
            task = TaskDetail.model_validate_json(task_file.read_text(encoding="utf-8"))
            self._tasks[task.task_id] = task

    def _task_path(self, task_id: str) -> Path:
        return self.storage_dir / f"{task_id}.json"

    def list(self) -> list[TaskDetail]:
        return list(self._tasks.values())

    def get(self, task_id: str) -> TaskDetail | None:
        return self._tasks.get(task_id)

    def save(self, task: TaskDetail) -> TaskDetail:
        self._tasks[task.task_id] = task
        self._task_path(task.task_id).write_text(task.model_dump_json(indent=2), encoding="utf-8")
        return task

    def extend(self, tasks: Iterable[TaskDetail]) -> None:
        for task in tasks:
            self.save(task)
