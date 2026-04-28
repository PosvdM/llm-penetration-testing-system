from fastapi import APIRouter

from app.schemas.task import (
    ReportPreviewResponse,
    TaskAdvanceResponse,
    TaskCreateRequest,
    TaskDetail,
    TaskStartResponse,
    TaskSummary,
)
from app.services.task_service import (
    advance_task,
    create_task,
    get_report_preview,
    get_task,
    list_tasks,
    start_task,
)

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.get("")
def get_tasks() -> list[TaskSummary]:
    return list_tasks()


@router.post("", status_code=201)
def post_task(payload: TaskCreateRequest) -> TaskDetail:
    return create_task(payload)


@router.get("/{task_id}")
def get_task_detail(task_id: str) -> TaskDetail:
    return get_task(task_id)


@router.post("/{task_id}/advance")
def post_advance_task(task_id: str) -> TaskAdvanceResponse:
    return advance_task(task_id)


@router.post("/{task_id}/start")
def post_start_task(task_id: str) -> TaskStartResponse:
    return start_task(task_id)


@router.get("/{task_id}/report")
def get_task_report(task_id: str) -> ReportPreviewResponse:
    return get_report_preview(task_id)
