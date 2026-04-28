from copy import deepcopy
from datetime import UTC, datetime
from threading import RLock, Thread
from time import sleep
from uuid import uuid4

from fastapi import HTTPException, status

from app.adapters.tools.executor import execute_adapter
from app.adapters.tools.registry import get_recon_adapters, get_scan_adapters
from app.orchestrator.machine import get_next_status, get_phase_label, workflow_progress
from app.orchestrator.states import TaskStatus
from app.repositories.task_repository import TaskRepository
from app.schemas.task import (
    ReportPreviewResponse,
    TaskAdvanceResponse,
    TaskCreateRequest,
    TaskDetail,
    TaskStartResponse,
    TaskSummary,
    TimelineEvent,
)
from app.services.llm_service import llm_analysis_service
from app.services.report_service import write_report
from app.services.verification_service import evaluate_verification

repository = TaskRepository()
service_lock = RLock()
AUTOMATION_STEP_DELAY_SECONDS = 0.2


def _timestamp() -> datetime:
    return datetime.now(UTC)


def _make_event(
    task_id: str,
    phase: TaskStatus,
    title: str,
    detail: str,
    event_status: str,
) -> TimelineEvent:
    return TimelineEvent(
        event_id=f"{task_id}-{phase.lower()}-{uuid4().hex[:8]}",
        title=title,
        status=event_status,  # type: ignore[arg-type]
        phase=phase,
        detail=detail,
    )


def _build_recon_plans(target: str):
    return [adapter.build_plan(target) for adapter in get_recon_adapters()]


def _build_scan_context(task: TaskDetail | None = None) -> dict:
    if task is None or task.llm_strategy_plan is None:
        return {}
    return {
        "priority_paths": task.llm_strategy_plan.priority_paths,
        "focus_areas": task.llm_strategy_plan.focus_areas,
        "verification_goals": task.llm_strategy_plan.verification_goals,
    }


def _build_scan_plans(target: str, task: TaskDetail | None = None):
    context = _build_scan_context(task)
    adapters = get_scan_adapters()
    if task and task.llm_strategy_plan is not None:
        requested = set(task.llm_strategy_plan.recommended_tools)
        if requested:
            adapters = [adapter for adapter in adapters if adapter.name in requested]
        else:
            adapters = []
    return [adapter.build_plan(target, context) for adapter in adapters]


def _refresh_planned_tools(task: TaskDetail) -> None:
    task.planned_tools = _build_recon_plans(task.target) + _build_scan_plans(task.target, task)


def _seed_task() -> TaskDetail:
    progress_current, progress_total = workflow_progress(TaskStatus.PENDING)
    return TaskDetail(
        task_id="demo-vulhub-s2-045",
        target="http://127.0.0.1:8080",
        scenario="Vulhub / Struts2 S2-045 演示任务",
        status=TaskStatus.PENDING,
        current_phase=get_phase_label(TaskStatus.PENDING),
        is_running=False,
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[
            _make_event(
                "demo-vulhub-s2-045",
                TaskStatus.PENDING,
                "任务已创建",
                "已为默认 Vulhub 演示场景初始化原型任务。",
                "active",
            )
        ],
        planned_tools=_build_recon_plans("http://127.0.0.1:8080") + _build_scan_plans("http://127.0.0.1:8080"),
    )


if not repository.list():
    repository.save(_seed_task())


def _to_summary(task: TaskDetail) -> TaskSummary:
    return TaskSummary(
        task_id=task.task_id,
        target=task.target,
        scenario=task.scenario,
        status=task.status,
        current_phase=task.current_phase,
        is_running=task.is_running,
        created_at=task.created_at,
    )


def _get_task_or_404(task_id: str) -> TaskDetail:
    task = repository.get(task_id)
    if task is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found.")
    return task


def _complete_current_event(task: TaskDetail) -> None:
    if task.timeline:
        task.timeline[-1].status = "done"


def _append_event(task: TaskDetail, phase: TaskStatus, title: str, detail: str, event_status: str) -> None:
    task.timeline.append(_make_event(task.task_id, phase, title, detail, event_status))


def _run_recon_stage(task: TaskDetail) -> str:
    results = []
    for adapter in get_recon_adapters():
        result = execute_adapter(adapter, task.target, task.task_id)
        results.append(result)
        output_hint = result.raw_output_path or "no artifact path recorded"
        _append_event(
            task,
            TaskStatus.RECON,
            f"{adapter.name} completed",
            f"{result.summary} Raw output: {output_hint}",
            "done",
        )
    task.tool_results = results
    task.latest_result = results[-1] if results else None
    succeeded = sum(1 for result in results if result.success)
    return f"Recon collected {succeeded}/{len(results)} adapter results for analysis."


def _run_analysis_stage(task: TaskDetail) -> str:
    task.llm_strategy_plan = llm_analysis_service.build_strategy_plan(task)
    task.analysis_summary = task.llm_strategy_plan.summary
    _refresh_planned_tools(task)
    _append_event(
        task,
        TaskStatus.ANALYSIS,
        "LLM analysis completed",
        (
            f"{task.analysis_summary} Selected tools: "
            f"{', '.join(task.llm_strategy_plan.recommended_tools) or 'none'}."
        ),
        "done",
    )
    return task.analysis_summary


def _run_scan_stage(task: TaskDetail) -> str:
    strategy_plan = task.llm_strategy_plan
    scan_context = _build_scan_context(task)
    scan_adapters = get_scan_adapters()
    if strategy_plan and strategy_plan.recommended_tools:
        requested = set(strategy_plan.recommended_tools)
        prioritized_adapters = [adapter for adapter in scan_adapters if adapter.name in requested]
        fallback_adapters = [adapter for adapter in scan_adapters if adapter.name not in requested]
        scan_adapters = prioritized_adapters or fallback_adapters
    elif strategy_plan and not strategy_plan.recommended_tools:
        _append_event(
            task,
            TaskStatus.SCAN,
            "LLM scan plan applied",
            "Recon did not confirm a stable reachable application surface, so application-layer scans were skipped.",
            "done",
        )
        return "Scan skipped because recon did not confirm a stable reachable application surface."
    selected_names = [adapter.name for adapter in scan_adapters]
    _append_event(
        task,
        TaskStatus.SCAN,
        "LLM scan plan applied",
        (
            f"Executing scan adapters selected by the LLM strategy plan: "
            f"{', '.join(selected_names) or 'none'}."
        ),
        "done",
    )
    scan_results = []
    for adapter in scan_adapters:
        result = execute_adapter(adapter, task.target, task.task_id, context=scan_context)
        scan_results.append(result)
        task.tool_results.append(result)
        task.latest_result = result
        output_hint = result.raw_output_path or "no artifact path recorded"
        _append_event(
            task,
            TaskStatus.SCAN,
            f"{adapter.name} completed",
            f"{result.summary} Raw output: {output_hint}",
            "done",
        )

    if not scan_results:
        return "Scan stage completed without any configured scan adapters."

    findings = sum(1 for result in scan_results if result.success)
    return (
        f"Scan completed with {findings}/{len(scan_results)} successful adapter executions. "
        f"Selected by LLM: {', '.join(selected_names) or 'none'}."
    )


def _run_verify_stage(task: TaskDetail) -> str:
    decision = evaluate_verification(task)
    task.verified_findings = decision.findings
    llm_summary = llm_analysis_service.summarize_verification(task)
    verification_context = []
    if decision.goal_status:
        verification_context.append("Goals: " + " | ".join(decision.goal_status))
    if decision.stop_condition_status:
        verification_context.append("Stops: " + " | ".join(decision.stop_condition_status))
    verification_context.append(f"Recommendation: {decision.recommendation}")
    task.verification_summary = " ".join([llm_summary, *verification_context]).strip()
    _append_event(
        task,
        TaskStatus.VERIFY,
        "Verification summary completed",
        task.verification_summary,
        "done",
    )
    return task.verification_summary


def _run_reporting_stage(task: TaskDetail) -> str:
    executive_summary = llm_analysis_service.summarize_report(task)
    task.report_artifact = write_report(task, executive_summary)
    _append_event(
        task,
        TaskStatus.REPORTING,
        "Report artifact generated",
        f"Report written to {task.report_artifact.report_path}",
        "done",
    )
    return executive_summary


def _phase_detail(task: TaskDetail, next_status: TaskStatus) -> str:
    if next_status == TaskStatus.RECON:
        return _run_recon_stage(task)
    if next_status == TaskStatus.ANALYSIS:
        return _run_analysis_stage(task)
    if next_status == TaskStatus.SCAN:
        return _run_scan_stage(task)
    if next_status == TaskStatus.VERIFY:
        return _run_verify_stage(task)
    if next_status == TaskStatus.POST_VERIFY:
        return "Evidence is being consolidated for reporting and reproducibility."
    if next_status == TaskStatus.REPORTING:
        return _run_reporting_stage(task)
    if next_status == TaskStatus.COMPLETED:
        return "Prototype workflow completed successfully."
    return f"Phase advanced to {next_status}."


def _advance_task_locked(task: TaskDetail) -> TaskAdvanceResponse:
    if task.is_running and task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
        task.is_running = False

    if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
        return TaskAdvanceResponse(task=deepcopy(task), advanced=False)

    current_status = task.status
    next_status = get_next_status(current_status)
    if next_status == current_status:
        return TaskAdvanceResponse(task=deepcopy(task), advanced=False)

    _complete_current_event(task)

    task.status = next_status
    task.current_phase = get_phase_label(next_status)
    task.progress_current, task.progress_total = workflow_progress(next_status)
    task.updated_at = _timestamp()
    event_status = "active" if next_status not in {TaskStatus.COMPLETED, TaskStatus.FAILED} else "done"
    _append_event(task, next_status, task.current_phase, "Phase entered.", event_status)
    phase_event = task.timeline[-1]
    phase_event.detail = _phase_detail(task, next_status)

    if next_status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
        task.is_running = False

    repository.save(task)
    return TaskAdvanceResponse(task=deepcopy(task), advanced=True)


def _automation_worker(task_id: str) -> None:
    try:
        while True:
            with service_lock:
                task = _get_task_or_404(task_id)
                if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
                    task.is_running = False
                    repository.save(task)
                    break
                _advance_task_locked(task)
            sleep(AUTOMATION_STEP_DELAY_SECONDS)
    except Exception as exc:
        with service_lock:
            task = repository.get(task_id)
            if task is not None:
                task.status = TaskStatus.FAILED
                task.current_phase = get_phase_label(TaskStatus.FAILED)
                task.is_running = False
                task.last_error = str(exc)
                task.updated_at = _timestamp()
                _complete_current_event(task)
                _append_event(task, TaskStatus.FAILED, "Workflow failed", str(exc), "done")
                repository.save(task)


def list_tasks() -> list[TaskSummary]:
    with service_lock:
        tasks = sorted(repository.list(), key=lambda task: task.created_at, reverse=True)
        return [_to_summary(task) for task in tasks]


def get_task(task_id: str) -> TaskDetail:
    with service_lock:
        task = _get_task_or_404(task_id)
        return deepcopy(task)


def create_task(payload: TaskCreateRequest) -> TaskDetail:
    with service_lock:
        task_id = f"task-{uuid4().hex[:8]}"
        progress_current, progress_total = workflow_progress(TaskStatus.PENDING)
        task = TaskDetail(
            task_id=task_id,
            target=payload.target,
            scenario=payload.scenario,
            status=TaskStatus.PENDING,
            current_phase=get_phase_label(TaskStatus.PENDING),
            is_running=False,
            progress_current=progress_current,
            progress_total=progress_total,
            timeline=[
                _make_event(
                    task_id,
                    TaskStatus.PENDING,
                    "Task created",
                    f"Authorized target registered: {payload.target}",
                    "active",
                )
            ],
            planned_tools=_build_recon_plans(payload.target) + _build_scan_plans(payload.target),
        )
        repository.save(task)
        return deepcopy(task)


def advance_task(task_id: str) -> TaskAdvanceResponse:
    with service_lock:
        task = _get_task_or_404(task_id)
        if task.is_running:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="该任务正在自动运行中，暂时不能手动推进。",
            )
        return _advance_task_locked(task)


def start_task(task_id: str) -> TaskStartResponse:
    with service_lock:
        task = _get_task_or_404(task_id)
        if task.is_running:
            return TaskStartResponse(task=deepcopy(task), started=False)
        if task.status in {TaskStatus.COMPLETED, TaskStatus.FAILED}:
            return TaskStartResponse(task=deepcopy(task), started=False)

        task.is_running = True
        task.updated_at = _timestamp()
        _complete_current_event(task)
        _append_event(
            task,
            task.status,
            "流程已启动",
            "该任务的自动化编排流程已经启动。",
            "active",
        )
        repository.save(task)

    worker = Thread(target=_automation_worker, args=(task_id,), daemon=True)
    worker.start()

    with service_lock:
        refreshed = _get_task_or_404(task_id)
        return TaskStartResponse(task=deepcopy(refreshed), started=True)


def get_report_preview(task_id: str) -> ReportPreviewResponse:
    with service_lock:
        task = _get_task_or_404(task_id)
        if task.report_artifact is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Report has not been generated for this task yet.",
            )

        report_path = task.report_artifact.report_path
        content = open(report_path, "r", encoding="utf-8").read()
        return ReportPreviewResponse(
            task_id=task_id,
            report_path=report_path,
            content=content,
        )
