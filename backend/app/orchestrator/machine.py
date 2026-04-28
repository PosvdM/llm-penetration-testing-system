from app.orchestrator.states import TASK_WORKFLOW, TaskStatus


ALLOWED_TRANSITIONS: dict[TaskStatus, TaskStatus] = {
    TaskStatus.PENDING: TaskStatus.RECON,
    TaskStatus.RECON: TaskStatus.ANALYSIS,
    TaskStatus.ANALYSIS: TaskStatus.SCAN,
    TaskStatus.SCAN: TaskStatus.VERIFY,
    TaskStatus.VERIFY: TaskStatus.POST_VERIFY,
    TaskStatus.POST_VERIFY: TaskStatus.REPORTING,
    TaskStatus.REPORTING: TaskStatus.COMPLETED,
}

PHASE_LABELS: dict[TaskStatus, str] = {
    TaskStatus.PENDING: "等待开始",
    TaskStatus.RECON: "Recon 侦察中",
    TaskStatus.ANALYSIS: "LLM 策略分析",
    TaskStatus.SCAN: "执行扫描工具",
    TaskStatus.VERIFY: "验证发现",
    TaskStatus.POST_VERIFY: "证据整理与归档",
    TaskStatus.REPORTING: "生成结构化报告",
    TaskStatus.COMPLETED: "流程已完成",
    TaskStatus.FAILED: "流程失败",
}


def get_next_status(status: TaskStatus) -> TaskStatus:
    return ALLOWED_TRANSITIONS.get(status, status)


def get_phase_label(status: TaskStatus) -> str:
    return PHASE_LABELS[status]


def workflow_progress(status: TaskStatus) -> tuple[int, int]:
    try:
        return TASK_WORKFLOW.index(status) + 1, len(TASK_WORKFLOW)
    except ValueError:
        return 0, len(TASK_WORKFLOW)
