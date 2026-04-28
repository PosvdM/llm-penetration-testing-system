from enum import StrEnum


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    RECON = "RECON"
    ANALYSIS = "ANALYSIS"
    SCAN = "SCAN"
    VERIFY = "VERIFY"
    POST_VERIFY = "POST_VERIFY"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


TASK_WORKFLOW: list[TaskStatus] = [
    TaskStatus.PENDING,
    TaskStatus.RECON,
    TaskStatus.ANALYSIS,
    TaskStatus.SCAN,
    TaskStatus.VERIFY,
    TaskStatus.POST_VERIFY,
    TaskStatus.REPORTING,
    TaskStatus.COMPLETED,
]
