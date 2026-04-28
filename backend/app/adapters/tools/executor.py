from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired, run
from time import perf_counter
from uuid import uuid4

from app.adapters.tools.base import ToolAdapter
from app.core.paths import RAW_OUTPUT_DIR, ensure_data_dirs
from app.schemas.tool import ToolExecutionResult


def _timestamp_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _write_output(task_id: str, tool_name: str, content: str) -> Path:
    ensure_data_dirs()
    task_dir = RAW_OUTPUT_DIR / task_id
    task_dir.mkdir(parents=True, exist_ok=True)
    output_path = task_dir / f"{_timestamp_slug()}-{tool_name}-{uuid4().hex[:6]}.log"
    output_path.write_text(content, encoding="utf-8")
    return output_path


def execute_adapter(
    adapter: ToolAdapter,
    target: str,
    task_id: str,
    timeout_seconds: int = 20,
    context: dict | None = None,
) -> ToolExecutionResult:
    if not adapter.is_available():
        simulated = adapter.simulate(target, context)
        output_path = _write_output(
            task_id,
            adapter.name,
            "\n".join(
                [
                    "[simulated execution]",
                    f"tool={adapter.name}",
                    f"target={target}",
                    f"context={context or {}}",
                    f"command={simulated.command}",
                    *simulated.evidence,
                ]
            ),
        )
        simulated.raw_output_path = str(output_path)
        return simulated

    start = perf_counter()
    command = adapter.build_args(target, context)
    try:
        completed: CompletedProcess[str] = run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        duration_ms = int((perf_counter() - start) * 1000)
        stdout = completed.stdout.strip()
        stderr = completed.stderr.strip()
        raw_text = "\n".join(
            [
                f"$ {' '.join(command)}",
                "",
                "[stdout]",
                stdout or "<empty>",
                "",
                "[stderr]",
                stderr or "<empty>",
            ]
        )
        output_path = _write_output(task_id, adapter.name, raw_text)
        parsed = adapter.parse_native_result(
            target=target,
            completed=completed,
            duration_ms=duration_ms,
            raw_output_path=str(output_path),
        )
        parsed.command = adapter.render_command(target, context)
        return parsed
    except TimeoutExpired:
        duration_ms = int((perf_counter() - start) * 1000)
        timeout_content = "\n".join(
            [
                f"$ {' '.join(command)}",
                "",
                f"[timeout] command exceeded {timeout_seconds} seconds",
            ]
        )
        output_path = _write_output(task_id, adapter.name, timeout_content)
        return ToolExecutionResult(
            tool_name=adapter.name,
            category=adapter.category,
            target=target,
            summary=f"{adapter.name} timed out after {timeout_seconds} seconds.",
            evidence=[f"timeout after {timeout_seconds}s"],
            success=False,
            command=adapter.render_command(target, context),
            available=True,
            execution_mode="native",
            raw_output_path=str(output_path),
            exit_code=None,
            duration_ms=duration_ms,
        )
