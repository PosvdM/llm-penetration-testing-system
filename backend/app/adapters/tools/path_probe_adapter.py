import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class PathProbeAdapter(ToolAdapter):
    name = "path_probe"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        args = [
            self.command_executable(),
            "-m",
            "app.adapters.tools.path_probe_runner",
            target,
        ]
        priority_paths = (context or {}).get("priority_paths", [])
        if priority_paths:
            args.append(json.dumps(priority_paths, ensure_ascii=False))
        return args

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        priority_paths = (context or {}).get("priority_paths", [])
        rationale = (
            "Probe a focused list of application paths to confirm admin panels, default content, "
            "and other immediately actionable web entry points."
        )
        if priority_paths:
            rationale = (
                "Probe the LLM-prioritized paths first, then fall back to baseline application checks "
                "for admin panels, default content, and other immediately actionable entry points."
            )
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=rationale,
            target=target,
            available=self.is_available(),
            execution_mode=self.execution_mode(),
        )

    def simulate(self, target: str, context=None) -> ToolExecutionResult:
        availability = self.is_available()
        priority_paths = (context or {}).get("priority_paths", [])
        first_path = priority_paths[0] if priority_paths else "/manager/html"
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary="Prototype path discovery suggests Tomcat default applications may be reachable.",
            evidence=[
                f"path: {first_path} -> 401",
                "path: /docs/ -> 200",
                f"binary available: {availability}",
            ],
            success=True,
            command=self.render_command(target, context),
            available=availability,
            execution_mode=self.execution_mode(),
        )

    def parse_native_result(
        self,
        *,
        target: str,
        completed,
        duration_ms: int,
        raw_output_path: str,
    ) -> ToolExecutionResult:
        stdout = completed.stdout.strip()
        evidence = ["No interesting application paths were confirmed."]
        summary = f"Path probe completed with return code {completed.returncode}."
        if stdout:
            try:
                payload = json.loads(stdout)
                interesting = payload.get("interesting", [])
                requested_paths = payload.get("requested_paths", [])
                if interesting:
                    evidence = []
                    for item in interesting[:5]:
                        line = f"path: {item.get('path', '/')} -> {item.get('status_code', 'unknown')}"
                        if item.get("title"):
                            line += f" | title: {item['title']}"
                        evidence.append(line)
                    summary = (
                        f"Path probe confirmed {len(interesting)} interesting application paths under "
                        f"{payload.get('base_url', target)}."
                    )
                    if requested_paths:
                        summary += f" Priority paths: {', '.join(requested_paths[:4])}."
                else:
                    checked = payload.get("checked", [])
                    if checked:
                        status_observations = []
                        for item in checked[:5]:
                            if item.get("status_code") is not None:
                                status_observations.append(
                                    f"path: {item.get('path', '/')} -> {item.get('status_code')}"
                                )
                        evidence = status_observations or [
                            f"checked {len(checked)} paths under {payload.get('base_url', target)} without a confirmed hit"
                        ]
                        summary = (
                            f"Path probe checked {len(checked)} paths under {payload.get('base_url', target)} "
                            "without confirming admin or default-content exposure."
                        )
                        if requested_paths:
                            summary += f" Priority paths: {', '.join(requested_paths[:4])}."
            except json.JSONDecodeError:
                evidence = stdout.splitlines()[:5]

        success = completed.returncode == 0
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary=summary,
            evidence=evidence,
            success=success,
            command=self.render_command(target),
            available=True,
            execution_mode="native",
            raw_output_path=raw_output_path,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
        )
