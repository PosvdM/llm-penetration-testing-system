import json

from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    category = "recon"
    command_name = "httpx"

    def build_args(self, target: str, context=None) -> list[str]:
        profile = self.target_profile(target)
        return [
            self.command_executable(),
            "-u",
            profile.request_url,
            "-json",
            "-silent",
            "-title",
            "-tech-detect",
            "-status-code",
            "-web-server",
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale="Confirm HTTP reachability and collect lightweight web fingerprints.",
            target=target,
            available=self.is_available(),
            execution_mode=self.execution_mode(),
        )

    def simulate(self, target: str, context=None) -> ToolExecutionResult:
        availability = self.is_available()
        return ToolExecutionResult(
            tool_name=self.name,
            category=self.category,
            target=target,
            summary="Prototype web probe confirmed an HTTP endpoint responding on the target.",
            evidence=[
                "status: 200",
                "title: Apache Tomcat/8.5.x",
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
        evidence = ["No HTTP response captured"]
        summary = f"httpx completed with return code {completed.returncode}."
        if stdout:
            try:
                payload = json.loads(stdout.splitlines()[0])
                evidence = [
                    f"url: {payload.get('url', target)}",
                    f"status_code: {payload.get('status_code', 'unknown')}",
                ]
                if payload.get("title"):
                    evidence.append(f"title: {payload['title']}")
                if payload.get("webserver"):
                    evidence.append(f"webserver: {payload['webserver']}")
                tech = payload.get("tech") or []
                if tech:
                    evidence.append(f"tech: {', '.join(tech)}")
                summary = (
                    f"httpx confirmed {payload.get('url', target)} with status "
                    f"{payload.get('status_code', 'unknown')}."
                )
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
