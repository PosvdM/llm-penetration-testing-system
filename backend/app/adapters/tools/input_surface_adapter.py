import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class InputSurfaceAdapter(ToolAdapter):
    name = "input_surface"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.input_surface_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Discover forms, same-origin routes, and other input-bearing entry points so the workflow "
                "can focus on realistic application surfaces instead of only default paths."
            ),
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
            summary="Prototype input-surface discovery identified a small set of candidate web entry points.",
            evidence=[
                "root: / -> 200",
                "form: POST /login | inputs: username,password",
                "link: /admin -> 200",
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
        evidence = ["No input-bearing surfaces were identified from the root page."]
        summary = f"Input-surface discovery completed with return code {completed.returncode}."

        if stdout:
            try:
                payload = json.loads(stdout)
                root = payload.get("root", {})
                forms = payload.get("forms", [])
                probed = payload.get("probed", [])
                evidence = []

                status_code = root.get("status_code")
                if status_code is not None:
                    root_line = f"root: / -> {status_code}"
                    if root.get("title"):
                        root_line += f" | title: {root['title']}"
                    evidence.append(root_line)

                for form in forms[:3]:
                    inputs = ",".join(form.get("inputs", [])[:4]) or "none"
                    evidence.append(
                        f"form: {form.get('method', 'GET')} {form.get('action', target)} | inputs: {inputs}"
                    )

                for item in probed[:3]:
                    line = f"link: {item.get('path', '/')} -> {item.get('status_code', 'unknown')}"
                    if item.get("title"):
                        line += f" | title: {item['title']}"
                    evidence.append(line)

                if forms or probed:
                    summary = (
                        f"Input-surface discovery found {len(forms)} forms and {len(probed)} candidate "
                        f"same-origin routes under {payload.get('base_url', target)}."
                    )
                elif root:
                    summary = (
                        f"Input-surface discovery reached {payload.get('base_url', target)} but did not find "
                        "forms or dynamic same-origin links from the root page."
                    )
                if not evidence:
                    evidence = ["No input-bearing surfaces were identified from the root page."]
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
