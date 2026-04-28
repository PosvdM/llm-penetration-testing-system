import json

from app.adapters.tools.base import ToolAdapter
from app.core.paths import BACKEND_DIR
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class LoginSQLiProbeAdapter(ToolAdapter):
    name = "login_sqli_probe"
    category = "scan"
    command_name = str(BACKEND_DIR / ".venv" / "Scripts" / "python.exe")

    def build_args(self, target: str, context=None) -> list[str]:
        return [
            self.command_executable(),
            "-m",
            "app.adapters.tools.login_sqli_probe_runner",
            target,
        ]

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Probe discovered login forms with a low-noise boolean SQLi payload so the workflow can "
                "confirm obvious authentication-bypass style SQL injection."
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
            summary="Prototype login SQLi probe identified login forms but did not confirm bypass.",
            evidence=[
                "form: /patientlogin.php -> user=loginid pass=password",
                "no confirmed login bypass from current form set",
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
        evidence = ["No login forms were confirmed as SQL-injectable from the current same-origin page set."]
        summary = f"Login SQLi probe completed with return code {completed.returncode}."

        if stdout:
            try:
                payload = json.loads(stdout)
                forms = payload.get("forms", [])
                confirmed = payload.get("confirmed", [])
                evidence = []

                for form in forms[:3]:
                    evidence.append(
                        f"form: {form.get('action', target)} -> user={form.get('username_field')} "
                        f"pass={form.get('password_field')}"
                    )

                for item in confirmed[:2]:
                    evidence.append(
                        f"confirmed: {item.get('page', '/')} -> {item.get('action', '/')} "
                        f"| user={item.get('username_field')} pass={item.get('password_field')} "
                        f"| success_hint={item.get('success_hint', 'unknown')}"
                    )

                if confirmed:
                    summary = (
                        f"Login SQLi probe confirmed {len(confirmed)} authentication-bypass indicator(s) under "
                        f"{payload.get('base_url', target)}."
                    )
                elif forms:
                    summary = (
                        f"Login SQLi probe identified {len(forms)} login form(s) under "
                        f"{payload.get('base_url', target)} but did not confirm bypass."
                    )
                    evidence.append("no confirmed login bypass from current form set")
                elif payload.get("error"):
                    summary = f"Login SQLi probe failed while inspecting {payload.get('base_url', target)}."
                    evidence = [f"error: {payload['error']}"]
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
