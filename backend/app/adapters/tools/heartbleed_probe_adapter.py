from app.adapters.tools.base import ToolAdapter
from app.schemas.tool import ToolExecutionPlan, ToolExecutionResult


class HeartbleedProbeAdapter(ToolAdapter):
    name = "heartbleed_probe"
    category = "scan"
    command_name = "nmap"

    def build_args(self, target: str, context=None) -> list[str]:
        profile = self.target_profile(target)
        args = [self.command_executable(), "-Pn", "--script", "ssl-heartbleed"]
        if profile.port is not None:
            args.extend(["-p", str(profile.port)])
        args.append(profile.host)
        return args

    def build_plan(self, target: str, context=None) -> ToolExecutionPlan:
        return ToolExecutionPlan(
            tool_name=self.name,
            category=self.category,
            command=self.render_command(target, context),
            rationale=(
                "Run the targeted ssl-heartbleed probe against TLS-enabled services so the workflow can "
                "confirm or reject CVE-2014-0160 exposure with reproducible evidence."
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
            summary="Prototype Heartbleed probe did not confirm CVE-2014-0160 exposure.",
            evidence=[
                "ssl-heartbleed: no vulnerable TLS heartbeat behavior observed",
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
        lowered = stdout.lower()
        success = completed.returncode == 0

        if "vulnerable:" in lowered and "ssl-heartbleed" in lowered:
            evidence = [
                "ssl-heartbleed: VULNERABLE",
                "state: VULNERABLE",
                "cve: CVE-2014-0160",
            ]
            summary = "Heartbleed probe confirmed CVE-2014-0160 exposure."
        elif "ssl-heartbleed" in lowered:
            evidence = ["ssl-heartbleed executed without a positive vulnerability match"]
            summary = "Heartbleed probe completed without confirming CVE-2014-0160."
        else:
            first_signal = next((line.strip() for line in stdout.splitlines() if line.strip()), "No Heartbleed signal captured")
            evidence = [first_signal]
            summary = f"Heartbleed probe completed with return code {completed.returncode}."

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
