import os
from pathlib import Path
from time import sleep, time

from fastapi.testclient import TestClient
import httpx

os.environ["OPENAI_API_KEY"] = ""

from app.main import app
from app.adapters.tools.command_probe_adapter import CommandProbeAdapter
from app.adapters.tools.heartbleed_probe_adapter import HeartbleedProbeAdapter
from app.adapters.tools.httpx_adapter import HttpxAdapter
from app.adapters.tools.input_surface_adapter import InputSurfaceAdapter
from app.adapters.tools.login_sqli_probe_adapter import LoginSQLiProbeAdapter
from app.adapters.tools.param_injection_probe_adapter import ParamInjectionProbeAdapter
from app.adapters.tools.sensitive_file_probe_adapter import SensitiveFileProbeAdapter
from app.adapters.tools.web_common import (
    extract_forms,
    extract_links,
    extract_query_candidates,
    response_indicates_success_delta,
    select_form_fields,
    snapshot_response,
)
from app.adapters.tools.nmap_adapter import NmapAdapter
from app.adapters.tools.nuclei_adapter import NucleiAdapter
from app.adapters.tools.path_probe_adapter import PathProbeAdapter
from app.adapters.tools.web_fingerprint_adapter import WebFingerprintAdapter
from app.core.paths import BACKEND_DIR
from app.core.targeting import parse_target
from app.orchestrator.machine import get_phase_label, workflow_progress
from app.orchestrator.states import TaskStatus
from app.repositories.task_repository import TaskRepository
from app.schemas.task import LLMStrategyPlan, TaskDetail, TimelineEvent
from app.schemas.tool import ToolExecutionResult
from app.services.report_service import write_report
from app.services.verification_service import build_verified_findings, evaluate_verification
from app.services.llm_service import llm_analysis_service
from app.services.task_service import _build_scan_plans


client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["app_name"] == "LLM Penetration Testing System"


def test_tool_resolution_for_known_binaries() -> None:
    nuclei_template = BACKEND_DIR / "app" / "assets" / "nuclei" / "local-http-fingerprint.yaml"
    assert NmapAdapter().resolve_command()
    assert HttpxAdapter().resolve_command()
    assert InputSurfaceAdapter().resolve_command()
    assert ParamInjectionProbeAdapter().resolve_command()
    assert CommandProbeAdapter().resolve_command()
    assert LoginSQLiProbeAdapter().resolve_command()
    assert SensitiveFileProbeAdapter().resolve_command()
    assert HeartbleedProbeAdapter().resolve_command()
    assert NucleiAdapter(nuclei_template).resolve_command()
    assert PathProbeAdapter().resolve_command()
    assert WebFingerprintAdapter().resolve_command()


def test_target_parser_normalizes_host_port_and_request_url() -> None:
    profile = parse_target("http://127.0.0.1:8080/manager/html?source=demo")

    assert profile.host == "127.0.0.1"
    assert profile.port == 8080
    assert profile.scheme == "http"
    assert profile.request_url == "http://127.0.0.1:8080/manager/html?source=demo"

    host_only = parse_target("127.0.0.1:8443")
    assert host_only.host == "127.0.0.1"
    assert host_only.port == 8443
    assert host_only.request_url == "https://127.0.0.1:8443"


def test_llm_strategy_plan_normalizes_descriptive_priority_paths() -> None:
    plan = LLMStrategyPlan(
        summary="demo",
        priority="medium",
        recommended_tools=["path_probe", "nuclei"],
        focus_areas=[],
        priority_paths=[
            "Root path and common application entry points",
            "Health or status endpoints",
            "Administrative or diagnostic paths commonly exposed on proxy-backed services",
        ],
        verification_goals=[],
        stop_conditions=[],
        rationale="demo",
    )

    normalized = llm_analysis_service._normalize_strategy_plan(plan)

    assert "/" in normalized.priority_paths
    assert "/health" in normalized.priority_paths
    assert "/status" in normalized.priority_paths
    assert "/manager/html" in normalized.priority_paths or "/admin" in normalized.priority_paths


def test_llm_strategy_plan_skips_scan_when_recon_is_not_reachable() -> None:
    plan = LLMStrategyPlan(
        summary="demo",
        priority="high",
        recommended_tools=["path_probe", "nuclei"],
        focus_areas=["tomcat admin surface"],
        priority_paths=["/manager/html"],
        verification_goals=["Confirm whether the target is reachable."],
        stop_conditions=[],
        rationale="demo",
    )
    recon_results = [
        ToolExecutionResult(
            tool_name="nmap",
            category="recon",
            target="http://127.0.0.1:8080",
            summary="Nmap completed with return code 0.",
            evidence=["8080/tcp closed http-proxy"],
            success=True,
            command="nmap ...",
            available=True,
            execution_mode="native",
        ),
        ToolExecutionResult(
            tool_name="httpx",
            category="recon",
            target="http://127.0.0.1:8080",
            summary="httpx completed with return code 0.",
            evidence=["No HTTP response captured"],
            success=True,
            command="httpx ...",
            available=True,
            execution_mode="native",
        ),
        ToolExecutionResult(
            tool_name="web_fingerprint",
            category="recon",
            target="http://127.0.0.1:8080",
            summary="Web fingerprinting collected stack hints for http://127.0.0.1:8080.",
            evidence=["url: http://127.0.0.1:8080", "status_code: 502"],
            success=True,
            command="web_fingerprint ...",
            available=True,
            execution_mode="native",
        ),
    ]

    guarded = llm_analysis_service._apply_reachability_guard(plan, recon_results)

    assert guarded.priority == "low"
    assert guarded.recommended_tools == []
    assert guarded.priority_paths == []
    assert any("stable reachable http response" in item.lower() for item in guarded.stop_conditions)


def test_llm_strategy_plan_skips_web_scan_for_non_http_open_port() -> None:
    plan = LLMStrategyPlan(
        summary="demo",
        priority="high",
        recommended_tools=["login_sqli_probe", "nuclei"],
        focus_areas=["login form sql injection"],
        priority_paths=[],
        verification_goals=["Confirm whether the target exposes SQL injection."],
        stop_conditions=[],
        rationale="demo",
    )
    recon_results = [
        ToolExecutionResult(
            tool_name="nmap",
            category="recon",
            target="123.58.224.8:3306",
            summary="Nmap completed with return code 0.",
            evidence=["3306/tcp open mysql MariaDB"],
            success=True,
            command="nmap ...",
            available=True,
            execution_mode="native",
        )
    ]

    guarded = llm_analysis_service._apply_reachability_guard(plan, recon_results)

    assert guarded.recommended_tools == []
    assert guarded.priority == "low"


def test_web_common_extracts_surfaces_and_query_candidates() -> None:
    body = """
    <html><body>
      <a href="/patientlogin.php">Patient</a>
      <a href="/index.php?cmd=ls%20/tmp">Run</a>
      <form method="post" action="/patientlogin.php">
        <input type="text" name="loginid" />
        <input type="password" name="password" />
      </form>
    </body></html>
    """

    links = extract_links("http://127.0.0.1:8080", body)
    forms = extract_forms("http://127.0.0.1:8080/patientlogin.php", body)
    username_field, password_field = select_form_fields(
        forms[0]["fields"],
        username_markers=("login", "user"),
        password_markers=("pass", "password"),
    )
    candidates = extract_query_candidates(
        "http://127.0.0.1:8080",
        body,
        parameter_filter=lambda key: key == "cmd",
    )

    assert "http://127.0.0.1:8080/patientlogin.php" in links
    assert forms[0]["action"] == "http://127.0.0.1:8080/patientlogin.php"
    assert username_field == "loginid"
    assert password_field == "password"
    assert candidates[0]["parameter"] == "cmd"
    assert candidates[0]["path"] == "/index.php"


def test_web_common_response_delta_detects_login_bypass_pattern() -> None:
    baseline_response = httpx.Response(
        200,
        headers={},
        text="<div class='alert-danger'>try submitting again</div>",
        request=httpx.Request("POST", "http://127.0.0.1:8080/patientlogin.php"),
    )
    injected_response = httpx.Response(
        200,
        headers={},
        text="<script>window.location='patientaccount.php';</script>",
        request=httpx.Request("POST", "http://127.0.0.1:8080/patientlogin.php"),
    )

    assert response_indicates_success_delta(
        snapshot_response(baseline_response),
        snapshot_response(injected_response),
        success_markers=("window.location", "account.php"),
        failure_markers=("alert-danger", "try submitting again"),
    )


def test_llm_service_extracts_text_from_chat_completion_stream() -> None:
    sse_lines = [
        'data: {"choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}',
        'data: {"choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}',
        'data: {"choices":[{"delta":{"content":" world"},"finish_reason":null}]}',
        'data: {"choices":[{"delta":{"content":""},"finish_reason":"stop"}]}',
        "data: [DONE]",
    ]

    text = llm_analysis_service._extract_chat_stream_output_text(sse_lines)

    assert text == "Hello world"


def test_adapters_build_tool_specific_targets() -> None:
    target = "http://127.0.0.1:8080/manager/html"
    nuclei_template = BACKEND_DIR / "app" / "assets" / "nuclei" / "local-http-fingerprint.yaml"
    scan_context = {"priority_paths": ["/admin", "/health"]}

    nmap_args = NmapAdapter().build_args(target)
    httpx_args = HttpxAdapter().build_args(target)
    input_surface_args = InputSurfaceAdapter().build_args(target)
    param_injection_args = ParamInjectionProbeAdapter().build_args(target)
    command_probe_args = CommandProbeAdapter().build_args(target)
    login_sqli_args = LoginSQLiProbeAdapter().build_args(target)
    sensitive_file_args = SensitiveFileProbeAdapter().build_args(target)
    heartbleed_args = HeartbleedProbeAdapter().build_args(target)
    nuclei_args = NucleiAdapter(nuclei_template).build_args(target)
    path_probe_args = PathProbeAdapter().build_args(target, scan_context)
    web_fingerprint_args = WebFingerprintAdapter().build_args(target)

    assert nmap_args[-1] == "127.0.0.1"
    assert "-p" in nmap_args
    assert "8080" in nmap_args
    assert httpx_args[2] == "http://127.0.0.1:8080/manager/html"
    assert input_surface_args[3] == target
    assert input_surface_args[1:3] == ["-m", "app.adapters.tools.input_surface_runner"]
    assert param_injection_args[3] == target
    assert param_injection_args[1:3] == ["-m", "app.adapters.tools.param_injection_probe_runner"]
    assert command_probe_args[3] == target
    assert command_probe_args[1:3] == ["-m", "app.adapters.tools.command_probe_runner"]
    assert login_sqli_args[3] == target
    assert login_sqli_args[1:3] == ["-m", "app.adapters.tools.login_sqli_probe_runner"]
    assert sensitive_file_args[3] == target
    assert sensitive_file_args[1:3] == ["-m", "app.adapters.tools.sensitive_file_probe_runner"]
    assert heartbleed_args[-1] == "127.0.0.1"
    assert "--script" in heartbleed_args
    assert "ssl-heartbleed" in heartbleed_args
    assert nuclei_args[2] == "http://127.0.0.1:8080/manager/html"
    assert path_probe_args[3] == target
    assert path_probe_args[1:3] == ["-m", "app.adapters.tools.path_probe_runner"]
    assert '"/admin"' in path_probe_args[-1]
    assert web_fingerprint_args[-1] == target
    assert web_fingerprint_args[1:3] == ["-m", "app.adapters.tools.web_fingerprint_runner"]


def test_build_scan_plans_respects_empty_llm_tool_selection() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.ANALYSIS)
    task = TaskDetail(
        task_id="task-no-scan",
        target="http://127.0.0.1:8080",
        scenario="No Scan Demo",
        status=TaskStatus.ANALYSIS,
        current_phase=get_phase_label(TaskStatus.ANALYSIS),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="demo",
            priority="low",
            recommended_tools=[],
            focus_areas=["restore confirmed application reachability"],
            priority_paths=[],
            verification_goals=[],
            stop_conditions=[],
            rationale="demo",
        ),
    )

    plans = _build_scan_plans(task.target, task)

    assert plans == []


def test_task_repository_persists_tasks_to_disk(tmp_path) -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.PENDING)
    repository = TaskRepository(storage_dir=tmp_path)
    task = TaskDetail(
        task_id="task-persisted",
        target="http://127.0.0.1:8080",
        scenario="Persistence Demo",
        status=TaskStatus.PENDING,
        current_phase=get_phase_label(TaskStatus.PENDING),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[
            TimelineEvent(
                event_id="timeline-1",
                title="Task created",
                status="active",
                phase=TaskStatus.PENDING,
                detail="Authorized target registered.",
            )
        ],
    )

    repository.save(task)
    reloaded = TaskRepository(storage_dir=tmp_path)

    persisted = reloaded.get("task-persisted")
    assert persisted is not None
    assert persisted.target == "http://127.0.0.1:8080"
    assert persisted.timeline[0].title == "Task created"


def test_verification_service_builds_structured_findings() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-demo",
        target="http://127.0.0.1:8080",
        scenario="Verification Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="Plan summary demo.",
            priority="high",
            recommended_tools=["input_surface", "command_probe", "path_probe", "nuclei"],
            focus_areas=["input-bearing endpoints", "command-style query parameters", "tomcat admin surface"],
            priority_paths=["/manager/html", "/docs/"],
            verification_goals=[
                "Identify reachable forms or dynamic input-bearing endpoints.",
                "Determine whether any discovered endpoint executes attacker-controlled command input.",
                "Confirm whether Tomcat admin or default paths are reachable.",
                "Correlate path exposure with nuclei template output.",
            ],
            stop_conditions=["Stop deeper expansion if both path discovery and nuclei produce no actionable signal."],
            rationale="Demo rationale.",
        ),
        tool_results=[
            ToolExecutionResult(
                tool_name="httpx",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="httpx confirmed http://127.0.0.1:8080 with status 200.",
                evidence=[
                    "url: http://127.0.0.1:8080",
                    "status_code: 200",
                    "title: Apache Tomcat/8.5.x",
                    "webserver: Apache-Coyote/1.1",
                ],
                success=True,
                command="httpx ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-httpx.log",
                exit_code=0,
                duration_ms=400,
            ),
            ToolExecutionResult(
                tool_name="web_fingerprint",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="Web fingerprinting collected stack hints for http://127.0.0.1:8080.",
                evidence=[
                    "url: http://127.0.0.1:8080",
                    "status_code: 200",
                    "title: Apache Tomcat/8.5.x",
                    "header: server=Apache-Coyote/1.1",
                    "tech: tomcat, servlet",
                ],
                success=True,
                command="web_fingerprint ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-web-fingerprint.log",
                exit_code=0,
                duration_ms=350,
            ),
            ToolExecutionResult(
                tool_name="input_surface",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Input-surface discovery found 1 forms and 2 candidate same-origin routes under http://127.0.0.1:8080.",
                evidence=[
                    "root: / -> 200 | title: Apache Tomcat/8.5.x",
                    "form: POST http://127.0.0.1:8080/login | inputs: username,password",
                    "link: /admin -> 200 | title: Admin Console",
                ],
                success=True,
                command="input_surface ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-input-surface.log",
                exit_code=0,
                duration_ms=450,
            ),
            ToolExecutionResult(
                tool_name="path_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Path probe confirmed 3 interesting application paths under http://127.0.0.1:8080.",
                evidence=[
                    "path: /manager/html -> 401 | title: Tomcat Web Application Manager",
                    "path: /docs/ -> 200 | title: Apache Tomcat Documentation",
                    "path: /examples/ -> 200 | title: Apache Tomcat Examples",
                ],
                success=True,
                command="path_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-path-probe.log",
                exit_code=0,
                duration_ms=700,
            ),
            ToolExecutionResult(
                tool_name="command_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Command probe confirmed 1 command-execution indicator(s) under http://127.0.0.1:8080.",
                evidence=[
                    "root: http://127.0.0.1:8080 -> 200",
                    "candidate: /index.php?cmd=whoami | parameter: cmd | source: body-text",
                    "confirmed: /index.php | parameter: cmd | marker: cmdprobe-1234abcd | status: 200",
                ],
                success=True,
                command="command_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-command-probe.log",
                exit_code=0,
                duration_ms=550,
            ),
            ToolExecutionResult(
                tool_name="nuclei",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Nuclei completed with return code 0.",
                evidence=["No nuclei matches returned by the local template."],
                success=True,
                command="nuclei ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-nuclei.log",
                exit_code=0,
                duration_ms=900,
            ),
        ],
    )

    findings = build_verified_findings(task)

    assert len(findings) >= 3
    assert any(
        finding.title == "Verified HTTP Surface" and finding.verification_status == "verified"
        for finding in findings
    )
    assert any(
        finding.title == "Tomcat Fingerprint Confirmed" and finding.confidence in {"medium", "high"}
        for finding in findings
    )
    assert any(
        finding.title == "Tomcat Administrative Paths Reachable"
        and finding.verification_status == "verified"
        for finding in findings
    )
    assert any(
        finding.title == "Input-Bearing Web Entry Points Discovered"
        and finding.verification_status == "verified"
        for finding in findings
    )
    assert any(
        finding.title == "Command Execution Confirmed"
        and finding.verification_status == "verified"
        and finding.severity == "critical"
        for finding in findings
    )
    assert any(
        finding.verification_status == "informational" and finding.artifact_paths
        for finding in findings
    )
    decision = evaluate_verification(task)
    assert any(item.startswith("met:") for item in decision.goal_status)
    assert decision.continue_testing is True
    assert "No active stop condition currently blocks further evidence collection" in decision.recommendation


def test_verification_service_avoids_false_positive_probe_hits() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-false-positive",
        target="http://127.0.0.1:8080",
        scenario="Verification False Positive Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        tool_results=[
            ToolExecutionResult(
                tool_name="httpx",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="httpx completed with return code 0.",
                evidence=["No HTTP response captured"],
                success=True,
                command="httpx ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-httpx.log",
                exit_code=0,
                duration_ms=400,
            ),
            ToolExecutionResult(
                tool_name="path_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Path probe checked 6 paths under http://127.0.0.1:8080 without confirming admin or default-content exposure.",
                evidence=[
                    "path: / -> 502",
                    "path: /manager/html -> 502",
                    "path: /docs/ -> 502",
                ],
                success=True,
                command="path_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-path-probe.log",
                exit_code=0,
                duration_ms=1400,
            ),
        ],
    )

    findings = build_verified_findings(task)

    assert not any(finding.title == "Verified HTTP Surface" for finding in findings)
    assert not any(
        finding.title in {"Tomcat Administrative Paths Reachable", "Default Tomcat Content Exposed"}
        for finding in findings
    )


def test_verification_service_treats_gateway_error_as_informational() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-gateway-error",
        target="http://127.0.0.1:8080",
        scenario="Verification Gateway Error Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        tool_results=[
            ToolExecutionResult(
                tool_name="web_fingerprint",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="Web fingerprinting collected stack hints for http://127.0.0.1:8080.",
                evidence=[
                    "url: http://127.0.0.1:8080",
                    "status_code: 502",
                ],
                success=True,
                command="web_fingerprint ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-web-fingerprint.log",
                exit_code=0,
                duration_ms=300,
            ),
            ToolExecutionResult(
                tool_name="nuclei",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Nuclei completed with return code 0.",
                evidence=["No nuclei matches returned by the local template."],
                success=True,
                command="nuclei ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-nuclei.log",
                exit_code=0,
                duration_ms=600,
            ),
        ],
    )

    findings = build_verified_findings(task)

    assert not any(finding.title == "Verified HTTP Surface" for finding in findings)
    assert any(
        finding.title == "Upstream Gateway Error Observed"
        and finding.verification_status == "informational"
        for finding in findings
    )


def test_verification_service_detects_directory_listing() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-directory-listing",
        target="http://127.0.0.1:8080",
        scenario="Directory Listing Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        tool_results=[
            ToolExecutionResult(
                tool_name="httpx",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="httpx confirmed http://127.0.0.1:8080 with status 200.",
                evidence=[
                    "url: http://127.0.0.1:8080",
                    "status_code: 200",
                ],
                success=True,
                command="httpx ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-httpx.log",
                exit_code=0,
                duration_ms=250,
            ),
            ToolExecutionResult(
                tool_name="web_fingerprint",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="Web fingerprinting collected stack hints for http://127.0.0.1:8080.",
                evidence=[
                    "url: http://127.0.0.1:8080",
                    "status_code: 200",
                    "title: Directory listing for /",
                    "header: server=SimpleHTTP/0.6 Python/3.10.0b2",
                ],
                success=True,
                command="web_fingerprint ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-web-fingerprint.log",
                exit_code=0,
                duration_ms=280,
            ),
            ToolExecutionResult(
                tool_name="path_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Path probe confirmed 1 interesting application paths under http://127.0.0.1:8080.",
                evidence=[
                    "path: / -> 200 | title: Directory listing for /",
                ],
                success=True,
                command="path_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-path-probe.log",
                exit_code=0,
                duration_ms=300,
            ),
        ],
    )

    findings = build_verified_findings(task)

    assert any(
        finding.title == "Directory Listing Exposed"
        and finding.verification_status == "verified"
        and finding.severity == "medium"
        for finding in findings
    )


def test_verification_service_detects_login_sqli() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-login-sqli",
        target="http://127.0.0.1:8080",
        scenario="Login SQLi Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="Login forms require SQLi verification.",
            priority="high",
            recommended_tools=["input_surface", "login_sqli_probe"],
            focus_areas=["input-bearing endpoints", "login form sql injection"],
            priority_paths=[],
            verification_goals=[
                "Identify reachable forms or dynamic input-bearing endpoints.",
                "Determine whether any discovered login form permits SQL-injection-based authentication bypass.",
            ],
            stop_conditions=[],
            rationale="Demo rationale.",
        ),
        tool_results=[
            ToolExecutionResult(
                tool_name="httpx",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="httpx confirmed http://127.0.0.1:8080 with status 200.",
                evidence=["url: http://127.0.0.1:8080", "status_code: 200", "title: Care And Cure Hospital"],
                success=True,
                command="httpx ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-httpx.log",
                exit_code=0,
                duration_ms=250,
            ),
            ToolExecutionResult(
                tool_name="input_surface",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Input-surface discovery found 0 forms and 3 candidate same-origin routes under http://127.0.0.1:8080.",
                evidence=[
                    "root: / -> 200 | title: Care And Cure Hospital",
                    "link: /adminlogin.php -> 200 | title: :: Care And Cure - Hospital Admin ::",
                    "link: /patientlogin.php -> 200 | title: :: Care And Cure - Hospital Admin ::",
                ],
                success=True,
                command="input_surface ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-input-surface.log",
                exit_code=0,
                duration_ms=300,
            ),
            ToolExecutionResult(
                tool_name="login_sqli_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Login SQLi probe confirmed 1 authentication-bypass indicator(s) under http://127.0.0.1:8080.",
                evidence=[
                    "form: http://127.0.0.1:8080/patientlogin.php -> user=loginid pass=password",
                    "confirmed: /patientlogin.php -> /patientlogin.php | user=loginid pass=password | success_hint=window.location",
                ],
                success=True,
                command="login_sqli_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-login-sqli.log",
                exit_code=0,
                duration_ms=500,
            ),
        ],
    )

    findings = build_verified_findings(task)
    assert any(
        finding.title == "SQL Injection Login Bypass Confirmed"
        and finding.verification_status == "verified"
        and finding.severity == "critical"
        for finding in findings
    )
    decision = evaluate_verification(task)
    assert any(item.startswith("met:") for item in decision.goal_status)


def test_verification_service_detects_param_injection_and_sensitive_files() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-generic-probes",
        target="http://127.0.0.1:8080",
        scenario="Generic Probe Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="Generic parameter and file exposure validation.",
            priority="high",
            recommended_tools=["param_injection_probe", "sensitive_file_probe"],
            focus_areas=["generic parameter injection", "sensitive file exposure"],
            priority_paths=[],
            verification_goals=[
                "Determine whether any discovered parameter shows generic injection behavior.",
                "Determine whether any common sensitive files or backups are directly exposed.",
            ],
            stop_conditions=[],
            rationale="Demo rationale.",
        ),
        tool_results=[
            ToolExecutionResult(
                tool_name="httpx",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="httpx confirmed http://127.0.0.1:8080 with status 200.",
                evidence=["url: http://127.0.0.1:8080", "status_code: 200"],
                success=True,
                command="httpx ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-httpx.log",
                exit_code=0,
                duration_ms=200,
            ),
            ToolExecutionResult(
                tool_name="param_injection_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Parameter injection probe confirmed 1 generic injection indicator(s) under http://127.0.0.1:8080.",
                evidence=[
                    "candidate: /doctor.php?doctorid=1 | parameter: doctorid | mode: query",
                    "confirmed: query /doctor.php | parameter: doctorid | kind: time-based | signal: delay=3.10s baseline=0.12s",
                ],
                success=True,
                command="param_injection_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-param.log",
                exit_code=0,
                duration_ms=550,
            ),
            ToolExecutionResult(
                tool_name="sensitive_file_probe",
                category="scan",
                target="http://127.0.0.1:8080",
                summary="Sensitive file probe confirmed 1 exposure(s) under http://127.0.0.1:8080.",
                evidence=[
                    "checked: /.env -> 200",
                    "confirmed: /.env -> 200 | hint: sensitive content markers detected",
                ],
                success=True,
                command="sensitive_file_probe ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-sensitive.log",
                exit_code=0,
                duration_ms=320,
            ),
        ],
    )

    findings = build_verified_findings(task)
    assert any(
        finding.title == "Parameter Injection Signal Confirmed" and finding.verification_status == "verified"
        for finding in findings
    )
    assert any(
        finding.title == "Sensitive File Exposure Confirmed" and finding.verification_status == "verified"
        for finding in findings
    )


def test_report_writer_uses_completed_status_for_reporting_stage() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.REPORTING)
    task = TaskDetail(
        task_id="task-report-status",
        target="http://127.0.0.1:8080",
        scenario="Reporting Status Demo",
        status=TaskStatus.REPORTING,
        current_phase=get_phase_label(TaskStatus.REPORTING),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="Plan summary demo.",
            priority="high",
            recommended_tools=["path_probe", "nuclei"],
            focus_areas=["tomcat admin surface"],
            priority_paths=["/manager/html"],
            verification_goals=["Confirm admin exposure."],
            stop_conditions=["Stop if both scan tools are clean."],
            rationale="Demo rationale.",
        ),
        verified_findings=[
            {
                "finding_id": "finding-report-1",
                "title": "Report Finding Demo",
                "severity": "medium",
                "source_tool": "web_fingerprint",
                "affected_asset": "http://127.0.0.1:8080",
                "confidence": "high",
                "summary": "Demo finding summary.",
                "impact": "Demo impact.",
                "evidence": ["status_code: 200"],
                "artifact_paths": ["D:/artifact-demo.log"],
                "remediation": "Demo remediation.",
                "next_steps": ["Demo next step."],
                "verification_status": "verified",
            }
        ],
        tool_results=[
            ToolExecutionResult(
                tool_name="web_fingerprint",
                category="recon",
                target="http://127.0.0.1:8080",
                summary="Web fingerprinting collected stack hints for http://127.0.0.1:8080.",
                evidence=["status_code: 200"],
                success=True,
                command="web_fingerprint ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-demo.log",
                exit_code=0,
                duration_ms=321,
            )
        ],
    )

    artifact = write_report(task, "Executive summary demo.")
    content = Path(artifact.report_path).read_text(encoding="utf-8")

    assert "- Final Status: COMPLETED" in content
    assert "## Finding Overview" in content
    assert "## LLM Strategy Plan" in content
    assert "- Recommended Tools: path_probe, nuclei" in content
    assert "- Verified Findings: 1" in content
    assert "## Tool Execution Summary" in content
    assert "- web_fingerprint: success=True" in content


def test_verification_service_detects_heartbleed() -> None:
    progress_current, progress_total = workflow_progress(TaskStatus.SCAN)
    task = TaskDetail(
        task_id="task-verify-heartbleed",
        target="https://127.0.0.1:443",
        scenario="Heartbleed Demo",
        status=TaskStatus.SCAN,
        current_phase=get_phase_label(TaskStatus.SCAN),
        progress_current=progress_current,
        progress_total=progress_total,
        timeline=[],
        llm_strategy_plan=LLMStrategyPlan(
            summary="TLS service requires targeted Heartbleed validation.",
            priority="high",
            recommended_tools=["heartbleed_probe"],
            focus_areas=["tls service exposure", "heartbleed validation"],
            priority_paths=[],
            verification_goals=["Confirm whether the TLS service is vulnerable to Heartbleed (CVE-2014-0160)."],
            stop_conditions=["Stop the Heartbleed branch if the target does not expose a TLS service on the requested port."],
            rationale="Demo rationale.",
        ),
        tool_results=[
            ToolExecutionResult(
                tool_name="nmap",
                category="recon",
                target="https://127.0.0.1:443",
                summary="Nmap completed with return code 0.",
                evidence=["443/tcp open ssl/http nginx 1.11.13"],
                success=True,
                command="nmap ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-nmap.log",
                exit_code=0,
                duration_ms=300,
            ),
            ToolExecutionResult(
                tool_name="heartbleed_probe",
                category="scan",
                target="https://127.0.0.1:443",
                summary="Heartbleed probe confirmed CVE-2014-0160 exposure.",
                evidence=[
                    "ssl-heartbleed: VULNERABLE",
                    "state: VULNERABLE",
                    "cve: CVE-2014-0160",
                ],
                success=True,
                command="nmap --script ssl-heartbleed ...",
                available=True,
                execution_mode="native",
                raw_output_path="D:/artifact-heartbleed.log",
                exit_code=0,
                duration_ms=500,
            ),
        ],
    )

    findings = build_verified_findings(task)
    assert any(
        finding.title == "Heartbleed Vulnerability Confirmed"
        and finding.verification_status == "verified"
        and finding.severity == "critical"
        for finding in findings
    )
    decision = evaluate_verification(task)
    assert any(item.startswith("met:") for item in decision.goal_status)


def test_list_seed_tasks() -> None:
    response = client.get("/api/tasks")

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) >= 1
    assert "created_at" in payload[0]
    created_times = [item["created_at"] for item in payload]
    assert created_times == sorted(created_times, reverse=True)


def test_create_task_and_fetch_detail() -> None:
    create_response = client.post(
        "/api/tasks",
        json={
            "target": "http://127.0.0.1:8888",
            "scenario": "Vulhub / Demo Create",
        },
    )

    assert create_response.status_code == 201
    created = create_response.json()
    assert created["status"] == "PENDING"
    assert created["timeline"][0]["title"] == "Task created"
    assert len(created["planned_tools"]) == 11

    task_id = created["task_id"]
    detail_response = client.get(f"/api/tasks/{task_id}")
    assert detail_response.status_code == 200
    detail = detail_response.json()
    assert detail["task_id"] == task_id
    assert detail["planned_tools"][0]["tool_name"] == "nmap"
    assert any(tool["tool_name"] == "web_fingerprint" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "input_surface" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "param_injection_probe" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "command_probe" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "login_sqli_probe" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "sensitive_file_probe" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "heartbleed_probe" for tool in detail["planned_tools"])
    assert any(tool["tool_name"] == "path_probe" for tool in detail["planned_tools"])
    assert detail["planned_tools"][-1]["tool_name"] == "nuclei"


def test_advance_task_updates_status_and_timeline() -> None:
    create_response = client.post(
        "/api/tasks",
        json={
            "target": "http://127.0.0.1:9999",
            "scenario": "Vulhub / Advance Flow",
        },
    )
    task_id = create_response.json()["task_id"]

    advance_response = client.post(f"/api/tasks/{task_id}/advance")
    assert advance_response.status_code == 200

    payload = advance_response.json()
    assert payload["advanced"] is True
    assert payload["task"]["status"] == "RECON"
    assert payload["task"]["latest_result"]["tool_name"] == "web_fingerprint"
    assert len(payload["task"]["tool_results"]) == 3
    assert len(payload["task"]["timeline"]) == 5
    assert Path(payload["task"]["tool_results"][0]["raw_output_path"]).exists()


def test_analysis_and_scan_stages_produce_outputs() -> None:
    create_response = client.post(
        "/api/tasks",
        json={
            "target": "http://127.0.0.1:9999",
            "scenario": "Vulhub / Analysis Flow",
        },
    )
    task_id = create_response.json()["task_id"]

    client.post(f"/api/tasks/{task_id}/advance")
    analysis_response = client.post(f"/api/tasks/{task_id}/advance")
    analysis_payload = analysis_response.json()
    assert analysis_payload["task"]["status"] == "ANALYSIS"
    assert analysis_payload["task"]["analysis_summary"] is not None
    assert "nuclei" in analysis_payload["task"]["analysis_summary"].lower()
    assert analysis_payload["task"]["llm_strategy_plan"] is not None
    recommended_tools = analysis_payload["task"]["llm_strategy_plan"]["recommended_tools"]
    assert "nuclei" in recommended_tools
    if "path_probe" in recommended_tools:
        path_plan = next(
            tool for tool in analysis_payload["task"]["planned_tools"] if tool["tool_name"] == "path_probe"
        )
        priority_paths = analysis_payload["task"]["llm_strategy_plan"]["priority_paths"]
        if priority_paths:
            assert priority_paths[0] in path_plan["command"]

    scan_response = client.post(f"/api/tasks/{task_id}/advance")
    scan_payload = scan_response.json()
    assert scan_payload["task"]["status"] == "SCAN"
    executed_scan_tools = {
        result["tool_name"] for result in scan_payload["task"]["tool_results"] if result["category"] == "scan"
    }
    assert executed_scan_tools == set(recommended_tools)


def test_start_task_runs_automatic_workflow() -> None:
    create_response = client.post(
        "/api/tasks",
        json={
            "target": "http://127.0.0.1:7777",
            "scenario": "Vulhub / Auto Run",
        },
    )
    task_id = create_response.json()["task_id"]

    start_response = client.post(f"/api/tasks/{task_id}/start")
    assert start_response.status_code == 200
    started_payload = start_response.json()
    assert started_payload["started"] is True
    assert started_payload["task"]["is_running"] is True

    deadline = time() + 40
    final_payload = started_payload["task"]
    while time() < deadline:
        detail_response = client.get(f"/api/tasks/{task_id}")
        final_payload = detail_response.json()
        if final_payload["status"] == "COMPLETED" and final_payload["is_running"] is False:
            break
        sleep(0.1)

    assert final_payload["status"] == "COMPLETED"
    assert final_payload["is_running"] is False
    assert final_payload["tool_results"][0]["tool_name"] == "nmap"
    assert Path(final_payload["tool_results"][0]["raw_output_path"]).exists()
    recommended_tools = final_payload["llm_strategy_plan"]["recommended_tools"]
    assert recommended_tools
    if "path_probe" in recommended_tools:
        assert any(result["tool_name"] == "path_probe" for result in final_payload["tool_results"])
    else:
        assert not any(result["tool_name"] == "path_probe" for result in final_payload["tool_results"])
    assert any(result["tool_name"] == "nuclei" for result in final_payload["tool_results"])
    assert final_payload["verification_summary"] is not None
    assert final_payload["report_artifact"] is not None
    assert Path(final_payload["report_artifact"]["report_path"]).exists()

    report_response = client.get(f"/api/tasks/{task_id}/report")
    assert report_response.status_code == 200
    report_payload = report_response.json()
    assert report_payload["task_id"] == task_id
    assert "# " in report_payload["content"]
