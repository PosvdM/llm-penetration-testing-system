from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import uuid4

from app.core.targeting import parse_target
from app.schemas.task import TaskDetail, VerifiedFinding
from app.schemas.tool import ToolExecutionResult

PATH_PROBE_VERIFIED_STATUS_MARKERS = (
    "-> 200",
    "-> 204",
    "-> 301",
    "-> 302",
    "-> 307",
    "-> 308",
    "-> 401",
    "-> 403",
    "-> 405",
)
HTTP_REACHABLE_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405}
HTTP_GATEWAY_ERROR_STATUS_CODES = {502, 503, 504}


@dataclass
class VerificationDecision:
    findings: list[VerifiedFinding]
    goal_status: list[str]
    stop_condition_status: list[str]
    continue_testing: bool
    recommendation: str


def evaluate_verification(task: TaskDetail) -> VerificationDecision:
    target_profile = parse_target(task.target)
    recon_results = [result for result in task.tool_results if result.category == "recon"]
    scan_results = [result for result in task.tool_results if result.category == "scan"]
    findings: list[VerifiedFinding] = []

    http_observation = _find_result(recon_results, "httpx")
    nmap_observation = _find_result(recon_results, "nmap")
    web_fingerprint_observation = _find_result(recon_results, "web_fingerprint") or _find_result(
        recon_results, "whatweb"
    )
    nuclei_observation = _find_result(scan_results, "nuclei")
    path_probe_observation = _find_result(scan_results, "path_probe")
    input_surface_observation = _find_result(scan_results, "input_surface")
    param_injection_observation = _find_result(scan_results, "param_injection_probe")
    command_probe_observation = _find_result(scan_results, "command_probe")
    login_sqli_observation = _find_result(scan_results, "login_sqli_probe")
    sensitive_file_observation = _find_result(scan_results, "sensitive_file_probe")
    heartbleed_observation = _find_result(scan_results, "heartbleed_probe")

    if _http_service_confirmed(http_observation, web_fingerprint_observation):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Verified HTTP Surface",
                severity="low",
                source_tool=_primary_source(http_observation, web_fingerprint_observation),
                affected_asset=target_profile.request_url,
                confidence="high",
                summary=(
                    "An HTTP endpoint responded during recon, confirming an exposed web surface "
                    "that should remain in scope for deeper validation."
                ),
                impact=(
                    "The application is remotely reachable and can host additional findings such as "
                    "default content, weak administration panels, or framework-specific issues."
                ),
                evidence=_merge_evidence(http_observation, web_fingerprint_observation),
                artifact_paths=_artifact_paths(http_observation, web_fingerprint_observation),
                remediation=(
                    "Restrict exposure to trusted networks when possible and continue with application "
                    "enumeration and authentication surface review."
                ),
                next_steps=[
                    "Enumerate application paths and default content.",
                    "Validate authentication and administrative interfaces.",
                ],
                verification_status="verified",
            )
        )

    if _directory_listing_confirmed(http_observation, web_fingerprint_observation, path_probe_observation):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Directory Listing Exposed",
                severity="medium",
                source_tool=_primary_source(path_probe_observation, web_fingerprint_observation, http_observation),
                affected_asset=target_profile.request_url,
                confidence="high",
                summary=(
                    "The target responded with a directory index page, confirming that remote users can browse "
                    "server-side file or folder listings directly over HTTP."
                ),
                impact=(
                    "Exposed directory listings can disclose sensitive filenames, deployment structure, scripts, "
                    "and follow-on attack paths that should not be public."
                ),
                evidence=_directory_listing_evidence(http_observation, web_fingerprint_observation, path_probe_observation),
                artifact_paths=_artifact_paths(http_observation, web_fingerprint_observation, path_probe_observation),
                remediation=(
                    "Disable autoindex or directory listing in the HTTP server, serve explicit index content, "
                    "and restrict direct exposure of filesystem-backed paths."
                ),
                next_steps=[
                    "Review listed files and directories for sensitive content exposure.",
                    "Verify whether nested directories also return browseable indexes.",
                ],
                verification_status="verified",
            )
        )
    elif _gateway_error_observed(http_observation, web_fingerprint_observation):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Upstream Gateway Error Observed",
                severity="info",
                source_tool=_primary_source(http_observation, web_fingerprint_observation),
                affected_asset=target_profile.request_url,
                confidence="medium",
                summary=(
                    "Recon reached an HTTP-facing component, but the observed response indicates an upstream "
                    "gateway or backend failure rather than a confirmed live application."
                ),
                impact=(
                    "A gateway error can still prove some network path exists, but it is not sufficient to "
                    "treat the underlying application as reachable or healthy."
                ),
                evidence=_merge_evidence(http_observation, web_fingerprint_observation),
                artifact_paths=_artifact_paths(http_observation, web_fingerprint_observation),
                remediation=(
                    "Validate the upstream application state, proxy configuration, and backend connectivity "
                    "before continuing deeper application testing."
                ),
                next_steps=[
                    "Recheck the endpoint after confirming the backend service state.",
                    "Differentiate reverse-proxy failure from application-layer denial or outage.",
                ],
                verification_status="informational",
            )
        )

    if _tomcat_fingerprint_confirmed(http_observation, web_fingerprint_observation):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Tomcat Fingerprint Confirmed",
                severity="medium",
                source_tool=_primary_source(http_observation, web_fingerprint_observation),
                affected_asset=target_profile.base_url,
                confidence="medium",
                summary=(
                    "Multiple recon signals indicate the target is backed by Apache Tomcat or a Tomcat-like "
                    "servlet container."
                ),
                impact=(
                    "Tomcat-specific administrative paths, default applications, and version-tied issues "
                    "become higher-priority follow-up targets."
                ),
                evidence=_merge_evidence(http_observation, web_fingerprint_observation),
                artifact_paths=_artifact_paths(http_observation, web_fingerprint_observation),
                remediation=(
                    "Review exposed Tomcat applications, remove unnecessary default content, and validate "
                    "that administrative consoles are not reachable without strong controls."
                ),
                next_steps=[
                    "Probe /manager, /host-manager, /docs, and /examples.",
                    "Confirm Tomcat version and patch level from authenticated or trusted sources.",
                ],
                verification_status="verified",
            )
        )

    if path_probe_observation is not None:
        findings.extend(_build_path_probe_findings(path_probe_observation, target_profile.base_url))

    if input_surface_observation is not None:
        findings.extend(_build_input_surface_findings(input_surface_observation, target_profile.base_url))

    if param_injection_observation is not None:
        findings.extend(_build_param_injection_findings(param_injection_observation, target_profile.base_url))

    if login_sqli_observation is not None:
        findings.extend(_build_login_sqli_findings(login_sqli_observation, target_profile.base_url))

    if command_probe_observation is not None:
        findings.extend(_build_command_probe_findings(command_probe_observation, target_profile.request_url))

    if sensitive_file_observation is not None:
        findings.extend(_build_sensitive_file_findings(sensitive_file_observation, target_profile.base_url))

    if heartbleed_observation is not None:
        findings.extend(_build_heartbleed_findings(heartbleed_observation, target_profile.host_with_port))

    if nuclei_observation is not None:
        if _nuclei_match_detected(nuclei_observation):
            findings.append(
                VerifiedFinding(
                    finding_id=_finding_id(),
                    title="Nuclei Template Match Detected",
                    severity="medium",
                    source_tool="nuclei",
                    affected_asset=target_profile.request_url,
                    confidence="medium",
                    summary=(
                        "The nuclei scan returned at least one positive template match, which should be "
                        "treated as a validated lead pending targeted reproduction."
                    ),
                    impact=(
                        "A positive nuclei match raises the likelihood of reachable attack surface or "
                        "framework exposure that warrants exploit-safe confirmation."
                    ),
                    evidence=_collect_evidence(nuclei_observation),
                    artifact_paths=_artifact_paths(nuclei_observation),
                    remediation=(
                        "Review the exact matched template, reproduce the condition safely, and patch or "
                        "reduce the exposed component if confirmed."
                    ),
                    next_steps=[
                        "Inspect the matched template metadata and request path.",
                        "Reproduce the condition manually before escalating severity.",
                    ],
                    verification_status="verified",
                )
            )
        else:
            findings.append(
                VerifiedFinding(
                    finding_id=_finding_id(),
                    title="No Confirmed Vulnerability Match From Current Template Set",
                    severity="info",
                    source_tool="nuclei",
                    affected_asset=target_profile.request_url,
                    confidence="medium",
                    summary=(
                        "The current lightweight nuclei template set completed without producing a positive "
                        "match. This reduces immediate confidence in template-covered issues but does not "
                        "clear the target."
                    ),
                    impact=(
                        "Coverage is currently limited to a minimal local template set, so the absence of a "
                        "match should be treated as incomplete verification rather than a clean bill of health."
                    ),
                    evidence=_collect_evidence(nuclei_observation),
                    artifact_paths=_artifact_paths(nuclei_observation),
                    remediation=(
                        "Expand the template corpus and continue with targeted checks for the identified "
                        "application stack."
                    ),
                    next_steps=[
                        "Add Tomcat-focused and framework-specific nuclei templates.",
                        "Correlate with manual path enumeration and authentication checks.",
                    ],
                    verification_status="informational",
                )
            )

    if _recon_disagreement(nmap_observation, http_observation):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Recon Signal Mismatch Requires Retest",
                severity="info",
                source_tool="recon-correlation",
                affected_asset=target_profile.host_with_port,
                confidence="medium",
                summary=(
                    "Direct HTTP probing produced a live response while the port scan did not capture a matching "
                    "open service. The target should be rescanned before stronger conclusions are drawn."
                ),
                impact=(
                    "Network path differences, input formatting issues, or transient state can skew tool output "
                    "and reduce confidence in the current evidence chain."
                ),
                evidence=_merge_evidence(nmap_observation, http_observation),
                artifact_paths=_artifact_paths(nmap_observation, http_observation),
                remediation=(
                    "Repeat targeted network validation with explicit host and port inputs, then compare the "
                    "updated evidence before moving to exploit validation."
                ),
                next_steps=[
                    "Re-run nmap with the normalized host and port.",
                    "Compare the raw artifacts to rule out tooling or environment drift.",
                ],
                verification_status="informational",
            )
        )

    goal_status = _evaluate_verification_goals(task, findings)
    stop_condition_status = _evaluate_stop_conditions(task, findings)
    continue_testing = not any(item.startswith("met:") for item in stop_condition_status)
    recommendation = _build_verification_recommendation(goal_status, stop_condition_status, continue_testing)
    return VerificationDecision(
        findings=findings,
        goal_status=goal_status,
        stop_condition_status=stop_condition_status,
        continue_testing=continue_testing,
        recommendation=recommendation,
    )


def build_verified_findings(task: TaskDetail) -> list[VerifiedFinding]:
    return evaluate_verification(task).findings


def _finding_id() -> str:
    return f"finding-{uuid4().hex[:8]}"


def _find_result(results: list[ToolExecutionResult], tool_name: str) -> ToolExecutionResult | None:
    return next((result for result in results if result.tool_name == tool_name), None)


def _collect_evidence(result: ToolExecutionResult | None) -> list[str]:
    if result is None:
        return []
    return result.evidence[:5]


def _merge_evidence(*results: ToolExecutionResult | None) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for result in results:
        if result is None:
            continue
        for item in result.evidence[:4]:
            if item not in seen:
                merged.append(item)
                seen.add(item)
    return merged


def _artifact_paths(*results: ToolExecutionResult | None) -> list[str]:
    return [result.raw_output_path for result in results if result and result.raw_output_path]


def _primary_source(*results: ToolExecutionResult | None) -> str:
    for result in results:
        if result is not None:
            return result.tool_name
    return "correlation"


def _evidence_blob(result: ToolExecutionResult | None) -> str:
    if result is None:
        return ""
    return " ".join([result.summary, *result.evidence]).lower()


def _http_service_confirmed(*results: ToolExecutionResult | None) -> bool:
    for result in results:
        if result is None or not result.success:
            continue
        evidence = " ".join(result.evidence).lower()
        if "no http response captured" in evidence or "no web fingerprint captured" in evidence:
            continue
        if "error:" in evidence:
            continue
        status_codes = _extract_status_codes(result)
        if any(code in HTTP_REACHABLE_STATUS_CODES for code in status_codes):
            return True
    return False


def _gateway_error_observed(*results: ToolExecutionResult | None) -> bool:
    for result in results:
        if result is None or not result.success:
            continue
        status_codes = _extract_status_codes(result)
        if any(code in HTTP_GATEWAY_ERROR_STATUS_CODES for code in status_codes):
            return True
    return False


def _tomcat_fingerprint_confirmed(
    httpx_result: ToolExecutionResult | None,
    web_fingerprint_result: ToolExecutionResult | None,
) -> bool:
    combined = f"{_evidence_blob(httpx_result)} {_evidence_blob(web_fingerprint_result)}"
    markers = ("tomcat", "apache-coyote", "servlet/4.0", "jsp")
    matches = sum(1 for marker in markers if marker in combined)
    return matches >= 2


def _nuclei_match_detected(nuclei_result: ToolExecutionResult) -> bool:
    combined = _evidence_blob(nuclei_result)
    if "no nuclei matches" in combined or "no nuclei match" in combined:
        return False
    return "matched-at" in combined or "template:" in combined or "severity:" in combined


def _recon_disagreement(
    nmap_result: ToolExecutionResult | None,
    httpx_result: ToolExecutionResult | None,
) -> bool:
    if not _http_service_confirmed(httpx_result):
        return False
    if nmap_result is None:
        return False
    combined = _evidence_blob(nmap_result)
    return "no open ports" in combined or ("open" not in combined and nmap_result.success)


def _directory_listing_confirmed(*results: ToolExecutionResult | None) -> bool:
    markers = (
        "directory listing for /",
        "directory listing for",
        "index of /",
        "index of",
        "autoindex",
    )
    for result in results:
        if result is None or not result.success:
            continue
        blob = _evidence_blob(result)
        if any(marker in blob for marker in markers):
            return True
    return False


def _directory_listing_evidence(*results: ToolExecutionResult | None) -> list[str]:
    evidence: list[str] = []
    for result in results:
        if result is None:
            continue
        for item in result.evidence[:5]:
            lowered = item.lower()
            if "directory listing" in lowered or "index of" in lowered or item.startswith("url:") or item.startswith("path: /"):
                if item not in evidence:
                    evidence.append(item)
    return evidence[:5]


def _build_path_probe_findings(
    result: ToolExecutionResult,
    base_url: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    evidence_blob = _evidence_blob(result)

    manager_hits = [
        item
        for item in result.evidence
        if ("/manager/html" in item or "/host-manager/html" in item) and _path_probe_hit_verified(item)
    ]
    if manager_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Tomcat Administrative Paths Reachable",
                severity="medium",
                source_tool="path_probe",
                affected_asset=base_url,
                confidence="high",
                summary=(
                    "Application path discovery confirmed that Tomcat administrative endpoints are reachable "
                    "over HTTP, even if they still require authentication."
                ),
                impact=(
                    "Reachable administrative consoles increase the value of password, access-control, and "
                    "default credential testing and make accidental exposure easier to verify."
                ),
                evidence=manager_hits,
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Restrict Tomcat administration interfaces to trusted networks, enforce strong "
                    "authentication, and remove internet exposure when not required."
                ),
                next_steps=[
                    "Validate whether the admin endpoints enforce authentication correctly.",
                    "Check for default credentials and misconfigurations in a lab-safe manner.",
                ],
                verification_status="verified",
            )
        )

    default_app_hits = [
        item
        for item in result.evidence
        if ("/docs/" in item or "/examples/" in item) and _path_probe_hit_verified(item)
    ]
    if default_app_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Default Tomcat Content Exposed",
                severity="low",
                source_tool="path_probe",
                affected_asset=base_url,
                confidence="high",
                summary=(
                    "Default documentation or example applications were reachable during focused path discovery."
                ),
                impact=(
                    "Default content can disclose framework version hints, sample functionality, and attack "
                    "paths that should not remain exposed in a hardened deployment."
                ),
                evidence=default_app_hits,
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Remove or restrict default documentation and example applications from production-like "
                    "deployments."
                ),
                next_steps=[
                    "Review any exposed sample content for version and feature disclosure.",
                    "Remove unnecessary default applications after validation.",
                ],
                verification_status="verified",
            )
        )

    if not findings and "no interesting application paths" in evidence_blob:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Focused Path Discovery Did Not Confirm Default Web Entry Points",
                severity="info",
                source_tool="path_probe",
                affected_asset=base_url,
                confidence="medium",
                summary=(
                    "The focused application path probe did not confirm the default administrative or sample "
                    "paths currently checked by the workflow."
                ),
                impact=(
                    "This narrows the immediately visible attack surface but does not rule out custom "
                    "application routes or hidden content."
                ),
                evidence=result.evidence,
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Continue with broader content discovery and custom application enumeration before treating "
                    "the web surface as low risk."
                ),
                next_steps=[
                    "Expand the path list or add content discovery tooling.",
                    "Correlate with framework-specific fingerprints and manual review.",
                ],
                verification_status="informational",
            )
        )

    return findings


def _build_input_surface_findings(
    result: ToolExecutionResult,
    base_url: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    form_hits = [item for item in result.evidence if item.lower().startswith("form:")]
    link_hits = [item for item in result.evidence if item.lower().startswith("link:")]

    if form_hits or link_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Input-Bearing Web Entry Points Discovered",
                severity="medium",
                source_tool="input_surface",
                affected_asset=base_url,
                confidence="medium",
                summary=(
                    "Focused discovery identified forms or likely dynamic same-origin routes that can serve as "
                    "higher-value validation targets than default root-page fingerprinting alone."
                ),
                impact=(
                    "Reachable input surfaces provide concrete places to continue authenticated checks, "
                    "parameter analysis, and scenario-specific validation workflows."
                ),
                evidence=[*form_hits[:3], *link_hits[:3]] or result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Inventory exposed input surfaces, enforce strong validation and authorization controls, "
                    "and review sensitive handlers before exposing them beyond trusted environments."
                ),
                next_steps=[
                    "Prioritize discovered forms and dynamic routes for scenario-specific validation.",
                    "Correlate discovered paths with framework fingerprints and server behavior.",
                ],
                verification_status="verified",
            )
        )
    elif "did not find forms" in _evidence_blob(result):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Root-Page Discovery Did Not Reveal Dynamic Input Surfaces",
                severity="info",
                source_tool="input_surface",
                affected_asset=base_url,
                confidence="medium",
                summary=(
                    "Root-page discovery did not reveal forms or obvious same-origin dynamic routes, so deeper "
                    "coverage likely requires custom path discovery or authenticated navigation."
                ),
                impact=(
                    "The current workflow may still miss custom application endpoints that are not linked from "
                    "the root page."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Expand route discovery depth and collect application-specific entry points before drawing "
                    "strong conclusions from the current coverage."
                ),
                next_steps=[
                    "Expand same-origin route enumeration beyond the root page.",
                    "Combine path discovery with authenticated or scenario-specific navigation where allowed.",
                ],
                verification_status="informational",
            )
        )

    return findings


def _build_param_injection_findings(
    result: ToolExecutionResult,
    affected_asset: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    confirmed_hits = [item for item in result.evidence if item.lower().startswith("confirmed:")]
    if confirmed_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Parameter Injection Signal Confirmed",
                severity="high",
                source_tool="param_injection_probe",
                affected_asset=affected_asset,
                confidence="high",
                summary=(
                    "Generic parameter mutation produced a reproducible error-based or time-based injection "
                    "signal on an application parameter."
                ),
                impact=(
                    "The target likely contains server-side input handling weaknesses that may enable SQL "
                    "injection or related backend query manipulation."
                ),
                evidence=confirmed_hits[:3],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Replace string-built backend queries with parameterized APIs, validate parameter types "
                    "strictly, and review all sibling handlers that accept the same input family."
                ),
                next_steps=[
                    "Map the exact parameter-to-query path and confirm the backend sink type.",
                    "Expand validation across adjacent parameters and request methods.",
                ],
                verification_status="verified",
            )
        )
    elif "no confirmed generic parameter injection signal" in _evidence_blob(result):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="No Confirmed Generic Parameter Injection Signal From Current Candidate Set",
                severity="info",
                source_tool="param_injection_probe",
                affected_asset=affected_asset,
                confidence="medium",
                summary=(
                    "The workflow exercised discovered parameters with low-noise generic payloads but did not "
                    "observe a reproducible error-based or time-based injection signal."
                ),
                impact=(
                    "This lowers confidence in straightforward generic injection on the current candidate set, "
                    "but it does not exclude stack-specific, authenticated, or second-order cases."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Preserve the artifacts and expand candidate discovery or payload families before ruling "
                    "out backend injection entirely."
                ),
                next_steps=[
                    "Test deeper routes and authenticated parameters where allowed.",
                    "Add stack-specific payload families if later evidence narrows the backend.",
                ],
                verification_status="informational",
            )
        )
    return findings


def _build_command_probe_findings(
    result: ToolExecutionResult,
    affected_asset: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    confirmed_hits = [item for item in result.evidence if item.lower().startswith("confirmed:")]

    if confirmed_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Command Execution Confirmed",
                severity="critical",
                source_tool="command_probe",
                affected_asset=affected_asset,
                confidence="high",
                summary=(
                    "A low-impact canary marker was returned only after injecting attacker-controlled command "
                    "input into a suspicious HTTP parameter, confirming remote command execution behavior."
                ),
                impact=(
                    "An attacker can likely execute arbitrary system commands through the exposed web entry "
                    "point, which can lead to full application compromise, data loss, and lateral movement."
                ),
                evidence=confirmed_hits[:3],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Remove direct command execution from request handlers, enforce strict allowlists or safe "
                    "APIs for required system operations, and isolate the service with least privilege."
                ),
                next_steps=[
                    "Capture the exact vulnerable endpoint and parameter for engineering remediation.",
                    "Review adjacent handlers for similar shell invocation patterns.",
                ],
                verification_status="verified",
            )
        )
    elif "no confirmed command execution indicator" in _evidence_blob(result):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="No Confirmed Command Execution Indicator From Current Candidate Set",
                severity="info",
                source_tool="command_probe",
                affected_asset=affected_asset,
                confidence="medium",
                summary=(
                    "The workflow found suspicious command-style parameters but did not reproduce a command "
                    "execution canary with the current low-impact probe set."
                ),
                impact=(
                    "This narrows the likelihood of straightforward query-parameter command execution, but it "
                    "does not clear POST handlers, authenticated routes, or non-echoing command sinks."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Expand candidate discovery into additional routes and request methods before ruling out "
                    "command-injection exposure."
                ),
                next_steps=[
                    "Inspect additional linked routes and form handlers for command-like parameters.",
                    "Test authenticated or alternate request methods when the scenario allows it.",
                ],
                verification_status="informational",
            )
        )

    return findings


def _build_login_sqli_findings(
    result: ToolExecutionResult,
    affected_asset: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    confirmed_hits = [item for item in result.evidence if item.lower().startswith("confirmed:")]

    if confirmed_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="SQL Injection Login Bypass Confirmed",
                severity="critical",
                source_tool="login_sqli_probe",
                affected_asset=affected_asset,
                confidence="high",
                summary=(
                    "A login form accepted a boolean SQL injection payload and produced an authentication "
                    "success indicator that was absent during the baseline invalid-login attempt."
                ),
                impact=(
                    "An attacker can likely bypass authentication and access protected application areas "
                    "without valid credentials."
                ),
                evidence=confirmed_hits[:3],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Replace string-built SQL with parameterized queries, centralize authentication logic, "
                    "and add server-side credential handling that is independent from raw input concatenation."
                ),
                next_steps=[
                    "Map the exact vulnerable login workflow and affected account role.",
                    "Retest all sibling login portals and password-reset flows for the same pattern.",
                ],
                verification_status="verified",
            )
        )
    elif "no confirmed login bypass" in _evidence_blob(result):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="No Confirmed Login SQL Injection From Current Form Set",
                severity="info",
                source_tool="login_sqli_probe",
                affected_asset=affected_asset,
                confidence="medium",
                summary=(
                    "The workflow identified candidate login forms but did not confirm SQL-injection-based "
                    "authentication bypass with the current low-noise payload set."
                ),
                impact=(
                    "This reduces confidence in straightforward boolean-based login bypass, but does not "
                    "exclude alternate parameters, request methods, or non-login SQL injection sinks."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Expand the candidate set and test additional form variants or parameter names before "
                    "ruling out authentication-related SQL injection."
                ),
                next_steps=[
                    "Inspect non-root login routes and role-specific portals.",
                    "Add error-based and time-based checks if the scenario requires broader SQLi coverage.",
                ],
                verification_status="informational",
            )
        )

    return findings


def _build_sensitive_file_findings(
    result: ToolExecutionResult,
    affected_asset: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    confirmed_hits = [item for item in result.evidence if item.lower().startswith("confirmed:")]
    if confirmed_hits:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Sensitive File Exposure Confirmed",
                severity="high",
                source_tool="sensitive_file_probe",
                affected_asset=affected_asset,
                confidence="high",
                summary=(
                    "A common sensitive file or backup artifact was fetched successfully and returned content "
                    "consistent with configuration, source, or repository metadata exposure."
                ),
                impact=(
                    "Sensitive file exposure can disclose credentials, source code, deployment secrets, and "
                    "other information that materially lowers the cost of follow-on compromise."
                ),
                evidence=confirmed_hits[:3],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Remove backup artifacts and development files from the web root, deny direct access to "
                    "sensitive paths, and rotate any disclosed credentials or secrets."
                ),
                next_steps=[
                    "Review all confirmed files for credential or source leakage.",
                    "Search for sibling backup and metadata artifacts in the same path family.",
                ],
                verification_status="verified",
            )
        )
    elif "no confirmed sensitive file exposure" in _evidence_blob(result):
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="No Confirmed Sensitive File Exposure From Current Path Set",
                severity="info",
                source_tool="sensitive_file_probe",
                affected_asset=affected_asset,
                confidence="medium",
                summary=(
                    "The focused common-path probe did not confirm direct exposure of the current sensitive "
                    "file shortlist."
                ),
                impact=(
                    "This reduces confidence in obvious root-level file leakage, but it does not rule out "
                    "application-specific backups or nested secrets."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Expand file exposure discovery only if later evidence suggests backups, framework metadata, "
                    "or deployment artifacts are present."
                ),
                next_steps=[
                    "Correlate with directory listing, stack clues, and deployment structure.",
                    "Add framework-specific secret path checks if warranted by new evidence.",
                ],
                verification_status="informational",
            )
        )
    return findings


def _build_heartbleed_findings(
    result: ToolExecutionResult,
    affected_asset: str,
) -> list[VerifiedFinding]:
    findings: list[VerifiedFinding] = []
    blob = _evidence_blob(result)

    if "cve-2014-0160" in blob or "ssl-heartbleed: vulnerable" in blob or "state: vulnerable" in blob:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Heartbleed Vulnerability Confirmed",
                severity="critical",
                source_tool="heartbleed_probe",
                affected_asset=affected_asset,
                confidence="high",
                summary=(
                    "The targeted TLS probe reported a positive Heartbleed match, confirming CVE-2014-0160 "
                    "exposure on the tested service."
                ),
                impact=(
                    "Heartbleed can expose process memory from the TLS service, including secrets, session "
                    "material, credentials, and other sensitive application data."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Upgrade the TLS stack to a non-vulnerable OpenSSL version, replace any exposed keys or "
                    "certificates, invalidate sessions, and retest the service."
                ),
                next_steps=[
                    "Inventory all certificates, keys, and sessions associated with the service.",
                    "Retest after patching to confirm the vulnerable heartbeat behavior is gone.",
                ],
                verification_status="verified",
            )
        )
    elif "ssl-heartbleed executed without a positive vulnerability match" in blob:
        findings.append(
            VerifiedFinding(
                finding_id=_finding_id(),
                title="Heartbleed Not Confirmed On Current TLS Service",
                severity="info",
                source_tool="heartbleed_probe",
                affected_asset=affected_asset,
                confidence="medium",
                summary=(
                    "The targeted Heartbleed probe ran successfully but did not produce a positive "
                    "CVE-2014-0160 match."
                ),
                impact=(
                    "This lowers confidence in Heartbleed exposure on the tested service, though other TLS "
                    "weaknesses may still be present."
                ),
                evidence=result.evidence[:5],
                artifact_paths=_artifact_paths(result),
                remediation=(
                    "Preserve the TLS scan artifacts and continue with other protocol-appropriate checks if "
                    "the scenario calls for them."
                ),
                next_steps=[
                    "Correlate the TLS service version and certificate metadata.",
                    "Expand verification to additional SSL/TLS weakness checks where relevant.",
                ],
                verification_status="informational",
            )
        )

    return findings


def _path_probe_hit_verified(evidence_line: str) -> bool:
    lowered = evidence_line.lower()
    return any(marker in lowered for marker in PATH_PROBE_VERIFIED_STATUS_MARKERS)


def _extract_status_codes(result: ToolExecutionResult | None) -> set[int]:
    if result is None:
        return set()
    codes: set[int] = set()
    for item in result.evidence:
        for match in re.findall(r"(?:status_code:\s*|->\s*)(\d{3})", item.lower()):
            try:
                codes.add(int(match))
            except ValueError:
                continue
    return codes


def _evaluate_verification_goals(task: TaskDetail, findings: list[VerifiedFinding]) -> list[str]:
    plan = task.llm_strategy_plan
    if plan is None or not plan.verification_goals:
        return []

    findings_blob = " ".join(
        [finding.title + " " + finding.summary + " " + " ".join(finding.evidence) for finding in findings]
    ).lower()
    statuses: list[str] = []
    for goal in plan.verification_goals:
        lowered = goal.lower()
        matched = False
        if "admin" in lowered or "default path" in lowered or "path" in lowered:
            matched = any(
                finding.title in {"Tomcat Administrative Paths Reachable", "Default Tomcat Content Exposed"}
                for finding in findings
            )
        elif "sensitive file" in lowered or "backup" in lowered or "configuration exposure" in lowered:
            matched = any(
                finding.source_tool == "sensitive_file_probe" and finding.verification_status == "verified"
                for finding in findings
            )
        elif "generic injection" in lowered or "parameter injection" in lowered:
            matched = any(
                finding.source_tool == "param_injection_probe" and finding.verification_status == "verified"
                for finding in findings
            )
        elif "sql injection" in lowered or "authentication bypass" in lowered or "login form" in lowered:
            matched = any(
                finding.source_tool == "login_sqli_probe" and finding.verification_status == "verified"
                for finding in findings
            )
        elif "heartbleed" in lowered or "cve-2014-0160" in lowered or "tls service" in lowered:
            matched = any(
                finding.source_tool == "heartbleed_probe" and finding.verification_status == "verified"
                for finding in findings
            )
        elif "command execution" in lowered or "rce" in lowered or "attacker-controlled command input" in lowered:
            matched = any(finding.source_tool == "command_probe" and finding.verification_status == "verified" for finding in findings)
        elif "form" in lowered or "input-bearing" in lowered or "dynamic endpoint" in lowered:
            matched = any(finding.source_tool == "input_surface" for finding in findings)
        elif "template" in lowered or "nuclei" in lowered:
            matched = any(finding.source_tool == "nuclei" for finding in findings)
        elif "http response" in lowered or "reachable" in lowered or "live service" in lowered:
            matched = any(finding.title == "Verified HTTP Surface" for finding in findings)
        elif "gateway" in lowered or "502" in lowered:
            matched = "502" in findings_blob or any(
                "502" in " ".join(result.evidence) for result in task.tool_results if result.tool_name == "web_fingerprint"
            )

        prefix = "met" if matched else "pending"
        statuses.append(f"{prefix}: {goal}")
    return statuses


def _evaluate_stop_conditions(task: TaskDetail, findings: list[VerifiedFinding]) -> list[str]:
    plan = task.llm_strategy_plan
    if plan is None or not plan.stop_conditions:
        return []

    statuses: list[str] = []
    for condition in plan.stop_conditions:
        lowered = condition.lower()
        matched = False
        if "both path discovery and nuclei" in lowered or "both scan tools" in lowered:
            matched = all(
                finding.verification_status == "informational"
                for finding in findings
                if finding.source_tool in {"path_probe", "nuclei"}
            ) and any(finding.source_tool == "nuclei" for finding in findings)
        elif "no http response" in lowered or "port closed" in lowered:
            matched = any(finding.title == "Recon Signal Mismatch Requires Retest" for finding in findings)
        elif "localhost-bound" in lowered or "outside the authorized test scope" in lowered:
            matched = "localhost" in task.target.lower() and "outside the authorized test scope" in lowered

        prefix = "met" if matched else "open"
        statuses.append(f"{prefix}: {condition}")
    return statuses


def _build_verification_recommendation(
    goal_status: list[str],
    stop_condition_status: list[str],
    continue_testing: bool,
) -> str:
    met_goals = sum(1 for item in goal_status if item.startswith("met:"))
    pending_goals = sum(1 for item in goal_status if item.startswith("pending:"))
    met_stops = sum(1 for item in stop_condition_status if item.startswith("met:"))
    if met_stops > 0:
        return (
            f"{met_goals} verification goals were satisfied, but {met_stops} stop conditions were met. "
            "Pause deeper testing and preserve the current evidence set for review."
        )
    if continue_testing and pending_goals > 0:
        return (
            f"{met_goals} verification goals were satisfied and {pending_goals} remain open. "
            "Continue targeted testing only if additional coverage is in scope."
        )
    return (
        f"{met_goals} verification goals were satisfied. No active stop condition currently blocks "
        "further evidence collection."
    )
