import json
from collections.abc import Iterable
import re

import httpx

from app.core.config import get_settings
from app.schemas.task import LLMStrategyPlan, TaskDetail, VerifiedFinding
from app.schemas.tool import ToolExecutionResult


class LLMAnalysisService:
    allowed_scan_tools = {
        "path_probe",
        "input_surface",
        "param_injection_probe",
        "command_probe",
        "login_sqli_probe",
        "sensitive_file_probe",
        "heartbleed_probe",
        "nuclei",
    }
    reachable_status_codes = {200, 204, 301, 302, 307, 308, 401, 403, 405}

    def __init__(self) -> None:
        self.settings = get_settings()

    def build_strategy_plan(self, task: TaskDetail) -> LLMStrategyPlan:
        if self.settings.openai_api_key:
            try:
                response_text = self._request_openai(
                    system_prompt=(
                        "You are a security analysis planner for an authorized penetration testing "
                        "lab workflow. Review the reconnaissance findings and produce a JSON object "
                        "with these keys only: summary, priority, recommended_tools, focus_areas, "
                        "priority_paths, verification_goals, stop_conditions, rationale. "
                        "recommended_tools must contain tool identifiers chosen from "
                        "['path_probe','input_surface','param_injection_probe','command_probe','login_sqli_probe','sensitive_file_probe','heartbleed_probe','nuclei']. priority must be one of low, medium, high. "
                        "Return valid JSON only."
                    ),
                    user_payload={
                        "target": task.target,
                        "scenario": task.scenario,
                        "recon_results": [
                            {
                                "tool": result.tool_name,
                                "summary": result.summary,
                                "evidence": result.evidence,
                                "mode": result.execution_mode,
                            }
                            for result in task.tool_results
                        ],
                    },
                )
                plan = self._normalize_strategy_plan(self._parse_strategy_plan(response_text))
                return self._apply_reachability_guard(plan, task.tool_results)
            except Exception:
                return self._fallback_strategy_plan(task.tool_results)
        return self._fallback_strategy_plan(task.tool_results)

    def analyze_recon(self, task: TaskDetail) -> str:
        plan = task.llm_strategy_plan or self.build_strategy_plan(task)
        task.llm_strategy_plan = plan
        return plan.summary

    def summarize_verification(self, task: TaskDetail) -> str:
        if self.settings.openai_api_key:
            try:
                return self._request_openai(
                    system_prompt=(
                        "You are a security validation reviewer. Based on scan evidence and "
                        "current findings, summarize what is actually verified, what remains "
                        "informational, and what should happen next. Keep it under 120 words."
                    ),
                    user_payload={
                        "target": task.target,
                        "analysis_summary": task.analysis_summary,
                        "findings": [finding.model_dump(mode="json") for finding in task.verified_findings],
                        "tool_results": [result.model_dump(mode="json") for result in task.tool_results],
                    },
                )
            except Exception:
                return self._fallback_verification(task.verified_findings)
        return self._fallback_verification(task.verified_findings)

    def summarize_report(self, task: TaskDetail) -> str:
        if self.settings.openai_api_key:
            try:
                return self._request_openai(
                    system_prompt=(
                        "You are writing the executive summary of an authorized penetration "
                        "testing report. Respond in Simplified Chinese only. Use professional "
                        "security-report wording and return Markdown only. Keep it concise and "
                        "structured as exactly four top-level bullet points covering: target context, "
                        "what was validated, whether any finding was confirmed, and the recommended next step."
                    ),
                    user_payload={
                        "target": task.target,
                        "scenario": task.scenario,
                        "analysis_summary": task.analysis_summary,
                        "verification_summary": task.verification_summary,
                        "findings": [finding.model_dump(mode="json") for finding in task.verified_findings],
                    },
                )
            except Exception:
                return self._fallback_report(task)
        return self._fallback_report(task)

    def _request_openai(self, *, system_prompt: str, user_payload: dict) -> str:
        wire_api = self.settings.openai_wire_api.strip().lower()
        with httpx.Client(timeout=30.0) as client:
            if wire_api == "chat_completions":
                return self._request_chat_completions(
                    client=client,
                    system_prompt=system_prompt,
                    user_payload=user_payload,
                )

            response = client.post(
                f"{self.settings.openai_base_url.rstrip('/')}/responses",
                headers={
                    "Authorization": f"Bearer {self.settings.openai_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.settings.openai_model,
                    "reasoning": {"effort": self.settings.llm_reasoning_effort},
                    "input": [
                        {
                            "role": "system",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": system_prompt,
                                }
                            ],
                        },
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": json.dumps(user_payload, ensure_ascii=False),
                                }
                            ],
                        },
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()

        text = self._extract_output_text(data)
        return text.strip()

    def _request_chat_completions(
        self,
        *,
        client: httpx.Client,
        system_prompt: str,
        user_payload: dict,
    ) -> str:
        url = f"{self.settings.openai_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ]

        with client.stream(
            "POST",
            url,
            headers=headers,
            json={
                "model": self.settings.openai_model,
                "messages": messages,
                "temperature": 0,
                "stream": True,
                "stream_options": {"include_usage": True},
            },
        ) as stream_response:
            stream_response.raise_for_status()
            return self._extract_chat_stream_output_text(stream_response.iter_lines()).strip()

    def _extract_output_text(self, data: dict) -> str:
        output = data.get("output", [])
        chunks: list[str] = []
        for item in output:
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    chunks.append(content.get("text", ""))
        return "\n".join(chunk for chunk in chunks if chunk).strip()

    def _extract_chat_output_text(self, data: dict) -> str:
        choices = data.get("choices", [])
        if not choices:
            return ""
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks: list[str] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") in {"text", "output_text"}:
                    chunks.append(item.get("text", ""))
            return "\n".join(chunk for chunk in chunks if chunk).strip()
        return ""

    def _extract_chat_stream_output_text(self, lines: Iterable[str]) -> str:
        chunks: list[str] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line or not line.startswith("data:"):
                continue

            payload = line[5:].strip()
            if payload == "[DONE]":
                break

            event = json.loads(payload)
            for choice in event.get("choices", []):
                delta = choice.get("delta", {})
                content = delta.get("content")
                if isinstance(content, str) and content:
                    chunks.append(content)
                    continue
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") in {"text", "output_text"}:
                            text = item.get("text", "")
                            if text:
                                chunks.append(text)

        return "".join(chunks)

    def _parse_strategy_plan(self, response_text: str) -> LLMStrategyPlan:
        start = response_text.find("{")
        end = response_text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise ValueError("No JSON object found in strategy plan response.")
        payload = json.loads(response_text[start : end + 1])
        return LLMStrategyPlan.model_validate(payload)

    def _normalize_strategy_plan(self, plan: LLMStrategyPlan) -> LLMStrategyPlan:
        recommended_tools = [tool for tool in plan.recommended_tools if tool in self.allowed_scan_tools]
        if plan.recommended_tools and not recommended_tools:
            recommended_tools = ["nuclei"]
        normalized_paths = self._normalize_priority_paths(plan.priority_paths)
        return plan.model_copy(
            update={
                "recommended_tools": recommended_tools,
                "priority_paths": normalized_paths,
            }
        )

    def _apply_reachability_guard(
        self,
        plan: LLMStrategyPlan,
        results: Iterable[ToolExecutionResult],
    ) -> LLMStrategyPlan:
        if self._recon_supports_web_scanning(results):
            return plan

        focus_areas = list(plan.focus_areas)
        if "restore confirmed application reachability" not in focus_areas:
            focus_areas.insert(0, "restore confirmed application reachability")

        stop_conditions = list(plan.stop_conditions)
        guard_condition = (
            "Stop application-layer scanning until a stable reachable HTTP response or open service port "
            "is confirmed."
        )
        if guard_condition not in stop_conditions:
            stop_conditions.insert(0, guard_condition)

        rationale = plan.rationale
        if "application-layer scans are deferred" not in rationale.lower():
            rationale = (
                f"{rationale} Recon currently does not confirm a stable reachable application surface, "
                "so application-layer scans are deferred."
            )

        return plan.model_copy(
            update={
                "priority": "low",
                "recommended_tools": [],
                "priority_paths": [],
                "focus_areas": focus_areas,
                "stop_conditions": stop_conditions,
                "rationale": rationale,
            }
        )

    def _recon_supports_web_scanning(self, results: Iterable[ToolExecutionResult]) -> bool:
        for result in results:
            combined = " ".join([result.summary, *result.evidence]).lower()
            if result.tool_name == "nmap" and "open" in combined and any(
                marker in combined
                for marker in ("http", "ssl/http", "https", "apache", "nginx", "tomcat", "php")
            ):
                return True
            if result.tool_name in {"httpx", "web_fingerprint", "whatweb"}:
                for status_code in self._extract_status_codes(combined):
                    if status_code in self.reachable_status_codes:
                        return True
                if any(marker in combined for marker in ("title:", "webserver:", "header:", "tech:")):
                    return True
        return False

    def _extract_status_codes(self, text: str) -> list[int]:
        return [int(match) for match in re.findall(r"(?:status_code:\s*|->\s*)(\d{3})", text)]

    def _normalize_priority_paths(self, priority_paths: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        keyword_map = {
            "root": ["/"],
            "entry": ["/"],
            "health": ["/health"],
            "status": ["/status"],
            "admin": ["/admin", "/manager/html", "/host-manager/html"],
            "diagnostic": ["/manager/status", "/status"],
            "proxy": ["/", "/health"],
            "gateway": ["/", "/health"],
            "login": ["/login"],
            "api": ["/api"],
            "robots": ["/robots.txt"],
            "favicon": ["/favicon.ico"],
        }

        for item in priority_paths:
            value = item.strip()
            if not value:
                continue
            if value.startswith("/"):
                candidate = value
                if candidate not in seen:
                    normalized.append(candidate)
                    seen.add(candidate)
                continue

            lowered = value.lower()
            for keyword, paths in keyword_map.items():
                if keyword in lowered:
                    for path in paths:
                        if path not in seen:
                            normalized.append(path)
                            seen.add(path)

        return normalized[:6]

    def _fallback_analysis(self, results: Iterable[ToolExecutionResult]) -> str:
        return self._fallback_strategy_plan(results).summary

    def _fallback_strategy_plan(self, results: Iterable[ToolExecutionResult]) -> LLMStrategyPlan:
        results = list(results)
        tool_names = [result.tool_name for result in results if result.success]
        combined = " ".join(
            " ".join(result.evidence) + " " + result.summary for result in results
        ).lower()
        has_http_signal = any(
            marker in combined
            for marker in ("status_code:", "title:", "header:", "tech:", "tomcat", "servlet", "apache-coyote")
        )
        has_tls_signal = any(
            marker in combined
            for marker in ("ssl/", "https", "tls", "certificate", "x509", "443/tcp", "8443/tcp")
        )
        mentions_tomcat = any(
            "tomcat" in " ".join(result.evidence).lower() or "tomcat" in result.summary.lower()
            for result in results
        )

        if not tool_names:
            return self._normalize_strategy_plan(
                LLMStrategyPlan(
                summary=(
                    "Recon produced limited confirmed signals. Run a lightweight nuclei pass first and "
                    "retain artifacts for manual review."
                ),
                priority="low",
                recommended_tools=[],
                focus_areas=["baseline vulnerability scan"],
                priority_paths=[],
                verification_goals=["Confirm whether the target exposes any template-covered weakness."],
                stop_conditions=["Stop after recon if no web signal is confirmed."],
                rationale="No strong recon signals were available, so deeper validation would be premature.",
                )
            )

        if has_tls_signal:
            return self._normalize_strategy_plan(
                LLMStrategyPlan(
                summary=(
                    "Recon indicates a TLS-enabled service. Prioritize targeted Heartbleed validation before "
                    "expanding into broader web checks."
                ),
                priority="high",
                recommended_tools=["heartbleed_probe"],
                focus_areas=[
                    "tls service exposure",
                    "heartbleed validation",
                    "openssl cve-2014-0160 coverage",
                ],
                priority_paths=[],
                verification_goals=[
                    "Confirm whether the TLS service is vulnerable to Heartbleed (CVE-2014-0160).",
                ],
                stop_conditions=[
                    "Stop the Heartbleed branch if the target does not expose a TLS service on the requested port.",
                ],
                rationale=(
                    "TLS exposure justifies a targeted protocol-level verification pass before unrelated "
                    "application-layer enumeration."
                ),
                )
            )

        if mentions_tomcat or has_http_signal:
            return self._normalize_strategy_plan(
                LLMStrategyPlan(
                summary=(
                    "Recon indicates an HTTP application with Tomcat-like or servlet-backed signals. "
                    "Prioritize entry-point discovery and path discovery before the focused nuclei pass."
                ),
                priority="high",
                recommended_tools=[
                    "input_surface",
                    "param_injection_probe",
                    "login_sqli_probe",
                    "command_probe",
                    "sensitive_file_probe",
                    "path_probe",
                    "nuclei",
                ],
                focus_areas=[
                    "input-bearing endpoints",
                    "generic parameter injection",
                    "login form sql injection",
                    "command-style query parameters",
                    "sensitive file exposure",
                    "tomcat admin surface",
                    "default content",
                    "template-backed web exposure",
                ],
                priority_paths=["/manager/html", "/host-manager/html", "/docs/", "/examples/"],
                verification_goals=[
                    "Identify reachable forms or dynamic input-bearing endpoints.",
                    "Determine whether any discovered parameter shows generic injection behavior.",
                    "Determine whether any discovered login form permits SQL-injection-based authentication bypass.",
                    "Determine whether any discovered endpoint executes attacker-controlled command input.",
                    "Determine whether any common sensitive files or backups are directly exposed.",
                    "Confirm whether Tomcat admin or default paths are reachable.",
                    "Correlate path exposure with nuclei template output.",
                ],
                stop_conditions=[
                    "Stop deeper expansion if both path discovery and nuclei produce no actionable signal.",
                ],
                rationale=(
                    "Tomcat-oriented signals justify focused application-path enumeration before broadening "
                    "verification work."
                ),
                )
            )

        return self._normalize_strategy_plan(
            LLMStrategyPlan(
            summary=(
                f"Recon succeeded with {', '.join(tool_names)}. Run nuclei first and only expand to path "
                "discovery if later web evidence justifies it."
            ),
            priority="medium",
            recommended_tools=["nuclei"],
            focus_areas=["general web exposure"],
            priority_paths=[],
            verification_goals=["Turn recon fingerprints into concrete vulnerability hypotheses."],
            stop_conditions=["Skip path discovery unless a stronger web stack signal appears."],
            rationale="Current evidence is insufficient to justify deeper focused path probing.",
            )
        )

    def _fallback_verification(self, findings: Iterable[VerifiedFinding]) -> str:
        findings = list(findings)
        if not findings:
            return (
                "The current workflow did not confirm exploitable vulnerabilities. Keep the scan "
                "artifacts and extend verification coverage before declaring the target clean."
            )
        verified_count = sum(1 for finding in findings if finding.verification_status == "verified")
        informational_count = sum(
            1 for finding in findings if finding.verification_status == "informational"
        )
        rejected_count = sum(1 for finding in findings if finding.verification_status == "rejected")
        return (
            f"Verification produced {verified_count} verified findings, {informational_count} informational "
            f"observations, and {rejected_count} rejected leads. Preserve the evidence chain and prioritize "
            "follow-up on the verified exposures first."
        )

    def _fallback_report(self, task: TaskDetail) -> str:
        verified_count = sum(
            1 for finding in task.verified_findings if finding.verification_status == "verified"
        )
        informational_count = sum(
            1 for finding in task.verified_findings if finding.verification_status == "informational"
        )
        if verified_count == 0 and informational_count == 0:
            return (
                "本次原型流程已完成侦察、分析、扫描与验证留痕，但基于当前本地模板与现有证据，"
                "尚未确认可成立的漏洞结论。"
            )
        return (
            f"本次原型流程已完成，当前共确认 {verified_count} 项已验证发现，"
            f"{informational_count} 项信息性观察。下一步应优先推进修复评估，并在授权范围内扩展扫描覆盖。"
        )


llm_analysis_service = LLMAnalysisService()
