from __future__ import annotations

import json
import sys
from uuid import uuid4

import httpx

from app.adapters.tools.web_common import (
    extract_query_candidates,
    marker_only_in_candidate,
    mutate_query_parameter,
    snapshot_response,
)
from app.core.targeting import parse_target

HTTP_TIMEOUT_SECONDS = 3.0
SUSPICIOUS_PARAM_NAMES = (
    "cmd",
    "exec",
    "command",
    "shell",
    "system",
    "proc",
    "process",
)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "target argument is required"}))
        return 1

    target = argv[1]
    profile = parse_target(target)
    request_url = profile.request_url
    base_url = profile.base_url
    marker = f"cmdprobe-{uuid4().hex[:8]}"
    payload_value = f"echo {marker}"

    payload: dict[str, object] = {
        "base_url": base_url,
        "request_url": request_url,
        "root": {},
        "candidates": [],
        "confirmed": [],
    }

    try:
        with httpx.Client(
            timeout=HTTP_TIMEOUT_SECONDS,
            follow_redirects=True,
            verify=False,
            trust_env=False,
        ) as client:
            root_response = client.get(request_url)
            root_body = root_response.text
            payload["root"] = {
                "url": str(root_response.request.url),
                "status_code": root_response.status_code,
                "server": root_response.headers.get("server"),
            }

            candidates = extract_query_candidates(
                base_url,
                root_body,
                parameter_filter=lambda key: key in SUSPICIOUS_PARAM_NAMES,
            )
            payload["candidates"] = candidates

            confirmed: list[dict[str, object]] = []
            for candidate in candidates[:4]:
                probe_url = mutate_query_parameter(candidate["url"], candidate["parameter"], payload_value)
                baseline_response = client.get(candidate["url"])
                probe_response = client.get(probe_url)
                if marker_only_in_candidate(
                    snapshot_response(baseline_response),
                    snapshot_response(probe_response),
                    marker=marker,
                ):
                    confirmed.append(
                        {
                            "path": candidate["path"],
                            "parameter": candidate["parameter"],
                            "source": candidate["source"],
                            "status_code": probe_response.status_code,
                            "marker": marker,
                            "probe_url": probe_url,
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
