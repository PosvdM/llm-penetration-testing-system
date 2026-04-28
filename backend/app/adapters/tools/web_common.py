from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit, urlunsplit

import httpx

STATIC_SUFFIXES = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
)
TEXT_QUERY_PATTERN = re.compile(
    r"(?P<candidate>(?:[A-Za-z0-9._/-]+)?[A-Za-z0-9._-]+\?(?:[A-Za-z0-9_.-]+=[^\r\n\"'<>]+))"
)


@dataclass(frozen=True)
class ResponseSnapshot:
    status_code: int
    body: str
    location: str
    title: str | None = None

    @property
    def blob(self) -> str:
        return " ".join([self.body.lower(), self.location.lower(), (self.title or "").lower()])


def extract_title(body: str) -> str | None:
    match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title or None


def same_origin(base_url: str, candidate: str) -> bool:
    base = urlparse(base_url)
    parsed = urlparse(candidate)
    return (parsed.scheme, parsed.netloc) == (base.scheme, base.netloc)


def normalize_same_origin_url(
    base_url: str,
    value: str,
    *,
    allow_queryless: bool = True,
    allow_static: bool = False,
) -> str | None:
    candidate = value.strip()
    if not candidate or candidate.startswith("#") or candidate.lower().startswith("javascript:"):
        return None

    absolute = urljoin(base_url, candidate)
    parsed = urlsplit(absolute)
    if not parsed.scheme or not parsed.netloc or not same_origin(base_url, absolute):
        return None
    if not allow_queryless and not parsed.query:
        return None
    if not allow_static and parsed.path.lower().endswith(STATIC_SUFFIXES):
        return None
    return absolute


def dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def extract_links(base_url: str, body: str, *, allow_static: bool = False) -> list[str]:
    hrefs = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    normalized = []
    for href in hrefs:
        absolute = normalize_same_origin_url(base_url, href, allow_static=allow_static)
        if absolute:
            normalized.append(absolute)
    return dedupe_strings(normalized)


def prioritize_links(
    base_url: str,
    links: list[str],
    *,
    keywords: tuple[str, ...],
    max_links: int,
) -> list[str]:
    prioritized = []
    fallback = []
    for link in links:
        path = urlparse(link).path.lower()
        if any(keyword in path for keyword in keywords):
            prioritized.append(link)
        else:
            fallback.append(link)
    ordered = dedupe_strings([*prioritized, *fallback])
    filtered = [link for link in ordered if link.rstrip("/") != base_url.rstrip("/")]
    return filtered[:max_links]


def extract_forms(page_url: str, body: str, *, max_forms: int = 8, max_inputs: int = 8) -> list[dict[str, object]]:
    forms: list[dict[str, object]] = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
        attributes = match.group(1)
        inner_html = match.group(2)
        action_match = re.search(r'action=["\']([^"\']*)["\']', attributes, re.IGNORECASE)
        method_match = re.search(r'method=["\']([^"\']+)["\']', attributes, re.IGNORECASE)
        action = action_match.group(1).strip() if action_match else ""
        action_url = normalize_same_origin_url(page_url, action) if action else page_url
        if not action_url:
            action_url = page_url

        fields = []
        inputs = []
        for input_match in re.finditer(r"<input\b([^>]*)>", inner_html, re.IGNORECASE):
            attrs = input_match.group(1)
            name_match = re.search(r'name=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if not name_match:
                continue
            field = {
                "name": name_match.group(1),
                "type": (type_match.group(1).lower() if type_match else "text"),
            }
            fields.append(field)
            inputs.append(field["name"])

        forms.append(
            {
                "page_url": page_url,
                "action": action_url,
                "method": (method_match.group(1).upper() if method_match else "GET"),
                "inputs": dedupe_strings(inputs)[:max_inputs],
                "fields": fields[:max_inputs],
            }
        )
    return forms[:max_forms]


def select_form_fields(
    fields: list[dict[str, str]],
    *,
    username_markers: tuple[str, ...],
    password_markers: tuple[str, ...],
) -> tuple[str | None, str | None]:
    username_field = None
    password_field = None

    for field in fields:
        field_name = field.get("name", "")
        field_type = field.get("type", "text").lower()
        lowered = field_name.lower()

        if password_field is None and (
            field_type == "password" or any(marker in lowered for marker in password_markers)
        ):
            password_field = field_name
            continue

        if username_field is None and any(marker in lowered for marker in username_markers):
            username_field = field_name

    return username_field, password_field


def extract_query_candidates(
    base_url: str,
    body: str,
    *,
    parameter_filter: Callable[[str], bool] | None = None,
) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    href_matches = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
    raw_matches = [match.group("candidate") for match in TEXT_QUERY_PATTERN.finditer(body)]

    for source, values in (("href", href_matches), ("body-text", raw_matches)):
        for value in values:
            absolute = normalize_same_origin_url(base_url, value, allow_queryless=False, allow_static=True)
            if not absolute:
                continue
            parsed = urlsplit(absolute)
            for key, original_value in parse_qsl(parsed.query, keep_blank_values=True):
                lowered = key.lower()
                if parameter_filter is not None and not parameter_filter(lowered):
                    continue
                dedupe_key = (absolute, lowered)
                if dedupe_key in seen:
                    continue
                candidates.append(
                    {
                        "url": absolute,
                        "path": parsed.path or "/",
                        "parameter": key,
                        "original_value": original_value,
                        "source": source,
                    }
                )
                seen.add(dedupe_key)
    return candidates


def mutate_query_parameter(url: str, parameter: str, replacement: str) -> str:
    parsed = urlsplit(url)
    query_items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query_items.append((key, replacement if key == parameter else value))
    new_query = urlencode(query_items, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))


def snapshot_response(response: httpx.Response) -> ResponseSnapshot:
    return ResponseSnapshot(
        status_code=response.status_code,
        body=response.text,
        location=response.headers.get("location", ""),
        title=extract_title(response.text),
    )


def marker_only_in_candidate(
    baseline: ResponseSnapshot,
    candidate: ResponseSnapshot,
    *,
    marker: str,
) -> bool:
    lowered_marker = marker.lower()
    return lowered_marker in candidate.blob and lowered_marker not in baseline.blob


def response_indicates_success_delta(
    baseline: ResponseSnapshot,
    candidate: ResponseSnapshot,
    *,
    success_markers: tuple[str, ...],
    failure_markers: tuple[str, ...],
) -> bool:
    baseline_blob = baseline.blob
    candidate_blob = candidate.blob
    baseline_failed = any(marker in baseline_blob for marker in failure_markers)
    candidate_success = any(marker in candidate_blob for marker in success_markers)
    if candidate_success and (baseline_failed or candidate_blob != baseline_blob):
        return True
    if candidate.status_code != baseline.status_code and candidate_success:
        return True
    return False
