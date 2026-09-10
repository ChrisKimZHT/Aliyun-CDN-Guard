from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import UriConfig


def normalize_uri(uri: str, uri_param: str, config: UriConfig) -> str:
    """Return a stable path/query key for aggregation and URI whitelisting."""
    uri = uri or "/"
    parsed = urlsplit(uri)
    path = parsed.path or "/"
    query = parsed.query or (uri_param or "").lstrip("?")
    if config.query_mode == "ignore_all":
        query = ""
    elif config.query_mode == "ignore_selected" and query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode([(key, value) for key, value in pairs if key not in config.ignored_names], doseq=True)
    return urlunsplit(("", "", path, query, ""))

