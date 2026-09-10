from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    pass


def _section(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _required(data: dict[str, Any], key: str, context: str) -> str:
    value = str(data.get(key, "")).strip()
    if not value:
        raise ConfigError(f"{context}.{key} is required")
    return value


def _bool(value: Any, context: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "yes", "on", "1"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "no", "off", "0"}:
        return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise ConfigError(f"{context} must be a boolean")


def _compile_optional(value: Any, context: str) -> re.Pattern[str] | None:
    if value in (None, ""):
        return None
    try:
        return re.compile(str(value))
    except re.error as exc:
        raise ConfigError(f"invalid regex in {context}: {exc}") from exc


def _compile_many(values: Any, context: str) -> tuple[re.Pattern[str], ...]:
    if values is None:
        return ()
    if not isinstance(values, list):
        raise ConfigError(f"{context} must be a list")
    result = []
    for value in values:
        pattern = _compile_optional(value, context)
        if pattern is None:
            raise ConfigError(f"empty regex in {context}")
        result.append(pattern)
    return tuple(result)


def _networks(values: Any, context: str) -> tuple[ipaddress._BaseNetwork, ...]:
    if values is None:
        return ()
    if not isinstance(values, list):
        raise ConfigError(f"{context} must be a list")
    result = []
    for value in values:
        try:
            result.append(ipaddress.ip_network(str(value), strict=False))
        except ValueError as exc:
            raise ConfigError(f"invalid IP/CIDR in {context}: {value}") from exc
    return tuple(result)


def _string_list(values: Any, context: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ConfigError(f"{context} must be a list")
    return [str(value) for value in values]


def _cdn_network(network: ipaddress._BaseNetwork) -> str:
    address = network.network_address.exploded
    return address if network.num_addresses == 1 else f"{address}/{network.prefixlen}"


@dataclass(frozen=True)
class SlsConfig:
    endpoint: str
    region: str
    project: str
    logstore: str
    consumer_group: str = "aliyun-cdn-guard"
    consumer_name: str = ""
    cursor_position: str = "end"
    fetch_interval_seconds: int = 2


@dataclass(frozen=True)
class CdnConfig:
    region: str
    endpoint: str
    domains: tuple[str, ...]
    ip_acl_xfwd: str = "on"
    sync_interval_seconds: int = 10
    dry_run: bool = True


@dataclass(frozen=True)
class DimensionConfig:
    enabled: bool = False
    match_regex: re.Pattern[str] | None = None


@dataclass(frozen=True)
class UriConfig(DimensionConfig):
    query_mode: str = "keep"
    ignored_names: frozenset[str] = frozenset()


@dataclass(frozen=True)
class DetectionConfig:
    threshold: int
    window_seconds: int
    retention_seconds: int
    ua: DimensionConfig
    uri: UriConfig


@dataclass(frozen=True)
class PenaltyConfig:
    base_duration_seconds: int
    multiplier: float
    max_duration_seconds: int


@dataclass(frozen=True)
class WhitelistConfig:
    domains: frozenset[str] = frozenset()
    ip_networks: tuple[ipaddress._BaseNetwork, ...] = ()
    ua_regexes: tuple[re.Pattern[str], ...] = ()
    uri_regexes: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class AppConfig:
    sls: SlsConfig
    cdn: CdnConfig
    detection: DetectionConfig
    penalty: PenaltyConfig
    whitelist: WhitelistConfig
    permanent_blocklist: dict[str, tuple[str, ...]] = field(default_factory=dict)
    storage_path: Path = Path("data/guard.db")
    log_level: str = "INFO"


def load_config(path: str | Path) -> AppConfig:
    config_path = Path(path)
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ConfigError(f"cannot read config: {config_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("configuration root must be a mapping")

    sls_raw = _section(raw, "sls")
    cdn_raw = _section(raw, "cdn")
    detection_raw = _section(raw, "detection")
    ua_raw = _section(detection_raw, "ua")
    uri_raw = _section(detection_raw, "uri")
    query_raw = _section(uri_raw, "query_parameters")
    penalty_raw = _section(raw, "penalty")
    whitelist_raw = _section(raw, "whitelist")

    domains_raw = cdn_raw.get("domains", [])
    if not isinstance(domains_raw, list) or not domains_raw:
        raise ConfigError("cdn.domains must be a non-empty list")
    domains = tuple(dict.fromkeys(str(item).strip().lower() for item in domains_raw if str(item).strip()))
    raw_ip_acl_xfwd = cdn_raw.get("ip_acl_xfwd", "on")
    if isinstance(raw_ip_acl_xfwd, bool):
        ip_acl_xfwd = "on" if raw_ip_acl_xfwd else "off"
    else:
        ip_acl_xfwd = str(raw_ip_acl_xfwd).lower()
    if ip_acl_xfwd not in {"on", "off", "all"}:
        raise ConfigError("cdn.ip_acl_xfwd must be on, off, or all")
    cursor_position = str(sls_raw.get("cursor_position", "end"))
    if cursor_position not in {"end", "begin"}:
        try:
            datetime.fromisoformat(cursor_position.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ConfigError("sls.cursor_position must be end, begin, or an ISO datetime") from exc

    threshold = int(detection_raw.get("threshold", 1000))
    window = int(detection_raw.get("window_seconds", 60))
    retention = int(detection_raw.get("retention_seconds", max(window, 3600)))
    if threshold < 1 or window < 1 or retention < window:
        raise ConfigError("threshold/window_seconds must be positive and retention_seconds >= window_seconds")

    query_mode = str(query_raw.get("mode", "keep"))
    if query_mode not in {"keep", "ignore_all", "ignore_selected"}:
        raise ConfigError("detection.uri.query_parameters.mode must be keep, ignore_all, or ignore_selected")
    ignored_names = query_raw.get("ignored_names", [])
    if not isinstance(ignored_names, list):
        raise ConfigError("detection.uri.query_parameters.ignored_names must be a list")

    base = int(penalty_raw.get("base_duration_seconds", 600))
    multiplier = float(penalty_raw.get("multiplier", 2.0))
    maximum = int(penalty_raw.get("max_duration_seconds", 86400))
    if base < 1 or multiplier < 1 or maximum < base:
        raise ConfigError("penalty requires base > 0, multiplier >= 1, and max >= base")

    permanent_raw = raw.get("permanent_blocklist", {}) or {}
    if not isinstance(permanent_raw, dict):
        raise ConfigError("permanent_blocklist must be a mapping of domain to IP list")
    permanent: dict[str, tuple[str, ...]] = {}
    for domain, values in permanent_raw.items():
        domain = str(domain).lower()
        if domain not in domains:
            raise ConfigError(f"permanent_blocklist domain is not in cdn.domains: {domain}")
        networks = _networks(values, f"permanent_blocklist.{domain}")
        permanent[domain] = tuple(_cdn_network(network) for network in networks)

    storage_raw = _section(raw, "storage")
    storage_path = Path(str(storage_raw.get("path", "data/guard.db")))
    if not storage_path.is_absolute():
        storage_path = (config_path.parent / storage_path).resolve()

    return AppConfig(
        sls=SlsConfig(
            endpoint=_required(sls_raw, "endpoint", "sls"),
            region=_required(sls_raw, "region", "sls"),
            project=_required(sls_raw, "project", "sls"),
            logstore=_required(sls_raw, "logstore", "sls"),
            consumer_group=str(sls_raw.get("consumer_group", "aliyun-cdn-guard")),
            consumer_name=str(sls_raw.get("consumer_name", "")),
            cursor_position=cursor_position,
            fetch_interval_seconds=max(1, int(sls_raw.get("fetch_interval_seconds", 2))),
        ),
        cdn=CdnConfig(
            region=_required(cdn_raw, "region", "cdn"),
            endpoint=str(cdn_raw.get("endpoint", "cdn.aliyuncs.com")),
            domains=domains,
            ip_acl_xfwd=ip_acl_xfwd,
            sync_interval_seconds=max(1, int(cdn_raw.get("sync_interval_seconds", 10))),
            dry_run=_bool(cdn_raw.get("dry_run", True), "cdn.dry_run"),
        ),
        detection=DetectionConfig(
            threshold=threshold,
            window_seconds=window,
            retention_seconds=retention,
            ua=DimensionConfig(_bool(ua_raw.get("enabled", False), "detection.ua.enabled"), _compile_optional(ua_raw.get("match_regex"), "detection.ua.match_regex")),
            uri=UriConfig(
                _bool(uri_raw.get("enabled", False), "detection.uri.enabled"),
                _compile_optional(uri_raw.get("match_regex"), "detection.uri.match_regex"),
                query_mode,
                frozenset(str(item) for item in ignored_names),
            ),
        ),
        penalty=PenaltyConfig(base, multiplier, maximum),
        whitelist=WhitelistConfig(
            domains=frozenset(item.lower() for item in _string_list(whitelist_raw.get("domains", []), "whitelist.domains")),
            ip_networks=_networks(whitelist_raw.get("ips", []), "whitelist.ips"),
            ua_regexes=_compile_many(whitelist_raw.get("ua_regexes", []), "whitelist.ua_regexes"),
            uri_regexes=_compile_many(whitelist_raw.get("uri_regexes", []), "whitelist.uri_regexes"),
        ),
        permanent_blocklist=permanent,
        storage_path=storage_path,
        log_level=str(_section(raw, "logging").get("level", "INFO")).upper(),
    )
