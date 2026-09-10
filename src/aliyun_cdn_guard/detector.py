from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import replace

from .config import AppConfig
from .models import AccessEvent, BlockDecision
from .normalization import normalize_uri
from .storage import Storage

logger = logging.getLogger(__name__)


class Detector:
    def __init__(self, config: AppConfig, storage: Storage):
        self.config = config
        self.storage = storage
        self._domains = frozenset(config.cdn.domains)

    def process(self, event: AccessEvent, now: int | None = None) -> BlockDecision | None:
        if event.domain not in self._domains:
            logger.warning("ignoring log for unmanaged domain %s", event.domain)
            return None
        try:
            address = ipaddress.ip_address(event.client_ip)
        except ValueError:
            logger.warning("ignoring invalid client_ip %r", event.client_ip)
            return None
        canonical_ip = address.exploded if address.version == 6 else str(address)
        if event.client_ip != canonical_ip:
            event = replace(event, client_ip=canonical_ip)

        uri_key = normalize_uri(event.uri, event.uri_param, self.config.detection.uri)
        wl = self.config.whitelist
        if (
            event.domain in wl.domains
            or any(address in network for network in wl.ip_networks)
            or any(pattern.search(event.user_agent) for pattern in wl.ua_regexes)
            or any(pattern.search(uri_key) for pattern in wl.uri_regexes)
        ):
            return None

        ua_config = self.config.detection.ua
        uri_config = self.config.detection.uri

        penalty = self.config.penalty
        detection = self.config.detection
        decision = self.storage.record_and_maybe_block(
            event=event,
            ua_key=event.user_agent if ua_config.enabled else "",
            uri_key=uri_key if uri_config.enabled else "",
            threshold=detection.threshold,
            window_seconds=detection.window_seconds,
            base_duration=penalty.base_duration_seconds,
            multiplier=penalty.multiplier,
            max_duration=penalty.max_duration_seconds,
            use_ua=ua_config.enabled,
            use_uri=uri_config.enabled,
            now=now,
        )
        if decision:
            logger.warning(
                "abuse threshold reached domain=%s ip=%s count=%d offense=%d blocked_until=%d",
                decision.domain, decision.client_ip, decision.count, decision.offense_count, decision.blocked_until,
            )
        return decision

    def prune(self, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        return self.storage.prune_events(now - self.config.detection.retention_seconds)
