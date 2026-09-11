from __future__ import annotations

import hashlib
from typing import Any

from aliyun.log.consumer import ConsumerProcessorBase
from loguru import logger

from .detector import Detector
from .models import AccessEvent


class LogProcessor(ConsumerProcessorBase):
    def __init__(self, detector: Detector):
        super().__init__()
        self.detector = detector

    def process(self, log_groups: Any, check_point_tracker: Any) -> None:
        for group in log_groups.LogGroups:
            for log in group.Logs:
                fields = {content.Key: content.Value for content in log.Contents}
                self.detector.record_received(fields.get("domain", "").strip().lower())
                event = self._to_event(fields, int(log.Time))
                if event is not None:
                    self.detector.process(event)
        self.save_checkpoint(check_point_tracker)

    @staticmethod
    def _to_event(fields: dict[str, str], timestamp: int) -> AccessEvent | None:
        domain = fields.get("domain", "").strip().lower()
        client_ip = fields.get("client_ip", "").strip()
        uri = fields.get("uri", "")
        if not domain or not client_ip:
            logger.warning("skipping log missing domain/client_ip")
            return None
        event_id = fields.get("uuid", "").strip()
        if not event_id:
            # A fallback only; CDN real-time logs normally include the globally unique uuid.
            raw = "\0".join((str(timestamp), domain, client_ip, fields.get("user_agent", ""), uri, fields.get("uri_param", "")))
            event_id = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        return AccessEvent(
            event_id=event_id,
            timestamp=timestamp,
            domain=domain,
            client_ip=client_ip,
            user_agent=fields.get("user_agent", ""),
            uri=uri,
            uri_param=fields.get("uri_param", ""),
        )
