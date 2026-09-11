from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .models import AccessEvent, BlockDecision


class BlockLog:
    """Append newly-created temporary blocks to a JSON Lines audit log."""

    def __init__(self, path: Path, *, dry_run: bool = False):
        self.path = path
        self.dry_run = dry_run
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: AccessEvent, decision: BlockDecision) -> None:
        duration = decision.blocked_until - decision.blocked_at
        record = {
            "schema_version": 1,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "dry_run": self.dry_run,
            "event_id": event.event_id,
            "event_timestamp": event.timestamp,
            "domain": decision.domain,
            "client_ip": decision.client_ip,
            "user_agent": event.user_agent,
            "uri": event.uri,
            "uri_param": event.uri_param,
            "request_count": decision.count,
            "offense_count": decision.offense_count,
            "blocked_at": decision.blocked_at,
            "blocked_until": decision.blocked_until,
            "duration_seconds": duration,
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8", newline="") as stream:
            stream.write(line)
            stream.flush()
