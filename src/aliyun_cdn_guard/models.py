from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessEvent:
    event_id: str
    timestamp: int
    domain: str
    client_ip: str
    user_agent: str
    uri: str
    uri_param: str = ""


@dataclass(frozen=True)
class BlockDecision:
    domain: str
    client_ip: str
    count: int
    blocked_until: int
    offense_count: int


@dataclass(frozen=True)
class BlockRecord:
    domain: str
    client_ip: str
    blocked_until: int
    offense_count: int
    cdn_owned: bool | None

