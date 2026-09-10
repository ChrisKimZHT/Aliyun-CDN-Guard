from __future__ import annotations

import ipaddress
import re

from aliyun_cdn_guard.config import DimensionConfig, UriConfig, WhitelistConfig
from aliyun_cdn_guard.detector import Detector
from aliyun_cdn_guard.models import AccessEvent
from aliyun_cdn_guard.storage import Storage

from conftest import make_config


def event(event_id: str, timestamp: int, ip: str = "203.0.113.10", ua: str = "agent", uri: str = "/x") -> AccessEvent:
    return AccessEvent(event_id, timestamp, "cdn.example.com", ip, ua, uri)


def test_ip_only_threshold_and_replay_deduplication(tmp_path):
    config = make_config(tmp_path)
    detector = Detector(config, Storage(config.storage_path))
    assert detector.process(event("1", 100), now=100) is None
    assert detector.process(event("1", 100), now=100) is None
    assert detector.process(event("2", 101, ua="other", uri="/y"), now=101) is None
    decision = detector.process(event("3", 102), now=102)
    assert decision is not None
    assert decision.count == 3
    assert decision.blocked_until == 112


def test_ua_and_uri_are_joint_dimensions(tmp_path):
    config = make_config(tmp_path, ua=DimensionConfig(True), uri=UriConfig(True, query_mode="ignore_all"))
    detector = Detector(config, Storage(config.storage_path))
    detector.process(event("1", 100, ua="a", uri="/x?p=1"), now=100)
    detector.process(event("2", 101, ua="b", uri="/x?p=2"), now=101)
    detector.process(event("3", 102, ua="a", uri="/y"), now=102)
    assert detector.process(event("4", 103, ua="a", uri="/x?p=9"), now=103) is None
    assert detector.process(event("5", 104, ua="a", uri="/x?p=8"), now=104) is not None


def test_regex_filter_and_any_whitelist_match_skip_recording(tmp_path):
    whitelist = WhitelistConfig(
        ip_networks=(ipaddress.ip_network("198.51.100.0/24"),),
        ua_regexes=(re.compile("TrustedBot"),),
        uri_regexes=(re.compile(r"^/health$"),),
    )
    config = make_config(tmp_path, threshold=1, ua=DimensionConfig(True, re.compile("BadBot")), whitelist=whitelist)
    detector = Detector(config, Storage(config.storage_path))
    assert detector.process(event("1", 100, ua="Browser"), now=100) is None
    assert detector.process(event("2", 100, ip="198.51.100.1", ua="BadBot"), now=100) is None
    assert detector.process(event("3", 100, ua="TrustedBot BadBot"), now=100) is None
    assert detector.process(event("4", 100, ua="BadBot", uri="/health"), now=100) is None
    assert detector.process(event("5", 100, ua="BadBot"), now=100) is not None


def test_penalty_multiplier_applies_after_expiry(tmp_path):
    config = make_config(tmp_path, threshold=1)
    detector = Detector(config, Storage(config.storage_path))
    first = detector.process(event("1", 100), now=100)
    second = detector.process(event("2", 111), now=111)
    assert first and first.blocked_until == 110
    assert second and second.offense_count == 2 and second.blocked_until == 131

