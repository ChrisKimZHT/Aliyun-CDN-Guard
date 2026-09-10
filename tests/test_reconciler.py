from __future__ import annotations

from aliyun_cdn_guard.cdn import BlacklistReconciler
from aliyun_cdn_guard.models import AccessEvent
from aliyun_cdn_guard.storage import Storage

from conftest import make_config


class FakeGateway:
    def __init__(self, entries: set[str]):
        self.entries = entries
        self.updates: list[set[str]] = []

    def get_blacklist(self, domain: str) -> set[str]:
        return set(self.entries)

    def set_blacklist(self, domain: str, entries: set[str]) -> None:
        self.entries = set(entries)
        self.updates.append(set(entries))


def add_block(storage: Storage, now: int, ip: str) -> None:
    storage.record_and_maybe_block(
        AccessEvent(ip, now, "cdn.example.com", ip, "", "/"), "", "", 1, 60, 10, 2, 100, False, False, now
    )


def test_preserves_external_and_removes_only_owned_after_expiry(tmp_path):
    config = make_config(tmp_path, threshold=1)
    storage = Storage(config.storage_path)
    gateway = FakeGateway({"192.0.2.1"})
    add_block(storage, 100, "203.0.113.1")
    reconciler = BlacklistReconciler(config, storage, gateway)  # type: ignore[arg-type]
    reconciler.reconcile_domain("cdn.example.com", now=100)
    assert gateway.entries == {"192.0.2.1", "203.0.113.1"}
    assert storage.blocks_for_domain("cdn.example.com")[0].cdn_owned is True
    reconciler.reconcile_domain("cdn.example.com", now=111)
    assert gateway.entries == {"192.0.2.1"}


def test_preexisting_same_ip_is_not_removed(tmp_path):
    config = make_config(tmp_path, threshold=1)
    storage = Storage(config.storage_path)
    gateway = FakeGateway({"203.0.113.1"})
    add_block(storage, 100, "203.0.113.1")
    reconciler = BlacklistReconciler(config, storage, gateway)  # type: ignore[arg-type]
    reconciler.reconcile_domain("cdn.example.com", now=100)
    assert storage.blocks_for_domain("cdn.example.com")[0].cdn_owned is False
    reconciler.reconcile_domain("cdn.example.com", now=111)
    assert gateway.entries == {"203.0.113.1"}


def test_permanent_policy_ownership_survives_config_removal(tmp_path):
    original = make_config(tmp_path, threshold=1)
    config = original.__class__(
        **{**original.__dict__, "permanent_blocklist": {"cdn.example.com": ("203.0.113.9",)}}
    )
    storage = Storage(config.storage_path)
    gateway = FakeGateway(set())
    reconciler = BlacklistReconciler(config, storage, gateway)  # type: ignore[arg-type]
    reconciler.reconcile_domain("cdn.example.com", now=100)
    assert gateway.entries == {"203.0.113.9"}

    removed = config.__class__(**{**config.__dict__, "permanent_blocklist": {}})
    BlacklistReconciler(removed, storage, gateway).reconcile_domain("cdn.example.com", now=101)  # type: ignore[arg-type]
    assert gateway.entries == set()
