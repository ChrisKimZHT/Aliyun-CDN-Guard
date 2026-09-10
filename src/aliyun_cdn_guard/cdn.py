from __future__ import annotations

import json
import logging
import threading
import time

from alibabacloud_cdn20180510 import models as cdn_models
from alibabacloud_cdn20180510.client import Client as CdnClient
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_tea_openapi import models as open_api_models

from .config import AppConfig
from .storage import Storage

logger = logging.getLogger(__name__)


class CdnGateway:
    def __init__(self, config: AppConfig, credential_client: CredentialClient):
        api_config = open_api_models.Config(
            credential=credential_client,
            region_id=config.cdn.region,
            endpoint=config.cdn.endpoint,
        )
        self.client = CdnClient(api_config)
        self.ip_acl_xfwd = config.cdn.ip_acl_xfwd

    def get_blacklist(self, domain: str) -> set[str]:
        request = cdn_models.DescribeCdnDomainConfigsRequest(
            domain_name=domain,
            function_names="ip_black_list_set",
        )
        response = self.client.describe_cdn_domain_configs(request)
        configs = getattr(getattr(response.body, "domain_configs", None), "domain_config", None) or []
        for item in configs:
            if item.function_name != "ip_black_list_set":
                continue
            args = getattr(getattr(item, "function_args", None), "function_arg", None) or []
            for argument in args:
                if argument.arg_name == "ip_list":
                    return {value.strip() for value in (argument.arg_value or "").split(",") if value.strip()}
        return set()

    def set_blacklist(self, domain: str, entries: set[str]) -> None:
        ipv4_count = 0
        ipv6_count = 0
        for entry in entries:
            if ":" in entry:
                ipv6_count += 1
            else:
                ipv4_count += 1
        serialized = ",".join(sorted(entries))
        if ipv4_count > 2000 or ipv6_count > 700 or len(serialized.encode("utf-8")) > 30_000:
            raise ValueError(
                f"CDN blacklist limit exceeded for {domain}: IPv4={ipv4_count}, IPv6={ipv6_count}, bytes={len(serialized.encode('utf-8'))}"
            )
        functions = json.dumps(
            [{"functionName": "ip_black_list_set", "functionArgs": [
                {"argName": "ip_list", "argValue": serialized},
                {"argName": "ip_acl_xfwd", "argValue": self.ip_acl_xfwd},
            ]}],
            separators=(",", ":"),
        )
        self.client.batch_set_cdn_domain_config(
            cdn_models.BatchSetCdnDomainConfigRequest(domain_names=domain, functions=functions)
        )


class BlacklistReconciler:
    def __init__(self, config: AppConfig, storage: Storage, gateway: CdnGateway):
        self.config = config
        self.storage = storage
        self.gateway = gateway
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="cdn-reconciler", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(5, self.config.cdn.sync_interval_seconds + 1))

    def _run(self) -> None:
        while not self._stop.is_set():
            for domain in self.config.cdn.domains:
                if self._stop.is_set():
                    return
                try:
                    self.reconcile_domain(domain)
                except Exception:
                    logger.exception("failed to reconcile CDN blacklist for %s", domain)
                self._stop.wait(0.35)  # CDN API limit is 3 requests/second per account.
            self._stop.wait(self.config.cdn.sync_interval_seconds)

    def reconcile_domain(self, domain: str, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        records = self.storage.blocks_for_domain(domain)
        permanent = set(self.config.permanent_blocklist.get(domain, ()))
        self.storage.sync_permanent_policy(domain, permanent)
        permanent_state = self.storage.permanent_for_domain(domain)

        if self.config.cdn.dry_run:
            desired = permanent | {record.client_ip for record in records if record.blocked_until > now}
            logger.info("dry-run CDN blacklist domain=%s desired_managed=%s", domain, sorted(desired))
            return

        current = self.gateway.get_blacklist(domain)
        desired = set(current)
        ownership: dict[str, bool] = {}
        permanent_ownership: dict[str, bool] = {}

        for record in records:
            if record.blocked_until > now:
                if record.cdn_owned is None:
                    ownership[record.client_ip] = record.client_ip not in current
                if record.cdn_owned is True or ownership.get(record.client_ip) is True:
                    desired.add(record.client_ip)
            elif record.cdn_owned is True:
                desired.discard(record.client_ip)

        for entry, owned in permanent_state.items():
            if entry in permanent:
                if owned is None:
                    permanent_ownership[entry] = entry not in current
                if owned is True or permanent_ownership.get(entry) is True:
                    desired.add(entry)
            elif owned is True:
                desired.discard(entry)
        if desired != current:
            self.gateway.set_blacklist(domain, desired)
            logger.info("updated CDN blacklist domain=%s entries=%d", domain, len(desired))
        if ownership:
            self.storage.set_ownership(domain, ownership)
        if permanent_ownership:
            self.storage.set_permanent_ownership(domain, permanent_ownership)
        removed_policy = set(permanent_state) - permanent
        if removed_policy:
            self.storage.delete_permanent_records(domain, removed_policy)
