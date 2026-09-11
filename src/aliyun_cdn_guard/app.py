from __future__ import annotations

import os
import signal
import socket
import threading
import time

from alibabacloud_credentials.client import Client as CredentialClient
from aliyun.log.consumer import ConsumerWorker, CursorPosition, LogHubConfig
from loguru import logger

from .block_log import BlockLog
from .cdn import BlacklistReconciler, CdnGateway
from .config import AppConfig
from .consumer import LogProcessor
from .credentials import SlsCredentialProvider
from .detector import Detector
from .storage import Storage


def run(config: AppConfig) -> None:
    storage = Storage(config.storage_path)
    detector = Detector(config, storage, BlockLog(config.block_log_path, dry_run=config.cdn.dry_run))
    credential_client = CredentialClient()
    initial = credential_client.get_credential()
    provider = SlsCredentialProvider(credential_client)
    consumer_name = config.sls.consumer_name or f"{socket.gethostname()}-{os.getpid()}"
    cursor = {
        "end": CursorPosition.END_CURSOR,
        "begin": CursorPosition.BEGIN_CURSOR,
    }.get(config.sls.cursor_position, CursorPosition.SPECIAL_TIMER_CURSOR)
    options = LogHubConfig(
        config.sls.endpoint,
        initial.access_key_id,
        initial.access_key_secret,
        config.sls.project,
        config.sls.logstore,
        config.sls.consumer_group,
        consumer_name,
        cursor_position=cursor,
        cursor_start_time=config.sls.cursor_position if cursor == CursorPosition.SPECIAL_TIMER_CURSOR else None,
        security_token=initial.security_token,
        data_fetch_interval=config.sls.fetch_interval_seconds,
        credentials_refresher=provider,
        region=config.sls.region,
    )
    worker = ConsumerWorker(LogProcessor, consumer_option=options, args=(detector,))
    reconciler = BlacklistReconciler(config, storage, CdnGateway(config, credential_client))
    stop_event = threading.Event()

    def request_stop(signum: int, _frame: object) -> None:
        logger.info("received signal={}, shutting down", signum)
        stop_event.set()

    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_stop)

    try:
        reconciler.start()
        worker.start()
        logger.info("guard started, consumer={}, dry_run={}", consumer_name, config.cdn.dry_run)
        while not stop_event.wait(30):
            deleted = detector.prune()
            if deleted:
                logger.debug("pruned {} old events", deleted)
    finally:
        worker.shutdown()
        reconciler.stop()
        storage.close()
        logger.info("guard stopped")
