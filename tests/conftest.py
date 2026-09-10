from __future__ import annotations

from pathlib import Path

from aliyun_cdn_guard.config import (
    AppConfig,
    CdnConfig,
    DetectionConfig,
    DimensionConfig,
    PenaltyConfig,
    SlsConfig,
    UriConfig,
    WhitelistConfig,
)


def make_config(tmp_path: Path, **detection_overrides: object) -> AppConfig:
    detection = DetectionConfig(
        threshold=int(detection_overrides.get("threshold", 3)),
        window_seconds=int(detection_overrides.get("window_seconds", 60)),
        retention_seconds=3600,
        ua=detection_overrides.get("ua", DimensionConfig()) ,  # type: ignore[arg-type]
        uri=detection_overrides.get("uri", UriConfig()),  # type: ignore[arg-type]
    )
    return AppConfig(
        sls=SlsConfig("https://cn-test.log.aliyuncs.com", "cn-test", "project", "logstore"),
        cdn=CdnConfig("cn-test", "cdn.aliyuncs.com", ("cdn.example.com",), dry_run=False),
        detection=detection,
        penalty=PenaltyConfig(10, 2.0, 100),
        whitelist=detection_overrides.get("whitelist", WhitelistConfig()),  # type: ignore[arg-type]
        storage_path=tmp_path / "guard.db",
    )
