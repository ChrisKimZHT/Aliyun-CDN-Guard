from pathlib import Path

import pytest

from aliyun_cdn_guard.config import ConfigError, load_config


def test_example_config_is_valid():
    config = load_config(Path(__file__).parents[1] / "config.example.yml")
    assert config.detection.threshold == 1000
    assert config.detection.uri.query_mode == "keep"
    assert config.cdn.dry_run is True
    assert config.cdn.ip_acl_xfwd == "on"


def test_rejects_retention_shorter_than_window(tmp_path):
    path = tmp_path / "bad.yml"
    path.write_text(
        "sls: {endpoint: x, region: r, project: p, logstore: l}\n"
        "cdn: {region: r, domains: [d]}\n"
        "detection: {threshold: 1, window_seconds: 60, retention_seconds: 10}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(path)
