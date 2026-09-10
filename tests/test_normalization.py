from aliyun_cdn_guard.config import UriConfig
from aliyun_cdn_guard.normalization import normalize_uri


def test_keep_query_from_uri():
    assert normalize_uri("/asset?a=1&b=2", "", UriConfig(query_mode="keep")) == "/asset?a=1&b=2"


def test_ignore_all_query():
    assert normalize_uri("/asset?a=1", "", UriConfig(query_mode="ignore_all")) == "/asset"


def test_ignore_selected_query_from_separate_field():
    config = UriConfig(query_mode="ignore_selected", ignored_names=frozenset({"token"}))
    assert normalize_uri("/asset", "token=secret&size=large", config) == "/asset?size=large"

