"""Alibaba Cloud CDN anti-abuse guard."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("aliyun-cdn-guard")
except PackageNotFoundError:
    # The distribution metadata is unavailable when importing directly from an
    # unpacked source tree that has not been installed.
    __version__ = "0+unknown"
