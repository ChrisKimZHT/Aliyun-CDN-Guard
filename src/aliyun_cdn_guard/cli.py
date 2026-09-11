from __future__ import annotations

import argparse
import sys

from dotenv import load_dotenv
from loguru import logger

from . import __version__
from .config import ConfigError, load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Alibaba Cloud CDN anti-abuse guard")
    parser.add_argument("--config", default="config.yml", help="YAML configuration path")
    parser.add_argument("--env-file", default=".env", help="dotenv file for local development")
    parser.add_argument("--check-config", action="store_true", help="validate configuration and exit")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    load_dotenv(args.env_file, override=False)
    # The Alibaba Cloud credentials SDK reads and caches credential-related
    # environment variables when it is imported.  Import the application only
    # after loading dotenv so local credentials are visible to the SDK.
    from .app import run

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    logger.remove()
    logger.add(
        sys.stderr,
        level=config.log_level,
    )
    if args.check_config:
        print("configuration is valid")
        return
    logger.info("aliyun-cdn-guard version={}", __version__)
    try:
        run(config)
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("guard terminated unexpectedly")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
