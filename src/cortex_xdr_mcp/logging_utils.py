"""Logging helpers for Cortex XDR MCP."""

from __future__ import annotations

import logging
import os
import sys


_DEFAULT_LEVEL = "INFO"
_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"
_PACKAGE_LOGGER_NAME = "cortex_xdr_mcp"
_PACKAGE_LOGGER = logging.getLogger(_PACKAGE_LOGGER_NAME)
if not _PACKAGE_LOGGER.handlers:
    _PACKAGE_LOGGER.addHandler(logging.NullHandler())
_PACKAGE_LOGGER.propagate = False


def configure_logging() -> None:
    """Configure stderr logging once for CLI and MCP entrypoints."""

    raw_level = os.getenv("CORTEX_XDR_MCP_LOG_LEVEL", _DEFAULT_LEVEL).strip().upper()
    level = getattr(logging, raw_level, None)
    invalid_level = not isinstance(level, int)
    if invalid_level:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    _PACKAGE_LOGGER.handlers = [handler]
    _PACKAGE_LOGGER.setLevel(level)
    _PACKAGE_LOGGER.propagate = False
    if invalid_level:
        _PACKAGE_LOGGER.warning(
            "Invalid CORTEX_XDR_MCP_LOG_LEVEL=%r; defaulting to %s",
            raw_level,
            _DEFAULT_LEVEL,
        )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def redact_secret(value: str, *, visible_chars: int = 4) -> str:
    if not value:
        return "<empty>"
    if len(value) <= visible_chars * 2:
        return "*" * len(value)
    return f"{value[:visible_chars]}...{value[-visible_chars:]}"
