"""Configuration loading for Cortex XDR connectivity."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

from .errors import ConfigError


def _env_flag(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


@dataclass(frozen=True)
class CortexXdrConfig:
    base_url: str
    api_key: str
    api_key_id: str
    auth_mode: str = "auto"
    timeout_seconds: int = 60
    verify_tls: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url.strip():
            raise ConfigError("base_url must be a non-empty string")
        if not isinstance(self.api_key, str) or not self.api_key.strip():
            raise ConfigError("api_key must be a non-empty string")
        if not isinstance(self.api_key_id, str) or not self.api_key_id.strip():
            raise ConfigError("api_key_id must be a non-empty string")
        if self.auth_mode not in {"auto", "standard", "advanced"}:
            raise ConfigError("CORTEX_XDR_AUTH_MODE must be one of: auto, standard, advanced")
        if not isinstance(self.timeout_seconds, int) or self.timeout_seconds <= 0:
            raise ConfigError("CORTEX_XDR_TIMEOUT_SECONDS must be a positive integer")

        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ConfigError("CORTEX_XDR_BASE_URL must be a valid http(s) URL")
        if parsed.path not in {"", "/"} or parsed.params:
            raise ConfigError("CORTEX_XDR_BASE_URL must not include a path")
        if parsed.query or parsed.fragment:
            raise ConfigError("CORTEX_XDR_BASE_URL must not include a query string or fragment")

    @classmethod
    def from_env(cls) -> "CortexXdrConfig":
        base_url = os.getenv("CORTEX_XDR_BASE_URL", "").strip().rstrip("/")
        api_key = os.getenv("CORTEX_XDR_API_KEY", "").strip()
        api_key_id = os.getenv("CORTEX_XDR_API_KEY_ID", "").strip()
        auth_mode = os.getenv("CORTEX_XDR_AUTH_MODE", "auto").strip().lower()
        timeout_raw = os.getenv("CORTEX_XDR_TIMEOUT_SECONDS", "60").strip()

        missing = []
        if not base_url:
            missing.append("CORTEX_XDR_BASE_URL")
        if not api_key:
            missing.append("CORTEX_XDR_API_KEY")
        if not api_key_id:
            missing.append("CORTEX_XDR_API_KEY_ID")
        if missing:
            raise ConfigError(
                "Missing Cortex XDR configuration: " + ", ".join(missing)
            )

        try:
            timeout_seconds = int(timeout_raw)
        except ValueError as exc:
            raise ConfigError("CORTEX_XDR_TIMEOUT_SECONDS must be an integer") from exc
        return cls(
            base_url=base_url,
            api_key=api_key,
            api_key_id=api_key_id,
            auth_mode=auth_mode,
            timeout_seconds=timeout_seconds,
            verify_tls=_env_flag("CORTEX_XDR_VERIFY_TLS", True),
        )
