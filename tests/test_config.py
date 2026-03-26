from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from cortex_xdr_mcp.config import CortexXdrConfig
from cortex_xdr_mcp.errors import ConfigError


class ConfigTests(unittest.TestCase):
    def test_from_env_loads_valid_config(self) -> None:
        with patch.dict(
            os.environ,
            {
                "CORTEX_XDR_BASE_URL": "https://example.test",
                "CORTEX_XDR_API_KEY": "secret",
                "CORTEX_XDR_API_KEY_ID": "7",
                "CORTEX_XDR_AUTH_MODE": "advanced",
                "CORTEX_XDR_TIMEOUT_SECONDS": "30",
                "CORTEX_XDR_VERIFY_TLS": "false",
            },
            clear=True,
        ):
            config = CortexXdrConfig.from_env()

        self.assertEqual(config.base_url, "https://example.test")
        self.assertEqual(config.auth_mode, "advanced")
        self.assertEqual(config.timeout_seconds, 30)
        self.assertFalse(config.verify_tls)

    def test_invalid_base_url_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            CortexXdrConfig(base_url="not-a-url", api_key="secret", api_key_id="7")

    def test_base_url_with_query_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            CortexXdrConfig(base_url="https://example.test?bad=1", api_key="secret", api_key_id="7")

    def test_base_url_with_path_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            CortexXdrConfig(base_url="https://example.test/api", api_key="secret", api_key_id="7")

    def test_non_positive_timeout_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="secret",
                api_key_id="7",
                timeout_seconds=0,
            )

    def test_invalid_auth_mode_is_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="secret",
                api_key_id="7",
                auth_mode="broken",
            )


if __name__ == "__main__":
    unittest.main()
