from __future__ import annotations

import json
import unittest

from cortex_xdr_mcp.client import CortexXdrClient, TransportResponse
from cortex_xdr_mcp.config import CortexXdrConfig
from cortex_xdr_mcp.errors import ApiError


class RecordingTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, *, method, url, headers, body, timeout_seconds, verify_tls):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "body": body,
                "timeout_seconds": timeout_seconds,
                "verify_tls": verify_tls,
            }
        )
        return self.responses.pop(0)


class ExplodingTransport:
    def send(self, **_: object) -> TransportResponse:
        raise RuntimeError("socket exploded")


class ClientAuthTests(unittest.TestCase):
    def test_standard_mode_uses_plain_headers(self) -> None:
        transport = RecordingTransport(
            [
                TransportResponse(
                    status_code=200,
                    headers={},
                    body=json.dumps({"status": "available"}).encode("utf-8"),
                )
            ]
        )
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="standard",
            ),
            transport=transport,
        )

        client.get("/public_api/v1/healthcheck")

        headers = transport.calls[0]["headers"]
        self.assertEqual(headers["Authorization"], "plain-key")
        self.assertEqual(headers["X-XDR-AUTH-ID"], "7")
        self.assertNotIn("X-XDR-NONCE", headers)
        self.assertNotIn("X-XDR-TIMESTAMP", headers)

    def test_auto_mode_falls_back_to_advanced_and_caches_it(self) -> None:
        transport = RecordingTransport(
            [
                TransportResponse(
                    status_code=401,
                    headers={},
                    body=json.dumps({"reply": {"err_msg": "Public API request unauthorized"}}).encode("utf-8"),
                ),
                TransportResponse(
                    status_code=200,
                    headers={},
                    body=json.dumps({"status": "available"}).encode("utf-8"),
                ),
                TransportResponse(
                    status_code=200,
                    headers={},
                    body=json.dumps({"status": "available"}).encode("utf-8"),
                ),
            ]
        )
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="auto",
            ),
            transport=transport,
        )

        client.get("/public_api/v1/healthcheck")
        client.get("/public_api/v1/healthcheck")

        self.assertEqual(len(transport.calls), 3)
        self.assertNotIn("X-XDR-NONCE", transport.calls[0]["headers"])
        self.assertIn("X-XDR-NONCE", transport.calls[1]["headers"])
        self.assertIn("X-XDR-TIMESTAMP", transport.calls[1]["headers"])
        self.assertIn("X-XDR-NONCE", transport.calls[2]["headers"])
        self.assertNotEqual(transport.calls[1]["headers"]["Authorization"], "plain-key")

    def test_client_includes_err_extra_in_api_error_message(self) -> None:
        transport = RecordingTransport(
            [
                TransportResponse(
                    status_code=403,
                    headers={},
                    body=json.dumps(
                        {
                            "reply": {
                                "err_msg": "Forbidden. Access was denied to this resource.",
                                "err_extra": "Insufficient permissions for api key",
                            }
                        }
                    ).encode("utf-8"),
                )
            ]
        )
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="advanced",
            ),
            transport=transport,
        )

        with self.assertRaises(ApiError) as raised:
            client.post("/public_api/v1/endpoints/get_endpoint", {"request_data": {"search_from": 0, "search_to": 1}})

        self.assertIn("Insufficient permissions for api key", str(raised.exception))

    def test_client_rejects_invalid_api_path(self) -> None:
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
            ),
            transport=RecordingTransport([]),
        )

        with self.assertRaises(ApiError) as raised:
            client.get("public_api/v1/healthcheck")

        self.assertIn("must start with '/'", str(raised.exception))

    def test_client_wraps_unexpected_transport_errors(self) -> None:
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="advanced",
            ),
            transport=ExplodingTransport(),
        )

        with self.assertRaises(ApiError) as raised:
            client.get("/public_api/v1/healthcheck")

        self.assertIn("Unexpected transport failure", str(raised.exception))
        self.assertEqual(raised.exception.path, "/public_api/v1/healthcheck")

    def test_client_surfaces_gzip_decode_failures(self) -> None:
        transport = RecordingTransport(
            [
                TransportResponse(
                    status_code=200,
                    headers={"content-encoding": "gzip"},
                    body=b"not-gzip",
                )
            ]
        )
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="advanced",
            ),
            transport=transport,
        )

        with self.assertRaises(ApiError) as raised:
            client.get("/public_api/v1/healthcheck")

        self.assertIn("decompress", str(raised.exception).lower())

    def test_client_rejects_unserializable_payloads(self) -> None:
        client = CortexXdrClient(
            CortexXdrConfig(
                base_url="https://example.test",
                api_key="plain-key",
                api_key_id="7",
                auth_mode="advanced",
            ),
            transport=RecordingTransport([]),
        )

        with self.assertRaises(ApiError) as raised:
            client.post("/public_api/v1/xql/start_xql_query", {"bad": object()})  # type: ignore[arg-type]

        self.assertIn("serialize", str(raised.exception).lower())


if __name__ == "__main__":
    unittest.main()
