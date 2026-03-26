"""Minimal Cortex XDR HTTP client built on the Python standard library."""

from __future__ import annotations

import hashlib
import gzip
import json
import secrets
import ssl
import string
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from .config import CortexXdrConfig
from .errors import ApiError
from .logging_utils import get_logger, redact_secret


logger = get_logger(__name__)


@dataclass
class TransportResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


class Transport(Protocol):
    def send(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: int,
        verify_tls: bool,
    ) -> TransportResponse: ...


class UrllibTransport:
    """Default HTTP transport."""

    def send(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: int,
        verify_tls: bool,
    ) -> TransportResponse:
        request = urllib.request.Request(url=url, data=body, method=method.upper(), headers=headers)
        ssl_context = None
        if not verify_tls:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds, context=ssl_context) as response:
                response_body = response.read()
                return TransportResponse(
                    status_code=response.getcode(),
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body=response_body,
                )
        except urllib.error.HTTPError as exc:
            return TransportResponse(
                status_code=exc.code,
                headers={k.lower(): v for k, v in exc.headers.items()},
                body=exc.read(),
            )
        except urllib.error.URLError as exc:
            raise ApiError(f"Failed to reach Cortex XDR API: {exc.reason}") from exc


class CortexXdrClient:
    """Thin client that handles headers, gzip, and JSON parsing."""

    def __init__(self, config: CortexXdrConfig, transport: Transport | None = None) -> None:
        self._config = config
        self._transport = transport or UrllibTransport()
        self._resolved_auth_mode: str | None = None

    def get(self, path: str) -> Any:
        return self._request_json("GET", path, None)

    def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._request_json("POST", path, payload if payload is not None else {})

    def _request_json(self, method: str, path: str, payload: dict[str, Any] | None) -> Any:
        method = self._validate_method(method)
        self._validate_path(path)
        if payload is not None and not isinstance(payload, dict):
            raise ApiError("Cortex XDR request payload must be an object", method=method, path=path)

        url = f"{self._config.base_url}{path}"
        body = None
        if payload is not None:
            try:
                body = json.dumps(payload).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise ApiError(
                    "Failed to serialize Cortex XDR request payload as JSON",
                    method=method,
                    path=path,
                ) from exc

        last_error: ApiError | None = None
        candidate_auth_modes = self._candidate_auth_modes()
        for index, auth_mode in enumerate(candidate_auth_modes):
            request_started = time.monotonic()
            headers = self._build_headers(auth_mode)
            if payload is not None:
                headers["Content-Type"] = "application/json"

            logger.debug(
                "Calling Cortex XDR API: method=%s path=%s auth_mode=%s key_id=%s",
                method,
                path,
                auth_mode,
                redact_secret(self._config.api_key_id, visible_chars=2),
            )
            try:
                response = self._transport.send(
                    method=method,
                    url=url,
                    headers=headers,
                    body=body,
                    timeout_seconds=self._config.timeout_seconds,
                    verify_tls=self._config.verify_tls,
                )
            except ApiError:
                logger.exception("Cortex XDR transport raised an API error for %s %s", method, path)
                raise
            except Exception as exc:
                logger.exception("Unexpected transport failure for %s %s", method, path)
                raise ApiError(
                    f"Unexpected transport failure while calling Cortex XDR API: {exc}",
                    method=method,
                    path=path,
                ) from exc

            raw_body = response.body
            if response.headers.get("content-encoding") == "gzip":
                try:
                    raw_body = gzip.decompress(raw_body)
                except (OSError, EOFError) as exc:
                    raise ApiError(
                        "Failed to decompress Cortex XDR response body",
                        status_code=response.status_code,
                        method=method,
                        path=path,
                    ) from exc

            try:
                text = raw_body.decode("utf-8") if raw_body else ""
            except UnicodeDecodeError as exc:
                raise ApiError(
                    "Failed to decode Cortex XDR response body as UTF-8",
                    status_code=response.status_code,
                    method=method,
                    path=path,
                ) from exc

            try:
                parsed = json.loads(text) if text else None
            except json.JSONDecodeError:
                parsed = text

            if response.status_code < 400:
                if self._config.auth_mode == "auto":
                    if self._resolved_auth_mode != auth_mode:
                        logger.info("Resolved Cortex XDR auth mode to %s", auth_mode)
                    self._resolved_auth_mode = auth_mode
                logger.debug(
                    "Cortex XDR API call succeeded: method=%s path=%s status=%s elapsed=%.3fs",
                    method,
                    path,
                    response.status_code,
                    time.monotonic() - request_started,
                )
                return parsed

            message = f"Cortex XDR API request failed with status {response.status_code}"
            if isinstance(parsed, dict):
                if isinstance(parsed.get("reply"), dict):
                    reply = parsed["reply"]
                    err_msg = reply.get("err_msg", message)
                    err_extra = reply.get("err_extra")
                    if isinstance(err_extra, str) and err_extra.strip():
                        message = f"{err_msg} ({err_extra.strip()})"
                    else:
                        message = err_msg
                else:
                    for key in ("message", "error", "reply"):
                        value = parsed.get(key)
                        if isinstance(value, str) and value:
                            message = value
                            break
            elif isinstance(parsed, str) and parsed:
                message = parsed

            last_error = ApiError(
                message,
                status_code=response.status_code,
                payload=parsed,
                method=method,
                path=path,
            )
            if not (
                self._config.auth_mode == "auto"
                and response.status_code == 401
                and index < len(candidate_auth_modes) - 1
            ):
                logger.warning(
                    "Cortex XDR API call failed: method=%s path=%s status=%s elapsed=%.3fs message=%s",
                    method,
                    path,
                    response.status_code,
                    time.monotonic() - request_started,
                    message,
                )
                raise last_error
            logger.info(
                "Cortex XDR auth mode %s was rejected for %s %s; retrying with %s",
                auth_mode,
                method,
                path,
                candidate_auth_modes[index + 1],
            )

        if last_error is not None:
            raise last_error
        raise ApiError("Cortex XDR API request failed")

    def _validate_method(self, method: str) -> str:
        normalized = method.upper()
        if normalized not in {"GET", "POST"}:
            raise ApiError(f"Unsupported HTTP method: {method}")
        return normalized

    def _validate_path(self, path: str) -> None:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ApiError("Cortex XDR API path must start with '/'", path=path if isinstance(path, str) else None)

    def _candidate_auth_modes(self) -> list[str]:
        if self._config.auth_mode != "auto":
            return [self._config.auth_mode]
        if self._resolved_auth_mode is not None:
            return [self._resolved_auth_mode]
        return ["standard", "advanced"]

    def _build_headers(self, auth_mode: str) -> dict[str, str]:
        headers = {
            "Accept-Encoding": "gzip",
            "X-XDR-AUTH-ID": self._config.api_key_id,
        }
        if auth_mode == "standard":
            headers["Authorization"] = self._config.api_key
            return headers
        if auth_mode == "advanced":
            nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
            timestamp = str(int(time.time() * 1000))
            digest = hashlib.sha256(f"{self._config.api_key}{nonce}{timestamp}".encode("utf-8")).hexdigest()
            headers["Authorization"] = digest
            headers["X-XDR-NONCE"] = nonce
            headers["X-XDR-TIMESTAMP"] = timestamp
            return headers
        raise ApiError(f"Unsupported auth mode: {auth_mode}")

    @property
    def effective_auth_mode(self) -> str:
        return self._resolved_auth_mode or self._config.auth_mode
