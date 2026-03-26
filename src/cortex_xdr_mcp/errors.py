"""Shared exception types."""

from __future__ import annotations


class CortexXdrMcpError(Exception):
    """Base error for the project."""


class ConfigError(CortexXdrMcpError):
    """Raised when required configuration is missing or invalid."""


class ApiError(CortexXdrMcpError):
    """Raised when the Cortex XDR API returns an error."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        payload: object | None = None,
        method: str | None = None,
        path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload
        self.method = method
        self.path = path


class ToolInputError(CortexXdrMcpError):
    """Raised when a tool call contains invalid input."""


class ProtocolError(CortexXdrMcpError):
    """Raised when an MCP protocol message is invalid."""
