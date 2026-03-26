"""A small MCP tool server runtime over stdio."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from typing import Any, Callable

from .errors import ProtocolError, ToolInputError
from .helpers import dump_json
from .logging_utils import get_logger


ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]
SUPPORTED_PROTOCOL_VERSION = "2024-11-05"
logger = get_logger(__name__)


@dataclass
class ToolDefinition:
    name: str
    description: str
    input_schema: dict[str, Any]
    handler: ToolHandler

    def descriptor(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class McpToolServer:
    """Minimal MCP server supporting initialize, ping, tools/list, and tools/call."""

    def __init__(self, *, name: str, version: str, instructions: str, tools: list[ToolDefinition]) -> None:
        self.name = name
        self.version = version
        self.instructions = instructions
        self.tools = {tool.name: tool for tool in tools}

    def run_stdio(self) -> None:
        logger.info("Starting MCP server %s version=%s tools=%s", self.name, self.version, len(self.tools))
        while True:
            try:
                message = self._read_message()
            except EOFError:
                logger.info("Stopping MCP server %s after EOF", self.name)
                return
            except Exception as exc:  # pragma: no cover - fatal framing issue
                logger.exception("Fatal MCP framing error in server %s", self.name)
                self._write_error(None, -32700, f"Parse error: {exc}")
                return

            if not isinstance(message, dict):
                logger.warning("Received non-object MCP message: %r", message)
                self._write_error(None, -32600, "Request must be a JSON object")
                continue

            if "id" not in message:
                self._handle_notification(message)
                continue

            request_id = message["id"]
            try:
                result = self._dispatch(message)
            except ProtocolError as exc:
                logger.warning("Protocol error for request %r: %s", request_id, exc)
                self._write_error(request_id, -32600, str(exc))
                continue
            except Exception as exc:  # pragma: no cover - unexpected errors
                logger.exception("Unexpected MCP runtime error for request %r", request_id)
                self._write_error(request_id, -32603, str(exc))
                continue

            self._write_message({"jsonrpc": "2.0", "id": request_id, "result": result})

    def _dispatch(self, message: dict[str, Any]) -> dict[str, Any]:
        method = message.get("method")
        if not isinstance(method, str) or not method:
            raise ProtocolError("Request method must be a non-empty string")
        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            raise ProtocolError("Request params must be an object")

        if method == "initialize":
            requested_version = params.get("protocolVersion")
            if isinstance(requested_version, str) and requested_version != SUPPORTED_PROTOCOL_VERSION:
                logger.warning(
                    "Client requested protocol version %s; responding with %s",
                    requested_version,
                    SUPPORTED_PROTOCOL_VERSION,
                )
            return {
                "protocolVersion": SUPPORTED_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.name, "version": self.version},
                "instructions": self.instructions,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [tool.descriptor() for tool in self.tools.values()]}
        if method == "tools/call":
            return self._call_tool(params)

        raise ProtocolError(f"Unsupported method: {method}")

    def _call_tool(self, params: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise ProtocolError("tools/call params must be an object")

        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ProtocolError("tools/call requires a tool name")
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise ProtocolError("tools/call arguments must be an object")

        tool = self.tools.get(name)
        if tool is None:
            raise ProtocolError(f"Unknown tool: {name}")

        started = time.monotonic()
        try:
            result = tool.handler(arguments)
            logger.info(
                "Tool call succeeded: server=%s tool=%s elapsed=%.3fs",
                self.name,
                name,
                time.monotonic() - started,
            )
            return self._tool_result(result, is_error=False)
        except ToolInputError as exc:
            logger.warning(
                "Tool input error: server=%s tool=%s elapsed=%.3fs error=%s",
                self.name,
                name,
                time.monotonic() - started,
                exc,
            )
            payload = {"error": str(exc), "tool": name}
            return self._tool_result(payload, is_error=True)
        except Exception as exc:
            logger.exception(
                "Unhandled tool exception: server=%s tool=%s elapsed=%.3fs",
                self.name,
                name,
                time.monotonic() - started,
            )
            payload = {"error": str(exc), "tool": name}
            return self._tool_result(payload, is_error=True)

    def _tool_result(self, payload: dict[str, Any], *, is_error: bool) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": dump_json(payload)}],
            "structuredContent": payload,
            "isError": is_error,
        }

    def _handle_notification(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        if method in {"notifications/initialized", "initialized"}:
            return

    def _read_message(self) -> dict[str, Any] | None:
        headers: dict[str, str] = {}
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                raise EOFError
            if line in {b"\r\n", b"\n"}:
                break
            key, sep, value = line.decode("utf-8").partition(":")
            if not sep:
                raise ProtocolError("Invalid message header")
            headers[key.strip().lower()] = value.strip()

        if "content-length" not in headers:
            raise ProtocolError("Missing Content-Length header")

        try:
            content_length = int(headers["content-length"])
        except ValueError as exc:
            raise ProtocolError("Invalid Content-Length header") from exc
        if content_length <= 0:
            raise ProtocolError("Content-Length must be a positive integer")
        body = self._read_exactly(content_length)
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ProtocolError(f"Invalid JSON body: {exc}") from exc

    def _read_exactly(self, content_length: int) -> bytes:
        remaining = content_length
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = sys.stdin.buffer.read(remaining)
            if not chunk:
                if not chunks:
                    raise EOFError
                raise ProtocolError("Unexpected EOF while reading message body")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _write_error(self, request_id: Any, code: int, message: str) -> None:
        self._write_message(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        )

    def _write_message(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
        sys.stdout.buffer.write(header)
        sys.stdout.buffer.write(body)
        sys.stdout.buffer.flush()
