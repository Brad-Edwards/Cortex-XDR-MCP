from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from cortex_xdr_mcp.errors import ProtocolError, ToolInputError
from cortex_xdr_mcp.mcp_runtime import McpToolServer, SUPPORTED_PROTOCOL_VERSION, ToolDefinition


def _raise_input_error(_: dict[str, object]) -> dict[str, object]:
    raise ToolInputError("bad tool input")


def _raise_runtime_error(_: dict[str, object]) -> dict[str, object]:
    raise RuntimeError("boom")


class _FakeStdin:
    def __init__(self, payload: bytes) -> None:
        self.buffer = io.BytesIO(payload)


class _ChunkedBuffer:
    def __init__(self, payload: bytes, *, chunk_size: int) -> None:
        self._stream = io.BytesIO(payload)
        self._chunk_size = chunk_size

    def readline(self, *args: object) -> bytes:
        return self._stream.readline(*args)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = self._chunk_size
        return self._stream.read(min(size, self._chunk_size))


class _ChunkedStdin:
    def __init__(self, payload: bytes, *, chunk_size: int) -> None:
        self.buffer = _ChunkedBuffer(payload, chunk_size=chunk_size)


class McpRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = McpToolServer(
            name="test-server",
            version="1.0.0",
            instructions="Use the tools.",
            tools=[
                ToolDefinition(
                    name="echo",
                    description="Echo input.",
                    input_schema={"type": "object"},
                    handler=lambda arguments: {"echo": arguments},
                ),
                ToolDefinition(
                    name="input_error",
                    description="Raise ToolInputError.",
                    input_schema={"type": "object"},
                    handler=_raise_input_error,
                ),
                ToolDefinition(
                    name="explode",
                    description="Raise RuntimeError.",
                    input_schema={"type": "object"},
                    handler=_raise_runtime_error,
                ),
            ],
        )

    def test_initialize_returns_supported_protocol_version(self) -> None:
        result = self.server._dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-01-01"},
            }
        )

        self.assertEqual(result["protocolVersion"], SUPPORTED_PROTOCOL_VERSION)
        self.assertEqual(result["serverInfo"]["name"], "test-server")

    def test_dispatch_rejects_non_object_params(self) -> None:
        with self.assertRaises(ProtocolError):
            self.server._dispatch({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []})

    def test_tool_call_wraps_tool_input_error(self) -> None:
        result = self.server._call_tool({"name": "input_error", "arguments": {}})

        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["error"], "bad tool input")

    def test_tool_call_wraps_unexpected_exception(self) -> None:
        result = self.server._call_tool({"name": "explode", "arguments": {}})

        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["error"], "boom")

    def test_read_message_rejects_invalid_content_length(self) -> None:
        payload = b"Content-Length: nope\r\n\r\n{}"
        with patch("sys.stdin", _FakeStdin(payload)):
            with self.assertRaises(ProtocolError):
                self.server._read_message()

    def test_read_message_handles_fragmented_body_reads(self) -> None:
        body = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
        payload = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8") + body
        with patch("sys.stdin", _ChunkedStdin(payload, chunk_size=5)):
            message = self.server._read_message()

        self.assertEqual(message["method"], "ping")


if __name__ == "__main__":
    unittest.main()
