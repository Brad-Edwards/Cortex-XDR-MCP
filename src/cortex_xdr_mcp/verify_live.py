"""Live MCP smoke verification helpers."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from .client import CortexXdrClient
from .config import CortexXdrConfig
from .errors import ApiError
from .helpers import dump_json
from .logging_utils import configure_logging, get_logger


DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_TOOL_TIMEOUT_SECONDS = 45
DEFAULT_XQL_WAIT_SECONDS = 15
logger = get_logger(__name__)


@dataclass(frozen=True)
class ToolSpecHint:
    api_paths: tuple[str, ...]
    required_license: str | None = None
    required_permission: str | None = None
    note: str | None = None


SPEC_HINTS: dict[tuple[str, str], ToolSpecHint] = {
    (
        "investigate",
        "search_endpoints",
    ): ToolSpecHint(
        api_paths=(
            "/public_api/v1/endpoints/get_endpoint",
            "/public_api/v1/endpoints/get_endpoints",
        ),
        required_license="Cortex XDR Prevent or Cortex XDR Pro per Endpoint",
        note="Both raw endpoint lookup APIs returned 403 during live checks, so this does not look like a bad filter payload.",
    ),
    (
        "investigate",
        "list_risky_entities",
    ): ToolSpecHint(
        api_paths=(
            "/public_api/v1/get_risky_hosts",
            "/public_api/v1/get_risky_users",
        ),
        required_license="Identity Threat Module",
        note="The spec marks risky host and risky user APIs as Identity Threat Module features.",
    ),
    (
        "investigate",
        "get_entity_risk",
    ): ToolSpecHint(
        api_paths=("/public_api/v1/get_risk_score",),
        required_license="Identity Threat Module",
    ),
    (
        "engineer",
        "list_profiles",
    ): ToolSpecHint(
        api_paths=("/public_api/v1/endpoints/get_profiles",),
        required_permission="profiles_view",
        note="The spec also lists two non-RBAC causes for 403 here: disabled feature flag ALPHAFEATURES_PUBLIC_API_GET_POLICIES or a secondary HA replica tenant.",
    ),
    (
        "engineer",
        "manage_agent_packages",
    ): ToolSpecHint(
        api_paths=("/public_api/v1/distributions/get_distributions",),
        required_license="Cortex XDR Prevent or Cortex XDR Pro per Endpoint",
        note="Distribution listing is documented under Endpoint Management APIs.",
    ),
    (
        "engineer",
        "list_device_control_violations",
    ): ToolSpecHint(
        api_paths=("/public_api/v1/device_control/get_violations",),
        required_license="Cortex XDR Prevent or Cortex XDR Pro per Endpoint",
        note="This is another Endpoint Management API, so repeated 403s alongside endpoint search usually point at the same access boundary.",
    ),
    (
        "admin",
        "list_rbac_roles",
    ): ToolSpecHint(
        api_paths=("/public_api/v1/rbac/get_roles",),
        required_license="Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB",
        note="A 403 here means the key cannot read RBAC data over the public API even if tenant info is accessible.",
    ),
}


@dataclass
class CheckResult:
    server: str
    tool: str
    status: str
    elapsed_seconds: float
    category: str
    details: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    hint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run_with_deadline(fn: object, deadline: float, timeout_msg: str) -> object:
    """Execute a blocking callable with a deadline using a daemon thread."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(timeout_msg)
    result: list[object] = [None]
    error: list[BaseException | None] = [None]

    def worker() -> None:
        try:
            result[0] = fn()  # type: ignore[operator]
        except Exception as exc:
            error[0] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout=remaining)
    if thread.is_alive():
        raise TimeoutError(timeout_msg)
    if error[0] is not None:
        raise error[0]
    return result[0]


def _readline_with_deadline(stream: object, deadline: float) -> bytes:
    def _read() -> bytes:
        line = stream.readline()  # type: ignore[union-attr]
        if not line:
            raise RuntimeError("Unexpected EOF while reading MCP response headers")
        return line  # type: ignore[return-value]

    return _run_with_deadline(_read, deadline, "Timed out while waiting for MCP response headers")  # type: ignore[return-value]


def _readexact_with_deadline(stream: object, length: int, deadline: float) -> bytes:
    def _read() -> bytes:
        chunks: list[bytes] = []
        remaining_bytes = length
        while remaining_bytes > 0:
            chunk = stream.read(remaining_bytes)  # type: ignore[union-attr]
            if not chunk:
                raise RuntimeError("Unexpected EOF while reading MCP response body")
            chunks.append(chunk)
            remaining_bytes -= len(chunk)
        return b"".join(chunks)

    return _run_with_deadline(_read, deadline, "Timed out while waiting for MCP response body")  # type: ignore[return-value]


def _send_message(proc: subprocess.Popen[bytes], payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("utf-8")
    if proc.stdin is None:
        raise RuntimeError("MCP child process has no stdin pipe")
    proc.stdin.write(header)
    proc.stdin.write(body)
    proc.stdin.flush()


def _recv_message(proc: subprocess.Popen[bytes], timeout_seconds: int) -> dict[str, Any]:
    if proc.stdout is None:
        raise RuntimeError("MCP child process has no stdout pipe")
    stream = proc.stdout
    deadline = time.monotonic() + timeout_seconds
    headers: dict[str, str] = {}
    while True:
        line = _readline_with_deadline(stream, deadline)
        if line in (b"\r\n", b"\n"):
            break
        key, separator, value = line.decode("utf-8").partition(":")
        if not separator:
            raise RuntimeError("Invalid MCP message header")
        headers[key.strip().lower()] = value.strip()
    if "content-length" not in headers:
        raise RuntimeError("MCP response is missing Content-Length")
    body = _readexact_with_deadline(stream, int(headers["content-length"]), deadline)
    return json.loads(body.decode("utf-8"))


def _rpc(
    proc: subprocess.Popen[bytes],
    request_id: int,
    method: str,
    params: dict[str, Any] | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    _send_message(proc, payload)
    return _recv_message(proc, timeout_seconds)


def _call_mcp_tool(
    *,
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    timeout_seconds: int,
) -> dict[str, Any]:
    logger.debug("Launching MCP smoke check: server=%s tool=%s", server_name, tool_name)
    proc = subprocess.Popen(
        [sys.executable, "-m", "cortex_xdr_mcp", server_name],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=os.environ.copy(),
    )
    try:
        _rpc(
            proc,
            1,
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "cortex-xdr-verify-live", "version": "0.1"},
            },
            min(timeout_seconds, 5),
        )
        _send_message(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        listed = _rpc(proc, 2, "tools/list", {}, min(timeout_seconds, 5))
        tools = listed.get("result", {}).get("tools", [])
        if tool_name not in {tool.get("name") for tool in tools if isinstance(tool, dict)}:
            raise RuntimeError(f"Tool {server_name}.{tool_name} is not exposed by the MCP server")
        result = _rpc(proc, 3, "tools/call", {"name": tool_name, "arguments": arguments}, timeout_seconds)
        return result.get("result", {})
    finally:
        proc.kill()
        proc.wait()


def _summarize_tool_payload(server: str, tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if "count" in payload:
        summary["count"] = payload.get("count")
    if "dry_run" in payload:
        summary["dry_run"] = payload.get("dry_run")
    if tool == "get_incident_casefile":
        summary["alert_count"] = len(payload.get("alerts", []))
        summary["has_artifacts"] = bool(payload.get("artifacts"))
    elif tool == "run_xql":
        summary["state"] = payload.get("state")
        summary["row_count"] = payload.get("row_count", len(payload.get("rows", [])))
    elif tool == "get_tenant_info":
        tenant = payload.get("tenant", {})
        if isinstance(tenant, dict):
            summary["tenant_keys"] = sorted(tenant.keys())[:5]
    elif tool == "list_risky_entities":
        items = payload.get("items", [])
        if items and isinstance(items[0], dict):
            summary["item_keys"] = sorted(items[0].keys())[:8]
    elif tool in {"list_profiles", "manage_agent_packages", "list_device_control_violations"}:
        items = payload.get("items", [])
        if items and isinstance(items[0], dict):
            summary["item_keys"] = sorted(items[0].keys())[:8]
    elif tool in {"update_incident", "update_alerts", "set_endpoint_isolation", "manage_iocs"}:
        request_payload = payload.get("payload", {})
        if isinstance(request_payload, dict):
            summary["payload_keys"] = sorted(request_payload.keys())
    elif server == "direct" and tool == "healthcheck":
        summary["status"] = payload.get("status")
        summary["auth_mode"] = payload.get("auth_mode")
    return summary


def _build_hint(server: str, tool: str, error: str) -> str | None:
    hint = SPEC_HINTS.get((server, tool))
    if hint is None:
        return None
    details = [f"API path: {', '.join(hint.api_paths)}"]
    if hint.required_permission:
        details.append(f"Required permission: {hint.required_permission}")
    if hint.required_license:
        details.append(f"Required license: {hint.required_license}")
    if error.lower().startswith("forbidden"):
        details.append("The tenant rejected the key before processing the request body.")
    if hint.note:
        details.append(hint.note)
    return " ".join(details)


def _run_healthcheck() -> CheckResult:
    start = time.monotonic()
    try:
        client = CortexXdrClient(CortexXdrConfig.from_env())
        response = client.get("/public_api/v1/healthcheck")
        status = response.get("status") if isinstance(response, dict) else None
        payload = {
            "status": status,
            "auth_mode": client.effective_auth_mode,
        }
        return CheckResult(
            server="direct",
            tool="healthcheck",
            status="passed",
            elapsed_seconds=round(time.monotonic() - start, 2),
            category="direct",
            details=_summarize_tool_payload("direct", "healthcheck", payload),
        )
    except Exception as exc:
        return CheckResult(
            server="direct",
            tool="healthcheck",
            status="failed",
            elapsed_seconds=round(time.monotonic() - start, 2),
            category="direct",
            error=str(exc),
        )


def _run_tool_check(
    *,
    server_name: str,
    tool_name: str,
    arguments: dict[str, Any],
    category: str,
    timeout_seconds: int,
) -> tuple[CheckResult, dict[str, Any] | None]:
    start = time.monotonic()
    try:
        result = _call_mcp_tool(
            server_name=server_name,
            tool_name=tool_name,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
        )
        payload = result.get("structuredContent", {})
        if result.get("isError", False):
            error = "Unknown MCP tool error"
            if isinstance(payload, dict):
                error = str(payload.get("error", error))
            return (
                CheckResult(
                    server=server_name,
                    tool=tool_name,
                    status="failed",
                    elapsed_seconds=round(time.monotonic() - start, 2),
                    category=category,
                    error=error,
                    hint=_build_hint(server_name, tool_name, error),
                ),
                payload if isinstance(payload, dict) else None,
            )
        normalized_payload = payload if isinstance(payload, dict) else {}
        return (
            CheckResult(
                server=server_name,
                tool=tool_name,
                status="passed",
                elapsed_seconds=round(time.monotonic() - start, 2),
                category=category,
                details=_summarize_tool_payload(server_name, tool_name, normalized_payload),
            ),
            normalized_payload,
        )
    except Exception as exc:
        error = str(exc)
        return (
            CheckResult(
                server=server_name,
                tool=tool_name,
                status="failed",
                elapsed_seconds=round(time.monotonic() - start, 2),
                category=category,
                error=error,
                hint=_build_hint(server_name, tool_name, error),
            ),
            None,
        )


def _skip_check(server_name: str, tool_name: str, category: str, reason: str) -> CheckResult:
    return CheckResult(
        server=server_name,
        tool=tool_name,
        status="skipped",
        elapsed_seconds=0.0,
        category=category,
        details={"reason": reason},
    )


def run_live_verification(
    *,
    include_admin: bool = True,
    include_extended: bool = True,
    tool_timeout_seconds: int = DEFAULT_TOOL_TIMEOUT_SECONDS,
    xql_wait_seconds: int = DEFAULT_XQL_WAIT_SECONDS,
) -> dict[str, Any]:
    checks: list[CheckResult] = [_run_healthcheck()]

    incident_id: str | None = None
    alert_id: str | None = None

    result, payload = _run_tool_check(
        server_name="investigate",
        tool_name="list_incidents",
        arguments={"limit": 1},
        category="tool_read",
        timeout_seconds=tool_timeout_seconds,
    )
    checks.append(result)
    if payload and payload.get("items"):
        first_incident = payload["items"][0]
        if isinstance(first_incident, dict):
            incident_id = first_incident.get("incident_id")

    result, payload = _run_tool_check(
        server_name="investigate",
        tool_name="list_alerts",
        arguments={"limit": 1},
        category="tool_read",
        timeout_seconds=tool_timeout_seconds,
    )
    checks.append(result)
    if payload and payload.get("items"):
        first_alert = payload["items"][0]
        if isinstance(first_alert, dict) and first_alert.get("alert_id") is not None:
            alert_id = str(first_alert["alert_id"])

    if incident_id:
        result, _ = _run_tool_check(
            server_name="investigate",
            tool_name="get_incident_casefile",
            arguments={"incident_id": incident_id, "include_event_summaries": True},
            category="tool_read",
            timeout_seconds=tool_timeout_seconds,
        )
        checks.append(result)
    else:
        checks.append(
            _skip_check(
                "investigate",
                "get_incident_casefile",
                "tool_read",
                "No incident_id was available from list_incidents",
            )
        )

    for tool_name, arguments in (
        ("list_risky_entities", {"entity_type": "hosts", "limit": 1}),
        ("run_xql", {"query": "dataset = xdr_data | limit 1", "wait_for_completion_seconds": xql_wait_seconds}),
        ("search_endpoints", {"limit": 1}),
    ):
        result, _ = _run_tool_check(
            server_name="investigate",
            tool_name=tool_name,
            arguments=arguments,
            category="tool_read",
            timeout_seconds=tool_timeout_seconds + xql_wait_seconds,
        )
        checks.append(result)

    if include_admin:
        result, _ = _run_tool_check(
            server_name="admin",
            tool_name="get_tenant_info",
            arguments={},
            category="tool_read",
            timeout_seconds=tool_timeout_seconds,
        )
        checks.append(result)

    if include_extended:
        for server_name, tool_name, arguments in (
            ("admin", "list_rbac_roles", {}),
            ("engineer", "list_profiles", {}),
            ("engineer", "manage_agent_packages", {"action": "list"}),
            ("engineer", "list_device_control_violations", {"limit": 1}),
        ):
            if server_name == "admin" and not include_admin:
                continue
            result, _ = _run_tool_check(
                server_name=server_name,
                tool_name=tool_name,
                arguments=arguments,
                category="tool_read",
                timeout_seconds=tool_timeout_seconds,
            )
            checks.append(result)

    if incident_id:
        result, _ = _run_tool_check(
            server_name="respond",
            tool_name="update_incident",
            arguments={
                "incident_id": incident_id,
                "status": "under_investigation",
                "reason": "verify-live smoke test payload validation",
                "dry_run": True,
            },
            category="tool_dry_run",
            timeout_seconds=tool_timeout_seconds,
        )
        checks.append(result)
    else:
        checks.append(
            _skip_check(
                "respond",
                "update_incident",
                "tool_dry_run",
                "No incident_id was available from list_incidents",
            )
        )

    if alert_id:
        result, _ = _run_tool_check(
            server_name="respond",
            tool_name="update_alerts",
            arguments={
                "alert_ids": [alert_id],
                "status": "new",
                "reason": "verify-live smoke test payload validation",
                "dry_run": True,
            },
            category="tool_dry_run",
            timeout_seconds=tool_timeout_seconds,
        )
        checks.append(result)
    else:
        checks.append(
            _skip_check(
                "respond",
                "update_alerts",
                "tool_dry_run",
                "No alert_id was available from list_alerts",
            )
        )

    for server_name, tool_name, arguments in (
        (
            "respond",
            "set_endpoint_isolation",
            {
                "endpoint_ids": ["example-endpoint-id"],
                "desired_state": "isolated",
                "reason": "verify-live smoke test payload validation",
                "dry_run": True,
            },
        ),
        (
            "engineer",
            "manage_iocs",
            {
                "reason": "verify-live smoke test payload validation",
                "dry_run": True,
                "indicators": [{"indicator": "1.2.3.4", "type": "IP"}],
            },
        ),
    ):
        result, _ = _run_tool_check(
            server_name=server_name,
            tool_name=tool_name,
            arguments=arguments,
            category="tool_dry_run",
            timeout_seconds=tool_timeout_seconds,
        )
        checks.append(result)

    summary = {
        "passed": sum(1 for check in checks if check.status == "passed"),
        "failed": sum(1 for check in checks if check.status == "failed"),
        "skipped": sum(1 for check in checks if check.status == "skipped"),
    }
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary,
        "checks": [check.to_dict() for check in checks],
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"Live verification summary: {report['summary']['passed']} passed, {report['summary']['failed']} failed, {report['summary']['skipped']} skipped",
    ]
    for check in report["checks"]:
        status = check["status"].upper().ljust(7)
        lines.append(
            f"{status} {check['server']}.{check['tool']} "
            f"({check['category']}, {check['elapsed_seconds']:.2f}s)"
        )
        details = check.get("details") or {}
        if details:
            details_text = ", ".join(f"{key}={value}" for key, value in details.items())
            lines.append(f"  Details: {details_text}")
        if check.get("error"):
            lines.append(f"  Error: {check['error']}")
        if check.get("hint"):
            lines.append(f"  Hint: {check['hint']}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m cortex_xdr_mcp verify-live",
        description="Run a live smoke test against the curated Cortex XDR MCP servers.",
    )
    parser.add_argument("--json", action="store_true", help="Emit the verification report as JSON.")
    parser.add_argument(
        "--no-admin",
        action="store_true",
        help="Skip admin-surface checks such as get_tenant_info and list_rbac_roles.",
    )
    parser.add_argument(
        "--no-extended",
        action="store_true",
        help="Skip the extra endpoint engineering and RBAC probes.",
    )
    parser.add_argument(
        "--tool-timeout",
        type=int,
        default=DEFAULT_TOOL_TIMEOUT_SECONDS,
        help=f"Maximum seconds to wait for an individual MCP tool call. Default: {DEFAULT_TOOL_TIMEOUT_SECONDS}.",
    )
    parser.add_argument(
        "--xql-wait",
        type=int,
        default=DEFAULT_XQL_WAIT_SECONDS,
        help=f"wait_for_completion_seconds for the XQL smoke query. Default: {DEFAULT_XQL_WAIT_SECONDS}.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    report = run_live_verification(
        include_admin=not args.no_admin,
        include_extended=not args.no_extended,
        tool_timeout_seconds=args.tool_timeout,
        xql_wait_seconds=args.xql_wait,
    )
    if args.json:
        sys.stdout.write(dump_json(report))
    else:
        sys.stdout.write(format_report(report))
    sys.stdout.write("\n")
    return 1 if report["summary"]["failed"] else 0
