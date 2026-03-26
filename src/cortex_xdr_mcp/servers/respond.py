"""Response-focused Cortex XDR MCP server."""

from __future__ import annotations

from ..mcp_runtime import McpToolServer, ToolDefinition
from ..service import XdrService
from .common import string_array, write_guard_properties


def build_server(service: XdrService, version: str) -> McpToolServer:
    write_props = write_guard_properties()
    tools = [
        ToolDefinition(
            name="update_incident",
            description="Update a known incident with status, assignee, severity, comment, notes, or resolution details.",
            input_schema={
                "type": "object",
                "required": ["incident_id", "reason"],
                "properties": {
                    **write_props,
                    "incident_id": {"type": "string"},
                    "status": {"type": "string"},
                    "assignee_email": {"type": "string"},
                    "severity": {"type": "string"},
                    "comment": {"type": "string"},
                    "notes": {"type": "string"},
                    "resolve_comment": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.update_incident,
        ),
        ToolDefinition(
            name="update_alerts",
            description="Update one or more known alerts with status, severity, or comment.",
            input_schema={
                "type": "object",
                "required": ["alert_ids", "reason"],
                "properties": {
                    **write_props,
                    "alert_ids": string_array("Known alert IDs to update."),
                    "status": {"type": "string"},
                    "severity": {"type": "string"},
                    "comment": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.update_alerts,
        ),
        ToolDefinition(
            name="set_endpoint_isolation",
            description="Isolate or unisolate explicitly identified endpoints.",
            input_schema={
                "type": "object",
                "required": ["endpoint_ids", "desired_state", "reason"],
                "properties": {
                    **write_props,
                    "endpoint_ids": string_array("Exact endpoint IDs to isolate or unisolate."),
                    "desired_state": {"type": "string", "enum": ["isolated", "unisolated"]},
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.set_endpoint_isolation,
        ),
        ToolDefinition(
            name="set_file_quarantine_state",
            description="Quarantine or restore a known file by explicit hash and endpoint identifiers.",
            input_schema={
                "type": "object",
                "required": ["desired_state", "file_hash", "reason"],
                "properties": {
                    **write_props,
                    "desired_state": {"type": "string", "enum": ["quarantined", "restored"]},
                    "file_hash": {"type": "string"},
                    "file_path": {"type": "string", "description": "Required when quarantining a file."},
                    "endpoint_ids": string_array("Required when quarantining a file."),
                    "endpoint_id": {"type": "string", "description": "Optional single endpoint for restore operations."},
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.set_file_quarantine_state,
        ),
        ToolDefinition(
            name="scan_endpoints",
            description="Start a malware scan on explicitly identified endpoints.",
            input_schema={
                "type": "object",
                "required": ["endpoint_ids", "reason"],
                "properties": {
                    **write_props,
                    "endpoint_ids": string_array("Exact endpoint IDs to scan."),
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.scan_endpoints,
        ),
        ToolDefinition(
            name="retrieve_endpoint_files",
            description="Retrieve files from explicitly identified endpoints and return download metadata once available.",
            input_schema={
                "type": "object",
                "required": ["endpoint_ids", "files", "reason"],
                "properties": {
                    **write_props,
                    "endpoint_ids": string_array("Exact endpoint IDs to retrieve files from."),
                    "files": {
                        "type": "object",
                        "description": "OS-specific file paths. Provide one or more of windows, linux, or macos.",
                        "properties": {
                            "windows": string_array("Windows file paths."),
                            "linux": string_array("Linux file paths."),
                            "macos": string_array("macOS file paths."),
                        },
                        "additionalProperties": False,
                    },
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.retrieve_endpoint_files,
        ),
        ToolDefinition(
            name="run_endpoint_script",
            description="Execute a known script library item on explicitly identified endpoints.",
            input_schema={
                "type": "object",
                "required": ["endpoint_ids", "script_uid", "reason"],
                "properties": {
                    **write_props,
                    "endpoint_ids": string_array("Exact endpoint IDs to run the script on."),
                    "script_uid": {"type": "string"},
                    "parameters": {"type": "object", "additionalProperties": True},
                    "timeout_seconds": {"type": "integer", "minimum": 1},
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.run_endpoint_script,
        ),
        ToolDefinition(
            name="run_forensics_triage",
            description="Start forensics triage on explicitly identified endpoints.",
            input_schema={
                "type": "object",
                "required": ["endpoint_ids", "reason"],
                "properties": {
                    **write_props,
                    "endpoint_ids": string_array("Exact endpoint IDs to triage."),
                    "collector_uuid": {"type": "string", "description": "Optional triage preset UUID."},
                },
                "additionalProperties": False,
            },
            handler=service.run_forensics_triage,
        ),
        ToolDefinition(
            name="manage_hash_reputation",
            description="Add known file hashes to the allowlist or blocklist.",
            input_schema={
                "type": "object",
                "required": ["reputation", "hashes", "reason"],
                "properties": {
                    **write_props,
                    "reputation": {"type": "string", "enum": ["allowlist", "blocklist"]},
                    "hashes": string_array("SHA256 hashes to add."),
                    "comment": {"type": "string"},
                    "incident_id": {"type": ["string", "integer"]},
                },
                "additionalProperties": False,
            },
            handler=service.manage_hash_reputation,
        ),
        ToolDefinition(
            name="check_job_status",
            description="Check the status of an async response, script, or package job.",
            input_schema={
                "type": "object",
                "required": ["job_kind", "job_id"],
                "properties": {
                    "job_kind": {"type": "string"},
                    "job_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.check_job_status,
        ),
    ]
    return McpToolServer(
        name="cortex-xdr-respond",
        version=version,
        instructions="Use these tools only when targets are already known. This server is intentionally write-capable and expects explicit IDs, a reason, and confirmation for mutating actions.",
        tools=tools,
    )
