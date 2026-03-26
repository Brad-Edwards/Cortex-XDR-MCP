"""Investigation-focused Cortex XDR MCP server."""

from __future__ import annotations

from ..mcp_runtime import McpToolServer, ToolDefinition
from ..service import XdrService
from .common import base_read_properties, string_array, time_range_schema


def build_server(service: XdrService, version: str) -> McpToolServer:
    tools = [
        ToolDefinition(
            name="list_incidents",
            description="List incidents with simple analyst-friendly filters instead of raw request_data filters.",
            input_schema={
                "type": "object",
                "properties": {
                    **base_read_properties(),
                    "statuses": string_array("Incident statuses to include."),
                    "alert_sources": string_array("Incident alert sources to include."),
                    "search_text": {"type": "string", "description": "Match incident descriptions containing this text."},
                    "starred": {"type": "boolean", "description": "Only return starred or unstarred incidents."},
                    "sort_order": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
                },
                "additionalProperties": False,
            },
            handler=service.list_incidents,
        ),
        ToolDefinition(
            name="list_alerts",
            description="List alerts by severity, source, IDs, or time range.",
            input_schema={
                "type": "object",
                "properties": {
                    **base_read_properties(),
                    "severities": string_array("Alert severities to include."),
                    "alert_sources": string_array("Alert sources to include."),
                    "alert_ids": {
                        "type": "array",
                        "items": {"type": ["string", "integer"]},
                        "description": "Specific alert IDs to fetch.",
                    },
                    "sort_order": {"type": "string", "enum": ["asc", "desc"], "default": "desc"},
                },
                "additionalProperties": False,
            },
            handler=service.list_alerts,
        ),
        ToolDefinition(
            name="get_incident_casefile",
            description="Build a normalized incident dossier with incident details, alerts, artifacts, event summaries, and optional PCAP metadata.",
            input_schema={
                "type": "object",
                "required": ["incident_id"],
                "properties": {
                    "incident_id": {"type": "string", "description": "Incident ID to inspect."},
                    "include_event_summaries": {"type": "boolean", "default": True},
                    "include_pcap_metadata": {"type": "boolean", "default": False},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.get_incident_casefile,
        ),
        ToolDefinition(
            name="search_endpoints",
            description="Search endpoints by explicit endpoint, host, user, group, platform, state, or time range.",
            input_schema={
                "type": "object",
                "properties": {
                    **base_read_properties(),
                    "endpoint_ids": string_array("Specific endpoint IDs to include."),
                    "hostnames": string_array("Exact hostnames to include."),
                    "usernames": string_array("Usernames currently associated with the endpoints."),
                    "platforms": string_array("Endpoint platforms, for example windows or macos."),
                    "statuses": string_array("Endpoint connection or operational statuses."),
                    "group_names": string_array("Endpoint group names."),
                    "aliases": string_array("Endpoint aliases."),
                    "isolation_state": {"type": "string", "enum": ["isolated", "unisolated"]},
                },
                "additionalProperties": False,
            },
            handler=service.search_endpoints,
        ),
        ToolDefinition(
            name="get_endpoint_context",
            description="Resolve one endpoint by exact ID or hostname and enrich it with risk and current policy context.",
            input_schema={
                "type": "object",
                "properties": {
                    "endpoint_id": {"type": "string"},
                    "hostname": {"type": "string"},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.get_endpoint_context,
        ),
        ToolDefinition(
            name="list_risky_entities",
            description="List the riskiest users or hosts based on Cortex XDR risk scoring.",
            input_schema={
                "type": "object",
                "properties": {
                    "entity_type": {"type": "string", "enum": ["hosts", "users"], "default": "hosts"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.list_risky_entities,
        ),
        ToolDefinition(
            name="get_entity_risk",
            description="Get the risk score and reasons for one host or user identifier.",
            input_schema={
                "type": "object",
                "required": ["entity_id"],
                "properties": {
                    "entity_id": {"type": "string", "description": "Host or user identifier accepted by Cortex XDR risk scoring."},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.get_entity_risk,
        ),
        ToolDefinition(
            name="run_xql",
            description="Run an XQL hunt and hide the query start plus result polling workflow behind one tool.",
            input_schema={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string", "description": "Full XQL query text."},
                    "time_range": time_range_schema(),
                    "wait_for_completion_seconds": {"type": "integer", "minimum": 0, "default": 30},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.run_xql,
        ),
    ]
    return McpToolServer(
        name="cortex-xdr-investigate",
        version=version,
        instructions="Use these tools for read-heavy investigation, incident triage, and hunting. Prefer the composed casefile and endpoint-context tools over low-level hunts when they fit the job.",
        tools=tools,
    )
