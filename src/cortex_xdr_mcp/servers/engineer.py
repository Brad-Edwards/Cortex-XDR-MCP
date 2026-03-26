"""Security engineering Cortex XDR MCP server."""

from __future__ import annotations

from ..mcp_runtime import McpToolServer, ToolDefinition
from ..service import XdrService
from .common import base_read_properties, string_array, write_guard_properties


def build_server(service: XdrService, version: str) -> McpToolServer:
    write_props = write_guard_properties()
    tools = [
        ToolDefinition(
            name="list_profiles",
            description="List endpoint security profiles by category and optional profile IDs.",
            input_schema={
                "type": "object",
                "properties": {
                    "category": {"type": "string", "enum": ["prevention", "extension"], "default": "prevention"},
                    "profile_ids": {"type": "array", "items": {"type": "integer"}},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.list_profiles,
        ),
        ToolDefinition(
            name="manage_prevention_profile",
            description="Create, update, inspect modules for, or extend signer allowlists on prevention profiles.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["create", "update", "list_modules", "add_signer_cn"]},
                    "profile": {"type": "object", "additionalProperties": True},
                    "profile_id": {"type": "integer"},
                    "profile_name": {"type": "string"},
                    "update_data": {"type": "object", "additionalProperties": True},
                    "profile_type": {"type": "string"},
                    "platform": {"type": "string"},
                    "signer_common_names": string_array("Signer common names to allowlist."),
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_prevention_profile,
        ),
        ToolDefinition(
            name="manage_exception_rule",
            description="List, inspect modules for, create, update, or delete legacy exception rules with typed top-level controls.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    **base_read_properties(),
                    "action": {"type": "string", "enum": ["list", "list_modules", "create", "update", "delete"]},
                    "platforms": string_array("Platforms to filter list results."),
                    "module_ids": {"type": "array", "items": {"type": "integer"}},
                    "rule": {"type": "object", "additionalProperties": True},
                    "exception_id": {"type": "string"},
                    "exception_ids": string_array("Legacy exception IDs to delete."),
                },
                "additionalProperties": False,
            },
            handler=service.manage_exception_rule,
        ),
        ToolDefinition(
            name="manage_prevention_override",
            description="Manage disable-prevention and disable-injection rule families through one tool surface. Supported actions: disable_prevention supports list/create/update/delete; disable_injection supports list/create/disable.",
            input_schema={
                "type": "object",
                "required": ["override_type", "action"],
                "properties": {
                    **write_props,
                    "override_type": {"type": "string", "enum": ["disable_prevention", "disable_injection"]},
                    "action": {
                        "type": "string",
                        "enum": ["list", "create", "update", "delete", "disable"],
                        "description": "disable_prevention supports list/create/update/delete. disable_injection supports list/create/disable.",
                    },
                    "rule": {"type": "object", "additionalProperties": True},
                    "rule_ids": string_array("Override rule IDs to disable or delete."),
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_prevention_override,
        ),
        ToolDefinition(
            name="manage_iocs",
            description="Ingest simple indicators in JSON or CSV form, with JSON as the default mode.",
            input_schema={
                "type": "object",
                "required": ["reason"],
                "properties": {
                    **write_props,
                    "mode": {"type": "string", "enum": ["json", "csv"], "default": "json"},
                    "indicators": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "csv_data": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.manage_iocs,
        ),
        ToolDefinition(
            name="manage_endpoint_tags",
            description="Assign or remove one tag on explicitly identified endpoints.",
            input_schema={
                "type": "object",
                "required": ["action", "endpoint_ids", "tag", "reason"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["assign", "remove"]},
                    "endpoint_ids": string_array("Exact endpoint IDs to tag."),
                    "tag": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.manage_endpoint_tags,
        ),
        ToolDefinition(
            name="manage_agent_packages",
            description="Create, inspect, fetch download URLs for, list, or delete agent installation packages.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["create", "status", "download_url", "list", "delete"]},
                    "package": {"type": "object", "additionalProperties": True},
                    "distribution_id": {"type": "string"},
                    "distribution_ids": string_array("Distribution IDs to delete."),
                    "package_type": {"type": "string"},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_agent_packages,
        ),
        ToolDefinition(
            name="list_device_control_violations",
            description="List device control violations by endpoint, user, or timeframe.",
            input_schema={
                "type": "object",
                "properties": {
                    **base_read_properties(),
                    "endpoint_ids": string_array("Exact endpoint IDs to include."),
                    "usernames": string_array("Usernames associated with the violations."),
                },
                "additionalProperties": False,
            },
            handler=service.list_device_control_violations,
        ),
    ]
    return McpToolServer(
        name="cortex-xdr-engineer",
        version=version,
        instructions="Use these tools for security engineering and policy workflows. They intentionally group related low-level endpoints into a smaller set of higher-signal operations.",
        tools=tools,
    )
