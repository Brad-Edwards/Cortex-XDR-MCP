"""Optional Cortex XDR admin MCP server."""

from __future__ import annotations

from ..mcp_runtime import McpToolServer, ToolDefinition
from ..service import XdrService
from .common import base_read_properties, write_guard_properties


def build_server(service: XdrService, version: str) -> McpToolServer:
    write_props = write_guard_properties()
    tools = [
        ToolDefinition(
            name="get_tenant_info",
            description="Get tenant and licensing information.",
            input_schema={
                "type": "object",
                "properties": {"include_raw": {"type": "boolean", "default": False}},
                "additionalProperties": False,
            },
            handler=service.get_tenant_info,
        ),
        ToolDefinition(
            name="list_rbac_users",
            description="List RBAC users.",
            input_schema={"type": "object", "properties": {"include_raw": {"type": "boolean", "default": False}}, "additionalProperties": False},
            handler=service.list_rbac_users,
        ),
        ToolDefinition(
            name="list_rbac_roles",
            description="List RBAC roles.",
            input_schema={"type": "object", "properties": {"include_raw": {"type": "boolean", "default": False}}, "additionalProperties": False},
            handler=service.list_rbac_roles,
        ),
        ToolDefinition(
            name="list_user_groups",
            description="List RBAC user groups.",
            input_schema={"type": "object", "properties": {"include_raw": {"type": "boolean", "default": False}}, "additionalProperties": False},
            handler=service.list_user_groups,
        ),
        ToolDefinition(
            name="set_user_role",
            description="Set a user's RBAC role.",
            input_schema={
                "type": "object",
                "required": ["user_email", "role_name", "reason"],
                "properties": {
                    **write_props,
                    "user_email": {"type": "string"},
                    "role_name": {"type": "string"},
                },
                "additionalProperties": False,
            },
            handler=service.set_user_role,
        ),
        ToolDefinition(
            name="manage_syslog_integration",
            description="Create, update, delete, list, or test syslog integrations.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["create", "update", "delete", "list", "test"]},
                    "integration": {"type": "object", "additionalProperties": True},
                    "selection": {"type": "object", "additionalProperties": True, "description": "Selector or payload for delete and test actions."},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_syslog_integration,
        ),
        ToolDefinition(
            name="manage_authentication_settings",
            description="Create, update, delete, list, or inspect IdP authentication settings.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["create", "update", "delete", "list", "metadata"]},
                    "settings": {"type": "object", "additionalProperties": True},
                    "selection": {"type": "object", "additionalProperties": True, "description": "Selector payload for delete operations."},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_authentication_settings,
        ),
        ToolDefinition(
            name="list_audit_logs",
            description="List management or agent audit logs over an optional time range.",
            input_schema={
                "type": "object",
                "properties": {
                    **base_read_properties(),
                    "audit_type": {"type": "string", "enum": ["management", "agents"], "default": "management"},
                },
                "additionalProperties": False,
            },
            handler=service.list_audit_logs,
        ),
        ToolDefinition(
            name="manage_xql_dataset",
            description="Create, delete, or list XQL datasets.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["create", "delete", "list"]},
                    "dataset": {"type": "object", "additionalProperties": True},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_xql_dataset,
        ),
        ToolDefinition(
            name="manage_lookup_dataset",
            description="Add to, remove from, or retrieve lookup dataset rows.",
            input_schema={
                "type": "object",
                "required": ["action"],
                "properties": {
                    **write_props,
                    "action": {"type": "string", "enum": ["add", "remove", "get"]},
                    "lookup": {"type": "object", "additionalProperties": True, "description": "Lookup query or row payload."},
                    "include_raw": {"type": "boolean", "default": False},
                },
                "additionalProperties": False,
            },
            handler=service.manage_lookup_dataset,
        ),
    ]
    return McpToolServer(
        name="cortex-xdr-admin",
        version=version,
        instructions="Use these tools for tenant administration and platform plumbing. This server is intentionally optional and should not be attached by default to analyst workflows.",
        tools=tools,
    )
