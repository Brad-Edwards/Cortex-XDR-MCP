from __future__ import annotations

import json
import unittest

from cortex_xdr_mcp import __version__
from cortex_xdr_mcp.service import XdrService
from cortex_xdr_mcp.servers import admin, engineer, investigate, respond

from .fakes import FakeClient


class ServerContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = XdrService(FakeClient())

    def test_server_toolsets_match_the_curated_split(self) -> None:
        servers = {
            "investigate": investigate.build_server(self.service, __version__),
            "respond": respond.build_server(self.service, __version__),
            "engineer": engineer.build_server(self.service, __version__),
            "admin": admin.build_server(self.service, __version__),
        }
        expected = {
            "investigate": {
                "list_incidents",
                "list_alerts",
                "get_incident_casefile",
                "search_endpoints",
                "get_endpoint_context",
                "list_risky_entities",
                "get_entity_risk",
                "run_xql",
            },
            "respond": {
                "update_incident",
                "update_alerts",
                "set_endpoint_isolation",
                "set_file_quarantine_state",
                "scan_endpoints",
                "retrieve_endpoint_files",
                "run_endpoint_script",
                "run_forensics_triage",
                "manage_hash_reputation",
                "check_job_status",
            },
            "engineer": {
                "list_profiles",
                "manage_prevention_profile",
                "manage_exception_rule",
                "manage_prevention_override",
                "manage_iocs",
                "manage_endpoint_tags",
                "manage_agent_packages",
                "list_device_control_violations",
            },
            "admin": {
                "get_tenant_info",
                "list_rbac_users",
                "list_rbac_roles",
                "list_user_groups",
                "set_user_role",
                "manage_syslog_integration",
                "manage_authentication_settings",
                "list_audit_logs",
                "manage_xql_dataset",
                "manage_lookup_dataset",
            },
        }
        for name, server in servers.items():
            self.assertEqual(set(server.tools), expected[name])

    def test_public_schemas_do_not_expose_raw_rest_shapes(self) -> None:
        servers = [
            investigate.build_server(self.service, __version__),
            respond.build_server(self.service, __version__),
            engineer.build_server(self.service, __version__),
            admin.build_server(self.service, __version__),
        ]
        banned_fragments = ['"request_data"', '"search_from"', '"search_to"', '"sort.keyword"']
        for server in servers:
            for tool in server.tools.values():
                schema_text = json.dumps(tool.input_schema, sort_keys=True)
                for fragment in banned_fragments:
                    self.assertNotIn(fragment, schema_text, msg=f"{tool.name} leaked {fragment}")

    def test_mcp_dispatch_lists_tools(self) -> None:
        server = investigate.build_server(self.service, __version__)
        result = server._dispatch({"method": "tools/list", "params": {}})
        tool_names = {tool["name"] for tool in result["tools"]}
        self.assertIn("get_incident_casefile", tool_names)
        self.assertIn("run_xql", tool_names)


if __name__ == "__main__":
    unittest.main()
