from __future__ import annotations

import unittest

from cortex_xdr_mcp.errors import ToolInputError
from cortex_xdr_mcp.service import XdrService

from .fakes import FakeClient


class AdminServiceTests(unittest.TestCase):
    def test_list_rbac_roles_lists_roles_directly(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/rbac/get_roles"): {
                    "reply": [
                        [{"pretty_name": "Security Admin", "permissions": ["Alerts"]}],
                        [{"pretty_name": "Investigator", "permissions": ["Incidents"]}],
                    ]
                },
            }
        )
        service = XdrService(client)

        result = service.list_rbac_roles({})

        self.assertEqual(result["count"], 2)
        self.assertEqual(
            client.calls[0][2],
            {"request_data": {}},
        )
        self.assertEqual(
            [item["pretty_name"] for item in result["items"]],
            ["Security Admin", "Investigator"],
        )

    def test_list_user_groups_lists_groups_directly(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/rbac/get_user_group"): {
                    "reply": [
                        {"group_name": "Tier 1", "pretty_name": "Tier 1", "user_email": ["a@example.com"]},
                        {"group_name": "Tier 2", "pretty_name": "Tier 2", "user_email": []},
                    ]
                }
            }
        )
        service = XdrService(client)

        result = service.list_user_groups({})

        self.assertEqual(result["count"], 2)
        self.assertEqual(client.calls[0][2], {"request_data": {}})
        self.assertEqual([item["group_name"] for item in result["items"]], ["Tier 1", "Tier 2"])

    def test_manage_authentication_settings_update_rewrites_domain_fields(self) -> None:
        service = XdrService(FakeClient())

        result = service.manage_authentication_settings(
            {
                "action": "update",
                "settings": {
                    "domain": "corp.example",
                    "type": "SAML",
                },
                "reason": "cleanup",
                "dry_run": True,
            }
        )

        self.assertEqual(
            result["payload"]["request_data"],
            {
                "type": "SAML",
                "current_domain_value": "corp.example",
                "new_domain_value": "corp.example",
            },
        )

    def test_manage_lookup_dataset_remove_wraps_single_filter_object(self) -> None:
        service = XdrService(FakeClient())

        result = service.manage_lookup_dataset(
            {
                "action": "remove",
                "lookup": {"dataset_name": "assets", "filters": {"field": "hostname", "value": "wkstn-7"}},
                "reason": "cleanup",
                "dry_run": True,
            }
        )

        self.assertEqual(
            result["payload"]["request_data"]["filters"],
            [{"field": "hostname", "value": "wkstn-7"}],
        )

    def test_manage_xql_dataset_requires_non_empty_dataset(self) -> None:
        service = XdrService(FakeClient())

        with self.assertRaises(ToolInputError):
            service.manage_xql_dataset(
                {
                    "action": "create",
                    "dataset": {},
                    "reason": "test",
                    "dry_run": True,
                }
            )


if __name__ == "__main__":
    unittest.main()
