from __future__ import annotations

import unittest

from cortex_xdr_mcp.errors import ToolInputError
from cortex_xdr_mcp.service import XdrService

from .fakes import FakeClient


class EngineerServiceTests(unittest.TestCase):
    def test_list_profiles_maps_category_to_api_type_field(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/endpoints/get_profiles"): {
                    "reply": [{"id": 7, "name": "Windows Default"}]
                }
            }
        )
        service = XdrService(client)

        result = service.list_profiles({"category": "prevention"})

        self.assertEqual(result["count"], 1)
        self.assertEqual(
            client.calls[0][2],
            {"request_data": {"type": "prevention"}},
        )

    def test_manage_exception_rule_list_normalizes_uppercase_reply_keys(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/legacy_exceptions/fetch"): {
                    "reply": {
                        "DATA": [{"id": "ex-1", "rule_name": "Allow updater"}],
                        "TOTAL_COUNT": 1,
                    }
                }
            }
        )
        service = XdrService(client)

        result = service.manage_exception_rule({"action": "list", "limit": 10})

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["items"][0]["id"], "ex-1")

    def test_manage_agent_packages_create_returns_job_handle(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/distributions/create"): {
                    "reply": {"distribution_id": "dist-1"}
                }
            }
        )
        service = XdrService(client)

        result = service.manage_agent_packages(
            {
                "action": "create",
                "package": {
                    "name": "windows-prod",
                    "platform": "windows",
                    "package_type": "standalone",
                    "agent_version": "8.0.0",
                    "deployment_platform": "standard",
                    "default_namespace": "default",
                    "run_on_master_node": False,
                    "run_on_all_nodes": True,
                },
                "reason": "new deployment wave",
                "confirm": True,
            }
        )

        self.assertEqual(result["job_kind"], "agent_package")
        self.assertEqual(result["job_id"], "dist-1")
        self.assertFalse(result["completed"])

    def test_manage_iocs_supports_dry_run(self) -> None:
        service = XdrService(FakeClient())

        result = service.manage_iocs(
            {
                "reason": "add fresh intel",
                "dry_run": True,
                "indicators": [{"indicator": "1.2.3.4", "type": "IP"}],
            }
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["mode"], "json")

    def test_manage_iocs_rejects_non_object_indicators(self) -> None:
        service = XdrService(FakeClient())

        with self.assertRaises(ToolInputError):
            service.manage_iocs(
                {
                    "reason": "add fresh intel",
                    "dry_run": True,
                    "indicators": ["1.2.3.4"],
                }
            )

    def test_manage_iocs_csv_uses_raw_request_data_string(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/indicators/insert_csv"): {
                    "reply": True
                }
            }
        )
        service = XdrService(client)
        csv_data = "indicator,type,severity,expiration_date\nexample.invalid,DOMAIN_NAME,LOW,Never\n"

        result = service.manage_iocs(
            {
                "mode": "csv",
                "csv_data": csv_data,
                "reason": "live verification",
                "confirm": True,
            }
        )

        self.assertEqual(result["mode"], "csv")
        self.assertEqual(
            client.calls[0][2],
            {"request_data": csv_data},
        )

    def test_list_device_control_violations_uses_keyword_sort_shape(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/device_control/get_violations"): {
                    "reply": {"result_count": 0, "total_count": 0, "violations": []}
                }
            }
        )
        service = XdrService(client)

        result = service.list_device_control_violations({"limit": 1})

        self.assertEqual(result["count"], 0)
        self.assertEqual(
            client.calls[0][2],
            {"request_data": {"search_from": 0, "search_to": 1, "sort": {"field": "timestamp", "keyword": "desc"}}},
        )

    def test_manage_prevention_override_requires_rule_for_create(self) -> None:
        service = XdrService(FakeClient())

        with self.assertRaises(ToolInputError):
            service.manage_prevention_override(
                {
                    "override_type": "disable_prevention",
                    "action": "create",
                    "reason": "hardening",
                    "dry_run": True,
                }
            )


if __name__ == "__main__":
    unittest.main()
