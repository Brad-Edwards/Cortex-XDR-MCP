from __future__ import annotations

import unittest

from cortex_xdr_mcp.errors import ToolInputError
from cortex_xdr_mcp.service import XdrService

from .fakes import FakeClient


class RespondServiceTests(unittest.TestCase):
    def test_set_endpoint_isolation_rejects_missing_confirm(self) -> None:
        service = XdrService(FakeClient())
        with self.assertRaises(ToolInputError):
            service.set_endpoint_isolation(
                {"endpoint_ids": ["ep-1"], "desired_state": "isolated", "reason": "containment"}
            )

    def test_set_endpoint_isolation_dry_run_does_not_call_api(self) -> None:
        client = FakeClient()
        service = XdrService(client)

        result = service.set_endpoint_isolation(
            {
                "endpoint_ids": ["ep-1"],
                "desired_state": "isolated",
                "reason": "containment",
                "dry_run": True,
            }
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(result["payload"]["request_data"]["endpoint_id"], "ep-1")
        self.assertEqual(client.calls, [])

    def test_run_endpoint_script_waits_for_status_and_results(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/scripts/run_script"): {"reply": {"action_id": 777, "status": 1}},
                ("POST", "/public_api/v1/scripts/get_script_execution_status"): [
                    {"reply": {"general_status": "PENDING"}},
                    {"reply": {"general_status": "COMPLETED_SUCCESSFULLY"}},
                ],
                ("POST", "/public_api/v1/scripts/get_script_execution_results"): {
                    "reply": {"results": [{"endpoint_id": "ep-1", "execution_status": "COMPLETED_SUCCESSFULLY"}]}
                },
            }
        )
        service = XdrService(client)

        result = service.run_endpoint_script(
            {
                "endpoint_ids": ["ep-1"],
                "script_uid": "script-1",
                "reason": "collect details",
                "confirm": True,
                "wait_for_completion_seconds": 1,
            }
        )

        self.assertTrue(result["completed"])
        self.assertEqual(result["job_id"], "777")
        self.assertEqual(result["artifacts"]["results"][0]["endpoint_id"], "ep-1")

    def test_retrieve_endpoint_files_adds_download_artifacts(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/endpoints/file_retrieval"): {
                    "reply": {"action_id": "901", "status": "1"}
                },
                ("POST", "/public_api/v1/actions/get_action_status"): {
                    "reply": {"data": {"ep-1": "COMPLETED_SUCCESSFULLY"}}
                },
                ("POST", "/public_api/v1/actions/file_retrieval_details"): {
                    "reply": {"data": {"ep-1": "https://download/link"}}
                },
            }
        )
        service = XdrService(client)

        result = service.retrieve_endpoint_files(
            {
                "endpoint_ids": ["ep-1"],
                "files": {"windows": ["C:\\temp\\foo.txt"]},
                "reason": "evidence collection",
                "confirm": True,
                "wait_for_completion_seconds": 0,
            }
        )

        self.assertTrue(result["completed"])
        self.assertEqual(result["artifacts"]["ep-1"], "https://download/link")

    def test_retrieve_endpoint_files_validates_os_file_lists(self) -> None:
        service = XdrService(FakeClient())

        with self.assertRaises(ToolInputError):
            service.retrieve_endpoint_files(
                {
                    "endpoint_ids": ["ep-1"],
                    "files": {"linux": "not-a-list"},
                    "reason": "evidence collection",
                    "dry_run": True,
                }
            )

    def test_check_job_status_requires_numeric_group_action_ids(self) -> None:
        service = XdrService(FakeClient())

        with self.assertRaises(ToolInputError):
            service.check_job_status({"job_kind": "endpoint_scan", "job_id": "abc"})

    def test_check_job_status_does_not_fetch_script_results_while_pending(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/scripts/get_script_execution_status"): {
                    "reply": {"general_status": "PENDING"}
                }
            }
        )
        service = XdrService(client)

        result = service.check_job_status({"job_kind": "endpoint_script", "job_id": "777"})

        self.assertFalse(result["completed"])
        self.assertEqual(result["artifacts"], {})
        self.assertEqual(len(client.calls), 1)


if __name__ == "__main__":
    unittest.main()
