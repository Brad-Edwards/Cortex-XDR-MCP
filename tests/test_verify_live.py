from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

from cortex_xdr_mcp import __main__
from cortex_xdr_mcp.verify_live import format_report, run_live_verification


class VerifyLiveTests(unittest.TestCase):
    def test_format_report_includes_failure_hint(self) -> None:
        report = {
            "summary": {"passed": 1, "failed": 1, "skipped": 0},
            "checks": [
                {
                    "server": "direct",
                    "tool": "healthcheck",
                    "status": "passed",
                    "elapsed_seconds": 0.1,
                    "category": "direct",
                    "details": {"status": "available", "auth_mode": "advanced"},
                    "error": None,
                    "hint": None,
                },
                {
                    "server": "engineer",
                    "tool": "list_profiles",
                    "status": "failed",
                    "elapsed_seconds": 0.2,
                    "category": "tool_read",
                    "details": {},
                    "error": "Forbidden. Access was denied to this resource.",
                    "hint": "API path: /public_api/v1/endpoints/get_profiles",
                },
            ],
        }

        rendered = format_report(report)

        self.assertIn("FAILED  engineer.list_profiles", rendered)
        self.assertIn("Hint: API path: /public_api/v1/endpoints/get_profiles", rendered)

    def test_run_live_verification_reports_skipped_dependent_write_when_no_incident_id(self) -> None:
        fake_results = {
            ("investigate", "list_incidents"): ({"status": "passed", "details": {"count": 0}}, {"items": []}),
            ("investigate", "list_alerts"): ({"status": "passed", "details": {"count": 0}}, {"items": []}),
            ("investigate", "list_risky_entities"): ({"status": "failed", "error": "boom"}, None),
            ("investigate", "run_xql"): ({"status": "passed", "details": {"state": "SUCCESS"}}, {"row_count": 1}),
            ("investigate", "search_endpoints"): ({"status": "failed", "error": "Forbidden"}, None),
            ("respond", "set_endpoint_isolation"): ({"status": "passed", "details": {"dry_run": True}}, {}),
            ("engineer", "manage_iocs"): ({"status": "passed", "details": {"dry_run": True}}, {}),
        }

        def fake_healthcheck() -> object:
            from cortex_xdr_mcp.verify_live import CheckResult

            return CheckResult(
                server="direct",
                tool="healthcheck",
                status="passed",
                elapsed_seconds=0.01,
                category="direct",
                details={"status": "available"},
            )

        def fake_run_tool_check(*, server_name: str, tool_name: str, arguments: dict, category: str, timeout_seconds: int):
            from cortex_xdr_mcp.verify_live import CheckResult

            data, payload = fake_results[(server_name, tool_name)]
            return (
                CheckResult(
                    server=server_name,
                    tool=tool_name,
                    status=data["status"],
                    elapsed_seconds=0.01,
                    category=category,
                    details=data.get("details", {}),
                    error=data.get("error"),
                ),
                payload,
            )

        with patch("cortex_xdr_mcp.verify_live._run_healthcheck", side_effect=fake_healthcheck):
            with patch("cortex_xdr_mcp.verify_live._run_tool_check", side_effect=fake_run_tool_check):
                report = run_live_verification(include_admin=False, include_extended=False)

        skipped = {(item["server"], item["tool"]) for item in report["checks"] if item["status"] == "skipped"}
        self.assertIn(("investigate", "get_incident_casefile"), skipped)
        self.assertIn(("respond", "update_incident"), skipped)
        self.assertIn(("respond", "update_alerts"), skipped)

    def test_cli_verify_live_json_dispatches(self) -> None:
        fake_report = {
            "summary": {"passed": 2, "failed": 0, "skipped": 0},
            "checks": [],
        }

        with patch("cortex_xdr_mcp.__main__.verify_live_main", return_value=0) as mocked:
            exit_code = __main__.main(["verify-live", "--json"])

        self.assertEqual(exit_code, 0)
        mocked.assert_called_once_with(["--json"])

    def test_verify_live_main_emits_json_and_returns_failure_code(self) -> None:
        fake_report = {
            "generated_at": "2026-03-25T00:00:00Z",
            "summary": {"passed": 1, "failed": 1, "skipped": 0},
            "checks": [],
        }

        with patch("cortex_xdr_mcp.verify_live.run_live_verification", return_value=fake_report):
            from cortex_xdr_mcp import verify_live

            stdout = io.StringIO()
            with patch("sys.stdout", stdout):
                exit_code = verify_live.main(["--json"])

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(stdout.getvalue()), fake_report)
