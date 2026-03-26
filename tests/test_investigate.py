from __future__ import annotations

import unittest

from cortex_xdr_mcp.errors import ApiError
from cortex_xdr_mcp.service import XdrService

from .fakes import FakeClient


class InvestigateServiceTests(unittest.TestCase):
    def test_get_incident_casefile_composes_extra_data_events_and_pcap(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/incidents/get_incident_extra_data"): {
                    "reply": {
                        "incident": {
                            "incident_id": "42",
                            "incident_name": "Credential Theft",
                            "status": "new",
                            "severity": "high",
                            "alert_count": 1,
                        },
                        "alerts": {
                            "data": [
                                {
                                    "alert_id": "101",
                                    "name": "Suspicious process",
                                    "severity": "high",
                                    "host_name": "wkstn-7",
                                    "endpoint_id": "ep-1",
                                }
                            ]
                        },
                        "network_artifacts": {"data": [{"type": "IP", "network_remote_ip": "8.8.8.8"}]},
                        "file_artifacts": {"data": [{"file_name": "evil.exe"}]},
                    }
                },
                ("POST", "/public_api/v2/alerts/get_alerts_multi_events"): {
                    "reply": {
                        "alerts": [
                            {
                                "alert_id": "101",
                                "name": "Suspicious process",
                                "severity": "high",
                                "event_id": ["evt-1", "evt-2"],
                                "event_type": ["PROCESS"],
                                "mitre_technique_id_and_name": ["T1059 - Command and Scripting Interpreter"],
                            }
                        ]
                    }
                },
                ("POST", "/public_api/v1/alerts/get_alerts_pcap"): {
                    "reply": {"alerts": [{"id": "101", "pcap_data": "encoded"}]}
                },
            }
        )
        service = XdrService(client)

        result = service.get_incident_casefile(
            {
                "incident_id": "42",
                "include_event_summaries": True,
                "include_pcap_metadata": True,
            }
        )

        self.assertEqual(result["incident"]["incident_id"], "42")
        self.assertEqual(result["alerts"][0]["alert_id"], "101")
        self.assertEqual(result["alert_event_summaries"][0]["event_count"], 2)
        self.assertEqual(result["pcap_metadata"][0]["id"], "101")
        pcap_request = client.calls[2][2]
        self.assertEqual(
            pcap_request["request_data"]["filters"][0]["field"],
            "alert_id_list",
        )

    def test_get_endpoint_context_enriches_with_risk(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/endpoints/get_endpoint"): {
                    "reply": {
                        "endpoints": [
                            {
                                "endpoint_id": "ep-1",
                                "endpoint_name": "wkstn-7",
                                "endpoint_status": "connected",
                                "assigned_prevention_policy": "Standard",
                                "users": ["alex"],
                                "is_isolated": "unisolated",
                            }
                        ]
                    }
                },
                ("POST", "/public_api/v1/get_risk_score"): {
                    "reply": {"id": "wkstn-7", "score": 95, "risk_level": "HIGH"}
                },
            }
        )
        service = XdrService(client)

        result = service.get_endpoint_context({"hostname": "wkstn-7"})

        self.assertEqual(result["endpoint"]["endpoint_id"], "ep-1")
        self.assertEqual(result["endpoint"]["risk"]["score"], 95)

    def test_get_endpoint_context_tolerates_risk_lookup_failures(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/endpoints/get_endpoint"): {
                    "reply": {
                        "endpoints": [
                            {
                                "endpoint_id": "ep-1",
                                "endpoint_name": "wkstn-7",
                                "endpoint_status": "connected",
                            }
                        ]
                    }
                },
                ("POST", "/public_api/v1/get_risk_score"): ApiError("No identity threat", status_code=403),
            }
        )
        service = XdrService(client)

        result = service.get_endpoint_context({"hostname": "wkstn-7"})

        self.assertIsNone(result["endpoint"]["risk"])

    def test_list_incidents_returns_next_cursor_when_more_results_exist(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/incidents/get_incidents"): {
                    "reply": {
                        "total_count": 3,
                        "result_count": 2,
                        "incidents": [
                            {"incident_id": "1", "incident_name": "one"},
                            {"incident_id": "2", "incident_name": "two"},
                        ],
                    }
                }
            }
        )
        service = XdrService(client)

        result = service.list_incidents({"limit": 2})

        self.assertTrue(result["truncated"])
        self.assertEqual(result["next_cursor"], 2)
        self.assertEqual(result["count"], 2)

    def test_run_xql_polls_until_success(self) -> None:
        client = FakeClient(
            {
                ("POST", "/public_api/v1/xql/start_xql_query"): {"reply": "qid-1"},
                ("POST", "/public_api/v1/xql/get_query_results"): [
                    {"reply": {"status": "PENDING"}},
                    {
                        "reply": {
                            "status": "SUCCESS",
                            "query_cost": {"tenant": 0.1},
                            "remaining_quota": 4.9,
                            "results": {"data": [{"event_id": "evt-1", "event_type": "PROCESS"}]},
                        }
                    },
                ],
            }
        )
        service = XdrService(client)

        result = service.run_xql({"query": "dataset=xdr_data | limit 1", "wait_for_completion_seconds": 1})

        self.assertEqual(result["query_id"], "qid-1")
        self.assertEqual(result["state"], "SUCCESS")
        self.assertEqual(result["row_count"], 1)
        self.assertEqual(result["schema"], ["event_id", "event_type"])


if __name__ == "__main__":
    unittest.main()
