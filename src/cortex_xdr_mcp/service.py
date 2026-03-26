"""Curated Cortex XDR workflows used by the MCP servers."""

from __future__ import annotations

import time
from typing import Any, Protocol

from .errors import ApiError, ToolInputError
from .helpers import (
    NON_TERMINAL_ACTION_STATES,
    TERMINAL_JOB_STATES,
    compact_list,
    first_non_empty,
    include_raw_payload,
    limit_value,
    parse_time_range,
    require_int,
    require_list_of_strings,
    require_object,
    require_string,
    validate_write_intent,
)
from .logging_utils import get_logger


logger = get_logger(__name__)


class ApiClient(Protocol):
    def get(self, path: str) -> Any: ...
    def post(self, path: str, payload: dict[str, Any] | None = None) -> Any: ...


class XdrService:
    """High-level workflows that hide raw request_data/filter internals."""

    def __init__(self, client: ApiClient) -> None:
        self.client = client

    def list_incidents(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = limit_value(arguments.get("limit"), default=25, maximum=100)
        statuses = arguments.get("statuses")
        search_text = arguments.get("search_text")
        alert_sources = arguments.get("alert_sources")
        starred = arguments.get("starred")
        include_raw = bool(arguments.get("include_raw", False))
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))
        sort_order = arguments.get("sort_order", "desc")
        if sort_order not in {"asc", "desc"}:
            raise ToolInputError("sort_order must be 'asc' or 'desc'")

        filters: list[dict[str, Any]] = []
        if statuses is not None:
            filters.append({"field": "status", "operator": "in", "value": require_list_of_strings(statuses, "statuses")})
        if alert_sources is not None:
            filters.append({"field": "alert_sources", "operator": "in", "value": require_list_of_strings(alert_sources, "alert_sources")})
        if search_text:
            filters.append({"field": "description", "operator": "contains", "value": require_string(search_text, "search_text")})
        if isinstance(starred, bool):
            filters.append({"field": "starred", "operator": "eq", "value": starred})
        if start_ms is not None:
            filters.append({"field": "creation_time", "operator": "gte", "value": start_ms})
            filters.append({"field": "creation_time", "operator": "lte", "value": end_ms})

        page = self._paged_fetch(
            path="/public_api/v1/incidents/get_incidents",
            limit=limit,
            page_size=100,
            filters=filters,
            sort={"field": "creation_time", "keyword": sort_order},
            item_key="incidents",
        )
        items = [self._normalize_incident(item) for item in page["items"]]
        result = {
            "items": items,
            "count": len(items),
            "truncated": page["truncated"],
        }
        if page["next_cursor"] is not None:
            result["next_cursor"] = page["next_cursor"]
        return include_raw_payload(result, include_raw, page["raw_pages"])

    def list_alerts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = limit_value(arguments.get("limit"), default=25, maximum=100)
        include_raw = bool(arguments.get("include_raw", False))
        severities = arguments.get("severities")
        alert_sources = arguments.get("alert_sources")
        alert_ids = arguments.get("alert_ids")
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))
        sort_order = arguments.get("sort_order", "desc")
        if sort_order not in {"asc", "desc"}:
            raise ToolInputError("sort_order must be 'asc' or 'desc'")

        filters: list[dict[str, Any]] = []
        if severities is not None:
            filters.append({"field": "severity", "operator": "in", "value": require_list_of_strings(severities, "severities")})
        if alert_sources is not None:
            filters.append({"field": "alert_source", "operator": "in", "value": require_list_of_strings(alert_sources, "alert_sources")})
        if alert_ids is not None:
            filters.append(
                {
                    "field": "alert_id_list",
                    "operator": "in",
                    "value": [int(value) for value in require_list_of_strings([str(v) for v in alert_ids], "alert_ids")],
                }
            )
        if start_ms is not None:
            filters.append({"field": "creation_time", "operator": "gte", "value": start_ms})
            filters.append({"field": "creation_time", "operator": "lte", "value": end_ms})

        page = self._paged_fetch(
            path="/public_api/v1/alerts/get_alerts",
            limit=limit,
            page_size=100,
            filters=filters,
            sort={"field": "creation_time", "keyword": sort_order},
            item_key="alerts",
        )
        items = [self._normalize_alert(item) for item in page["items"]]
        result = {
            "items": items,
            "count": len(items),
            "truncated": page["truncated"],
        }
        if page["next_cursor"] is not None:
            result["next_cursor"] = page["next_cursor"]
        return include_raw_payload(result, include_raw, page["raw_pages"])

    def get_incident_casefile(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident_id = require_string(arguments.get("incident_id"), "incident_id")
        include_event_summaries = bool(arguments.get("include_event_summaries", True))
        include_pcap_metadata = bool(arguments.get("include_pcap_metadata", False))
        include_raw = bool(arguments.get("include_raw", False))

        extra = self.client.post(
            "/public_api/v1/incidents/get_incident_extra_data",
            {"request_data": {"incident_id": incident_id}},
        )
        reply = extra.get("reply", {})
        incident = reply.get("incident", {})
        alerts_obj = reply.get("alerts", {})
        alerts = alerts_obj.get("data", [])
        alert_ids = [int(alert["alert_id"]) for alert in alerts if str(alert.get("alert_id", "")).isdigit()]

        event_summaries = []
        multi_events_raw = None
        if include_event_summaries and alert_ids:
            multi_events_raw = self.client.post(
                "/public_api/v2/alerts/get_alerts_multi_events",
                {
                    "request_data": {
                        "filters": [{"field": "alert_id_list", "operator": "in", "value": alert_ids}]
                    }
                },
            )
            event_summaries = [
                self._summarize_multi_event(alert) for alert in multi_events_raw.get("reply", {}).get("alerts", [])
            ]

        pcap_metadata = []
        pcap_raw = None
        if include_pcap_metadata and alert_ids:
            pcap_raw = self.client.post(
                "/public_api/v1/alerts/get_alerts_pcap",
                {
                    "request_data": {
                        "filters": [{"field": "alert_id_list", "operator": "in", "value": alert_ids}],
                        "search_from": 0,
                        "search_to": max(len(alert_ids), 1),
                    }
                },
            )
            pcap_metadata = pcap_raw.get("reply", {}).get("alerts", [])

        result = {
            "incident": self._normalize_incident(incident),
            "alerts": [self._normalize_alert(alert) for alert in alerts],
            "artifacts": {
                "network": reply.get("network_artifacts", {}).get("data", []),
                "files": reply.get("file_artifacts", {}).get("data", []),
            },
            "alert_event_summaries": event_summaries,
            "pcap_metadata": pcap_metadata,
        }
        raw = {"incident_extra_data": extra}
        if multi_events_raw is not None:
            raw["alert_multi_events"] = multi_events_raw
        if pcap_raw is not None:
            raw["pcap"] = pcap_raw
        return include_raw_payload(result, include_raw, raw)

    def search_endpoints(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = limit_value(arguments.get("limit"), default=25, maximum=100)
        include_raw = bool(arguments.get("include_raw", False))
        endpoint_ids = arguments.get("endpoint_ids")
        hostnames = arguments.get("hostnames")
        usernames = arguments.get("usernames")
        platforms = arguments.get("platforms")
        statuses = arguments.get("statuses")
        group_names = arguments.get("group_names")
        aliases = arguments.get("aliases")
        isolate_state = arguments.get("isolation_state")
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))

        filters: list[dict[str, Any]] = []
        if endpoint_ids is not None:
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": require_list_of_strings(endpoint_ids, "endpoint_ids")})
        if hostnames is not None:
            filters.append({"field": "hostname", "operator": "in", "value": require_list_of_strings(hostnames, "hostnames")})
        if usernames is not None:
            filters.append({"field": "username", "operator": "in", "value": require_list_of_strings(usernames, "usernames")})
        if platforms is not None:
            filters.append({"field": "platform", "operator": "in", "value": require_list_of_strings(platforms, "platforms")})
        if statuses is not None:
            filters.append({"field": "endpoint_status", "operator": "in", "value": require_list_of_strings(statuses, "statuses")})
        if group_names is not None:
            filters.append({"field": "group_name", "operator": "in", "value": require_list_of_strings(group_names, "group_names")})
        if aliases is not None:
            filters.append({"field": "alias", "operator": "in", "value": require_list_of_strings(aliases, "aliases")})
        if isolate_state is not None:
            filters.append({"field": "isolate", "operator": "in", "value": [require_string(isolate_state, "isolation_state")]})
        if start_ms is not None:
            filters.append({"field": "last_seen", "operator": "gte", "value": start_ms})
            filters.append({"field": "last_seen", "operator": "lte", "value": end_ms})

        page = self._paged_fetch(
            path="/public_api/v1/endpoints/get_endpoint",
            limit=limit,
            page_size=100,
            filters=filters,
            sort={"field": "last_seen", "keyword": "DESC"},
            item_key="endpoints",
        )
        items = [self._normalize_endpoint(endpoint) for endpoint in page["items"]]
        result = {
            "items": items,
            "count": len(items),
            "truncated": page["truncated"],
        }
        if page["next_cursor"] is not None:
            result["next_cursor"] = page["next_cursor"]
        return include_raw_payload(result, include_raw, page["raw_pages"])

    def get_endpoint_context(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        endpoint_id = arguments.get("endpoint_id")
        hostname = arguments.get("hostname")
        if bool(endpoint_id) == bool(hostname):
            raise ToolInputError("Provide exactly one of endpoint_id or hostname")

        filters = []
        if endpoint_id:
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": [require_string(endpoint_id, "endpoint_id")]})
        else:
            filters.append({"field": "hostname", "operator": "in", "value": [require_string(hostname, "hostname")]})

        response = self.client.post(
            "/public_api/v1/endpoints/get_endpoint",
            {"request_data": {"search_from": 0, "search_to": 2, "filters": filters}},
        )
        endpoints = response.get("reply", {}).get("endpoints", [])
        if not endpoints:
            raise ToolInputError("No endpoint matched the requested identifier")
        if len(endpoints) > 1:
            raise ToolInputError("The requested identifier matched multiple endpoints")
        endpoint = endpoints[0]

        risk_raw = None
        risk = None
        risk_target = endpoint.get("endpoint_name") or endpoint.get("endpoint_id")
        if risk_target:
            try:
                risk_raw = self.client.post("/public_api/v1/get_risk_score", {"request_data": {"id": risk_target}})
                risk = risk_raw.get("reply")
            except ApiError as exc:
                logger.warning("Risk enrichment failed for endpoint %s: %s", risk_target, exc)
                risk = None

        context = self._normalize_endpoint(endpoint)
        context["risk"] = risk
        result = {"endpoint": context}
        raw = {"endpoint_lookup": response}
        if risk_raw is not None:
            raw["risk_score"] = risk_raw
        return include_raw_payload(result, include_raw, raw)

    def list_risky_entities(self, arguments: dict[str, Any]) -> dict[str, Any]:
        entity_type = require_string(arguments.get("entity_type", "hosts"), "entity_type").lower()
        limit = limit_value(arguments.get("limit"), default=25, maximum=200)
        include_raw = bool(arguments.get("include_raw", False))
        if entity_type not in {"hosts", "users"}:
            raise ToolInputError("entity_type must be 'hosts' or 'users'")

        path = "/public_api/v1/get_risky_hosts" if entity_type == "hosts" else "/public_api/v1/get_risky_users"
        raw = self.client.post(path, {})
        items = raw.get("reply", [])[:limit]
        result = {"items": items, "count": len(items), "truncated": len(raw.get("reply", [])) > limit}
        return include_raw_payload(result, include_raw, raw)

    def get_entity_risk(self, arguments: dict[str, Any]) -> dict[str, Any]:
        entity_id = require_string(arguments.get("entity_id"), "entity_id")
        include_raw = bool(arguments.get("include_raw", False))
        raw = self.client.post("/public_api/v1/get_risk_score", {"request_data": {"id": entity_id}})
        result = {"entity": raw.get("reply")}
        return include_raw_payload(result, include_raw, raw)

    def run_xql(self, arguments: dict[str, Any]) -> dict[str, Any]:
        query = require_string(arguments.get("query"), "query")
        include_raw = bool(arguments.get("include_raw", False))
        wait_seconds = arguments.get("wait_for_completion_seconds", 30)
        if not isinstance(wait_seconds, int) or wait_seconds < 0:
            raise ToolInputError("wait_for_completion_seconds must be a non-negative integer")

        request_data: dict[str, Any] = {"query": query}
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))
        if start_ms is not None:
            request_data["timeframe"] = {"from": start_ms, "to": end_ms}

        start_raw = self.client.post("/public_api/v1/xql/start_xql_query", {"request_data": request_data})
        query_id = start_raw.get("reply")
        if not isinstance(query_id, str):
            raise ToolInputError("Cortex XDR did not return a query identifier")

        deadline = time.time() + wait_seconds
        final_raw = None
        while True:
            final_raw = self.client.post("/public_api/v1/xql/get_query_results", {"request_data": {"query_id": query_id}})
            reply = final_raw.get("reply", {})
            status = reply.get("status")
            if status != "PENDING":
                break
            if time.time() >= deadline:
                break
            time.sleep(1)

        reply = final_raw.get("reply", {}) if isinstance(final_raw, dict) else {}
        rows = []
        truncated = False
        schema = []
        results = reply.get("results", {})
        data = results.get("data")
        if isinstance(data, list):
            rows = data
            if rows:
                schema = sorted(rows[0].keys())
        elif isinstance(data, str):
            rows = []
        if "stream_id" in results:
            truncated = True

        result = {
            "query_id": query_id,
            "state": reply.get("status", "UNKNOWN"),
            "rows": rows,
            "row_count": len(rows),
            "schema": schema,
            "truncated": truncated,
            "query_cost": reply.get("query_cost"),
            "remaining_quota": reply.get("remaining_quota"),
        }
        raw = {"start": start_raw, "results": final_raw}
        return include_raw_payload(result, include_raw, raw)

    def update_incident(self, arguments: dict[str, Any]) -> dict[str, Any]:
        incident_id = require_string(arguments.get("incident_id"), "incident_id")
        dry_run, reason = validate_write_intent(arguments)
        update_data = {
            "status": arguments.get("status"),
            "assigned_user_mail": arguments.get("assignee_email"),
            "manual_severity": arguments.get("severity"),
            "resolve_comment": arguments.get("resolve_comment"),
            "notes": arguments.get("notes"),
        }
        if arguments.get("comment"):
            update_data["comment"] = {"comment_action": "add", "value": require_string(arguments["comment"], "comment")}
        update_data = {key: value for key, value in update_data.items() if value not in (None, "", [])}
        if not update_data:
            raise ToolInputError("At least one incident field must be provided")

        payload = {"request_data": {"incident_id": incident_id, "update_data": update_data}}
        preview = {"operation": "update_incident", "incident_id": incident_id, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview

        raw = self.client.post("/public_api/v1/incidents/update_incident", payload)
        return {"operation": "update_incident", "incident_id": incident_id, "reason": reason, "result": raw}

    def update_alerts(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_ids = require_list_of_strings([str(value) for value in arguments.get("alert_ids", [])], "alert_ids")
        dry_run, reason = validate_write_intent(arguments)
        update_data = {
            "status": arguments.get("status"),
            "severity": arguments.get("severity"),
            "comment": arguments.get("comment"),
        }
        update_data = {key: value for key, value in update_data.items() if value not in (None, "", [])}
        if not update_data:
            raise ToolInputError("At least one alert field must be provided")
        payload = {"request_data": {"alert_id_list": alert_ids, "update_data": update_data}}
        preview = {"operation": "update_alerts", "alert_ids": alert_ids, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/alerts/update_alerts", payload)
        return {"operation": "update_alerts", "alert_ids": alert_ids, "reason": reason, "result": raw}

    def set_endpoint_isolation(self, arguments: dict[str, Any]) -> dict[str, Any]:
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        desired_state = require_string(arguments.get("desired_state"), "desired_state").lower()
        if desired_state not in {"isolated", "unisolated"}:
            raise ToolInputError("desired_state must be 'isolated' or 'unisolated'")
        dry_run, reason = validate_write_intent(arguments)
        incident_id = arguments.get("incident_id")

        payload = self._endpoint_targets_payload(endpoint_ids, incident_id=incident_id)
        path = "/public_api/v1/endpoints/isolate" if desired_state == "isolated" else "/public_api/v1/endpoints/unisolate"
        preview = {"operation": "set_endpoint_isolation", "desired_state": desired_state, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview

        raw = self.client.post(path, payload)
        action_id = first_non_empty(raw.get("reply", {}).get("action_id"), raw.get("reply", {}).get("group_action_id"))
        return self._complete_action_job(
            job_kind="endpoint_isolation",
            job_id=str(action_id),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
        )

    def set_file_quarantine_state(self, arguments: dict[str, Any]) -> dict[str, Any]:
        desired_state = require_string(arguments.get("desired_state"), "desired_state").lower()
        if desired_state not in {"quarantined", "restored"}:
            raise ToolInputError("desired_state must be 'quarantined' or 'restored'")
        dry_run, reason = validate_write_intent(arguments)
        file_hash = require_string(arguments.get("file_hash"), "file_hash")
        incident_id = arguments.get("incident_id")

        if desired_state == "quarantined":
            endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
            file_path = require_string(arguments.get("file_path"), "file_path")
            payload = {
                "request_data": {
                    "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}]
                }
            }
            payload["request_data"]["file_path"] = file_path
            payload["request_data"]["file_hash"] = file_hash
            if incident_id is not None:
                payload["request_data"]["incident_id"] = incident_id
            path = "/public_api/v1/endpoints/quarantine"
        else:
            payload = {"request_data": {"file_hash": file_hash}}
            endpoint_id = arguments.get("endpoint_id")
            if endpoint_id is not None:
                payload["request_data"]["endpoint_id"] = require_string(endpoint_id, "endpoint_id")
            if incident_id is not None:
                payload["request_data"]["incident_id"] = incident_id
            path = "/public_api/v1/endpoints/restore"

        preview = {"operation": "set_file_quarantine_state", "desired_state": desired_state, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview

        raw = self.client.post(path, payload)
        action_id = raw.get("reply", {}).get("action_id")
        return self._complete_action_job(
            job_kind="file_quarantine",
            job_id=str(action_id),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
        )

    def scan_endpoints(self, arguments: dict[str, Any]) -> dict[str, Any]:
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        dry_run, reason = validate_write_intent(arguments)
        incident_id = arguments.get("incident_id")
        payload = {
            "request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}]
            }
        }
        if incident_id is not None:
            payload["request_data"]["incident_id"] = incident_id
        preview = {"operation": "scan_endpoints", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/endpoints/scan", payload)
        return self._complete_action_job(
            job_kind="endpoint_scan",
            job_id=str(raw.get("reply", {}).get("action_id")),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
        )

    def retrieve_endpoint_files(self, arguments: dict[str, Any]) -> dict[str, Any]:
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        files = arguments.get("files")
        if not isinstance(files, dict) or not compact_list([files.get("windows"), files.get("linux"), files.get("macos")]):
            raise ToolInputError("files must include at least one non-empty OS-specific path list")
        normalized_files = {
            key: require_list_of_strings(value, f"files.{key}")
            for key, value in files.items()
            if key in {"windows", "linux", "macos"} and value
        }
        if not normalized_files:
            raise ToolInputError("files must include at least one non-empty OS-specific path list")
        dry_run, reason = validate_write_intent(arguments)
        payload = {
            "request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}]
            }
        }
        if arguments.get("incident_id") is not None:
            payload["request_data"]["incident_id"] = arguments["incident_id"]
        payload["request_data"]["files"] = normalized_files
        preview = {"operation": "retrieve_endpoint_files", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/endpoints/file_retrieval", payload)
        return self._complete_action_job(
            job_kind="file_retrieval",
            job_id=str(raw.get("reply", {}).get("action_id")),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
            include_artifacts=True,
        )

    def run_endpoint_script(self, arguments: dict[str, Any]) -> dict[str, Any]:
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        script_uid = require_string(arguments.get("script_uid"), "script_uid")
        parameters = arguments.get("parameters") or {}
        if not isinstance(parameters, dict):
            raise ToolInputError("parameters must be an object")
        dry_run, reason = validate_write_intent(arguments)
        payload = {
            "request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}],
                "script_uid": script_uid,
            }
        }
        if parameters:
            payload["request_data"]["parameters_values"] = parameters
        if arguments.get("timeout_seconds") is not None:
            payload["request_data"]["timeout"] = arguments["timeout_seconds"]
        if arguments.get("incident_id") is not None:
            payload["request_data"]["incident_id"] = arguments["incident_id"]

        preview = {"operation": "run_endpoint_script", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/scripts/run_script", payload)
        return self._complete_script_job(
            job_kind="endpoint_script",
            job_id=str(raw.get("reply", {}).get("action_id")),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
        )

    def run_forensics_triage(self, arguments: dict[str, Any]) -> dict[str, Any]:
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        dry_run, reason = validate_write_intent(arguments)
        payload = {"request_data": {"agent_ids": endpoint_ids}}
        if arguments.get("collector_uuid") is not None:
            payload["request_data"]["collector_uuid"] = require_string(arguments["collector_uuid"], "collector_uuid")
        preview = {"operation": "run_forensics_triage", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/triage_endpoint", payload)
        action_id = first_non_empty(raw.get("reply", {}).get("group_action_id"), raw.get("reply", {}).get("GROUP_ACTION_ID"))
        return self._complete_action_job(
            job_kind="forensics_triage",
            job_id=str(action_id),
            reason=reason,
            initial_response=raw,
            wait_seconds=arguments.get("wait_for_completion_seconds", 30),
        )

    def manage_hash_reputation(self, arguments: dict[str, Any]) -> dict[str, Any]:
        reputation = require_string(arguments.get("reputation"), "reputation").lower()
        if reputation not in {"allowlist", "blocklist"}:
            raise ToolInputError("reputation must be 'allowlist' or 'blocklist'")
        hash_list = require_list_of_strings(arguments.get("hashes"), "hashes")
        dry_run, reason = validate_write_intent(arguments)
        payload = {"request_data": {"hash_list": hash_list}}
        comment = arguments.get("comment")
        if comment:
            payload["request_data"]["comment"] = require_string(comment, "comment")
        if arguments.get("incident_id") is not None:
            payload["request_data"]["incident_id"] = arguments["incident_id"]
        preview = {"operation": "manage_hash_reputation", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        path = "/public_api/v1/hash_exceptions/allowlist" if reputation == "allowlist" else "/public_api/v1/hash_exceptions/blocklist"
        raw = self.client.post(path, payload)
        return {
            "operation": "manage_hash_reputation",
            "reason": reason,
            "reputation": reputation,
            "completed": bool(raw),
            "result": raw,
        }

    def check_job_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        job_kind = require_string(arguments.get("job_kind"), "job_kind")
        job_id = require_string(arguments.get("job_id"), "job_id")
        if job_kind == "endpoint_script":
            status = self.client.post("/public_api/v1/scripts/get_script_execution_status", {"request_data": {"action_id": job_id}})
            state = status.get("reply", {}).get("general_status", "UNKNOWN")
            artifacts: Any = {}
            if state in TERMINAL_JOB_STATES:
                result = self.client.post("/public_api/v1/scripts/get_script_execution_results", {"request_data": {"action_id": job_id}})
                artifacts = result.get("reply")
            return {
                "job_kind": job_kind,
                "job_id": job_id,
                "state": state,
                "completed": state in TERMINAL_JOB_STATES,
                "artifacts": artifacts,
            }

        group_action_id = self._require_numeric_identifier(job_id, "job_id")
        status = self.client.post("/public_api/v1/actions/get_action_status", {"request_data": {"group_action_id": group_action_id}})
        return self._normalize_action_job(job_kind=job_kind, job_id=job_id, status_response=status)

    def list_profiles(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        category = require_string(arguments.get("category", "prevention"), "category")
        profile_ids = arguments.get("profile_ids")
        payload = {"request_data": {"type": category}}
        if profile_ids is not None:
            if not isinstance(profile_ids, list) or not profile_ids or any(isinstance(item, bool) or not isinstance(item, int) for item in profile_ids):
                raise ToolInputError("profile_ids must be a non-empty array of integers")
            payload["request_data"]["profile_ids"] = profile_ids
        raw = self.client.post("/public_api/v1/endpoints/get_profiles", payload)
        items = raw.get("reply", [])
        result = {"items": items, "count": len(items), "truncated": False}
        return include_raw_payload(result, include_raw, raw)

    def manage_prevention_profile(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))

        if action == "list_modules":
            payload = {
                "request_data": {
                    "profile_type": self._normalize_prevention_profile_type(
                        require_string(arguments.get("profile_type"), "profile_type")
                    ),
                    "platform": self._normalize_prevention_profile_platform(
                        require_string(arguments.get("platform"), "platform")
                    ),
                }
            }
            raw = self.client.post("/public_api/v1/profiles/prevention/get_modules", payload)
            return include_raw_payload({"action": action, "modules": raw.get("reply", raw)}, include_raw, raw)

        if action == "add_signer_cn":
            dry_run, reason = validate_write_intent(arguments)
            payload = {
                "request_data": {
                    "profile_name": require_string(arguments.get("profile_name"), "profile_name"),
                    "signers": require_list_of_strings(arguments.get("signer_common_names"), "signer_common_names"),
                }
            }
            preview = {"action": action, "reason": reason, "payload": payload}
            if dry_run:
                preview["dry_run"] = True
                return preview
            raw = self.client.post("/public_api/v1/profiles/add_signer_cn_to_allowlist", payload)
            return {"action": action, "reason": reason, "result": raw}

        dry_run, reason = validate_write_intent(arguments)
        if action == "create":
            profile = arguments.get("profile")
            profile = require_object(profile, "profile")
            payload = {
                "request_data": {
                    "name": require_string(profile.get("name"), "profile.name"),
                    "profile_type": self._normalize_prevention_profile_type(
                        require_string(profile.get("profile_type"), "profile.profile_type")
                    ),
                    "platform": self._normalize_prevention_profile_platform(
                        require_string(profile.get("platform"), "profile.platform")
                    ),
                    "modules": profile.get("modules"),
                }
            }
            if not isinstance(payload["request_data"]["modules"], dict) or not payload["request_data"]["modules"]:
                raise ToolInputError("profile.modules must be a non-empty object")
            if profile.get("description") is not None:
                payload["request_data"]["description"] = profile["description"]
            path = "/public_api/v1/profiles/prevention/add"
        elif action == "update":
            payload = {
                "request_data": {
                    "profile_id": arguments.get("profile_id"),
                    "update_data": arguments.get("update_data"),
                }
            }
            if not isinstance(payload["request_data"]["profile_id"], int):
                raise ToolInputError("profile_id must be an integer")
            if not isinstance(payload["request_data"]["update_data"], dict) or not payload["request_data"]["update_data"]:
                raise ToolInputError("update_data must be a non-empty object")
            update_data = payload["request_data"]["update_data"]
            if isinstance(update_data.get("profile_type"), str):
                update_data["profile_type"] = self._normalize_prevention_profile_type(update_data["profile_type"])
            if isinstance(update_data.get("platform"), str):
                update_data["platform"] = self._normalize_prevention_profile_platform(update_data["platform"])
            path = "/public_api/v1/profiles/prevention/edit"
        else:
            raise ToolInputError("action must be one of: create, update, list_modules, add_signer_cn")

        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def manage_exception_rule(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if action == "list":
            limit = limit_value(arguments.get("limit"), default=25, maximum=100)
            request_data: dict[str, Any] = {"search_from": 0, "search_to": limit}
            filters: list[dict[str, Any]] = []
            if arguments.get("platforms"):
                filters.append({"field": "platform", "operator": "in", "value": require_list_of_strings(arguments["platforms"], "platforms")})
            if arguments.get("module_ids"):
                filters.append({"field": "module", "operator": "in", "value": arguments["module_ids"]})
            if filters:
                request_data["filters"] = filters
            raw = self.client.post("/public_api/v1/legacy_exceptions/fetch", {"request_data": request_data})
            reply = raw.get("reply", {})
            items = reply.get("data") or reply.get("DATA") or []
            total_count = reply.get("total_count", reply.get("TOTAL_COUNT", len(items)))
            result = {"items": items[:limit], "count": len(items[:limit]), "truncated": len(items) < int(total_count)}
            if len(items) < int(total_count):
                result["next_cursor"] = len(items)
            return include_raw_payload(result, include_raw, raw)
        if action == "list_modules":
            raw = self.client.post("/public_api/v1/legacy_exceptions/get_modules", {})
            return include_raw_payload({"action": action, "modules": raw.get("reply", raw)}, include_raw, raw)

        dry_run, reason = validate_write_intent(arguments)
        if action == "create":
            rule = arguments.get("rule")
            rule = require_object(rule, "rule")
            payload = {
                "request_data": {
                    "name": require_string(rule.get("name"), "rule.name"),
                    "platform": require_string(rule.get("platform"), "rule.platform"),
                    "module": rule.get("module_id"),
                    "profile_ids": rule.get("profile_ids", []),
                    "status": require_string(rule.get("status"), "rule.status"),
                    "scope": require_string(rule.get("scope"), "rule.scope"),
                    "conditions": rule.get("conditions"),
                }
            }
            if payload["request_data"]["module"] is None:
                raise ToolInputError("rule.module_id is required")
            if not isinstance(payload["request_data"]["conditions"], dict):
                raise ToolInputError("rule.conditions must be an object")
            if rule.get("description") is not None:
                payload["request_data"]["description"] = rule["description"]
            path = "/public_api/v1/legacy_exceptions/add"
        elif action == "update":
            rule = arguments.get("rule")
            update_data = dict(require_object(rule, "rule"))
            if "module" not in update_data and "module_id" in update_data:
                update_data["module"] = update_data.pop("module_id")
            payload = {
                "request_data": {
                    "exception_id": require_string(arguments.get("exception_id"), "exception_id"),
                    "update_data": update_data,
                }
            }
            path = "/public_api/v1/legacy_exceptions/edit"
        elif action == "delete":
            payload = {
                "request_data": {
                    "exception_ids": require_list_of_strings(arguments.get("exception_ids"), "exception_ids")
                }
            }
            path = "/public_api/v1/legacy_exceptions/delete"
        else:
            raise ToolInputError("action must be one of: list, list_modules, create, update, delete")

        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def manage_prevention_override(self, arguments: dict[str, Any]) -> dict[str, Any]:
        override_type = require_string(arguments.get("override_type"), "override_type").lower()
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if override_type not in {"disable_prevention", "disable_injection"}:
            raise ToolInputError("override_type must be 'disable_prevention' or 'disable_injection'")

        if action == "list":
            path = (
                "/public_api/v1/disable_prevention/fetch"
                if override_type == "disable_prevention"
                else "/public_api/v1/disable_injection_prevention_rules/fetch"
            )
            raw = self.client.post(path, {"request_data": {}})
            reply = raw.get("reply", raw)
            items = reply.get("data", []) if isinstance(reply, dict) else reply
            count = len(items) if isinstance(items, list) else 0
            return include_raw_payload(
                {
                    "action": action,
                    "override_type": override_type,
                    "items": items if isinstance(items, list) else [],
                    "count": count,
                    "truncated": False,
                },
                include_raw,
                raw,
            )

        dry_run, reason = validate_write_intent(arguments)
        payload_rule = arguments.get("rule")
        path = None
        payload = None
        if isinstance(payload_rule, dict):
            payload_rule = dict(payload_rule)
            scope = payload_rule.get("scope")
            if isinstance(scope, str) and scope.lower() == "global":
                payload_rule.pop("profile_ids", None)
        if override_type == "disable_prevention":
            if action == "create":
                payload = {"request_data": payload_rule}
                path = "/public_api/v1/disable_prevention/add"
            elif action == "update":
                payload = {"request_data": payload_rule}
                path = "/public_api/v1/disable_prevention/edit"
            elif action == "delete":
                payload = {"request_data": {"rule_ids": require_list_of_strings(arguments.get("rule_ids"), "rule_ids")}}
                path = "/public_api/v1/disable_prevention/delete"
        else:
            if action == "create":
                payload = {"request_data": payload_rule}
                path = "/public_api/v1/disable_injection_prevention_rules/add"
            elif action == "disable":
                payload = {"request_data": {"rule_ids": require_list_of_strings(arguments.get("rule_ids"), "rule_ids")}}
                path = "/public_api/v1/disable_injection_prevention_rules/disable"

        if path is None or payload is None:
            if override_type == "disable_prevention":
                raise ToolInputError("disable_prevention supports only: list, create, update, delete")
            raise ToolInputError("disable_injection supports only: list, create, disable")
        if action in {"create", "update"}:
            payload_rule = require_object(payload_rule, "rule")

        preview = {"action": action, "override_type": override_type, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "override_type": override_type, "reason": reason, "result": raw}

    def manage_iocs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        mode = require_string(arguments.get("mode", "json"), "mode").lower()
        dry_run, reason = validate_write_intent(arguments)
        if mode == "json":
            indicators = arguments.get("indicators")
            if not isinstance(indicators, list) or not indicators:
                raise ToolInputError("indicators must be a non-empty array of objects")
            if any(not isinstance(item, dict) for item in indicators):
                raise ToolInputError("indicators must contain only objects")
            payload = {"request_data": indicators}
            path = "/public_api/v1/indicators/insert_jsons"
        elif mode == "csv":
            csv_data = arguments.get("csv_data")
            if not isinstance(csv_data, str) or not csv_data.strip():
                raise ToolInputError("csv_data must be a non-empty string")
            payload = {"request_data": csv_data}
            path = "/public_api/v1/indicators/insert_csv"
        else:
            raise ToolInputError("mode must be 'json' or 'csv'")

        preview = {"operation": "manage_iocs", "reason": reason, "mode": mode, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"operation": "manage_iocs", "reason": reason, "mode": mode, "result": raw}

    def manage_endpoint_tags(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        if action not in {"assign", "remove"}:
            raise ToolInputError("action must be 'assign' or 'remove'")
        endpoint_ids = require_list_of_strings(arguments.get("endpoint_ids"), "endpoint_ids")
        tag = require_string(arguments.get("tag"), "tag")
        dry_run, reason = validate_write_intent(arguments)
        payload = {
            "request_data": {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}]
            }
        }
        payload["request_data"]["tag"] = tag
        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        path = "/public_api/v1/tags/agents/assign" if action == "assign" else "/public_api/v1/tags/agents/remove"
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def manage_agent_packages(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if action == "list":
            raw = self.client.post(
                "/public_api/v1/distributions/get_distributions",
                {"request_data": {"search_from": 0, "search_to": 100}},
            )
            reply = raw.get("reply", {})
            items = reply.get("data", [])
            return include_raw_payload({"action": action, "items": items, "count": len(items), "truncated": False}, include_raw, raw)
        if action == "status":
            distribution_id = require_string(arguments.get("distribution_id"), "distribution_id")
            raw = self.client.post("/public_api/v1/distributions/get_status", {"request_data": {"distribution_id": distribution_id}})
            return include_raw_payload({"action": action, "distribution_id": distribution_id, "status": raw.get("reply", {}).get("status")}, include_raw, raw)
        if action == "download_url":
            distribution_id = require_string(arguments.get("distribution_id"), "distribution_id")
            package_type = require_string(arguments.get("package_type"), "package_type")
            raw = self.client.post(
                "/public_api/v1/distributions/get_dist_url",
                {"request_data": {"distribution_id": distribution_id, "package_type": package_type}},
            )
            return include_raw_payload({"action": action, "distribution_id": distribution_id, "download": raw.get("reply", raw)}, include_raw, raw)

        dry_run, reason = validate_write_intent(arguments)
        if action == "create":
            package = arguments.get("package")
            package = require_object(package, "package")
            payload = {"request_data": package}
            preview = {"action": action, "reason": reason, "payload": payload}
            if dry_run:
                preview["dry_run"] = True
                return preview
            raw = self.client.post("/public_api/v1/distributions/create", payload)
            return {
                "job_kind": "agent_package",
                "job_id": str(raw.get("reply", {}).get("distribution_id")),
                "state": "SUBMITTED",
                "completed": False,
                "reason": reason,
                "artifacts": {"distribution_id": raw.get("reply", {}).get("distribution_id")},
            }
        if action == "delete":
            distribution_ids = require_list_of_strings(arguments.get("distribution_ids"), "distribution_ids")
            preview = {"action": action, "reason": reason, "distribution_ids": distribution_ids}
            if dry_run:
                preview["dry_run"] = True
                return preview
            results = []
            for distribution_id in distribution_ids:
                raw = self.client.post(
                    "/public_api/v1/distributions/delete",
                    {"request_data": {"distribution_id": distribution_id}},
                )
                results.append({"distribution_id": distribution_id, "result": raw})
            return {"action": action, "reason": reason, "results": results}
        raise ToolInputError("action must be one of: create, status, download_url, list, delete")

    def list_device_control_violations(self, arguments: dict[str, Any]) -> dict[str, Any]:
        limit = limit_value(arguments.get("limit"), default=25, maximum=100)
        include_raw = bool(arguments.get("include_raw", False))
        endpoint_ids = arguments.get("endpoint_ids")
        usernames = arguments.get("usernames")
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))

        filters = []
        if endpoint_ids:
            filters.append({"field": "endpoint_id_list", "operator": "in", "value": require_list_of_strings(endpoint_ids, "endpoint_ids")})
        if usernames:
            filters.append({"field": "username", "operator": "in", "value": require_list_of_strings(usernames, "usernames")})
        if start_ms is not None:
            filters.append({"field": "timestamp", "operator": "gte", "value": start_ms})
            filters.append({"field": "timestamp", "operator": "lte", "value": end_ms})

        page = self._paged_fetch(
            path="/public_api/v1/device_control/get_violations",
            limit=limit,
            page_size=100,
            filters=filters,
            sort={"field": "timestamp", "keyword": "desc"},
            item_key="violations",
        )
        result = {"items": page["items"], "count": len(page["items"]), "truncated": page["truncated"]}
        if page["next_cursor"] is not None:
            result["next_cursor"] = page["next_cursor"]
        return include_raw_payload(result, include_raw, page["raw_pages"])

    def get_tenant_info(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        raw = self.client.post("/public_api/v1/system/get_tenant_info", {})
        return include_raw_payload({"tenant": raw.get("reply", raw)}, include_raw, raw)

    def list_rbac_users(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        raw = self.client.post("/public_api/v1/rbac/get_users", {"request_data": {}})
        items = raw.get("reply", [])
        if not isinstance(items, list):
            items = [items] if items else []
        result = {"items": items, "count": len(items), "truncated": False}
        return include_raw_payload(result, include_raw, raw)

    def list_rbac_roles(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        raw = self.client.post("/public_api/v1/rbac/get_roles", {"request_data": {}})
        items = self._flatten_reply_items(raw.get("reply", []))
        result = {"items": items, "count": len(items), "truncated": False}
        return include_raw_payload(result, include_raw, raw)

    def list_user_groups(self, arguments: dict[str, Any]) -> dict[str, Any]:
        include_raw = bool(arguments.get("include_raw", False))
        raw = self.client.post("/public_api/v1/rbac/get_user_group", {"request_data": {}})
        items = self._flatten_reply_items(raw.get("reply", []))
        result = {"items": items, "count": len(items), "truncated": False}
        return include_raw_payload(result, include_raw, raw)

    def set_user_role(self, arguments: dict[str, Any]) -> dict[str, Any]:
        user_email = require_string(arguments.get("user_email"), "user_email")
        role_name = require_string(arguments.get("role_name"), "role_name")
        dry_run, reason = validate_write_intent(arguments)
        payload = {"request_data": {"user_emails": [user_email], "role_name": role_name}}
        preview = {"operation": "set_user_role", "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post("/public_api/v1/rbac/set_user_role", payload)
        return {"operation": "set_user_role", "reason": reason, "result": raw}

    def manage_syslog_integration(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if action == "list":
            items: list[Any] = []
            raw_pages: list[Any] = []
            seen_ids: set[Any] = set()
            for status in ("ACTIVE", "INACTIVE", "ERROR", "DISABLED"):
                raw = self.client.post(
                    "/public_api/v1/integrations/syslog/get",
                    {"request_data": {"filters": [{"field": "status", "operator": "eq", "value": status}]}},
                )
                raw_pages.append(raw)
                page_items = raw.get("objects", [])
                if not isinstance(page_items, list):
                    continue
                for item in page_items:
                    item_id = item.get("SYSLOG_INTEGRATION_ID") if isinstance(item, dict) else None
                    dedupe_key = item_id if item_id is not None else repr(item)
                    if dedupe_key in seen_ids:
                        continue
                    seen_ids.add(dedupe_key)
                    items.append(item)
            return include_raw_payload(
                {"action": action, "items": items, "count": len(items), "truncated": False},
                include_raw,
                raw_pages,
            )
        dry_run, reason = validate_write_intent(arguments)
        integration = arguments.get("integration")
        selection = arguments.get("selection", arguments.get("request_data", {}))
        if action in {"create", "update"}:
            integration = require_object(integration, "integration")
            payload = {"request_data": integration}
            path = "/public_api/v1/integrations/syslog/create" if action == "create" else "/public_api/v1/integrations/syslog/update"
        elif action == "delete":
            selection = require_object(selection, "selection", allow_empty=True)
            payload = {"request_data": selection}
            path = "/public_api/v1/integrations/syslog/delete"
        elif action == "test":
            selection = require_object(selection, "selection", allow_empty=True)
            payload = {"request_data": selection}
            path = "/public_api/v1/integrations/syslog/test"
        else:
            raise ToolInputError("action must be one of: create, update, delete, list, test")
        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def manage_authentication_settings(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if action == "list":
            raw = self.client.post("/public_api/v1/authentication-settings/get/settings", {"request_data": {}})
            return include_raw_payload({"action": action, "items": raw.get("reply", raw)}, include_raw, raw)
        if action == "metadata":
            raw = self.client.post("/public_api/v1/authentication-settings/get/metadata", {"request_data": {}})
            return include_raw_payload({"action": action, "items": raw.get("reply", raw)}, include_raw, raw)

        dry_run, reason = validate_write_intent(arguments)
        settings = arguments.get("settings")
        selection = arguments.get("selection", arguments.get("request_data", {}))
        if action in {"create", "update"}:
            request_data = dict(require_object(settings, "settings"))
            if action == "update":
                current_domain_value = request_data.pop("current_domain_value", None)
                new_domain_value = request_data.pop("new_domain_value", None)
                if current_domain_value is None:
                    current_domain_value = request_data.pop("domain", None)
                if not isinstance(current_domain_value, str):
                    raise ToolInputError("settings.current_domain_value or settings.domain is required for update")
                request_data["current_domain_value"] = current_domain_value
                if new_domain_value is None:
                    new_domain_value = current_domain_value
                if new_domain_value is not None:
                    if not isinstance(new_domain_value, str):
                        raise ToolInputError("settings.new_domain_value must be a string")
                    request_data["new_domain_value"] = new_domain_value
            payload = {"request_data": request_data}
            path = "/public_api/v1/authentication-settings/create" if action == "create" else "/public_api/v1/authentication-settings/update"
        elif action == "delete":
            selection = require_object(selection, "selection", allow_empty=True)
            payload = {"request_data": selection}
            path = "/public_api/v1/authentication-settings/delete"
        else:
            raise ToolInputError("action must be one of: create, update, delete, list, metadata")
        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def list_audit_logs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        audit_type = require_string(arguments.get("audit_type", "management"), "audit_type").lower()
        include_raw = bool(arguments.get("include_raw", False))
        start_ms, end_ms = parse_time_range(arguments.get("time_range"))
        path = "/public_api/v1/audits/management_logs" if audit_type == "management" else "/public_api/v1/audits/agents_reports"
        request_data = {}
        if start_ms is not None:
            request_data["filters"] = [{"field": "timestamp", "operator": "gte", "value": start_ms}, {"field": "timestamp", "operator": "lte", "value": end_ms}]
        raw = self.client.post(path, {"request_data": request_data})
        return include_raw_payload({"audit_type": audit_type, "items": raw.get("reply", raw)}, include_raw, raw)

    def manage_xql_dataset(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        if action == "list":
            raw = self.client.post("/public_api/v1/xql/get_datasets", {"request_data": {}})
            return include_raw_payload({"action": action, "items": raw.get("reply", raw)}, include_raw, raw)
        dry_run, reason = validate_write_intent(arguments)
        dataset = require_object(arguments.get("dataset"), "dataset")
        payload = {"request_data": dataset}
        if action == "create":
            path = "/public_api/v1/xql/add_dataset"
        elif action == "delete":
            path = "/public_api/v2/xql/delete_dataset"
        else:
            raise ToolInputError("action must be one of: create, delete, list")
        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def manage_lookup_dataset(self, arguments: dict[str, Any]) -> dict[str, Any]:
        action = require_string(arguments.get("action"), "action").lower()
        include_raw = bool(arguments.get("include_raw", False))
        request_data = arguments.get("lookup", arguments.get("request_data", {}))
        request_data = require_object(request_data, "lookup", allow_empty=action == "get")
        if action == "get":
            raw = self.client.post("/public_api/v1/xql/lookups/get_data", {"request_data": request_data})
            reply = raw.get("reply", raw)
            items = reply.get("data", []) if isinstance(reply, dict) else reply
            result = {"action": action, "items": items if isinstance(items, list) else [], "count": len(items) if isinstance(items, list) else 0}
            return include_raw_payload(result, include_raw, raw)
        dry_run, reason = validate_write_intent(arguments)
        if action == "add":
            path = "/public_api/v1/xql/lookups/add_data"
        elif action == "remove":
            filters = request_data.get("filters")
            if isinstance(filters, dict):
                request_data = dict(request_data)
                request_data["filters"] = [filters]
            elif not isinstance(filters, list):
                raise ToolInputError("lookup.filters must be an object or an array for remove")
            path = "/public_api/v1/xql/lookups/remove_data"
        else:
            raise ToolInputError("action must be one of: add, remove, get")
        payload = {"request_data": request_data}
        preview = {"action": action, "reason": reason, "payload": payload}
        if dry_run:
            preview["dry_run"] = True
            return preview
        raw = self.client.post(path, payload)
        return {"action": action, "reason": reason, "result": raw}

    def _paged_fetch(
        self,
        *,
        path: str,
        limit: int,
        page_size: int,
        filters: list[dict[str, Any]],
        sort: dict[str, Any] | None,
        item_key: str,
    ) -> dict[str, Any]:
        items: list[Any] = []
        raw_pages: list[Any] = []
        offset = 0
        next_cursor = None
        truncated = False

        while len(items) < limit:
            remaining = limit - len(items)
            request_data: dict[str, Any] = {
                "search_from": offset,
                "search_to": offset + min(page_size, remaining),
            }
            if filters:
                request_data["filters"] = filters
            if sort:
                request_data["sort"] = sort
            raw = self.client.post(path, {"request_data": request_data})
            raw_pages.append(raw)
            reply = raw.get("reply", {})
            page_items = reply.get(item_key, [])
            if not isinstance(page_items, list):
                page_items = []
            items.extend(page_items[:remaining])
            result_count = int(reply.get("result_count", len(page_items) or 0))
            total_count = reply.get("total_count")

            if total_count is not None and offset + result_count < int(total_count):
                next_cursor = offset + result_count
                truncated = len(items) >= limit

            if result_count == 0 or result_count < min(page_size, remaining) or len(items) >= limit:
                break

            offset += result_count

        return {
            "items": items[:limit],
            "raw_pages": raw_pages,
            "truncated": truncated,
            "next_cursor": next_cursor if truncated else None,
        }

    def _endpoint_targets_payload(self, endpoint_ids: list[str], *, incident_id: Any | None = None) -> dict[str, Any]:
        request_data: dict[str, Any]
        if len(endpoint_ids) == 1:
            request_data = {"endpoint_id": endpoint_ids[0]}
        else:
            request_data = {
                "filters": [{"field": "endpoint_id_list", "operator": "in", "value": endpoint_ids}]
            }
        if incident_id is not None:
            request_data["incident_id"] = incident_id
        return {"request_data": request_data}

    def _complete_action_job(
        self,
        *,
        job_kind: str,
        job_id: str,
        reason: str,
        initial_response: Any,
        wait_seconds: int,
        include_artifacts: bool = False,
    ) -> dict[str, Any]:
        wait_seconds = require_int(wait_seconds, "wait_for_completion_seconds", minimum=0)
        group_action_id = self._require_numeric_identifier(job_id, "job_id")
        status_response = None
        deadline = time.time() + wait_seconds
        while True:
            status_response = self.client.post(
                "/public_api/v1/actions/get_action_status",
                {"request_data": {"group_action_id": group_action_id}},
            )
            normalized = self._normalize_action_job(job_kind=job_kind, job_id=job_id, status_response=status_response)
            if normalized["completed"] or time.time() >= deadline:
                if include_artifacts and normalized["completed"]:
                    try:
                        details = self.client.post(
                            "/public_api/v1/actions/file_retrieval_details",
                            {"request_data": {"group_action_id": group_action_id}},
                        )
                        normalized["artifacts"] = details.get("reply", {}).get("data", {})
                    except ApiError as exc:
                        logger.warning("File retrieval artifact lookup failed for job %s: %s", job_id, exc)
                normalized["reason"] = reason
                normalized["initial_response"] = initial_response
                return normalized
            time.sleep(1)

    def _complete_script_job(
        self,
        *,
        job_kind: str,
        job_id: str,
        reason: str,
        initial_response: Any,
        wait_seconds: int,
    ) -> dict[str, Any]:
        wait_seconds = require_int(wait_seconds, "wait_for_completion_seconds", minimum=0)
        deadline = time.time() + wait_seconds
        status_response = None
        while True:
            status_response = self.client.post(
                "/public_api/v1/scripts/get_script_execution_status",
                {"request_data": {"action_id": job_id}},
            )
            state = status_response.get("reply", {}).get("general_status", "UNKNOWN")
            completed = state in TERMINAL_JOB_STATES
            if completed or time.time() >= deadline:
                artifacts = {}
                if completed:
                    results = self.client.post(
                        "/public_api/v1/scripts/get_script_execution_results",
                        {"request_data": {"action_id": job_id}},
                    )
                    artifacts = results.get("reply", {})
                return {
                    "job_kind": job_kind,
                    "job_id": job_id,
                    "state": state,
                    "completed": completed,
                    "reason": reason,
                    "artifacts": artifacts,
                    "initial_response": initial_response,
                }
            time.sleep(1)

    def _normalize_action_job(self, *, job_kind: str, job_id: str, status_response: Any) -> dict[str, Any]:
        statuses = status_response.get("reply", {}).get("data", {})
        if not isinstance(statuses, dict):
            statuses = {}
        state_values = set(statuses.values())
        completed = bool(state_values) and state_values.issubset(TERMINAL_JOB_STATES)
        if not state_values:
            state = "UNKNOWN"
        elif state_values == {"COMPLETED_SUCCESSFULLY"}:
            state = "COMPLETED_SUCCESSFULLY"
        elif state_values.intersection(NON_TERMINAL_ACTION_STATES):
            state = "IN_PROGRESS"
        elif "FAILED" in state_values or "TIMEOUT" in state_values:
            state = "FAILED"
        elif "COMPLETED_PARTIAL" in state_values:
            state = "COMPLETED_PARTIAL"
        else:
            state = ",".join(sorted(state_values))
        return {
            "job_kind": job_kind,
            "job_id": job_id,
            "state": state,
            "completed": completed,
            "artifacts": statuses,
        }

    def _flatten_reply_items(self, reply: Any) -> list[Any]:
        items: list[Any] = []
        if isinstance(reply, list):
            for entry in reply:
                if isinstance(entry, list):
                    items.extend(item for item in entry if isinstance(item, dict))
                elif isinstance(entry, dict):
                    items.append(entry)
        return items

    def _require_numeric_identifier(self, value: Any, field_name: str) -> int:
        if isinstance(value, bool):
            raise ToolInputError(f"{field_name} must be a numeric identifier")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        raise ToolInputError(f"{field_name} must be a numeric identifier")

    def _normalize_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        return {
            "incident_id": incident.get("incident_id"),
            "name": incident.get("incident_name"),
            "status": incident.get("status"),
            "severity": first_non_empty(incident.get("manual_severity"), incident.get("severity")),
            "description": incident.get("description"),
            "assigned_user_email": incident.get("assigned_user_mail"),
            "alert_count": incident.get("alert_count"),
            "hosts": incident.get("hosts", []),
            "users": incident.get("users", []),
            "creation_time": incident.get("creation_time"),
            "modification_time": incident.get("modification_time"),
            "xdr_url": incident.get("xdr_url"),
            "tags": incident.get("tags", []),
        }

    def _normalize_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": alert.get("alert_id"),
            "name": alert.get("name"),
            "severity": alert.get("severity"),
            "source": first_non_empty(alert.get("source"), alert.get("alert_source")),
            "host_name": alert.get("host_name"),
            "endpoint_id": alert.get("endpoint_id"),
            "user_names": compact_list(alert.get("user_name")),
            "detection_timestamp": alert.get("detection_timestamp"),
            "category": alert.get("category"),
            "status": first_non_empty(alert.get("resolution_status"), alert.get("status")),
            "is_pcap": alert.get("is_pcap"),
        }

    def _summarize_multi_event(self, alert: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": alert.get("alert_id"),
            "name": alert.get("name"),
            "severity": alert.get("severity"),
            "mitre_techniques": compact_list(alert.get("mitre_technique_id_and_name")),
            "mitre_tactics": compact_list(alert.get("mitre_tactic_id_and_name")),
            "host_name": alert.get("host_name"),
            "endpoint_id": alert.get("endpoint_id"),
            "event_types": compact_list(alert.get("event_type")),
            "event_count": len(compact_list(alert.get("event_id"))),
            "description": alert.get("description"),
        }

    def _normalize_endpoint(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        return {
            "endpoint_id": endpoint.get("endpoint_id"),
            "endpoint_name": first_non_empty(endpoint.get("endpoint_name"), endpoint.get("host_name")),
            "alias": endpoint.get("alias"),
            "status": first_non_empty(endpoint.get("endpoint_status"), endpoint.get("operational_status")),
            "os_type": endpoint.get("os_type"),
            "os_version": first_non_empty(endpoint.get("operating_system"), endpoint.get("os_version")),
            "last_seen": endpoint.get("last_seen"),
            "first_seen": endpoint.get("first_seen"),
            "users": compact_list(endpoint.get("users")),
            "ip_addresses": compact_list(endpoint.get("ip")),
            "public_ip": endpoint.get("public_ip"),
            "isolation_state": first_non_empty(endpoint.get("is_isolated"), endpoint.get("isolate")),
            "group_names": compact_list(endpoint.get("group_name")),
            "prevention_policy": first_non_empty(endpoint.get("assigned_prevention_policy"), endpoint.get("policy_name")),
            "extension_policy": endpoint.get("assigned_extensions_policy"),
        }

    def _normalize_prevention_profile_type(self, value: str) -> str:
        normalized = value.strip().lower()
        mapping = {
            "exploit": "Exploit",
            "malware": "Malware",
            "restrictions": "Restrictions",
            "agent settings": "Agent Settings",
            "agent_settings": "Agent Settings",
        }
        return mapping.get(normalized, value.strip())

    def _normalize_prevention_profile_platform(self, value: str) -> str:
        normalized = value.strip().lower()
        mapping = {
            "windows": "Windows",
            "macos": "macOS",
            "linux": "Linux",
            "android": "Android",
            "ios": "iOS",
            "serverless function": "Serverless Function",
            "serverless_function": "Serverless Function",
        }
        return mapping.get(normalized, value.strip())
