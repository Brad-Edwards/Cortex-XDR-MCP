# Cortex-XDR-MCP

Curated MCP servers for Palo Alto Cortex XDR.

This repo intentionally does **not** convert the full Cortex XDR REST/OpenAPI surface into MCP tools. Instead, it exposes a smaller set of workflow-oriented tools split into four servers:

- `cortex-xdr-investigate`
- `cortex-xdr-respond`
- `cortex-xdr-engineer`
- `cortex-xdr-admin` (optional)

The implementation is dependency-light and uses only the Python standard library at runtime.

## Architecture

The repo is intentionally split into a few small layers:

- `client.py` handles signing, auth fallback, transport errors, gzip, and JSON decoding
- `service.py` owns the curated Cortex XDR workflows and input validation
- `servers/` exposes the workflow layer as MCP tool sets
- `mcp_runtime.py` provides the stdio MCP runtime
- `verify_live.py` runs a repeatable smoke test against a live tenant
- `tests/` covers transport, runtime, contracts, and service behavior

This keeps the MCP-facing tool design stable even when the underlying Cortex API is inconsistent.

## Why This Shape

The Cortex XDR OpenAPI spec in [notes/xdr_api/Cortex-XDR.json](/home/atomik/src/Cortex-XDR-MCP/notes/xdr_api/Cortex-XDR.json) is large and endpoint-heavy. This project follows a curated MCP design:

- no generic REST passthrough
- no raw `request_data` or filter-array tools
- read-heavy investigation separated from write-heavy response
- async Cortex workflows wrapped into single MCP tools where practical

## Servers

### `cortex-xdr-investigate`

Read-heavy tools for incident triage, endpoint context, risk review, and XQL hunts.

Tools:

- `list_incidents`
- `list_alerts`
- `get_incident_casefile`
- `search_endpoints`
- `get_endpoint_context`
- `list_risky_entities`
- `get_entity_risk`
- `run_xql`

### `cortex-xdr-respond`

Explicit-ID response tools for containment and remediation.

Tools:

- `update_incident`
- `update_alerts`
- `set_endpoint_isolation`
- `set_file_quarantine_state`
- `scan_endpoints`
- `retrieve_endpoint_files`
- `run_endpoint_script`
- `run_forensics_triage`
- `manage_hash_reputation`
- `check_job_status`

### `cortex-xdr-engineer`

Security engineering and endpoint policy workflows.

Tools:

- `list_profiles`
- `manage_prevention_profile`
- `manage_exception_rule`
- `manage_prevention_override`
- `manage_iocs`
- `manage_endpoint_tags`
- `manage_agent_packages`
- `list_device_control_violations`

### `cortex-xdr-admin`

Optional tenant/admin surface. Keep this detached from default analyst agents.

Tools:

- `get_tenant_info`
- `list_rbac_users`
- `list_rbac_roles`
- `list_user_groups`
- `set_user_role`
- `manage_syslog_integration`
- `manage_authentication_settings`
- `list_audit_logs`
- `manage_xql_dataset`
- `manage_lookup_dataset`

## Configuration

Set these environment variables before starting any server:

- `CORTEX_XDR_BASE_URL`
- `CORTEX_XDR_API_KEY`
- `CORTEX_XDR_API_KEY_ID`

Optional:

- `CORTEX_XDR_TIMEOUT_SECONDS` default: `60`
- `CORTEX_XDR_VERIFY_TLS` default: `true`
- `CORTEX_XDR_AUTH_MODE` default: `auto`
- `CORTEX_XDR_MCP_LOG_LEVEL` default: `INFO`

`CORTEX_XDR_AUTH_MODE=auto` will try standard public API auth first and automatically fall back to advanced signed auth with `X-XDR-NONCE` and `X-XDR-TIMESTAMP` if the tenant rejects the standard header form.

Logging is written to stderr so MCP stdio traffic on stdout stays clean. Set `CORTEX_XDR_MCP_LOG_LEVEL=DEBUG` when you need request-level troubleshooting.

An example is provided in [.env.example](/home/atomik/src/Cortex-XDR-MCP/.env.example).

## Safety And Validation

The public MCP surface is designed to make mistakes harder:

- mutating tools require a non-empty `reason`
- mutating tools require `confirm=true` unless `dry_run=true`
- unsafe free-form raw REST arguments are intentionally not exposed
- list/search pagination is capped and normalized internally
- tool inputs are validated before API calls are made
- API and runtime failures are returned as structured errors

## Running

### Development mode

Use `PYTHONPATH=src` directly from the repo:

```bash
PYTHONPATH=src python3 -m cortex_xdr_mcp investigate
PYTHONPATH=src python3 -m cortex_xdr_mcp respond
PYTHONPATH=src python3 -m cortex_xdr_mcp engineer
PYTHONPATH=src python3 -m cortex_xdr_mcp admin
PYTHONPATH=src python3 -m cortex_xdr_mcp verify-live
```

### Installed mode

Install the package locally and use the generated scripts:

```bash
uv pip install -e .
cortex-xdr-investigate
cortex-xdr-respond
cortex-xdr-engineer
cortex-xdr-admin
cortex-xdr-verify-live
```

## Live Verification

You can run a repeatable smoke test against a live Cortex XDR tenant without mutating state:

```bash
PYTHONPATH=src python3 -m cortex_xdr_mcp verify-live
```

Useful flags:

- `--json` for machine-readable output
- `--no-admin` to skip admin-surface probes
- `--no-extended` to skip the extra endpoint engineering and RBAC probes
- `--tool-timeout 60` to increase per-tool timeout
- `--xql-wait 30` to give the XQL smoke query a longer completion window

The verifier:

- runs a direct health check to confirm auth
- exercises representative MCP tools over stdio
- uses only `dry_run=true` for write-capable tools
- annotates known `403` and feature-gated failures with spec-based hints

## Testing

Run the unit and contract tests with:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -t .
python3 -m compileall src
```

The test suite is meant to fail loudly on:

- auth and transport regressions
- MCP protocol/runtime regressions
- service request-shape drift
- input-validation changes that accidentally broaden unsafe behavior

If you add or change a tool, update both the tool-specific unit tests and the contract tests.

## Notes

- The implementation currently stays within the provided Cortex XDR API scope.
- The strict XDR spec does not expose a first-class vulnerability API, so the design emphasizes investigation, response, and engineering workflows instead.
- The optional admin server exists, but it should not be attached by default in low-trust agent setups.
- The client supports both standard and advanced Cortex XDR API authentication modes.
- Some Cortex XDR endpoints are still tenant- or feature-gated even when they exist in the spec; `verify-live` helps separate code issues from tenant capability issues.
