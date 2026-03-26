# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-26

### Fixed
- Use public `ssl.create_default_context()` instead of private `ssl._create_unverified_context()` for TLS bypass
- `manage_iocs` CSV mode no longer strips trailing newlines from CSV data
- `manage_agent_packages` delete dry_run preview now shows all distribution IDs instead of only the first
- `list_rbac_users` return shape now includes `count` and `truncated` fields consistent with other list endpoints
- `verify_live.py` replaced `select.select()` with thread-based I/O deadlines for Windows compatibility
- Replaced private `client._resolved_auth_mode` access in verify_live with public `effective_auth_mode` property

### Changed
- Unified duplicate `TERMINAL_ACTION_STATES` and `TERMINAL_SCRIPT_STATES` into single `TERMINAL_JOB_STATES` constant
- Replaced Node.js `.gitignore` template with Python-appropriate entries
- Removed incorrect `OpenAI Codex` author attribution from `pyproject.toml`

### Added
- `py.typed` marker for PEP 561 type checking support
- `CHANGELOG.md`

## [0.1.0] - 2026-03-25

### Added
- Initial implementation with four curated MCP servers: investigate, respond, engineer, admin
- Zero-dependency HTTP client with standard and advanced Cortex XDR auth modes
- Stdio MCP runtime supporting initialize, ping, tools/list, and tools/call
- Live verification tool (`verify-live`) with spec-based 403 hints
- Safety guards: `reason` + `confirm` required for mutations, `dry_run` support throughout
- Unit and contract test suite
