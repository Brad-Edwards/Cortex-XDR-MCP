"""CLI entrypoints for the curated Cortex XDR MCP servers."""

from __future__ import annotations

import sys

from . import __version__
from .client import CortexXdrClient
from .config import CortexXdrConfig
from .logging_utils import configure_logging
from .service import XdrService
from .servers import admin, engineer, investigate, respond
from .verify_live import main as verify_live_main


def _build_service() -> XdrService:
    config = CortexXdrConfig.from_env()
    client = CortexXdrClient(config)
    return XdrService(client)


def _run(server_name: str) -> int:
    configure_logging()
    service = _build_service()
    builders = {
        "investigate": investigate.build_server,
        "cortex-xdr-investigate": investigate.build_server,
        "respond": respond.build_server,
        "cortex-xdr-respond": respond.build_server,
        "engineer": engineer.build_server,
        "cortex-xdr-engineer": engineer.build_server,
        "admin": admin.build_server,
        "cortex-xdr-admin": admin.build_server,
    }
    builder = builders.get(server_name)
    if builder is None:
        raise SystemExit(
            "Usage: python -m cortex_xdr_mcp [investigate|respond|engineer|admin]"
        )
    builder(service, __version__).run_stdio()
    return 0


def investigate_entry() -> None:
    _run("investigate")


def respond_entry() -> None:
    _run("respond")


def engineer_entry() -> None:
    _run("engineer")


def admin_entry() -> None:
    _run("admin")


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        raise SystemExit(
            "Usage: python -m cortex_xdr_mcp [investigate|respond|engineer|admin|verify-live]"
        )
    if args[0] == "verify-live":
        return verify_live_main(args[1:])
    if len(args) != 1:
        raise SystemExit(
            "Usage: python -m cortex_xdr_mcp [investigate|respond|engineer|admin|verify-live]"
        )
    return _run(args[0])


if __name__ == "__main__":
    raise SystemExit(main())
