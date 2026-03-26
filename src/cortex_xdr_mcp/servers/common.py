"""Shared schema fragments for the curated server surfaces."""

from __future__ import annotations

from typing import Any


def string_array(description: str) -> dict[str, Any]:
    return {"type": "array", "items": {"type": "string"}, "description": description}


def time_range_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "description": "Use either last_hours or both start and end ISO-8601 timestamps.",
        "properties": {
            "last_hours": {"type": "integer", "minimum": 1},
            "start": {"type": "string"},
            "end": {"type": "string"},
        },
        "additionalProperties": False,
    }


def base_read_properties() -> dict[str, Any]:
    return {
        "limit": {
            "type": "integer",
            "description": "Maximum number of items to return.",
            "minimum": 1,
            "maximum": 200,
        },
        "time_range": time_range_schema(),
        "include_raw": {
            "type": "boolean",
            "description": "Include the raw Cortex XDR API responses in the result.",
            "default": False,
        },
    }


def write_guard_properties() -> dict[str, Any]:
    return {
        "reason": {
            "type": "string",
            "description": "Human-readable reason for the action.",
        },
        "confirm": {
            "type": "boolean",
            "description": "Must be true to execute a mutating action unless dry_run=true.",
        },
        "dry_run": {
            "type": "boolean",
            "description": "Preview the resolved request without sending it to Cortex XDR.",
            "default": False,
        },
        "wait_for_completion_seconds": {
            "type": "integer",
            "description": "How long to wait for an async job before returning a resumable job handle.",
            "minimum": 0,
            "default": 30,
        },
    }
