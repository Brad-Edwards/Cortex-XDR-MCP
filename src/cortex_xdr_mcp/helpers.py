"""General helpers shared across tools."""

from __future__ import annotations

import datetime as dt
import json
import time
from typing import Any

from .errors import ToolInputError


TERMINAL_JOB_STATES = {
    "CANCELLED",
    "ABORTED",
    "EXPIRED",
    "COMPLETED_PARTIAL",
    "COMPLETED_SUCCESSFULLY",
    "FAILED",
    "TIMEOUT",
}
NON_TERMINAL_ACTION_STATES = {"PENDING", "IN_PROGRESS", "PENDING_ABORT"}


def utc_now_ms() -> int:
    return int(time.time() * 1000)


def iso_to_epoch_ms(value: str) -> int:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ToolInputError(f"Invalid ISO-8601 timestamp: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return int(parsed.timestamp() * 1000)


def parse_time_range(time_range: dict[str, Any] | None) -> tuple[int | None, int | None]:
    if not time_range:
        return None, None
    if not isinstance(time_range, dict):
        raise ToolInputError("time_range must be an object")

    if "last_hours" in time_range:
        last_hours = time_range["last_hours"]
        if not isinstance(last_hours, int) or last_hours <= 0:
            raise ToolInputError("time_range.last_hours must be a positive integer")
        end_ms = utc_now_ms()
        return end_ms - (last_hours * 60 * 60 * 1000), end_ms

    start = time_range.get("start")
    end = time_range.get("end")
    if not start or not end:
        raise ToolInputError("time_range must include either last_hours or both start and end")

    start_ms = iso_to_epoch_ms(start)
    end_ms = iso_to_epoch_ms(end)
    if start_ms > end_ms:
        raise ToolInputError("time_range.start must be before time_range.end")
    return start_ms, end_ms


def dump_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


def compact_list(values: list[Any] | None) -> list[Any]:
    if not values:
        return []
    return [value for value in values if value not in (None, "", [], {})]


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def require_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolInputError(f"{field_name} must be a non-empty string")
    return value.strip()


def require_bool(value: Any, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise ToolInputError(f"{field_name} must be a boolean")
    return value


def require_object(value: Any, field_name: str, *, allow_empty: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolInputError(f"{field_name} must be an object")
    if not allow_empty and not value:
        raise ToolInputError(f"{field_name} must be a non-empty object")
    return value


def require_int(value: Any, field_name: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolInputError(f"{field_name} must be an integer")
    if minimum is not None and value < minimum:
        if minimum == 0:
            raise ToolInputError(f"{field_name} must be a non-negative integer")
        raise ToolInputError(f"{field_name} must be at least {minimum}")
    return value


def require_list_of_strings(value: Any, field_name: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ToolInputError(f"{field_name} must be a non-empty array of strings")
    normalized = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ToolInputError(f"{field_name} must contain only non-empty strings")
        normalized.append(item.strip())
    return normalized


def maybe_list_of_strings(value: Any, field_name: str) -> list[str] | None:
    if value is None:
        return None
    return require_list_of_strings(value, field_name)


def limit_value(value: Any, *, default: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolInputError("limit must be a positive integer")
    return min(value, maximum)


def include_raw_payload(result: dict[str, Any], include_raw: bool, raw: Any) -> dict[str, Any]:
    if include_raw:
        result["raw"] = raw
    return result


def validate_write_intent(arguments: dict[str, Any]) -> tuple[bool, str]:
    dry_run_value = arguments.get("dry_run", False)
    if dry_run_value is None:
        dry_run_value = False
    dry_run = require_bool(dry_run_value, "dry_run")
    reason = require_string(arguments.get("reason"), "reason")
    confirm_value = arguments.get("confirm", False)
    if confirm_value is None:
        confirm_value = False
    confirm = require_bool(confirm_value, "confirm")
    if not dry_run and not confirm:
        raise ToolInputError("Mutating tools require confirm=true unless dry_run=true")
    return dry_run, reason
