from __future__ import annotations

import unittest
from unittest.mock import patch

from cortex_xdr_mcp.errors import ToolInputError
from cortex_xdr_mcp.helpers import limit_value, parse_time_range, require_object, validate_write_intent


class HelperTests(unittest.TestCase):
    def test_parse_time_range_supports_last_hours(self) -> None:
        with patch("cortex_xdr_mcp.helpers.utc_now_ms", return_value=3_600_000):
            start_ms, end_ms = parse_time_range({"last_hours": 1})

        self.assertEqual(start_ms, 0)
        self.assertEqual(end_ms, 3_600_000)

    def test_parse_time_range_rejects_inverted_range(self) -> None:
        with self.assertRaises(ToolInputError):
            parse_time_range({"start": "2026-03-26T10:00:00Z", "end": "2026-03-26T09:00:00Z"})

    def test_validate_write_intent_requires_boolean_flags(self) -> None:
        with self.assertRaises(ToolInputError):
            validate_write_intent({"reason": "testing", "dry_run": "true"})

        with self.assertRaises(ToolInputError):
            validate_write_intent({"reason": "testing", "confirm": "true"})

    def test_limit_value_rejects_booleans(self) -> None:
        with self.assertRaises(ToolInputError):
            limit_value(True, default=1, maximum=10)

    def test_require_object_rejects_empty_object_by_default(self) -> None:
        with self.assertRaises(ToolInputError):
            require_object({}, "payload")


if __name__ == "__main__":
    unittest.main()
