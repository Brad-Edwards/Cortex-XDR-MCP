"""Fake client helpers for unit tests."""

from __future__ import annotations

import copy
from collections import defaultdict
from typing import Any


class FakeClient:
    def __init__(self, responses: dict[tuple[str, str], Any] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[tuple[str, str, Any]] = []
        self._counters = defaultdict(int)

    def get(self, path: str) -> Any:
        return self._consume("GET", path, None)

    def post(self, path: str, payload: dict[str, Any] | None = None) -> Any:
        return self._consume("POST", path, payload)

    def _consume(self, method: str, path: str, payload: Any) -> Any:
        key = (method, path)
        self.calls.append((method, path, copy.deepcopy(payload)))
        if key not in self.responses:
            raise AssertionError(f"Unexpected {method} call for {path}")
        response = self.responses[key]
        if callable(response):
            return copy.deepcopy(response(payload))
        if isinstance(response, Exception):
            raise copy.deepcopy(response)
        if isinstance(response, list):
            index = self._counters[key]
            if index >= len(response):
                raise AssertionError(f"No more queued responses for {method} {path}")
            self._counters[key] += 1
            queued_response = response[index]
            if isinstance(queued_response, Exception):
                raise copy.deepcopy(queued_response)
            return copy.deepcopy(queued_response)
        return copy.deepcopy(response)
