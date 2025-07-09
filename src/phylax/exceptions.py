"""Exception classes for Phylax."""

from __future__ import annotations

from typing import Any

from .config import Policy


class PhylaxViolation(RuntimeError):
    """Raised (optionally) when a policy violation is set to `trigger=raise`."""

    def __init__(
        self, policy: Policy, sample: str, context: dict[str, Any] | None = None
    ):
        msg = (
            f"Policy '{policy.id}' ({policy.severity}) violated – trigger={policy.trigger}.\n"
            f"Sample: {sample[:120]}..."
        )
        super().__init__(msg)
        self.policy = policy
        self.sample = sample
        self.context = context or {}
