"""Configuration and policy models for Phylax."""

from __future__ import annotations

from pathlib import Path
import re

from pydantic import BaseModel, Field, model_validator
import yaml


class Policy(BaseModel):
    """Represents a single security/compliance rule."""

    id: str = Field(..., description="Unique policy identifier")
    type: str = Field(..., description="Policy engine type - e.g. regex, spdx, custom")
    pattern: str | None = Field(
        None, description="Regex pattern or other matcher, depending on type"
    )
    severity: str = Field("medium", description="low | medium | high | critical")
    trigger: str = Field(
        "log", description="raise | log | human_review | quarantine | mitigate"
    )
    allowed: list[str] | None = Field(
        None, description="Allow-list for SPDX or other list-based checks"
    )
    scope: list[str] | None = Field(
        None,
        description="Scope of monitoring: input, output, network, file, console, analysis",
    )

    # compiled regex is not a pydantic field (private attr)
    _compiled: re.Pattern[str] | None = None

    @model_validator(mode="after")  # type: ignore[misc]
    def _compile_regex(self) -> Policy:
        """Compile regex pattern after validation."""
        if self.type == "regex" and self.pattern:
            self._compiled = re.compile(self.pattern, re.MULTILINE | re.IGNORECASE)
        return self

    def matches(self, data: str | bytes) -> bool:
        """Return True if *data* violates this policy."""
        if self.type == "regex":
            txt = data.decode() if isinstance(data, bytes) else data
            return bool(self._compiled and self._compiled.search(txt))
        if self.type == "spdx":
            if not isinstance(data, str):
                return False
            return data not in (self.allowed or [])
        if self.type == "custom":
            func = getattr(self, "custom_func", None)
            return bool(func and func(data))
        raise ValueError(f"Unknown policy type: {self.type}")

    def applies_to_scope(self, scope: str) -> bool:
        """Check if policy applies to the given scope."""
        if not self.scope:
            return True  # No scope restriction means applies to all
        return scope in self.scope


class PhylaxConfig(BaseModel):
    """Top-level config object - version & list of policies."""

    version: int = 1
    policies: list[Policy]

    @classmethod
    def from_yaml(cls, path: str | Path | bytes) -> PhylaxConfig:
        """Parse YAML string or file into a config object."""
        content = str(path)

        # Check if it's a file path (simple heuristic: single line, reasonable length, no newlines)
        max_path_length = 500
        if (
            isinstance(path, str | Path)
            and len(content) < max_path_length
            and "\n" not in content
            and content.strip()
        ):
            try:
                path_obj = Path(content)
                if path_obj.exists():
                    content = path_obj.read_text()
            except (OSError, ValueError):
                # If path operations fail, treat as YAML string
                pass

        data = yaml.safe_load(content)
        return cls(**data)
