"""Configuration and policy models for Phylax."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, List, Optional

import yaml
from pydantic import BaseModel, Field, model_validator


class Policy(BaseModel):
    """Represents a single security/compliance rule."""

    id: str = Field(..., description="Unique policy identifier")
    type: str = Field(..., description="Policy engine type – e.g. regex, spdx, custom")
    pattern: Optional[str] = Field(
        None, description="Regex pattern or other matcher, depending on type"
    )
    severity: str = Field("medium", description="low | medium | high | critical")
    trigger: str = Field(
        "log", description="raise | log | human_review | quarantine | mitigate"
    )
    allowed: Optional[List[str]] = Field(
        None, description="Allow‑list for SPDX or other list‑based checks"
    )
    scope: Optional[List[str]] = Field(
        None, description="Scope of monitoring: input, output, network, file, console, analysis"
    )

    # compiled regex is not a pydantic field (private attr)
    _compiled: Optional[re.Pattern] = None

    @model_validator(mode='after')
    def _compile_regex(self):
        """Compile regex pattern after validation."""
        if self.type == "regex" and self.pattern:
            self._compiled = re.compile(self.pattern, re.MULTILINE | re.IGNORECASE)
        return self

    def matches(self, data: str | bytes) -> bool:
        """Return True if *data* violates this policy."""
        if self.type == "regex":
            if not isinstance(data, (str, bytes)):
                return False
            txt = data.decode() if isinstance(data, bytes) else data
            return bool(self._compiled and self._compiled.search(txt))
        elif self.type == "spdx":
            if not isinstance(data, str):
                return False
            return data not in (self.allowed or [])
        elif self.type == "custom":
            func = getattr(self, "custom_func", None)
            return bool(func and func(data))
        raise ValueError(f"Unknown policy type: {self.type}")

    def applies_to_scope(self, scope: str) -> bool:
        """Check if policy applies to the given scope."""
        if not self.scope:
            return True  # No scope restriction means applies to all
        return scope in self.scope


class PhylaxConfig(BaseModel):
    """Top‑level config object – version & list of policies."""

    version: int = 1
    policies: List[Policy]

    @classmethod
    def from_yaml(cls, path: str | Path | bytes | str) -> "PhylaxConfig":
        """Parse YAML string or file into a config object."""
        content = str(path)
        
        # Check if it's a file path (simple heuristic: single line, reasonable length, no newlines)
        if (isinstance(path, (str, Path)) and 
            len(content) < 500 and 
            '\n' not in content and 
            content.strip()):
            try:
                path_obj = Path(content)
                if path_obj.exists():
                    content = path_obj.read_text()
            except (OSError, ValueError):
                # If path operations fail, treat as YAML string
                pass
        
        data = yaml.safe_load(content)
        return cls(**data)
