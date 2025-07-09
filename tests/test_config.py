"""Tests for Phylax configuration and policy models."""

import pytest

from phylax.config import PhylaxConfig, Policy


class TestPolicy:
    """Test the Policy model."""

    def test_regex_policy_creation(self):
        """Test creating a regex policy."""
        policy = Policy(
            id="test_regex",
            type="regex",
            pattern=r"\d{3}-\d{2}-\d{4}",
            severity="high",
            trigger="raise",
        )

        assert policy.id == "test_regex"
        assert policy.type == "regex"
        assert policy.pattern == r"\d{3}-\d{2}-\d{4}"
        assert policy.severity == "high"
        assert policy.trigger == "raise"
        assert policy._compiled is not None

    def test_regex_policy_matches(self):
        """Test regex policy matching."""
        policy = Policy(
            id="ssn_detector",
            type="regex",
            pattern=r"\d{3}-\d{2}-\d{4}",
            severity="high",
            trigger="raise",
        )

        # Should match SSN pattern
        assert policy.matches("My SSN is 123-45-6789") is True

        # Should not match random text
        assert policy.matches("No SSN here") is False

    def test_spdx_policy_creation(self):
        """Test creating an SPDX policy."""
        policy = Policy(
            id="license_check",
            type="spdx",
            allowed=["MIT", "Apache-2.0", "BSD-3-Clause"],
            severity="medium",
            trigger="log",
        )

        assert policy.id == "license_check"
        assert policy.type == "spdx"
        assert policy.allowed == ["MIT", "Apache-2.0", "BSD-3-Clause"]

    def test_spdx_policy_matches(self):
        """Test SPDX policy matching."""
        policy = Policy(
            id="license_check",
            type="spdx",
            allowed=["MIT", "Apache-2.0"],
            severity="medium",
            trigger="log",
        )

        # Should allow listed licenses
        assert policy.matches("MIT") is False
        assert policy.matches("Apache-2.0") is False

        # Should block unlisted licenses
        assert policy.matches("GPL-3.0") is True
        assert policy.matches("Proprietary") is True

    def test_policy_scope_filtering(self):
        """Test policy scope filtering."""
        policy = Policy(
            id="input_only",
            type="regex",
            pattern=r"secret",
            scope=["input", "analysis"],
        )

        assert policy.applies_to_scope("input") is True
        assert policy.applies_to_scope("analysis") is True
        assert policy.applies_to_scope("output") is False
        assert policy.applies_to_scope("network") is False

    def test_policy_no_scope_restriction(self):
        """Test policy with no scope restriction."""
        policy = Policy(id="global_policy", type="regex", pattern=r"password")

        # Should apply to all scopes when none specified
        assert policy.applies_to_scope("input") is True
        assert policy.applies_to_scope("output") is True
        assert policy.applies_to_scope("network") is True
        assert policy.applies_to_scope("console") is True


class TestPhylaxConfig:
    """Test the PhylaxConfig model."""

    def test_config_creation(self):
        """Test creating a configuration."""
        policies = [
            Policy(id="test_policy", type="regex", pattern=r"test", severity="low")
        ]

        config = PhylaxConfig(version=1, policies=policies)

        assert config.version == 1
        assert len(config.policies) == 1
        assert config.policies[0].id == "test_policy"

    def test_config_from_yaml_string(self):
        """Test creating config from YAML string."""
        yaml_content = """
version: 1
policies:
  - id: pii_ssn
    type: regex
    pattern: "\\\\d{3}-\\\\d{2}-\\\\d{4}"
    severity: high
    trigger: raise
  - id: sensitive_keywords
    type: regex
    pattern: "(?i)(password|secret|token)"
    severity: medium
    trigger: log
"""

        config = PhylaxConfig.from_yaml(yaml_content)

        assert config.version == 1
        assert len(config.policies) == 2

        # Check first policy
        ssn_policy = config.policies[0]
        assert ssn_policy.id == "pii_ssn"
        assert ssn_policy.type == "regex"
        assert ssn_policy.severity == "high"
        assert ssn_policy.trigger == "raise"

        # Check second policy
        keyword_policy = config.policies[1]
        assert keyword_policy.id == "sensitive_keywords"
        assert keyword_policy.type == "regex"
        assert keyword_policy.severity == "medium"
        assert keyword_policy.trigger == "log"

    def test_invalid_policy_type(self):
        """Test that invalid policy types raise errors."""
        policy = Policy(id="invalid_policy", type="invalid_type", pattern="test")

        with pytest.raises(ValueError, match="Unknown policy type"):
            policy.matches("test data")
