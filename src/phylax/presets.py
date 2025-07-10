"""Predefined security and compliance presets for Phylax."""

from __future__ import annotations

from typing import ClassVar

from .config import Policy


class PresetRegistry:
    """Registry for predefined security and compliance presets."""

    _presets: ClassVar[dict[str, list[Policy]]] = {}

    @classmethod
    def register_preset(cls, name: str, policies: list[Policy]) -> None:
        """Register a new preset."""
        cls._presets[name] = policies

    @classmethod
    def get_preset(cls, name: str) -> list[Policy]:
        """Get policies for a preset."""
        if name not in cls._presets:
            raise ValueError(f"Unknown preset: {name}. Available presets: {list(cls._presets.keys())}")
        return cls._presets[name].copy()

    @classmethod
    def list_presets(cls) -> list[str]:
        """List all available presets."""
        return list(cls._presets.keys())

    @classmethod
    def extend_preset(cls, base_preset: str, additional_policies: list[Policy]) -> list[Policy]:
        """Extend a preset with additional policies."""
        base_policies = cls.get_preset(base_preset)
        return base_policies + additional_policies


# HIPAA Compliance Preset
HIPAA_POLICIES = [
    Policy(
        id="hipaa_ssn",
        type="regex",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="hipaa_medical_record_number",
        type="regex",
        pattern=r"\b(?:MRN|medical record|record number)[:\s]+[A-Z0-9]{6,}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="hipaa_dob",
        type="regex",
        pattern=r"\b(?:DOB|date of birth|born)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        severity="high",
        trigger="raise",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="hipaa_phone_number",
        type="regex",
        pattern=r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
        severity="medium",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="hipaa_email",
        type="regex",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        severity="medium",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="hipaa_patient_names",
        type="regex",
        pattern=r"\b(?:patient|pt)[:\s]+[A-Z][a-z]+\s+[A-Z][a-z]+\b",
        severity="high",
        trigger="human_review",
        scope=["output", "analysis", "network"],
    ),
]

# SOC 2 Compliance Preset
SOC2_POLICIES = [
    Policy(
        id="soc2_api_key",
        type="regex",
        pattern=r"(?i)(?:api[_\-]?key|apikey)[:\s=]+['\"]?[A-Za-z0-9]{20,}['\"]?",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="soc2_secret_key",
        type="regex",
        pattern=r"(?i)(?:secret[_\-]?key|secretkey)[:\s=]+['\"]?[A-Za-z0-9]{20,}['\"]?",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="soc2_password",
        type="regex",
        pattern=r"(?i)(?:password|pwd)[:\s=]+['\"]?[A-Za-z0-9@#$%^&*!]{8,}['\"]?",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="soc2_jwt_token",
        type="regex",
        pattern=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="soc2_database_connection",
        type="regex",
        pattern=r"(?i)(?:mongodb|mysql|postgres|oracle)[:\s]*//[^\s]+",
        severity="high",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="soc2_aws_credentials",
        type="regex",
        pattern=r"(?i)(?:aws_access_key_id|aws_secret_access_key)[:\s=]+[A-Za-z0-9/+=]{20,}",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
]

# PCI DSS Compliance Preset
PCI_DSS_POLICIES = [
    Policy(
        id="pci_credit_card_visa",
        type="regex",
        pattern=r"\b4[0-9]{12}(?:[0-9]{3})?\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="pci_credit_card_mastercard",
        type="regex",
        pattern=r"\b5[1-5][0-9]{14}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="pci_credit_card_amex",
        type="regex",
        pattern=r"\b3[47][0-9]{13}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="pci_credit_card_discover",
        type="regex",
        pattern=r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="pci_cvv",
        type="regex",
        pattern=r"\b(?:cvv|cvc|security code)[:\s]+[0-9]{3,4}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="pci_track_data",
        type="regex",
        pattern=r"%[A-Z]?[0-9]{13,19}\^[A-Z\s/]+\^[0-9]{4}",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
]

# GDPR Compliance Preset
GDPR_POLICIES = [
    Policy(
        id="gdpr_email",
        type="regex",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        severity="medium",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="gdpr_phone_eu",
        type="regex",
        pattern=r"\b(?:\+[1-9]\d{1,3}[-.\s]?)?\(?[0-9]{1,4}\)?[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b",
        severity="medium",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="gdpr_ip_address",
        type="regex",
        pattern=r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        severity="medium",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="gdpr_personal_identifiers",
        type="regex",
        pattern=r"\b(?:passport|id card|driver.?license|national.?id)[:\s]+[A-Z0-9]{6,}\b",
        severity="high",
        trigger="human_review",
        scope=["output", "analysis", "network"],
    ),
]

# Financial Services Preset
FINANCIAL_POLICIES = [
    Policy(
        id="fin_account_number",
        type="regex",
        pattern=r"\b(?:account|acct)[:\s]+[0-9]{8,17}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="fin_routing_number",
        type="regex",
        pattern=r"\b(?:routing|ABA)[:\s]+[0-9]{9}\b",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="fin_swift_code",
        type="regex",
        pattern=r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b",
        severity="high",
        trigger="raise",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="fin_iban",
        type="regex",
        pattern=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b",
        severity="high",
        trigger="raise",
        scope=["output", "analysis", "network"],
    ),
]

# Enterprise Security Preset
ENTERPRISE_POLICIES = [
    Policy(
        id="enterprise_private_ip",
        type="regex",
        pattern=r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        severity="high",
        trigger="log",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="enterprise_internal_url",
        type="regex",
        pattern=r"\b(?:https?://)?(?:intranet|internal|corp|private)\.[A-Za-z0-9.-]+\b",
        severity="high",
        trigger="log",
        scope=["output", "analysis", "network"],
    ),
    Policy(
        id="enterprise_env_var",
        type="regex",
        pattern=r"(?i)[A-Z0-9_]*(?:SECRET|PASSWORD|TOKEN|KEY)=[^\s]+",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="enterprise_ssh_key",
        type="regex",
        pattern=r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="enterprise_slack_token",
        type="regex",
        pattern=r"xox(?:b|p|r|o|a)-[A-Za-z0-9-]{10,48}",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
    Policy(
        id="enterprise_google_oauth",
        type="regex",
        pattern=r"ya29\.[A-Za-z0-9_-]{60,}",
        severity="critical",
        trigger="raise",
        scope=["output", "analysis", "network", "console"],
    ),
]

# Register all presets
PresetRegistry.register_preset("hipaa", HIPAA_POLICIES)
PresetRegistry.register_preset("soc2", SOC2_POLICIES)
PresetRegistry.register_preset("pci_dss", PCI_DSS_POLICIES)
PresetRegistry.register_preset("gdpr", GDPR_POLICIES)
PresetRegistry.register_preset("financial", FINANCIAL_POLICIES)
PresetRegistry.register_preset("enterprise", ENTERPRISE_POLICIES)

# Convenience function for getting presets
def get_preset(name: str) -> list[Policy]:
    """Get policies for a preset."""
    return PresetRegistry.get_preset(name)

def list_presets() -> list[str]:
    """List all available presets."""
    return PresetRegistry.list_presets()

def extend_preset(base_preset: str, additional_policies: list[Policy]) -> list[Policy]:
    """Extend a preset with additional policies."""
    return PresetRegistry.extend_preset(base_preset, additional_policies)
