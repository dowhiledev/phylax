"""Test preset functionality."""

import pytest
from phylax import PhylaxConfig, Policy, get_preset, list_presets, extend_preset, PresetRegistry
from phylax.exceptions import PhylaxViolation


def test_list_presets():
    """Test listing available presets."""
    presets = list_presets()
    assert "hipaa" in presets
    assert "soc2" in presets
    assert "pci_dss" in presets
    assert "gdpr" in presets
    assert "financial" in presets
    assert "enterprise" in presets


def test_get_preset():
    """Test getting a preset."""
    hipaa_policies = get_preset("hipaa")
    assert len(hipaa_policies) == 6
    assert all(isinstance(p, Policy) for p in hipaa_policies)

    enterprise_policies = get_preset("enterprise")
    assert len(enterprise_policies) == 6
    
    # Test invalid preset
    with pytest.raises(ValueError, match="Unknown preset"):
        get_preset("invalid_preset")


def test_extend_preset():
    """Test extending a preset with additional policies."""
    custom_policy = Policy(
        id="test_custom",
        type="regex",
        pattern="test",
        severity="low",
        trigger="log"
    )
    
    extended = extend_preset("hipaa", [custom_policy])
    assert len(extended) == 7  # 6 HIPAA + 1 custom
    assert extended[-1].id == "test_custom"


def test_config_from_preset():
    """Test creating config from single preset."""
    config = PhylaxConfig.from_preset("hipaa")
    assert len(config.policies) == 6
    assert config.version == 1

    enterprise_config = PhylaxConfig.from_preset("enterprise")
    assert len(enterprise_config.policies) == 6


def test_config_from_multiple_presets():
    """Test creating config from multiple presets."""
    config = PhylaxConfig.from_presets(["hipaa", "soc2"])
    assert len(config.policies) == 12  # 6 HIPAA + 6 SOC2
    
    # Test with additional policies
    custom_policy = Policy(
        id="test_custom",
        type="regex",
        pattern="test",
        severity="low",
        trigger="log"
    )
    config_extended = PhylaxConfig.from_presets(["hipaa"], [custom_policy])
    assert len(config_extended.policies) == 7


def test_yaml_with_presets():
    """Test YAML configuration with presets."""
    yaml_config = """
version: 1
presets:
  - hipaa
  - soc2
policies:
  - id: custom_test
    type: regex
    pattern: "test"
    severity: low
    trigger: log
"""
    
    config = PhylaxConfig.from_yaml(yaml_config)
    assert len(config.policies) == 13  # 6 HIPAA + 6 SOC2 + 1 custom
    
    # Check that custom policy is present
    custom_policies = [p for p in config.policies if p.id == "custom_test"]
    assert len(custom_policies) == 1


def test_preset_deduplication():
    """Test that duplicate policies are handled correctly."""
    # Create a custom policy with the same ID as a preset policy
    custom_policy = Policy(
        id="hipaa_ssn",  # Same ID as in HIPAA preset
        type="regex",
        pattern="different_pattern",
        severity="low",
        trigger="log"
    )
    
    config = PhylaxConfig.from_presets(["hipaa"], [custom_policy])
    
    # Should have 6 HIPAA policies + 1 custom, but no duplicates
    assert len(config.policies) == 6
    
    # The custom policy should NOT override the preset policy
    ssn_policy = next(p for p in config.policies if p.id == "hipaa_ssn")
    assert ssn_policy.severity == "critical"  # From preset, not custom


def test_preset_functionality():
    """Test that preset policies actually work."""
    from phylax import Phylax
    
    # Test HIPAA preset
    hipaa_config = PhylaxConfig.from_preset("hipaa")
    phylax = Phylax(hipaa_config, monitor_console=False)
    
    # This should trigger HIPAA SSN violation
    with pytest.raises(PhylaxViolation):
        phylax.analyze("SSN: 123-45-6789", context="test")
    
    # Test PCI DSS preset
    pci_config = PhylaxConfig.from_preset("pci_dss")
    phylax_pci = Phylax(pci_config, monitor_console=False)
    
    # This should trigger PCI credit card violation
    with pytest.raises(PhylaxViolation):
        phylax_pci.analyze("Credit card: 4532123456789012", context="test")


if __name__ == "__main__":
    # Run basic tests
    test_list_presets()
    test_get_preset()
    test_extend_preset()
    test_config_from_preset()
    test_config_from_multiple_presets()
    test_yaml_with_presets()
    test_preset_deduplication()
    test_preset_functionality()
    print("All tests passed!")
