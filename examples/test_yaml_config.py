#!/usr/bin/env python3
"""Test the YAML configuration with presets."""

from phylax import PhylaxConfig

def test_yaml_config():
    """Test loading YAML configuration with presets."""
    print("=== Testing YAML Configuration with Presets ===")
    
    # Load the YAML config
    with open("preset_config.yaml", "r") as f:
        yaml_content = f.read()
    
    config = PhylaxConfig.from_yaml(yaml_content)
    
    print(f"Total policies loaded: {len(config.policies)}")
    print("Policies from presets:")
    
    preset_policies = [p for p in config.policies if p.id.startswith(('hipaa_', 'soc2_'))]
    custom_policies = [p for p in config.policies if p.id.startswith('custom_')]
    
    print(f"  - HIPAA/SOC2 policies: {len(preset_policies)}")
    print(f"  - Custom policies: {len(custom_policies)}")
    
    print("\nCustom policies:")
    for policy in custom_policies:
        print(f"  - {policy.id}: {policy.pattern} (severity: {policy.severity})")
    
    print("\nConfiguration loaded successfully!")

if __name__ == "__main__":
    test_yaml_config()
