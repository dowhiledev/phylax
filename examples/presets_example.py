"""Example demonstrating Phylax presets functionality."""

import logging
from phylax import Phylax, PhylaxConfig, PhylaxViolation, Policy, get_preset, list_presets, extend_preset

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def demonstrate_presets():
    """Demonstrate various ways to use presets."""
    
    print("=== Phylax Presets Demo ===\n")
    
    # Show available presets
    print("1. Available Presets:")
    print("-" * 30)
    for preset_name in list_presets():
        policies = get_preset(preset_name)
        print(f"• {preset_name.upper()}: {len(policies)} policies")
    print()
    
    # Example 1: Using a single preset
    print("2. Using Single Preset (HIPAA):")
    print("-" * 30)
    
    hipaa_config = PhylaxConfig.from_preset("hipaa")
    print(f"HIPAA config loaded with {len(hipaa_config.policies)} policies")
    
    with Phylax(hipaa_config, monitor_console=False) as phylax:
        @phylax.on_violation
        def handle_violation(policy, sample, context):
            print(f"🚨 HIPAA Violation: {policy.id} (severity: {policy.severity})")
        
        try:
            # This should trigger HIPAA violations
            sensitive_data = "Patient John Doe, SSN: 123-45-6789, DOB: 01/15/1980"
            phylax.analyze(sensitive_data, context="Medical record processing")
            print("✅ Data passed HIPAA compliance")
        except PhylaxViolation as e:
            print(f"❌ HIPAA violation detected: {e}")
    
    print()
    
    # Example 2: Using multiple presets
    print("3. Using Multiple Presets (SOC2 + PCI DSS):")
    print("-" * 30)
    
    multi_config = PhylaxConfig.from_presets(["soc2", "pci_dss"])
    print(f"Multi-preset config loaded with {len(multi_config.policies)} policies")
    
    with Phylax(multi_config, monitor_console=False) as phylax:
        @phylax.on_violation
        def handle_violation(policy, sample, context):
            print(f"🚨 Security Violation: {policy.id}")
        
        try:
            # This should trigger both SOC2 and PCI violations
            sensitive_data = "API Key: abc123xyz789, Credit Card: 4532123456789012"
            phylax.analyze(sensitive_data, context="Payment processing")
            print("✅ Data passed security compliance")
        except PhylaxViolation as e:
            print(f"❌ Security violation detected: {e}")
    
    print()
    
    # Example 3: Extending presets with custom policies
    print("4. Extending Presets with Custom Policies:")
    print("-" * 30)
    
    # Create custom policies
    custom_policies = [
        Policy(
            id="custom_internal_id",
            type="regex",
            pattern=r"EMP-\d{6}",
            severity="medium",
            trigger="log",
            scope=["output", "analysis"],
        ),
        Policy(
            id="custom_project_code",
            type="regex",
            pattern=r"PRJ-[A-Z]{3}-\d{4}",
            severity="low",
            trigger="log",
            scope=["output", "analysis"],
        ),
    ]
    
    # Extend GDPR preset with custom policies
    extended_policies = extend_preset("gdpr", custom_policies)
    extended_config = PhylaxConfig(version=1, policies=extended_policies)
    
    print(f"Extended GDPR config: {len(extended_config.policies)} policies")
    print("Custom policies added:")
    for policy in custom_policies:
        print(f"  • {policy.id}: {policy.pattern}")
    
    with Phylax(extended_config, monitor_console=False) as phylax:
        @phylax.on_violation
        def handle_violation(policy, sample, context):
            print(f"🚨 Policy Violation: {policy.id}")
        
        # Test with data that triggers both GDPR and custom policies
        test_data = "Employee EMP-123456 on project PRJ-ABC-2024, email: john.doe@company.com"
        phylax.analyze(test_data, context="Employee data processing")
        print("✅ Data analyzed with extended policies")
    
    print()
    
    # Example 4: Using presets in YAML configuration
    print("5. Using Presets in YAML Configuration:")
    print("-" * 30)
    
    yaml_config = """
version: 1
presets:
  - hipaa
  - soc2
policies:
  - id: custom_employee_id
    type: regex
    pattern: "EMP-\\\\d{6}"
    severity: medium
    trigger: log
    scope: [output, analysis]
"""
    
    config_with_presets = PhylaxConfig.from_yaml(yaml_config)
    print(f"YAML config with presets: {len(config_with_presets.policies)} total policies")
    
    # Count policies by source
    preset_policy_count = len(get_preset("hipaa")) + len(get_preset("soc2"))
    custom_policy_count = len(config_with_presets.policies) - preset_policy_count
    print(f"  • Preset policies: {preset_policy_count}")
    print(f"  • Custom policies: {custom_policy_count}")
    
    print()
    
    # Example 5: Show policy details for a preset
    print("6. Detailed Policy Information:")
    print("-" * 30)
    
    pci_policies = get_preset("pci_dss")
    print(f"PCI DSS Preset ({len(pci_policies)} policies):")
    for policy in pci_policies[:3]:  # Show first 3 policies
        print(f"  • {policy.id}:")
        print(f"    Pattern: {policy.pattern}")
        print(f"    Severity: {policy.severity}")
        print(f"    Trigger: {policy.trigger}")
        print(f"    Scope: {policy.scope}")
        print()

def test_real_world_scenario():
    """Test a real-world scenario with financial data processing."""
    print("=== Real-World Scenario: Financial Data Processing ===\n")
    
    # Create a configuration for financial services
    financial_config = PhylaxConfig.from_presets(["financial", "pci_dss"])
    
    # Sample financial data that should trigger violations
    financial_data = [
        "Customer account: 1234567890123456, routing: 123456789",
        "Payment card: 4532123456789012, CVV: 123",
        "Wire transfer to SWIFT: ABCDUS33XXX, IBAN: GB33BUKB20201555555555",
    ]
    
    with Phylax(financial_config, monitor_console=False) as phylax:
        violation_count = 0
        
        @phylax.on_violation
        def handle_violation(policy, sample, context):
            nonlocal violation_count
            violation_count += 1
            print(f"🚨 Financial Violation #{violation_count}: {policy.id}")
            print(f"   Data: {sample[:50]}...")
            print(f"   Context: {context.get('context', 'N/A')}")
        
        for i, data in enumerate(financial_data, 1):
            try:
                phylax.analyze(data, context=f"Financial transaction {i}")
                print(f"✅ Transaction {i} passed compliance")
            except PhylaxViolation as e:
                print(f"❌ Transaction {i} blocked: {e}")
    
    print(f"\nTotal violations detected: {violation_count}")

if __name__ == "__main__":
    demonstrate_presets()
    print("\n" + "="*60 + "\n")
    test_real_world_scenario()
