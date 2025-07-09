# Phylax Presets

Phylax provides built-in presets for common security and compliance standards. These presets contain predefined policies that help you quickly implement industry-standard security measures.

## Available Presets

### HIPAA (Health Insurance Portability and Accountability Act)
- `hipaa_ssn`: Detects Social Security Numbers
- `hipaa_medical_record_number`: Detects medical record numbers
- `hipaa_dob`: Detects dates of birth
- `hipaa_phone_number`: Detects phone numbers
- `hipaa_email`: Detects email addresses
- `hipaa_patient_names`: Detects patient names

### SOC 2 (Service Organization Control 2)
- `soc2_api_key`: Detects API keys
- `soc2_secret_key`: Detects secret keys
- `soc2_password`: Detects passwords
- `soc2_jwt_token`: Detects JWT tokens
- `soc2_database_connection`: Detects database connection strings
- `soc2_aws_credentials`: Detects AWS credentials

### PCI DSS (Payment Card Industry Data Security Standard)
- `pci_credit_card_visa`: Detects Visa credit cards
- `pci_credit_card_mastercard`: Detects MasterCard credit cards
- `pci_credit_card_amex`: Detects American Express cards
- `pci_credit_card_discover`: Detects Discover cards
- `pci_cvv`: Detects CVV codes
- `pci_track_data`: Detects magnetic stripe track data

### GDPR (General Data Protection Regulation)
- `gdpr_email`: Detects email addresses
- `gdpr_phone_eu`: Detects European phone numbers
- `gdpr_ip_address`: Detects IP addresses
- `gdpr_personal_identifiers`: Detects personal identifiers

### Financial Services
- `fin_account_number`: Detects account numbers
- `fin_routing_number`: Detects routing numbers
- `fin_swift_code`: Detects SWIFT codes
- `fin_iban`: Detects IBAN numbers

## Usage

### Basic Usage

```python
from phylax import PhylaxConfig, Phylax, list_presets, get_preset

# List available presets
print(list_presets())  # ['hipaa', 'soc2', 'pci_dss', 'gdpr', 'financial']

# Get policies for a specific preset
hipaa_policies = get_preset("hipaa")
print(f"HIPAA has {len(hipaa_policies)} policies")

# Create config from a single preset
config = PhylaxConfig.from_preset("hipaa")
with Phylax(config) as phylax:
    phylax.analyze("Patient data...", context="medical records")
```

### Using Multiple Presets

```python
# Combine multiple presets
config = PhylaxConfig.from_presets(["hipaa", "soc2"])

# Or with additional custom policies
custom_policy = Policy(
    id="custom_rule",
    type="regex",
    pattern="CUSTOM-\\d{6}",
    severity="medium",
    trigger="log"
)

config = PhylaxConfig.from_presets(["hipaa", "soc2"], [custom_policy])
```

### Extending Presets

```python
from phylax import extend_preset

# Extend a preset with additional policies
extended_policies = extend_preset("hipaa", [custom_policy])
config = PhylaxConfig(version=1, policies=extended_policies)
```

### YAML Configuration

```yaml
version: 1
presets:
  - hipaa
  - soc2
policies:
  - id: custom_employee_id
    type: regex
    pattern: "EMP-\\d{6}"
    severity: medium
    trigger: log
    scope: [output, analysis]
```

### Advanced Usage

```python
from phylax import PresetRegistry

# Register a custom preset
custom_policies = [
    Policy(id="custom1", type="regex", pattern="test", severity="low", trigger="log"),
    Policy(id="custom2", type="regex", pattern="demo", severity="medium", trigger="log")
]
PresetRegistry.register_preset("my_custom_preset", custom_policies)

# Use the custom preset
config = PhylaxConfig.from_preset("my_custom_preset")
```

## Policy Configuration

Each preset contains policies with the following characteristics:

- **Severity levels**: `low`, `medium`, `high`, `critical`
- **Triggers**: `log`, `raise`, `human_review`, `quarantine`, `mitigate`
- **Scopes**: `input`, `output`, `network`, `file`, `console`, `analysis`

Most preset policies are configured to trigger on critical violations (like credit card numbers) or log warnings for less sensitive data.

## Best Practices

1. **Start with presets**: Choose presets that match your compliance requirements
2. **Extend with custom policies**: Add organization-specific rules on top of standard presets
3. **Test thoroughly**: Validate that preset policies work with your specific data patterns
4. **Regular updates**: Keep presets updated as regulations change
5. **Documentation**: Document any custom policies you add to presets

## Customization

You can customize preset behavior by:

1. **Overriding policies**: Define policies with the same ID to override preset defaults
2. **Adding custom policies**: Extend presets with additional rules
3. **Modifying triggers**: Create custom violation handlers
4. **Scope adjustment**: Modify which monitoring scopes apply to each policy

## Example: Healthcare Application

```python
from phylax import PhylaxConfig, Phylax, Policy

# Start with HIPAA preset
config = PhylaxConfig.from_preset("hipaa")

# Add custom healthcare policies
custom_policies = [
    Policy(
        id="custom_patient_id",
        type="regex",
        pattern="PAT-\\d{8}",
        severity="high",
        trigger="raise",
        scope=["output", "analysis"]
    ),
    Policy(
        id="custom_medical_device",
        type="regex",
        pattern="DEV-[A-Z]{3}-\\d{4}",
        severity="medium",
        trigger="log",
        scope=["network", "analysis"]
    )
]

# Extend HIPAA with custom policies
config = PhylaxConfig.from_presets(["hipaa"], custom_policies)

# Use in your application
with Phylax(config) as phylax:
    @phylax.on_violation
    def handle_violation(policy, sample, context):
        if policy.severity == "critical":
            # Alert security team
            print(f"CRITICAL: {policy.id} violation detected")
        else:
            # Log for compliance audit
            print(f"INFO: {policy.id} policy triggered")
    
    # Process patient data
    result = phylax.analyze(patient_data, context="patient_processing")
```

This approach ensures your application meets HIPAA requirements while adding custom rules specific to your organization.
