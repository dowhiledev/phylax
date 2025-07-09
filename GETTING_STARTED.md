# Getting Started with Phylax

Phylax is a security and compliance layer for Python AI agents that helps detect and prevent data leaks, PII exposure, and policy violations.

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/phylax.git
cd phylax

# Install with uv (recommended)
uv pip install -e .

# Or install with pip
pip install -e .
```

## 5-Minute Quick Start

### 1. Basic Usage with Context Manager

```python
from phylax import Phylax, PhylaxConfig, Policy

# Create a simple policy
config = PhylaxConfig(
    version=1,
    policies=[
        Policy(
            id="ssn_detector",
            type="regex",
            pattern=r"\d{3}-\d{2}-\d{4}",
            severity="high",
            trigger="raise"
        )
    ]
)

# Use as context manager for automatic monitoring
phylax = Phylax(config)

with phylax:
    # This will be monitored automatically
    user_input = "My SSN is 123-45-6789"  # ❌ Will raise PhylaxViolation
```

### 2. Explicit Analysis

```python
# Analyze specific data without context manager
phylax = Phylax(config)

try:
    # Check input data
    safe_input = phylax.analyze_input("Hello, how are you?")  # ✅ Safe

    # Check output data
    safe_output = phylax.analyze_output("SSN: 123-45-6789")  # ❌ Will raise
except PhylaxViolation as e:
    print(f"Security violation: {e}")
```

### 3. YAML Configuration

Create `policies.yaml`:
```yaml
version: 1
policies:
  - id: pii_ssn
    type: regex
    pattern: '\d{3}-\d{2}-\d{4}'
    severity: high
    trigger: raise
    scope: ["output", "analysis"]

  - id: sensitive_keywords
    type: regex
    pattern: '(?i)(password|secret|token|key)'
    severity: medium
    trigger: log
```

Use it in code:
```python
from phylax import Phylax, PhylaxConfig

# Load from YAML file
config = PhylaxConfig.from_yaml_file("policies.yaml")
phylax = Phylax(config)

# Now use phylax as before
with phylax:
    # Your AI agent code here
    pass
```

### 4. Event Callbacks

```python
# Register violation handlers
@phylax.on_violation
def handle_violation(policy, sample, context):
    print(f"🚨 SECURITY ALERT: {policy.id}")
    # Log to security system, send alerts, etc.

@phylax.on_input
def log_input(data):
    print(f"📥 Input: {data}")

@phylax.on_output
def log_output(data):
    print(f"📤 Output: {data}")
```

## CLI Usage

```bash
# Validate a policy configuration
phylax validate policies.yaml

# Scan text for violations
phylax scan "Check this text for SSN: 123-45-6789"

# Show version
phylax --version
```

## Next Steps

- Check out the [examples/](examples/) directory for complete working examples
- Read the full [README.md](README.md) for detailed documentation
- Run the test suite: `uv run pytest tests/`
- Explore the [examples/security_policies.yaml](examples/security_policies.yaml) for comprehensive policy examples

## Common Use Cases

1. **AI Chat Applications**: Monitor user inputs and bot responses
2. **API Gateways**: Scan requests and responses for sensitive data
3. **Data Processing Pipelines**: Ensure compliance during data transformation
4. **Agent Frameworks**: Add security layer to autonomous agent actions
5. **Development Testing**: Validate that your code doesn't leak sensitive information

Happy coding with Phylax! 🛡️
