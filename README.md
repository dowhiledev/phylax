# Phylax

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://badge.fury.io/py/phylax.svg)](https://badge.fury.io/py/phylax)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Phylax** is a Security & Compliance layer for Python-based AI agents. It provides both automatic monitoring and explicit analysis capabilities to ensure your AI applications comply with security policies and don't accidentally leak sensitive information.

## Features

| Feature | Description |
|---------|-------------|
| **Plug and Play Design** | Automatically monitor all activity within a `with Phylax(...):` block |
| **Explicit Analysis** | Use `phylax.analyze()` for targeted compliance checks on specific data |
| **Built-in Presets** | Ready-made compliance presets for HIPAA, SOC 2, PCI DSS, GDPR, Financial Services, and Enterprise Security |
| **Flexible Configuration** | YAML-based policy configuration supporting regex, SPDX, and custom policies |
| **Multiple Trigger Types** | Choose from raise, log, human_review, or custom violation handling |
| **Comprehensive Monitoring** | Console output, function calls, network requests, and file operations |
| **Event Hooks** | Custom callbacks for input, output, and violation events |
| **Thread-Safe** | Safe for concurrent use |
| **Custom Extractors** | Define how to extract meaningful data from complex objects |
| **Selective Ignore** | Temporarily disable compliance checking with `phylax.ignore()` context manager |

## Quick Start

### Installation

```bash
# Using uv (recommended)
uv add phylax

# Using pip
pip install phylax
```

### Basic Usage

```python
from phylax import Phylax, PhylaxConfig, Policy

# Define security policies
config = PhylaxConfig(
    version=1,
    policies=[
        Policy(
            id="pii_ssn",
            type="regex",
            pattern=r"\d{3}-\d{2}-\d{4}",
            severity="high",
            trigger="raise",
            scope=["output", "analysis"]
        ),
        Policy(
            id="sensitive_keywords",
            type="regex",
            pattern=r"(?i)(password|secret|token)",
            severity="medium",
            trigger="log",
            scope=["input", "output", "analysis"]
        )
    ]
)

def my_ai_agent(prompt: str) -> str:
    # Your AI agent logic here
    return f"Response to '{prompt}': Here's some data that might contain PII"

# Method 1: Explicit Analysis (Recommended)
phylax = Phylax(config)

# Analyze specific data
user_input = "Tell me something"
safe_input = phylax.analyze_input(user_input, context="User query validation")

response = my_ai_agent(safe_input)
safe_response = phylax.analyze_output(response, context="AI response validation")

# Method 2: Automatic Monitoring
with Phylax(config) as phylax:
    # All function calls within this block are automatically monitored
    response = my_ai_agent("Hello world")
    print(f"Response: {response}")
```

### Using Presets

Phylax provides built-in presets for common compliance standards:

```python
from phylax import PhylaxConfig, list_presets

# See available presets
print(list_presets())  # ['hipaa', 'soc2', 'pci_dss', 'gdpr', 'financial', 'enterprise']

# Use a single preset
config = PhylaxConfig.from_preset("hipaa")

# Combine multiple presets
config = PhylaxConfig.from_presets(["hipaa", "soc2"])

# Extend presets with custom policies
custom_policies = [
    Policy(
        id="custom_employee_id",
        type="regex",
        pattern="EMP-\\d{6}",
        severity="medium",
        trigger="log"
    )
]
config = PhylaxConfig.from_presets(["hipaa"], custom_policies)

# Use presets in YAML
yaml_config = """
version: 1
presets:
  - hipaa
  - soc2
policies:
  - id: custom_rule
    type: regex
    pattern: "CUSTOM-\\d{6}"
    severity: medium
    trigger: log
"""
config = PhylaxConfig.from_yaml(yaml_config)
```

### YAML Configuration

Create a `policies.yaml` file:

```yaml
version: 1
policies:
  - id: pii_ssn
    type: regex
    pattern: "\\d{3}-\\d{2}-\\d{4}"
    severity: high
    trigger: raise
    scope: [output, analysis, network]

  - id: sensitive_keywords
    type: regex
    pattern: "(?i)(password|secret|token|api_key)"
    severity: medium
    trigger: log
    scope: [input, output, analysis]

  - id: license_compliance
    type: spdx
    allowed: [MIT, Apache-2.0, BSD-3-Clause]
    severity: medium
    trigger: log
    scope: [file, analysis]
```

Then use it in your code:

```python
from phylax import Phylax

# Load configuration from YAML
phylax = Phylax("policies.yaml")

# Use as before...
result = phylax.analyze("Some data to check", context="Data validation")
```

## Advanced Usage

### Custom Violation Handling

```python
phylax = Phylax(config)

@phylax.on_violation
def handle_security_violation(policy, sample, context):
    # Log to security system
    security_logger.alert(
        policy_id=policy.id,
        severity=policy.severity,
        sample=sample[:100],  # Truncate for logging
        context=context
    )

    # Send to monitoring dashboard
    dashboard.report_violation(policy, context)

    # Notify security team for high-severity violations
    if policy.severity == "high":
        notify_security_team(policy, sample, context)

# Your AI agent calls...
safe_output = phylax.analyze_output(ai_response, context="Final output check")
```

### Custom Input/Output Extractors

```python
def extract_message_content(data):
    """Extract text from complex message objects."""
    if isinstance(data, dict):
        return data.get('content', str(data))
    elif hasattr(data, 'content'):
        return data.content
    return str(data)

def extract_response_text(data):
    """Extract text from AI response objects."""
    if isinstance(data, dict):
        return data.get('text', data.get('response', str(data)))
    elif hasattr(data, 'text'):
        return data.text
    return str(data)

phylax = Phylax(
    config,
    input_extractor=extract_message_content,
    output_extractor=extract_response_text
)

# Now Phylax will use your custom extractors
complex_input = {"content": "User message", "metadata": {...}}
complex_output = {"text": "AI response", "confidence": 0.95}

phylax.analyze_input(complex_input)
phylax.analyze_output(complex_output)
```

### Monitoring Specific Activities

```python
# Monitor only specific activities
phylax = Phylax(
    config,
    monitor_network=True,      # Monitor HTTP requests/responses
    monitor_console=False,     # Don't monitor print statements (default)
    monitor_files=True,        # Monitor file operations
    monitor_function_calls=True # Monitor function calls (default)
)

with phylax:
    # Network requests are monitored
    response = requests.get("https://api.example.com/data")

    # File operations are monitored
    with open("sensitive_data.txt", "r") as f:
        content = f.read()

    # Function calls are monitored
    result = my_ai_function(content)
```

### Ignoring Compliance Checks

Sometimes you may want to temporarily disable compliance checking for specific contexts where you know the data is safe or for internal operations:

```python
phylax = Phylax(config)

with phylax:
    # This will be monitored
    response = ai_agent("Process this user input")

    # Temporarily disable monitoring for internal operations
    with phylax.ignore():
        # No compliance checking happens here
        internal_debug_data = extract_debug_info(response)
        log_internal_metrics(internal_debug_data)
        cleanup_temp_files()

    # Monitoring resumes here
    final_response = post_process(response)

# Or use ignore with explicit analysis
user_input = "Tell me about security"
safe_input = phylax.analyze_input(user_input)

with phylax.ignore():
    # Internal processing without compliance checks
    internal_context = build_internal_context(safe_input)
    debug_tokens = tokenize_for_debugging(internal_context)

# Back to normal monitoring
final_output = phylax.analyze_output(generate_response(safe_input))
```

### Integration with AI Frameworks

#### CrewAI Integration

```python
from crewai import Agent, Task, Crew
from phylax import Phylax

# Wrap CrewAI agents with Phylax monitoring
config = PhylaxConfig.from_yaml("security_policies.yaml")

with Phylax(config) as phylax:
    # Define your agents
    researcher = Agent(
        role='Researcher',
        goal='Research the given topic',
        backstory='Expert researcher with access to various sources'
    )

    # Define tasks
    research_task = Task(
        description='Research AI safety best practices',
        agent=researcher
    )

    # Run crew with automatic monitoring
    crew = Crew(agents=[researcher], tasks=[research_task])
    result = crew.kickoff()  # All agent interactions monitored
```

#### LangChain Integration

```python
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from phylax import Phylax

config = PhylaxConfig.from_yaml("security_policies.yaml")
phylax = Phylax(config)

# Explicit monitoring approach
llm = OpenAI(temperature=0.7)
chain = LLMChain(llm=llm, prompt=prompt_template)

# Monitor input and output explicitly
user_query = "Tell me about user authentication"
safe_query = phylax.analyze_input(user_query, context="User query")

response = chain.run(safe_query)
safe_response = phylax.analyze_output(response, context="LLM response")

print(f"Safe response: {safe_response}")
```

## Policy Configuration

### Policy Types

#### Regex Policies
```yaml
- id: credit_card_detector
  type: regex
  pattern: "\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}[-\\s]?\\d{4}"
  severity: high
  trigger: raise
  scope: [output, analysis]
```

#### SPDX License Policies
```yaml
- id: license_compliance
  type: spdx
  allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause]
  severity: medium
  trigger: log
  scope: [file, analysis]
```

#### Custom Policies
```python
# Define custom validation function
def check_custom_policy(data: str) -> bool:
    # Your custom logic here
    return "forbidden_pattern" in data.lower()

# Add to policy (programmatically)
policy = Policy(
    id="custom_check",
    type="custom",
    severity="medium",
    trigger="log"
)
policy.custom_func = check_custom_policy
```

### Trigger Types

- **`raise`**: Raise a `PhylaxViolation` exception
- **`log`**: Log the violation (default)
- **`human_review`**: Queue for human review (implement via `on_violation` callback)
- **`mitigate`**: Custom mitigation (implement via `on_violation` callback)

### Scope Types

- **`input`**: Monitor data going into functions/agents
- **`output`**: Monitor data coming from functions/agents
- **`network`**: Monitor HTTP requests and responses
- **`file`**: Monitor file read operations
- **`console`**: Monitor stdout/stderr output
- **`analysis`**: Monitor explicit `analyze()` calls

## Command Line Interface

Phylax includes a CLI for validation and testing:

```bash
# Validate a policy configuration file
phylax validate policies.yaml

# Scan text against policies
phylax scan "Check this text for violations"

# Scan with custom config
phylax scan "Text to check" --config my_policies.yaml

# Show version
phylax --version
```

## Development

### Setting up Development Environment

```bash
# Clone the repository
git clone https://github.com/dowhiledev/phylax.git
cd phylax

# Install with development dependencies using uv
uv sync --dev

# Or install development extras with pip
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=phylax

# Run specific test file
uv run pytest tests/test_core.py
```

### Code Quality

```bash
# Format and lint code
uv run ruff format .
uv run ruff check . --fix

# Type checking
uv run mypy src/phylax
```

## Examples

Check out the `examples/` directory for comprehensive examples:

- `basic_usage.py` - Basic Phylax usage patterns
- `yaml_config_example.py` - Using YAML configuration files
- `security_policies.yaml` - Example security policy configuration

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

If you discover a security vulnerability, please send an e-mail to security@phylax.dev. All security vulnerabilities will be promptly addressed.

## Support

- **Documentation**: [https://phylax.readthedocs.io](https://phylax.readthedocs.io)
- **Issues**: [GitHub Issues](https://github.com/dowhiledev/phylax/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dowhiledev/phylax/discussions)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
