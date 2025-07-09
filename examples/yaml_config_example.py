"""Example using YAML configuration file."""

import logging
from pathlib import Path

from phylax import Phylax, PhylaxViolation

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class ChatBot:
    """Example chatbot that might leak sensitive information."""

    def __init__(self, name: str):
        self.name = name
        self.conversation_history = []

    def chat(self, message: str) -> str:
        """Process a chat message and return response."""
        response = f"{self.name}: "

        if "personal" in message.lower():
            response += "Your SSN is 123-45-6789 and email is user@example.com"
        elif "password" in message.lower():
            response += "Your password is super_secret123!"
        elif "database" in message.lower():
            response += "The database_password is admin123"
        elif "file" in message.lower():
            response += "Check /etc/passwd for user info"
        elif "credit" in message.lower():
            response += "Your credit card is 4532 1234 5678 9012"
        else:
            response += f"I understand you said: {message}"

        # Store conversation
        self.conversation_history.append((message, response))
        return response

    def get_history(self):
        """Get conversation history."""
        return self.conversation_history


def main():
    """Demonstrate YAML configuration usage."""

    print("=== Phylax with YAML Configuration ===\n")

    # Load configuration from YAML file
    config_path = Path(__file__).parent / "security_policies.yaml"

    # Create chatbot
    bot = ChatBot("SecurityBot")

    # Test conversations
    test_messages = [
        "Hello, how are you?",  # Safe
        "Tell me something personal",  # Will trigger PII policies
        "What's my password?",  # Will trigger credential policies
        "Show me database info",  # Will trigger high-risk policies
        "What files should I check?",  # Will trigger path policies
        "What's my credit card number?",  # Will trigger PII policies
    ]

    # Example 1: Explicit monitoring
    print("1. Explicit Analysis with YAML Config")
    print("-" * 40)

    phylax = Phylax(config_path, monitor_console=False, monitor_function_calls=False)

    violations_log = []

    @phylax.on_violation
    def log_violation(policy, sample, context):
        violation_info = {
            "policy_id": policy.id,
            "severity": policy.severity,
            "trigger": policy.trigger,
            "sample": sample[:50] + "..." if len(sample) > 50 else sample,
            "context": context.get("context", "N/A"),
        }
        violations_log.append(violation_info)

        print(f"🚨 VIOLATION: {policy.id}")
        print(f"   Severity: {policy.severity}")
        print(f"   Context: {violation_info['context']}")
        print(f"   Sample: {violation_info['sample']}")
        print()

    for message in test_messages:
        print(f"User: {message}")

        try:
            # Analyze input
            safe_input = phylax.analyze_input(message, context="User message analysis")

            # Get bot response
            response = bot.chat(message)
            print(f"Bot: {response}")

            # Analyze output
            safe_output = phylax.analyze_output(
                response, context="Bot response analysis"
            )

        except PhylaxViolation as e:
            print(f"🚫 BLOCKED: {e}")

        print("-" * 40)

    # Example 2: Automatic monitoring with context manager
    print("\n2. Automatic Monitoring of Bot Interactions")
    print("-" * 40)

    bot2 = ChatBot("AutoBot")

    with Phylax(
        config_path, monitor_console=False, monitor_function_calls=True
    ) as auto_phylax:
        violations_count = 0

        @auto_phylax.on_violation
        def count_violations(policy, sample, context):
            nonlocal violations_count
            violations_count += 1
            print(
                f"🚨 Auto-detected #{violations_count}: {policy.id} in {context.get('function', 'unknown')}"
            )

        try:
            # These calls are automatically monitored
            for message in test_messages[:3]:  # Test first 3 messages
                print(f"User: {message}")
                response = bot2.chat(message)  # Automatically monitored
                print(f"AutoBot: {response}")
                print()

        except PhylaxViolation as e:
            print(f"🚫 Auto-blocked: {e}")

    # Summary
    print("\n3. Security Summary")
    print("-" * 40)
    print(f"Total violations detected: {len(violations_log)}")

    # Group by severity
    by_severity = {}
    for violation in violations_log:
        severity = violation["severity"]
        by_severity[severity] = by_severity.get(severity, 0) + 1

    for severity, count in by_severity.items():
        print(f"  {severity.upper()}: {count}")

    print(f"\nBot conversation history: {len(bot.get_history())} exchanges")

    print("\n=== YAML Example completed ===")


if __name__ == "__main__":
    main()
