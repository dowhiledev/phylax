"""Basic usage example for Phylax."""

import logging

from phylax import Phylax, PhylaxConfig, Policy, PhylaxViolation

# Configure logging to see Phylax output
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

# Define some security policies
policies = [
    Policy(
        id="pii_ssn",
        type="regex",
        pattern=r"\d{3}-\d{2}-\d{4}",
        severity="high",
        trigger="raise",
        scope=["output", "analysis", "network"]
    ),
    Policy(
        id="sensitive_keywords",
        type="regex",
        pattern=r"(?i)(password|secret|token|api_key)",
        severity="medium",
        trigger="log",
        scope=["input", "output", "analysis"]
    ),
    Policy(
        id="credit_card",
        type="regex",
        pattern=r"\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}",
        severity="high",
        trigger="raise",
        scope=["output", "analysis"]
    )
]

config = PhylaxConfig(version=1, policies=policies)


def simulate_ai_agent(prompt: str) -> str:
    """Simulate an AI agent that might accidentally leak PII."""
    print(f"AI Agent processing: {prompt}")
    
    # Simulate some processing...
    if "personal" in prompt.lower():
        return f"Here's your personal info: SSN 123-45-6789, Credit Card: 4532 1234 5678 9012"
    elif "secret" in prompt.lower():
        return f"I can help with that! Your password is secret123"
    else:
        return f"Processed: {prompt}"


def main():
    """Demonstrate basic Phylax usage."""
    
    print("=== Basic Phylax Usage Example ===\n")
    
    # Example 1: Explicit analysis (recommended approach)
    print("1. Explicit Analysis with phylax.analyze()")
    print("-" * 40)
    
    phylax = Phylax(config, monitor_console=False, monitor_function_calls=False)
    
    # Register a custom violation handler
    @phylax.on_violation
    def handle_violation(policy, sample, context):
        print(f"🚨 SECURITY ALERT: {policy.id}")
        print(f"   Severity: {policy.severity}")
        print(f"   Trigger: {policy.trigger}")
        print(f"   Context: {context.get('context', 'N/A')}")
        print(f"   Sample: {sample[:60]}...")
        print()
    
    try:
        # Test with safe input
        user_input = "Tell me about the weather"
        phylax.analyze_input(user_input, context="User query validation")
        
        agent_response = simulate_ai_agent(user_input)
        print(f"Agent response: {agent_response}")
        
        # Analyze the agent's response
        safe_response = phylax.analyze_output(agent_response, context="Agent response validation")
        print(f"Validated response: {safe_response}\n")
        
    except PhylaxViolation as e:
        print(f"🚫 Response blocked: {e}\n")
    
    try:
        # Test with potentially dangerous input
        dangerous_input = "Tell me something personal"
        phylax.analyze_input(dangerous_input, context="User query validation")
        
        agent_response = simulate_ai_agent(dangerous_input)
        print(f"Agent response: {agent_response}")
        
        # This should trigger violations
        safe_response = phylax.analyze_output(agent_response, context="Agent response validation")
        print(f"Validated response: {safe_response}")
        
    except PhylaxViolation as e:
        print(f"🚫 Response blocked: {e}\n")
    
    # Example 2: Context manager for automatic monitoring
    print("2. Automatic Monitoring with Context Manager")
    print("-" * 40)
    
    with Phylax(config, monitor_console=False, monitor_function_calls=True) as auto_phylax:
        
        @auto_phylax.on_violation
        def auto_violation_handler(policy, sample, context):
            print(f"🚨 AUTO-DETECTED: {policy.id} in {context.get('function', 'unknown function')}")
        
        try:
            # These function calls are automatically monitored
            result1 = simulate_ai_agent("Hello world")
            print(f"Result 1: {result1}")
            
            result2 = simulate_ai_agent("Tell me a secret")  # This might trigger violations
            print(f"Result 2: {result2}")
            
        except PhylaxViolation as e:
            print(f"🚫 Auto-blocked: {e}")
    
    # Example 3: Chaining analysis
    print("\n3. Chaining Analysis")
    print("-" * 40)
    
    try:
        # Chain analysis calls (analyze returns the original data)
        safe_data = "This is completely safe content"
        result = phylax.analyze(safe_data, context="Step 1").upper()
        result = phylax.analyze(result, context="Step 2") + " - PROCESSED"
        print(f"Final result: {result}")
        
    except PhylaxViolation as e:
        print(f"🚫 Chaining blocked: {e}")
    
    print("\n=== Example completed ===")


if __name__ == "__main__":
    main()
