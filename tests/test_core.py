"""Tests for Phylax core functionality."""

import pytest

from phylax import Phylax, PhylaxConfig, PhylaxViolation, Policy


class TestPhylax:
    """Test the main Phylax class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.test_policies = [
            Policy(
                id="ssn_detector",
                type="regex",
                pattern=r"\d{3}-\d{2}-\d{4}",
                severity="high",
                trigger="raise",
                scope=["output", "analysis"]
            ),
            Policy(
                id="password_detector",
                type="regex",
                pattern=r"(?i)password",
                severity="medium",
                trigger="log",
                scope=["input", "output", "analysis"]
            )
        ]
        
        self.config = PhylaxConfig(version=1, policies=self.test_policies)

    def test_phylax_creation(self):
        """Test creating a Phylax instance."""
        phylax = Phylax(self.config)
        
        assert phylax.cfg == self.config
        assert not phylax._active
        assert phylax.monitor_network is True
        assert phylax.monitor_console is False  # Default changed to False
        assert phylax.monitor_files is False
        assert phylax.monitor_function_calls is True

    def test_phylax_creation_with_yaml(self):
        """Test creating Phylax with YAML config."""
        yaml_config = """
version: 1
policies:
  - id: test_policy
    type: regex
    pattern: "test"
    severity: low
    trigger: log
"""
        
        phylax = Phylax(yaml_config)
        
        assert phylax.cfg.version == 1
        assert len(phylax.cfg.policies) == 1
        assert phylax.cfg.policies[0].id == "test_policy"

    def test_context_manager(self):
        """Test Phylax as context manager."""
        phylax = Phylax(self.config, monitor_function_calls=False)
        
        assert not phylax._active
        
        with phylax:
            assert phylax._active
        
        assert not phylax._active

    def test_context_manager_nested_error(self):
        """Test that nested context managers raise error."""
        phylax = Phylax(self.config)
        
        with phylax:
            with pytest.raises(RuntimeError, match="already active"):
                with phylax:
                    pass

    def test_analyze_method(self):
        """Test explicit analyze method."""
        phylax = Phylax(self.config)
        
        # Safe data should pass through
        safe_data = "This is safe content"
        result = phylax.analyze(safe_data)
        assert result == safe_data
        
        # Violation should raise exception
        with pytest.raises(PhylaxViolation):
            phylax.analyze("My SSN is 123-45-6789")

    def test_analyze_input_output_methods(self):
        """Test specific analyze_input and analyze_output methods."""
        phylax = Phylax(self.config)
        
        # Test analyze_input
        safe_input = "Hello world"
        result = phylax.analyze_input(safe_input)
        assert result == safe_input
        
        # Test analyze_output
        safe_output = "Goodbye world"
        result = phylax.analyze_output(safe_output)
        assert result == safe_output
        
        # Test violation in output
        with pytest.raises(PhylaxViolation):
            phylax.analyze_output("Your SSN is 123-45-6789")

    def test_analyze_chaining(self):
        """Test that analyze methods can be chained."""
        phylax = Phylax(self.config, monitor_function_calls=False)
        
        with phylax:
            # This should work since analyze returns the original data
            result = phylax.analyze("safe").upper()
            assert result == "SAFE"

    def test_violation_callback(self):
        """Test violation callback registration."""
        phylax = Phylax(self.config)
        
        violations_captured = []
        
        @phylax.on_violation
        def capture_violation(policy, sample, context):
            violations_captured.append((policy.id, sample[:20], context['scope']))
        
        # Test with log trigger (shouldn't raise)
        phylax.analyze("password123")  # Should trigger password_detector
        
        assert len(violations_captured) == 1
        policy_id, sample, scope = violations_captured[0]
        assert policy_id == "password_detector"
        assert "password123" in sample
        assert scope == "analysis"

    def test_input_output_callbacks(self):
        """Test input/output callback registration."""
        phylax = Phylax(self.config)
        
        input_data = []
        output_data = []
        
        @phylax.on_input
        def capture_input(data):
            input_data.append(data)
        
        @phylax.on_output
        def capture_output(data):
            output_data.append(data)
        
        # Test with input analysis
        phylax.analyze_input("test input")
        assert "test input" in input_data
        
        # Test with output analysis
        phylax.analyze_output("test output")
        assert "test output" in output_data

    def test_scope_filtering(self):
        """Test that policies only apply to their specified scopes."""
        phylax = Phylax(self.config)
        
        # SSN detector only applies to output and analysis scopes
        # So analyzing as "input" shouldn't trigger it
        ssn_data = "SSN: 123-45-6789"
        
        # This should not raise because ssn_detector doesn't apply to input scope
        result = phylax.analyze_input(ssn_data)
        assert result == ssn_data
        
        # But this should raise because ssn_detector applies to output scope
        with pytest.raises(PhylaxViolation):
            phylax.analyze_output(ssn_data)

    def test_scan_text_method(self):
        """Test the scan_text convenience method."""
        phylax = Phylax(self.config)
        
        violations_found = []
        
        @phylax.on_violation
        def capture_violations(policy, sample, context):
            violations_found.append(policy.id)
        
        with phylax:
            phylax.scan_text("This contains password")
        
        # Should find password_detector violation
        assert "password_detector" in violations_found

    def test_default_extractor(self):
        """Test the default data extractor."""
        phylax = Phylax(self.config)
        
        # Test string data
        assert phylax._default_extractor("test") == "test"
        
        # Test bytes data
        assert phylax._default_extractor(b"test") == "test"
        
        # Test other data types
        assert phylax._default_extractor(123) == "123"
        assert phylax._default_extractor(["list", "data"]) == "['list', 'data']"

    def test_custom_extractors(self):
        """Test custom input/output extractors."""
        def custom_input_extractor(data):
            if isinstance(data, dict):
                return data.get("message", str(data))
            return str(data)
        
        def custom_output_extractor(data):
            if isinstance(data, dict):
                return data.get("response", str(data))
            return str(data)
        
        phylax = Phylax(
            self.config,
            input_extractor=custom_input_extractor,
            output_extractor=custom_output_extractor
        )
        
        # Test with dictionary input
        input_dict = {"message": "password123", "other": "data"}
        
        violations_found = []
        
        @phylax.on_violation
        def capture_violations(policy, sample, context):
            violations_found.append(sample)
        
        phylax.analyze_input(input_dict)
        
        # Should extract "password123" from the message field
        assert any("password123" in v for v in violations_found)
