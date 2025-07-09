"""Command-line interface for Phylax."""

import argparse
import sys
from pathlib import Path

from .config import PhylaxConfig
from .core import Phylax
from .version import __version__


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Phylax: Security & Compliance layer for Python AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phylax --version                    Show version information
  phylax validate policy.yaml        Validate a policy configuration file
  phylax scan "suspicious text"      Scan text against default policies
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"Phylax {__version__}"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Validate command
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a policy configuration file"
    )
    validate_parser.add_argument(
        "config_file",
        type=Path,
        help="Path to the YAML policy configuration file"
    )
    
    # Scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan text against policies"
    )
    scan_parser.add_argument(
        "text",
        help="Text to scan for policy violations"
    )
    scan_parser.add_argument(
        "--config",
        type=Path,
        help="Path to policy configuration file (optional)"
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == "validate":
            validate_config(args.config_file)
        elif args.command == "scan":
            scan_text(args.text, args.config)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


def validate_config(config_file: Path) -> None:
    """Validate a policy configuration file."""
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    
    try:
        config = PhylaxConfig.from_yaml(config_file)
        print(f"✅ Configuration file is valid: {config_file}")
        print(f"   Version: {config.version}")
        print(f"   Policies: {len(config.policies)}")
        
        for policy in config.policies:
            print(f"   - {policy.id} ({policy.type}, {policy.severity})")
            
    except Exception as e:
        raise ValueError(f"Invalid configuration: {e}")


def scan_text(text: str, config_file: Path = None) -> None:
    """Scan text against policies."""
    if config_file:
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        config = PhylaxConfig.from_yaml(config_file)
    else:
        # Use default minimal policies for demonstration
        config = PhylaxConfig(
            version=1,
            policies=[
                {
                    "id": "pii_ssn",
                    "type": "regex",
                    "pattern": r"\d{3}-\d{2}-\d{4}",
                    "severity": "high",
                    "trigger": "log"
                },
                {
                    "id": "sensitive_keywords",
                    "type": "regex", 
                    "pattern": r"(?i)(password|secret|token)",
                    "severity": "medium",
                    "trigger": "log"
                }
            ]
        )
    
    phylax = Phylax(config, monitor_console=False, monitor_network=False, monitor_function_calls=False)
    
    violations_found = []
    
    @phylax.on_violation
    def collect_violations(policy, sample, context):
        violations_found.append((policy, sample, context))
    
    # Analyze the text
    phylax.analyze(text, context="CLI scan")
    
    if violations_found:
        print(f"🚨 Found {len(violations_found)} policy violation(s):")
        for policy, sample, context in violations_found:
            print(f"   - Policy: {policy.id} ({policy.severity})")
            print(f"     Sample: {sample[:80]}...")
    else:
        print("✅ No policy violations found")


if __name__ == "__main__":
    main()
