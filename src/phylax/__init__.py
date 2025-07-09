"""Phylax: A Security & Compliance layer for Python-based AI agents.

Phylax provides both context manager and explicit analysis approaches for monitoring
AI agent activity and enforcing security/compliance policies.

Example usage:
    # Context manager approach (automatic monitoring)
    with Phylax(config) as phylax:
        result = my_agent_function(prompt)
    
    # Explicit analysis approach
    phylax = Phylax(config)
    safe_output = phylax.analyze(agent_output, context="Agent response")

Features:
    - Context manager for automatic monitoring of function calls, network, console, files
    - Explicit analysis methods for targeted compliance checks
    - YAML-based policy configuration (regex, SPDX, custom)
    - Flexible trigger system (raise, log, human review, custom)
    - Event hooks for custom violation handling
    - Thread-safe operation
    - Support for custom input/output extractors
"""

from .core import Phylax, PhylaxViolation
from .config import PhylaxConfig, Policy
from .version import __version__

__all__ = [
    "Phylax",
    "PhylaxConfig", 
    "Policy",
    "PhylaxViolation",
    "__version__",
]
