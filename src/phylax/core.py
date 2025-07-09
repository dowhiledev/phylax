"""Main Phylax context manager and core functionality."""

from __future__ import annotations

import builtins
from collections.abc import Callable
import logging
from pathlib import Path
import sys
import threading
import time
from typing import Any
import uuid

try:
    import httpx
except ImportError:
    httpx = None

try:
    import requests
except ImportError:
    requests = None

from .config import PhylaxConfig, Policy
from .exceptions import PhylaxViolation
from .interceptors import InterceptingWriter, PhylaxTracer


class Phylax:
    """Context manager that monitors all activity within its scope."""

    def __init__(
        self,
        config: PhylaxConfig | str | Path | bytes,
        monitor_network: bool = True,
        monitor_console: bool = False,  # Changed default to False
        monitor_files: bool = False,
        monitor_function_calls: bool = True,
        input_extractor: Callable[[Any], str] | None = None,
        output_extractor: Callable[[Any], str] | None = None,
    ):
        self.cfg = (
            config
            if isinstance(config, PhylaxConfig)
            else PhylaxConfig.from_yaml(config)
        )
        self.monitor_network = monitor_network
        self.monitor_console = monitor_console
        self.monitor_files = monitor_files
        self.monitor_function_calls = monitor_function_calls
        self._log = logging.getLogger("phylax")

        # Custom extractors
        self._input_extractor = input_extractor or self._default_extractor
        self._output_extractor = output_extractor or self._default_extractor

        # Event hooks
        self._on_input: list[Callable[[Any], Any]] = []
        self._on_output: list[Callable[[Any], Any]] = []
        self._on_violation: list[Callable[[Policy, str, dict[str, Any]], None]] = []

        # State tracking
        self._active = False
        self._patches_applied = []

        # Original references for patching
        self._orig_stdout = None
        self._orig_stderr = None
        self._orig_requests_send = None
        self._orig_open = None
        self._orig_tracer = None

        # Tracer for function monitoring
        self._tracer = PhylaxTracer(self)

        # Thread safety
        self._lock = threading.Lock()

    def _default_extractor(self, data: Any) -> str:
        """Default extractor that converts data to string."""
        try:
            if isinstance(data, str):
                return data
            if isinstance(data, bytes):
                return data.decode("utf-8", errors="ignore")
            return str(data)
        except Exception:
            return "<extraction_failed>"

    # ------------------------------------------------------------------
    # Context Manager Protocol
    # ------------------------------------------------------------------

    def __enter__(self):
        with self._lock:
            if self._active:
                raise RuntimeError("Phylax context is already active")

            self._active = True
            self._apply_patches()
            self._log.debug("Phylax monitoring context activated")
            return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        with self._lock:
            if self._active:
                self._remove_patches()
                self._active = False
                self._log.debug("Phylax monitoring context deactivated")
            return False

    # ------------------------------------------------------------------
    # Patching Methods
    # ------------------------------------------------------------------

    def _apply_patches(self):
        """Apply all configured patches."""
        if self.monitor_console:
            self._patch_console()
        if self.monitor_network:
            self._patch_network()
        if self.monitor_files:
            self._patch_files()
        if self.monitor_function_calls:
            self._patch_function_calls()

    def _remove_patches(self):
        """Remove all applied patches."""
        if "console" in self._patches_applied:
            self._unpatch_console()
        if "network" in self._patches_applied:
            self._unpatch_network()
        if "files" in self._patches_applied:
            self._unpatch_files()
        if "function_calls" in self._patches_applied:
            self._unpatch_function_calls()
        self._patches_applied.clear()

    def _patch_console(self):
        """Patch stdout/stderr to monitor console output."""
        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr

        sys.stdout = InterceptingWriter(self._orig_stdout, self)
        sys.stderr = InterceptingWriter(self._orig_stderr, self)

        self._patches_applied.append("console")

    def _unpatch_console(self):
        """Restore original stdout/stderr."""
        if self._orig_stdout:
            sys.stdout = self._orig_stdout
        if self._orig_stderr:
            sys.stderr = self._orig_stderr

    def _patch_network(self):
        """Patch network libraries to monitor requests/responses."""
        if not requests:
            self._log.warning("requests library not available for network monitoring")
            return

        # Patch requests
        def _patched_send(session, req, **kwargs):
            # Monitor request
            if req.body:
                self._scan_payload(req.body, scope="network", direction="request")

            # Execute original request
            resp = self._orig_requests_send(session, req, **kwargs)

            # Monitor response
            if hasattr(resp, "text"):
                self._scan_payload(resp.text, scope="network", direction="response")

            return resp

        if not self._orig_requests_send:
            self._orig_requests_send = requests.Session.send
            requests.Session.send = _patched_send

        self._patches_applied.append("network")

    def _unpatch_network(self):
        """Restore original network methods."""
        if self._orig_requests_send and requests:
            requests.Session.send = self._orig_requests_send

    def _patch_files(self):
        """Patch file operations to monitor file I/O."""

        def _patched_open(*args, **kwargs):
            file_obj = self._orig_open(*args, **kwargs)

            # Monitor file content if it's readable
            if hasattr(file_obj, "read") and "r" in kwargs.get("mode", "r"):
                try:
                    content = file_obj.read()
                    file_obj.seek(0)  # Reset file pointer
                    self._scan_payload(content, scope="file", direction="input")
                except Exception as exc:
                    self._log.debug("Could not monitor file content: %s", exc)

            return file_obj

        if not self._orig_open:
            self._orig_open = builtins.open
            builtins.open = _patched_open

        self._patches_applied.append("files")

    def _unpatch_files(self):
        """Restore original file operations."""
        if self._orig_open:
            builtins.open = self._orig_open

    def _patch_function_calls(self):
        """Patch sys.settrace to monitor function calls."""
        self._orig_tracer = sys.gettrace()
        sys.settrace(self._tracer.trace_calls)
        self._patches_applied.append("function_calls")

    def _unpatch_function_calls(self):
        """Restore original tracer."""
        sys.settrace(self._orig_tracer)

    # ------------------------------------------------------------------
    # Analysis Methods
    # ------------------------------------------------------------------

    def analyze(
        self, data: Any, *, context: str | None = None, data_type: str = "mixed"
    ) -> Any:
        """
        Explicitly analyze data for policy violations.

        Args:
            data: The data to analyze (string, object, etc.)
            context: Optional context description for violation reporting
            data_type: Type of data being analyzed (input, output, mixed)

        Returns:
            The original data (for chaining)

        Raises:
            PhylaxViolation: If a policy violation is detected and trigger=raise
        """
        analysis_context = {
            "method": "analyze",
            "data_type": data_type,
            "timestamp": time.time(),
        }

        if context:
            analysis_context["context"] = context

        self._scan_payload(
            data, scope="analysis", direction=data_type, context=analysis_context
        )

        # Fire analysis callbacks
        for cb in self._on_input if data_type == "input" else self._on_output:
            try:
                cb(data)
            except Exception as exc:
                self._log.warning("analysis callback failed: %s", exc)

        return data

    def analyze_input(self, data: Any, *, context: str | None = None) -> Any:
        """Analyze input data for policy violations.

        Args:
            data: The data to analyze
            context: Optional context information

        Returns:
            The input data if no violations are found

        Raises:
            PhylaxViolation: If a policy violation is detected
        """
        analysis_context = {
            "method": "analyze_input",
            "direction": "input",
            "data_type": "input",
        }
        if context:
            analysis_context["context"] = context

        # Scan with input scope specifically
        self._scan_payload(
            data, scope="input", direction="input", context=analysis_context
        )

        # Fire input callbacks
        for cb in self._on_input:
            try:
                cb(data)
            except Exception as exc:
                self._log.warning("on_input callback failed: %s", exc)

        return data

    def analyze_output(self, data: Any, *, context: str | None = None) -> Any:
        """Analyze output data for policy violations.

        Args:
            data: The data to analyze
            context: Optional context information

        Returns:
            The output data if no violations are found

        Raises:
            PhylaxViolation: If a policy violation is detected
        """
        analysis_context = {
            "method": "analyze_output",
            "direction": "output",
            "data_type": "output",
        }
        if context:
            analysis_context["context"] = context

        # Scan with output scope specifically
        self._scan_payload(
            data, scope="output", direction="output", context=analysis_context
        )

        # Fire output callbacks
        for cb in self._on_output:
            try:
                cb(data)
            except Exception as exc:
                self._log.warning("on_output callback failed: %s", exc)

        return data

    # ------------------------------------------------------------------
    # Legacy Monitoring Methods
    # ------------------------------------------------------------------

    def monitor_call(self, func: Callable, *args, **kwargs):
        """Manually monitor a function call (legacy method, not needed with auto-monitoring)."""
        # Extract and monitor input
        input_data = self._input_extractor(args[0] if args else kwargs)
        self._scan_payload(input_data, scope="input", direction="input")

        # Fire input callbacks
        for cb in self._on_input:
            try:
                cb(input_data)
            except Exception as exc:
                self._log.warning("on_input callback failed: %s", exc)

        # Execute function
        result = func(*args, **kwargs)

        # Extract and monitor output
        output_data = self._output_extractor(result)
        self._scan_payload(output_data, scope="output", direction="output")

        # Fire output callbacks
        for cb in self._on_output:
            try:
                cb(output_data)
            except Exception as exc:
                self._log.warning("on_output callback failed: %s", exc)

        return result

    def _scan_payload(
        self,
        data: Any,
        *,
        scope: str,
        direction: str,
        context: dict[str, Any] | None = None,
    ):
        """Scan payload for policy violations."""
        # For explicit analysis methods, always scan regardless of _active state
        # For automatic monitoring, only scan when _active is True
        method = context.get("method") if context else None
        is_explicit_analysis = method in [
            "analyze",
            "analyze_input",
            "analyze_output",
            "scan_text",
        ]

        if not is_explicit_analysis and not self._active:
            return

        try:
            txt_repr = self._default_extractor(data)
        except Exception as exc:
            self._log.debug("Cannot convert payload to str for scanning: %s", exc)
            return

        for policy in self.cfg.policies:
            if policy.applies_to_scope(scope) and policy.matches(txt_repr):
                violation_context = {
                    "scope": scope,
                    "direction": direction,
                    "timestamp": time.time(),
                }
                if context:
                    violation_context.update(context)
                self._handle_violation(
                    policy, sample=txt_repr, context=violation_context
                )

    def _handle_violation(self, policy: Policy, sample: str, context: dict[str, Any]):
        """Handle a policy violation."""
        self._log.warning(
            "%s violation of policy '%s' in scope '%s'",
            policy.severity.upper(),
            policy.id,
            context.get("scope", "unknown"),
        )

        # Fire user hooks first
        for cb in self._on_violation:
            try:
                cb(policy, sample, context)
            except Exception as exc:
                self._log.error("on_violation callback failed: %s", exc)

        # Built‑in trigger implementations
        trigger = policy.trigger.lower()
        if trigger in {"raise", "raise_", "quarantine"}:
            raise PhylaxViolation(policy, sample, context)
        if trigger == "log":
            pass  # already logged
        elif trigger == "human_review":
            self._send_for_human_review(policy, sample, context)
        elif trigger == "mitigate":
            pass  # Users can handle via on_violation hooks
        else:
            self._log.debug("Unknown trigger '%s' – ignoring", trigger)

    def _send_for_human_review(
        self, policy: Policy, sample: str, context: dict[str, Any]
    ):
        """Stub to integrate e.g. Slack, email, ticket system."""
        ticket_id = uuid.uuid4().hex[:8]
        self._log.warning(
            "Queued human review ticket %s for policy %s", ticket_id, policy.id
        )

    # ------------------------------------------------------------------
    # Event Hooks
    # ------------------------------------------------------------------

    def on_input(self, fn: Callable[[Any], Any]):
        """Register input callback."""
        self._on_input.append(fn)
        return fn

    def on_output(self, fn: Callable[[Any], Any]):
        """Register output callback."""
        self._on_output.append(fn)
        return fn

    def on_violation(self, fn: Callable[[Policy, str, dict[str, Any]], None]):
        """Register violation callback."""
        self._on_violation.append(fn)
        return fn

    # ------------------------------------------------------------------
    # Convenience Methods
    # ------------------------------------------------------------------

    def scan_text(self, text: str, scope: str = "analysis"):
        """Manually scan text for violations."""
        self._scan_payload(text, scope=scope, direction="manual")

    def get_httpx_transport(self):
        """Get HTTPX transport for manual integration."""
        if not httpx:
            raise ImportError("httpx is required for HTTPX transport integration")

        class _InterceptTransport(httpx.HTTPTransport):
            def __init__(self, phylax: Phylax, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.phylax = phylax

            def handle_request(self, request):
                self.phylax._scan_payload(
                    request.content, scope="network", direction="request"
                )
                response = super().handle_request(request)
                self.phylax._scan_payload(
                    response.content, scope="network", direction="response"
                )
                return response

        return _InterceptTransport(self)
