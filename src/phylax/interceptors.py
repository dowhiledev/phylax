"""Core interceptor classes for Phylax."""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, TextIO

if TYPE_CHECKING:
    from .core import Phylax


class InterceptingWriter:
    """Intercepts writes to stdout/stderr for monitoring."""

    def __init__(self, original: TextIO, phylax: Phylax) -> None:
        self.original = original
        self.phylax = phylax

    def write(self, text: str) -> int:
        # Monitor output safely
        with contextlib.suppress(Exception):
            self.phylax._scan_payload(text, scope="console", direction="output")
        return self.original.write(text)

    def flush(self) -> None:
        return self.original.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self.original, name)


class PhylaxTracer:
    """Custom tracer that monitors function calls and returns."""

    def __init__(self, phylax: Phylax) -> None:
        self.phylax = phylax
        self.call_stack: list[dict[str, Any]] = []

    def trace_calls(self, frame: Any, event: str, arg: Any) -> Any:
        """Trace function for monitoring calls and returns."""
        try:
            if event == "call":
                self._handle_call(frame, arg)
            elif event == "return":
                self._handle_return(frame, arg)
            elif event == "exception":
                self._handle_exception(frame, arg)
        except Exception:
            # Don't let tracing errors break execution
            # This is intentionally broad to avoid breaking user code
            # We log the error and continue rather than crashing
            self.phylax._log.debug("Tracing error occurred", exc_info=True)
        return self.trace_calls

    def _handle_call(self, frame: Any, _arg: Any) -> None:
        """Handle function call event."""
        func_name = frame.f_code.co_name
        filename = frame.f_code.co_filename

        # Skip internal Python functions, Phylax internals, and problematic modules
        if (
            filename.startswith("<")
            or "phylax" in filename.lower()
            or func_name.startswith("_")
            or "site-packages" in filename
            or func_name in ("write", "flush", "__getattr__")
            or "IPython" in filename
            or "ipykernel" in filename
        ):
            return

        # Get function arguments safely
        args: list[Any] = []
        try:
            arg_names = frame.f_code.co_varnames[: frame.f_code.co_argcount]
            args.extend(
                frame.f_locals[name]
                for name in arg_names
                if name in frame.f_locals and name != "self"
            )
        except Exception:
            return

        # Monitor function input
        if args:
            with contextlib.suppress(Exception):
                input_data = self.phylax._input_extractor(
                    args[0] if len(args) == 1 else args
                )
                self.phylax._scan_payload(
                    input_data,
                    scope="input",
                    direction="input",
                    context={"function": func_name, "file": filename},
                )

        # Track call for return monitoring
        self.call_stack.append(
            {"function": func_name, "file": filename, "frame_id": id(frame)}
        )

    def _handle_return(self, frame: Any, return_value: Any) -> None:
        """Handle function return event."""
        if not self.call_stack:
            return

        # Find matching call
        frame_id = id(frame)
        call_info = None
        for i, call in enumerate(self.call_stack):
            if call["frame_id"] == frame_id:
                call_info = self.call_stack.pop(i)
                break

        if call_info and return_value is not None:
            with contextlib.suppress(Exception):
                # Monitor function output
                output_data = self.phylax._output_extractor(return_value)
                self.phylax._scan_payload(
                    output_data,
                    scope="output",
                    direction="output",
                    context={
                        "function": call_info["function"],
                        "file": call_info["file"],
                    },
                )

    def _handle_exception(self, frame: Any, _exc_info: Any) -> None:
        """Handle exception event."""
        # Clean up call stack for this frame
        frame_id = id(frame)
        self.call_stack = [
            call for call in self.call_stack if call["frame_id"] != frame_id
        ]
