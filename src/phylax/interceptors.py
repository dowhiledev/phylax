"""Core interceptor classes for Phylax."""

from __future__ import annotations

import builtins
import logging
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, TextIO

from .config import PhylaxConfig, Policy


class InterceptingWriter:
    """Intercepts writes to stdout/stderr for monitoring."""
    
    def __init__(self, original: TextIO, phylax: 'Phylax'):
        self.original = original
        self.phylax = phylax
        
    def write(self, text: str) -> int:
        # Monitor output safely
        try:
            self.phylax._scan_payload(text, scope="console", direction="output")
        except Exception:
            # Don't let monitoring break the output
            pass
        return self.original.write(text)
    
    def flush(self):
        return self.original.flush()
    
    def __getattr__(self, name):
        return getattr(self.original, name)


class PhylaxTracer:
    """Custom tracer that monitors function calls and returns."""
    
    def __init__(self, phylax: 'Phylax'):
        self.phylax = phylax
        self.call_stack = []
        
    def trace_calls(self, frame, event, arg):
        """Trace function for monitoring calls and returns."""
        try:
            if event == 'call':
                self._handle_call(frame, arg)
            elif event == 'return':
                self._handle_return(frame, arg)
            elif event == 'exception':
                self._handle_exception(frame, arg)
        except Exception:
            # Don't let tracing errors break execution
            pass
        return self.trace_calls
    
    def _handle_call(self, frame, arg):
        """Handle function call event."""
        func_name = frame.f_code.co_name
        filename = frame.f_code.co_filename
        
        # Skip internal Python functions, Phylax internals, and problematic modules
        if (filename.startswith('<') or 
            'phylax' in filename.lower() or
            func_name.startswith('_') or
            'site-packages' in filename or
            func_name in ('write', 'flush', '__getattr__') or
            'IPython' in filename or
            'ipykernel' in filename):
            return
            
        # Get function arguments safely
        args = []
        try:
            arg_names = frame.f_code.co_varnames[:frame.f_code.co_argcount]
            for name in arg_names:
                if name in frame.f_locals and name != 'self':
                    args.append(frame.f_locals[name])
        except Exception:
            return
        
        # Monitor function input
        if args:
            try:
                input_data = self.phylax._input_extractor(args[0] if len(args) == 1 else args)
                self.phylax._scan_payload(input_data, scope="input", direction="input", context={
                    "function": func_name,
                    "file": filename
                })
            except Exception:
                pass
        
        # Track call for return monitoring
        self.call_stack.append({
            'function': func_name,
            'file': filename,
            'frame_id': id(frame)
        })
    
    def _handle_return(self, frame, return_value):
        """Handle function return event."""
        if not self.call_stack:
            return
            
        # Find matching call
        frame_id = id(frame)
        call_info = None
        for i, call in enumerate(self.call_stack):
            if call['frame_id'] == frame_id:
                call_info = self.call_stack.pop(i)
                break
        
        if call_info and return_value is not None:
            try:
                # Monitor function output
                output_data = self.phylax._output_extractor(return_value)
                self.phylax._scan_payload(output_data, scope="output", direction="output", context={
                    "function": call_info['function'],
                    "file": call_info['file']
                })
            except Exception:
                pass
    
    def _handle_exception(self, frame, exc_info):
        """Handle exception event."""
        # Clean up call stack for this frame
        frame_id = id(frame)
        self.call_stack = [call for call in self.call_stack if call['frame_id'] != frame_id]
