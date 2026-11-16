"""
String buffer utility for efficient string building.

In Python, we can use StringIO or just accumulate strings,
but this provides a familiar interface for the port.
"""

from io import StringIO
from typing import List, Any


class StringBuffer:
    """
    A string buffer for efficient string concatenation.

    Mimics the C StringBuffer but uses Python's StringIO internally.
    """

    def __init__(self, initial: str = ""):
        self._buffer = StringIO()
        if initial:
            self._buffer.write(initial)

    def add(self, s: str) -> 'StringBuffer':
        """Append a string to the buffer."""
        self._buffer.write(s)
        return self

    def printf(self, fmt: str, *args: Any) -> 'StringBuffer':
        """Append a formatted string (like printf)."""
        self._buffer.write(fmt % args if args else fmt)
        return self

    def addprintf(self, fmt: str, *args: Any) -> 'StringBuffer':
        """Alias for printf."""
        return self.printf(fmt, *args)

    def set(self, s: str) -> 'StringBuffer':
        """Replace the buffer contents."""
        self._buffer = StringIO()
        self._buffer.write(s)
        return self

    def clear(self) -> 'StringBuffer':
        """Clear the buffer."""
        self._buffer = StringIO()
        return self

    def getvalue(self) -> str:
        """Get the buffer contents as a string."""
        return self._buffer.getvalue()

    def __str__(self) -> str:
        return self.getvalue()

    def __repr__(self) -> str:
        return f"StringBuffer({self.getvalue()!r})"

    def __len__(self) -> int:
        return len(self.getvalue())

    def __bool__(self) -> bool:
        return bool(self.getvalue())
