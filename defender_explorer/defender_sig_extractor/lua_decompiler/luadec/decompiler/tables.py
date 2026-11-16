"""
Table construction tracking for decompilation.

Tracks table construction from NEWTABLE through SETTABLE/SETLIST
instructions to reconstruct table constructor syntax.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from ..bytecode.proto import is_identifier


@dataclass
class TableItem:
    """A single item in a table constructor."""
    value: str
    key: Optional[str] = None  # None for array part
    index: Optional[int] = None  # For array part


@dataclass
class DecTable:
    """
    Table under construction.

    Tracks all items added to a table between NEWTABLE and
    when the table is used or closed.
    """
    reg: int                     # Target register
    pc: int = 0                  # Creation PC
    array: List[TableItem] = field(default_factory=list)
    keyed: List[TableItem] = field(default_factory=list)
    array_size: int = 0          # Hint from NEWTABLE B
    keyed_size: int = 0          # Hint from NEWTABLE C
    pending_index: int = 1       # Next array index (1-based)
    used: bool = False           # Has the table been used?

    def add_array_item(self, value: str) -> None:
        """Add an item to the array part."""
        self.array.append(TableItem(value=value, index=self.pending_index))
        self.pending_index += 1

    def add_array_items(self, values: List[str], start_index: int) -> None:
        """Add multiple items to the array part from SETLIST."""
        for i, value in enumerate(values):
            self.array.append(TableItem(value=value, index=start_index + i))
        self.pending_index = start_index + len(values)

    def add_keyed_item(self, key: str, value: str) -> None:
        """Add an item to the keyed part."""
        self.keyed.append(TableItem(value=value, key=key))

    def to_string(self, multiline: bool = False, indent: int = 0) -> str:
        """
        Generate the table constructor string.

        Args:
            multiline: Use multiline format
            indent: Base indentation level
        """
        parts = []
        indent_str = "  " * (indent + 1) if multiline else ""
        sep = ",\n" if multiline else ", "

        # Sort array items by index
        sorted_array = sorted(self.array, key=lambda x: x.index or 0)

        # Add array items
        for item in sorted_array:
            if multiline:
                parts.append(f"{indent_str}{item.value}")
            else:
                parts.append(item.value)

        # Add keyed items
        for item in self.keyed:
            key_str = self._format_key(item.key)
            if multiline:
                parts.append(f"{indent_str}{key_str} = {item.value}")
            else:
                parts.append(f"{key_str} = {item.value}")

        if not parts:
            return "{}"

        if multiline:
            inner = sep.join(parts)
            base_indent = "  " * indent
            return f"{{\n{inner}\n{base_indent}}}"
        else:
            return "{" + ", ".join(parts) + "}"

    def _format_key(self, key: str) -> str:
        """Format a key for table constructor."""
        if not key:
            return "[]"

        # Check if it's a string literal
        if key.startswith('"') or key.startswith("'"):
            # Extract the string content
            inner = key[1:-1]
            if is_identifier(inner):
                return inner
            return f"[{key}]"

        # Check if it's a valid identifier
        if is_identifier(key):
            return key

        # Use bracket notation
        return f"[{key}]"


class TableTracker:
    """
    Tracks all tables under construction during decompilation.
    """

    def __init__(self):
        self.tables: Dict[int, DecTable] = {}  # reg -> table

    def start_table(self, reg: int, pc: int, array_size: int = 0, keyed_size: int = 0) -> DecTable:
        """Start tracking a new table."""
        table = DecTable(
            reg=reg,
            pc=pc,
            array_size=array_size,
            keyed_size=keyed_size
        )
        self.tables[reg] = table
        return table

    def get_table(self, reg: int) -> Optional[DecTable]:
        """Get the table being constructed in a register."""
        return self.tables.get(reg)

    def has_table(self, reg: int) -> bool:
        """Check if a register has a table under construction."""
        return reg in self.tables

    def finish_table(self, reg: int) -> Optional[str]:
        """
        Finish table construction and return the constructor string.

        Removes the table from tracking.
        """
        table = self.tables.pop(reg, None)
        if table:
            return table.to_string()
        return None

    def clear(self) -> None:
        """Clear all tracked tables."""
        self.tables.clear()

    def add_item(self, reg: int, key: Optional[str], value: str) -> bool:
        """
        Add an item to a table.

        Returns True if the item was added, False if no table found.
        """
        table = self.get_table(reg)
        if not table:
            return False

        if key is None:
            table.add_array_item(value)
        else:
            table.add_keyed_item(key, value)

        return True

    def set_list(self, reg: int, values: List[str], start_index: int) -> bool:
        """
        Add multiple items from SETLIST.

        Returns True if items were added, False if no table found.
        """
        table = self.get_table(reg)
        if not table:
            return False

        table.add_array_items(values, start_index)
        return True
