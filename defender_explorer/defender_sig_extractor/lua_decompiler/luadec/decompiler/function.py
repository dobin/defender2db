"""
Decompilation state management.

The DecompilerState class tracks all state needed during decompilation
including register contents, pending operations, and control flow.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Any, Tuple, TYPE_CHECKING

from ..ast.statements import AstStatement, StatementType
from .loops import LoopItem, LoopTree
from .booleans import BoolOp, BooleanBuilder
from .tables import TableTracker

if TYPE_CHECKING:
    from ..bytecode.proto import Proto


# Maximum number of registers
MAXARG_A = 256


@dataclass
class VarListItem:
    """Pending variable assignment."""
    dest: str       # Destination variable name
    src: str        # Source expression
    reg: int        # Register involved


@dataclass
class RegisterInfo:
    """Information about a register's contents."""
    value: Optional[str] = None  # Symbolic value
    priority: int = 0            # Operator priority
    is_table: bool = False       # Is a table under construction
    local_idx: int = -1          # Local variable index (-1 if temp)
    is_pending: bool = False     # Has pending code to flush
    is_internal: bool = False    # Internal use (FOR loop vars)
    call_returns: int = 0        # Number of call results
    set_pc: int = -1             # PC where value was set
    used: bool = False           # Has value been consumed
    is_call_result: bool = False # True if value is a call result
    temp_name: Optional[str] = None  # Temp variable name if assigned
    is_method: bool = False      # True if this is a method call (from SELF)
    original_call_expr: Optional[str] = None  # Original call expression for temp var emission


class DecompilerState:
    """
    Main decompilation state container.

    Tracks register contents, pending operations, control flow state,
    and output generation during decompilation.
    """

    def __init__(self, proto: 'Proto', funcnumstr: str = "0"):
        self.proto = proto
        self.funcnumstr = funcnumstr

        # Program counter
        self.pc: int = 0

        # Register state - now using RegisterInfo for better tracking
        self.registers: List[RegisterInfo] = [RegisterInfo() for _ in range(MAXARG_A)]

        # Backward compatibility properties
        self.R: List[Optional[str]] = [None] * MAXARG_A
        self.Rprio: List[int] = [0] * MAXARG_A
        self.Rtabl: List[bool] = [False] * MAXARG_A
        self.Rvar: List[int] = [-1] * MAXARG_A
        self.Rpend: List[bool] = [False] * MAXARG_A
        self.Rinternal: List[bool] = [False] * MAXARG_A
        self.Rcall: List[int] = [0] * MAXARG_A

        # Last call register for variable returns
        self.last_call: int = 0
        self.last_call_pc: int = -1

        # Table construction tracking
        self.tables: TableTracker = TableTracker()

        # Pending test state for boolean expressions
        self.test_pending: int = 0   # Register being tested + 1, or 0 if none
        self.test_jump: int = 0      # PC of test jump destination
        self.test_type: int = 0      # Type of test (for AND/OR)
        self.test_reg: int = -1      # Register involved in test

        # Pending assignments
        self.vpend: List[VarListItem] = []
        self.tpend: Set[int] = set()

        # Loop tracking
        self.loop_tree: Optional[LoopTree] = None
        self.loop_ptr: Optional[LoopItem] = None

        # Control flow
        self.breaks: Set[int] = set()
        self.continues: Set[int] = set()
        self.jmpdests: Dict[int, AstStatement] = {}  # pc -> jump dest statement

        # If/else tracking
        self.if_stack: List[Tuple[int, int, AstStatement]] = []  # (then_end, else_end, if_stmt)

        # do/end block tracking
        self.do_opens: Set[int] = set()
        self.do_closes: Set[int] = set()

        # Local variable management
        self.released_local: int = 0
        self.ignore_for_variables: bool = False
        self.free_local: int = 0
        self.local_pending: Dict[int, str] = {}  # reg -> pending value
        self.local_declarations: List[Tuple[int, List[str], List[str]]] = []  # (pc, names, values)

        # Boolean operations
        self.bools: List[BoolOp] = []
        self.bool_builder: BooleanBuilder = BooleanBuilder()

        # AST
        self.func_block: Optional[AstStatement] = None
        self.curr_stmt: Optional[AstStatement] = None
        self.first_line: int = 0
        self.last_line: int = 0

        # Output
        self.indent: int = 0

        # Error tracking
        self.error: Optional[str] = None

    def _sync_register_info(self, r: int) -> None:
        """Sync RegisterInfo with legacy arrays."""
        info = self.registers[r]
        self.R[r] = info.value
        self.Rprio[r] = info.priority
        self.Rtabl[r] = info.is_table
        self.Rvar[r] = info.local_idx
        self.Rpend[r] = info.is_pending
        self.Rinternal[r] = info.is_internal
        self.Rcall[r] = info.call_returns

    def _sync_from_legacy(self, r: int) -> None:
        """Sync legacy arrays back to RegisterInfo."""
        info = self.registers[r]
        info.value = self.R[r]
        info.priority = self.Rprio[r]
        info.is_table = self.Rtabl[r]
        info.local_idx = self.Rvar[r]
        info.is_pending = self.Rpend[r]
        info.is_internal = self.Rinternal[r]
        info.call_returns = self.Rcall[r]

    def get_register(self, r: int, consume: bool = True) -> str:
        """
        Get the symbolic value of a register.

        If consume=True, marks the register as used (for tracking expression reuse).
        If the register holds a table, returns the table constructor.
        """
        info = self.registers[r]

        # Handle table registers
        if info.is_table:
            self._flush_table(r)
            info = self.registers[r]  # Re-fetch after flush

        # If already has a temp name, use it
        if info.temp_name:
            return info.temp_name

        # Check if this is a reused call result - need to generate temp var
        if consume and info.used and info.is_call_result and info.local_idx < 0:
            # This call result has already been used, need to create a temp var
            temp_name = f"l_{r}_{self.pc}"
            info.temp_name = temp_name

            # Emit the local declaration using the original call expression
            original_expr = info.original_call_expr or info.value or f"TEMP_{r}"
            self.add_statement(f"local {temp_name} = {original_expr}")

            return temp_name

        # Mark as consumed if needed
        if consume and info.local_idx < 0:
            info.used = True
            info.is_pending = False
            self.tpend.discard(r)

        # Sync legacy
        self._sync_register_info(r)

        # Return value or generate placeholder
        if info.value is None:
            # Check if it's a local variable
            local_name = self._get_active_local_name(r)
            if local_name:
                return local_name
            return f"TEMP_{r}"

        return info.value

    def peek_register(self, r: int) -> Optional[str]:
        """Get register value without consuming it."""
        return self.get_register(r, consume=False)

    def set_register(self, r: int, value: str, prio: int = 0) -> None:
        """
        Set the symbolic value of a register.

        Handles variable assignments and pending operations.
        """
        info = self.registers[r]

        # Check if this is a boolean expression result
        if self._check_boolean_assignment(r, value):
            return

        # Check if register holds a local variable BEFORE clearing temp_name
        if info.local_idx >= 0:
            # Queue as variable assignment
            # First try the temp_name (for synthetic locals like l_0_1)
            # Then fall back to debug info
            var_name = info.temp_name or self._get_local_name_by_idx(info.local_idx)
            if var_name:
                self.vpend.append(VarListItem(dest=var_name, src=value, reg=r))
                # Update the register value but keep it marked as local
                info.value = var_name  # Keep using the local name
                info.priority = prio
                info.is_table = False
                info.is_pending = False
                info.call_returns = 0
                info.set_pc = self.pc
                info.used = False
                info.is_call_result = False
                info.is_method = False
                info.original_call_expr = None
                self._sync_register_info(r)
                return

        # Not a local - store as temp register
        info.value = value
        info.priority = prio
        info.is_table = False
        info.is_pending = True
        info.call_returns = 0
        info.set_pc = self.pc
        info.used = False
        info.temp_name = None  # Clear any stale temp name
        info.is_call_result = False
        info.is_method = False
        info.original_call_expr = None

        self.tpend.add(r)

        # Sync legacy
        self._sync_register_info(r)

    def _check_boolean_assignment(self, r: int, value: str) -> bool:
        """Check if this assignment is part of a boolean expression."""
        if self.test_pending == r + 1 and self.test_jump == self.pc + 2:
            # This is a boolean assignment pattern
            self.test_pending = 0
            return True
        return False

    def declare_local(self, name: str, reg: int, value: Optional[str] = None) -> None:
        """Declare a local variable in a register."""
        info = self.registers[reg]
        info.local_idx = reg  # Use reg as index for simplicity
        info.value = name
        info.priority = 0
        info.is_pending = False
        info.used = False

        self.tpend.discard(reg)
        self._sync_register_info(reg)

        # Track for local declaration output
        if value is not None:
            self.local_pending[reg] = value

    def release_local(self, reg: int) -> None:
        """Release a local variable from a register."""
        info = self.registers[reg]
        info.local_idx = -1
        self._sync_register_info(reg)

    def is_local(self, reg: int) -> bool:
        """Check if a register holds a local variable."""
        return self.registers[reg].local_idx >= 0

    def _get_active_local_name(self, reg: int) -> Optional[str]:
        """Get active local variable name at current PC."""
        count = 0
        for locvar in self.proto.locvars:
            if locvar.startpc <= self.pc < locvar.endpc:
                if count == reg:
                    return locvar.varname
                count += 1
        return None

    def _get_local_name_by_idx(self, idx: int) -> Optional[str]:
        """Get local variable name by index."""
        if 0 <= idx < len(self.proto.locvars):
            return self.proto.locvars[idx].varname
        return None

    def _flush_table(self, r: int) -> None:
        """Flush a table under construction."""
        table_str = self.tables.finish_table(r)
        if table_str:
            info = self.registers[r]
            info.value = table_str
            info.is_table = False

    def start_table(self, r: int, array_hint: int, hash_hint: int) -> None:
        """Start tracking a table in a register."""
        self.tables.start_table(r, self.pc, array_hint, hash_hint)
        info = self.registers[r]
        info.is_table = True
        info.value = None
        info.is_pending = True
        info.set_pc = self.pc
        info.temp_name = None  # Clear any stale temp name
        info.used = False
        info.is_call_result = False
        info.is_method = False
        self._sync_register_info(r)

    def add_statement(self, code: str) -> None:
        """Add a simple statement to the current block."""
        if self.curr_stmt:
            stmt = AstStatement.make_simple(code)
            stmt.line = self.pc
            self.curr_stmt.add_child(stmt)

    def add_block_statement(self, stmt: AstStatement) -> None:
        """Add a block statement to the current block."""
        if self.curr_stmt:
            stmt.line = self.pc
            self.curr_stmt.add_child(stmt)

    def enter_block(self, stmt: AstStatement) -> None:
        """Enter a new block."""
        self.add_block_statement(stmt)
        self.curr_stmt = stmt

    def leave_block(self) -> None:
        """Leave the current block."""
        if self.curr_stmt and self.curr_stmt.parent:
            self.curr_stmt = self.curr_stmt.parent

    def flush_pending_assignments(self) -> None:
        """Flush pending variable assignments to statements."""
        if not self.vpend:
            return

        # Group consecutive assignments
        for item in self.vpend:
            self.add_statement(f"{item.dest} = {item.src}")

        self.vpend.clear()

    def flush_local_declarations(self) -> None:
        """Flush pending local declarations."""
        if not self.local_pending:
            return

        # Sort by register to maintain order
        sorted_regs = sorted(self.local_pending.keys())

        names = []
        values = []
        for reg in sorted_regs:
            info = self.registers[reg]
            if info.value:
                names.append(info.value)
                val = self.local_pending[reg]
                if val != "nil":
                    values.append(val)

        if names:
            if values:
                self.add_statement(f"local {', '.join(names)} = {', '.join(values)}")
            else:
                self.add_statement(f"local {', '.join(names)}")

        self.local_pending.clear()

    def get_local_name(self, reg: int) -> Optional[str]:
        """Get the local variable name for a register at current PC."""
        for locvar in self.proto.locvars:
            if locvar.startpc <= self.pc < locvar.endpc:
                if reg == 0:
                    return locvar.varname
                reg -= 1
        return None

    def get_upvalue_name(self, idx: int) -> str:
        """Get the upvalue name at index."""
        if 0 <= idx < len(self.proto.upvalues) and self.proto.upvalues[idx]:
            return self.proto.upvalues[idx]
        return f"upval_{idx}"

    def get_constant(self, idx: int) -> Any:
        """Get constant at index."""
        if 0 <= idx < len(self.proto.k):
            return self.proto.k[idx]
        return None

    def set_error(self, msg: str) -> None:
        """Set an error message."""
        if not self.error:
            self.error = msg

    def mark_call_result(self, reg: int, num_results: int) -> None:
        """Mark a register as containing call results."""
        info = self.registers[reg]
        info.call_returns = num_results
        if num_results == 0:  # Variable results
            self.last_call = reg
            self.last_call_pc = self.pc
        self._sync_register_info(reg)

    def get_call_results_range(self) -> Tuple[int, int]:
        """Get the range of registers with variable call results."""
        if self.last_call_pc == self.pc - 1:
            # Results from previous instruction
            return self.last_call, self.last_call + 10  # Estimate
        return -1, -1
