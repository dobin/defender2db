"""
Local variable name guessing for decompilation.

When debug info is stripped, we need to generate meaningful variable names
based on usage patterns and context. This module provides heuristics for
guessing variable names.

Based on the original luadec's guess.c functionality.
"""

from typing import List, Optional, Dict, Set, Tuple, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from ..bytecode.proto import Proto


@dataclass
class VarInfo:
    """Information about a local variable."""
    reg: int                # Register number
    name: str               # Guessed name
    start_pc: int = 0       # Scope start
    end_pc: int = 0         # Scope end
    is_param: bool = False  # Is a function parameter
    source_hint: str = ""   # What hint led to this name


class NameGuesser:
    """
    Guesses local variable names based on usage patterns.

    Strategies:
    1. Use debug info if available (locvars)
    2. Use parameter position patterns (a0, a1, ... or self, arg1, ...)
    3. Analyze assignment sources (e.g., x = obj.name -> name)
    4. Analyze function call patterns (e.g., for k,v in pairs())
    5. Use common naming conventions
    """

    def __init__(self, proto: 'Proto'):
        self.proto = proto
        self.used_names: Set[str] = set()
        self.var_info: Dict[int, VarInfo] = {}  # reg -> VarInfo

    def guess_all_locals(self) -> Dict[int, str]:
        """
        Guess names for all local variables.

        Returns dict mapping register -> guessed name.
        """
        # First, use debug info if available
        self._use_debug_info()

        # Guess parameter names
        self._guess_parameters()

        # Analyze bytecode for additional hints
        self._analyze_bytecode()

        # Return mapping
        return {reg: info.name for reg, info in self.var_info.items()}

    def _use_debug_info(self) -> None:
        """Extract names from debug info (locvars)."""
        for i, locvar in enumerate(self.proto.locvars):
            if locvar.varname and not locvar.varname.startswith('('):
                # Skip internal names like "(for index)"
                reg = self._count_active_at(i, locvar.startpc)
                if reg >= 0:
                    self.var_info[reg] = VarInfo(
                        reg=reg,
                        name=locvar.varname,
                        start_pc=locvar.startpc,
                        end_pc=locvar.endpc,
                        source_hint="debug_info"
                    )
                    self.used_names.add(locvar.varname)

    def _count_active_at(self, target_idx: int, pc: int) -> int:
        """Count active locals to determine register for a locvar entry."""
        count = 0
        for i, locvar in enumerate(self.proto.locvars):
            if i == target_idx:
                return count
            if locvar.startpc <= pc < locvar.endpc:
                count += 1
        return -1

    def _guess_parameters(self) -> None:
        """Guess names for function parameters."""
        num_params = self.proto.numparams

        for i in range(num_params):
            if i in self.var_info:
                continue  # Already have a name from debug info

            # Use different patterns based on context
            if i == 0 and self._is_method():
                name = "self"
            else:
                name = self._generate_param_name(i)

            self.var_info[i] = VarInfo(
                reg=i,
                name=name,
                start_pc=0,
                end_pc=self.proto.sizecode,
                is_param=True,
                source_hint="parameter"
            )
            self.used_names.add(name)

    def _is_method(self) -> bool:
        """Check if this function is likely a method (uses self pattern)."""
        # Check if first parameter is used with : syntax
        # This is a heuristic - check for SELF opcode usage
        from ..bytecode.instruction import Instruction
        from ..bytecode.opcodes import OpCode

        if self.proto.numparams < 1:
            return False

        for i in range(min(10, self.proto.sizecode)):
            inst = Instruction.decode(self.proto.code[i])
            if inst.op == OpCode.SELF and inst.b == 0:
                # First parameter is used as self
                return True
        return False

    def _generate_param_name(self, index: int) -> str:
        """Generate a parameter name for the given index."""
        # Common patterns
        if index == 0:
            candidates = ["arg", "x", "a", "param"]
        elif index == 1:
            candidates = ["arg2", "y", "b", "param2"]
        elif index == 2:
            candidates = ["arg3", "z", "c", "param3"]
        else:
            candidates = [f"arg{index + 1}", f"a{index}"]

        for name in candidates:
            if name not in self.used_names:
                return name

        # Fallback
        return f"a{index}"

    def _analyze_bytecode(self) -> None:
        """Analyze bytecode for variable naming hints."""
        from ..bytecode.instruction import Instruction
        from ..bytecode.opcodes import OpCode

        code = self.proto.code
        n = self.proto.sizecode

        for pc in range(n):
            inst = Instruction.decode(code[pc])

            # GETTABLE pattern: r = table.field -> name might be "field"
            if inst.op == OpCode.GETTABLE:
                self._hint_from_gettable(inst, pc)

            # GETGLOBAL pattern: r = GlobalName -> might hint at usage
            elif inst.op == OpCode.GETGLOBAL:
                self._hint_from_getglobal(inst, pc)

            # TFORLOOP pattern: for k,v in pairs/ipairs
            elif inst.op == OpCode.TFORLOOP:
                self._hint_from_tforloop(inst, pc)

            # FORPREP pattern: for i = start, end
            elif inst.op == OpCode.FORPREP:
                self._hint_from_forloop(inst, pc)

    def _hint_from_gettable(self, inst, pc: int) -> None:
        """Extract hints from table field access."""
        from ..bytecode.instruction import is_k, index_k

        if not is_k(inst.c):
            return

        # Get the constant (field name)
        const_idx = index_k(inst.c)
        if const_idx >= len(self.proto.k):
            return

        const = self.proto.k[const_idx]
        if not isinstance(const, str):
            return

        # Use field name as hint for the destination register
        if inst.a not in self.var_info or self.var_info[inst.a].source_hint == "temp":
            field_name = const
            if self._is_valid_identifier(field_name) and field_name not in self.used_names:
                self.var_info[inst.a] = VarInfo(
                    reg=inst.a,
                    name=field_name,
                    start_pc=pc,
                    end_pc=self.proto.sizecode,
                    source_hint="field_access"
                )
                self.used_names.add(field_name)

    def _hint_from_getglobal(self, inst, pc: int) -> None:
        """Extract hints from global variable access."""
        const_idx = inst.bx
        if const_idx >= len(self.proto.k):
            return

        const = self.proto.k[const_idx]
        if not isinstance(const, str):
            return

        # Common patterns: getting a "type" might mean variable is of that type
        global_name = const.lower()

        # Map common global names to variable name hints
        hints = {
            "pairs": ("k", "v"),
            "ipairs": ("i", "v"),
            "next": ("k", "v"),
            "type": None,
            "tostring": "str",
            "tonumber": "num",
            "string": "str",
            "table": "tbl",
            "math": None,
            "io": "file",
            "os": None,
        }

        # This is used later by _hint_from_tforloop

    def _hint_from_tforloop(self, inst, pc: int) -> None:
        """Guess names for generic for loop variables."""
        # TFORLOOP R(A) C: loop vars are at R(A+3), R(A+4), ...
        base_reg = inst.a + 3

        # Check if we already have names
        has_names = all(
            (base_reg + i) in self.var_info
            for i in range(inst.c)
        )
        if has_names:
            return

        # Try to determine iterator type by looking back for GETGLOBAL
        iterator_name = self._find_iterator_name(pc)

        if iterator_name == "pairs":
            var_names = ["k", "v"]
        elif iterator_name == "ipairs":
            var_names = ["i", "v"]
        elif iterator_name == "io.lines" or iterator_name == "lines":
            var_names = ["line"]
        elif iterator_name == "string.gmatch" or iterator_name == "gmatch":
            var_names = ["match"]
        else:
            var_names = [f"v{i}" for i in range(inst.c)]

        # Assign names
        for i in range(inst.c):
            reg = base_reg + i
            if reg not in self.var_info:
                name = var_names[i] if i < len(var_names) else f"v{i}"
                if name in self.used_names:
                    name = f"{name}_{reg}"
                self.var_info[reg] = VarInfo(
                    reg=reg,
                    name=name,
                    start_pc=pc,
                    end_pc=self.proto.sizecode,
                    source_hint="tforloop"
                )
                self.used_names.add(name)

    def _find_iterator_name(self, tforloop_pc: int) -> Optional[str]:
        """Find the iterator function name for a TFORLOOP."""
        from ..bytecode.instruction import Instruction
        from ..bytecode.opcodes import OpCode

        # Look back for GETGLOBAL or GETTABLE that set up the iterator
        for pc in range(tforloop_pc - 1, max(0, tforloop_pc - 20), -1):
            inst = Instruction.decode(self.proto.code[pc])

            if inst.op == OpCode.GETGLOBAL:
                const_idx = inst.bx
                if const_idx < len(self.proto.k):
                    const = self.proto.k[const_idx]
                    if isinstance(const, str):
                        return const

            if inst.op == OpCode.GETTABLE:
                from ..bytecode.instruction import is_k, index_k
                if is_k(inst.c):
                    const_idx = index_k(inst.c)
                    if const_idx < len(self.proto.k):
                        const = self.proto.k[const_idx]
                        if isinstance(const, str):
                            return const

        return None

    def _hint_from_forloop(self, inst, pc: int) -> None:
        """Guess name for numeric for loop variable."""
        # FORPREP R(A) sBx: loop var is at R(A+3)
        loop_var_reg = inst.a + 3

        if loop_var_reg in self.var_info:
            return

        # Use common names
        name = self._unique_name("i", ["i", "j", "k", "n", "idx"])
        self.var_info[loop_var_reg] = VarInfo(
            reg=loop_var_reg,
            name=name,
            start_pc=pc,
            end_pc=self.proto.sizecode,
            source_hint="forloop"
        )
        self.used_names.add(name)

    def _unique_name(self, preferred: str, candidates: List[str]) -> str:
        """Get a unique name from candidates."""
        for name in candidates:
            if name not in self.used_names:
                return name
        # Generate unique suffix
        base = preferred
        i = 1
        while f"{base}{i}" in self.used_names:
            i += 1
        return f"{base}{i}"

    def _is_valid_identifier(self, name: str) -> bool:
        """Check if name is a valid Lua identifier."""
        if not name:
            return False
        if not (name[0].isalpha() or name[0] == '_'):
            return False
        return all(c.isalnum() or c == '_' for c in name)

    def get_local_name(self, reg: int, pc: int) -> Optional[str]:
        """Get the name for a local variable at a given PC."""
        # First check debug info
        for locvar in self.proto.locvars:
            if locvar.startpc <= pc < locvar.endpc:
                if reg == 0:
                    return locvar.varname
                reg -= 1

        # Then check guessed names
        if reg in self.var_info:
            info = self.var_info[reg]
            if info.start_pc <= pc <= info.end_pc:
                return info.name

        return None


def guess_local_names(proto: 'Proto') -> Dict[int, str]:
    """
    Guess all local variable names for a function.

    Returns a dict mapping register number to guessed name.
    """
    guesser = NameGuesser(proto)
    return guesser.guess_all_locals()


def improve_temp_name(current_name: str, context: str) -> str:
    """
    Improve a temporary variable name based on context.

    Args:
        current_name: Current temp name (e.g., "_tmp4")
        context: Context hint (e.g., "table", "result", "stmt")

    Returns:
        Improved name
    """
    context_mappings = {
        "table": "tbl",
        "result": "result",
        "statement": "stmt",
        "prepared": "stmt",
        "query": "stmt",
        "connection": "conn",
        "database": "db",
        "file": "f",
        "handle": "handle",
        "callback": "cb",
        "function": "fn",
        "iterator": "iter",
        "index": "idx",
        "count": "count",
        "length": "len",
        "size": "size",
        "string": "str",
        "number": "num",
        "boolean": "bool",
    }

    context_lower = context.lower()
    for key, value in context_mappings.items():
        if key in context_lower:
            return value

    return current_name
