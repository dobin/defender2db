"""
Boolean expression handling for decompilation.

Lua's bytecode uses sequences of TEST/TESTSET and comparison operations
followed by JMP to implement boolean expressions. This module reconstructs
the original boolean expressions from these sequences.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Set
from enum import Enum

from ..bytecode.opcodes import OpCode, COMPARISON_OPERATORS, INVERTED_COMPARISON_OPERATORS


class BoolOpType(Enum):
    """Type of boolean operation."""
    AND = "and"
    OR = "or"


@dataclass
class IfBlock:
    """Represents an if/then/else structure detected in bytecode."""
    condition_start: int    # PC of first condition instruction
    condition_end: int      # PC after condition (first then instruction)
    then_start: int         # First instruction of then block
    then_end: int           # Last instruction of then block (exclusive)
    else_start: int = -1    # First instruction of else block (-1 if no else)
    else_end: int = -1      # Last instruction of else block (exclusive)
    endif: int = -1         # PC after the entire if statement
    is_elseif: bool = False # Is this an elseif branch?


@dataclass
class BoolOp:
    """
    A single boolean operation from a TEST/TESTSET or comparison instruction.

    Stores the operands and operator for later reconstruction.
    """
    op1: str                    # Left operand string
    op2: str                    # Right operand string (empty for TEST)
    op: OpCode                  # Comparison or TEST opcode
    neg: bool = False           # Is the result negated?
    pc: int = 0                 # Source PC
    dest: int = -1              # Jump destination
    is_and: bool = True         # Part of AND chain (vs OR chain)


@dataclass
class LogicExp:
    """
    Boolean expression tree node.

    Handles complex and/or chains from sequential comparisons.
    Each node is either:
    - A leaf node (comparison or test) with op1, op2, op
    - A chain node grouping sub-expressions with and/or
    """
    # Tree structure
    parent: Optional['LogicExp'] = None
    next: Optional['LogicExp'] = None
    prev: Optional['LogicExp'] = None
    subexp: Optional['LogicExp'] = None

    # Is this a chain (internal) node?
    is_chain: bool = False

    # Leaf node data
    op1: Optional[str] = None
    op2: Optional[str] = None
    op: Optional[OpCode] = None
    dest: int = 0
    neg: bool = False

    @classmethod
    def from_bool_op(cls, bop: BoolOp) -> 'LogicExp':
        """Create a leaf node from a BoolOp."""
        return cls(
            op1=bop.op1,
            op2=bop.op2,
            op=bop.op,
            dest=bop.dest,
            neg=bop.neg,
            is_chain=False
        )

    @classmethod
    def make_chain(cls, dest: int) -> 'LogicExp':
        """Create a chain node for grouping."""
        return cls(dest=dest, is_chain=True)

    def find_root(self) -> 'LogicExp':
        """Find the root of the expression tree."""
        node = self
        while node.parent:
            node = node.parent
        return node

    def to_string(self, dest: int, inv: bool = False, rev: bool = False) -> str:
        """
        Convert this expression tree to a Lua string.

        Args:
            dest: The destination PC for determining and/or
            inv: Invert the entire expression
            rev: Reverse operand order
        """
        if self.is_chain:
            return self._chain_to_string(dest, inv, rev)
        else:
            return self._leaf_to_string(inv, rev)

    def _leaf_to_string(self, inv: bool = False, rev: bool = False) -> str:
        """Convert a leaf node to string."""
        neg = self.neg ^ inv

        # Handle TEST (single operand)
        if self.op in (OpCode.TEST, OpCode.TESTSET):
            if neg:
                return f"not {self.op1}"
            else:
                return self.op1

        # Handle comparisons
        if self.op in COMPARISON_OPERATORS:
            op_str = INVERTED_COMPARISON_OPERATORS[self.op] if neg else COMPARISON_OPERATORS[self.op]

            if rev:
                # Reverse for right-to-left evaluation
                return f"{self.op2} {op_str} {self.op1}"
            else:
                return f"{self.op1} {op_str} {self.op2}"

        # Fallback
        return self.op1 or ""

    def _chain_to_string(self, dest: int, inv: bool, rev: bool) -> str:
        """Convert a chain node to string."""
        parts = []
        curr = self.subexp

        while curr:
            # Determine if this sub-expression uses and or or
            # If dest matches subexp dest, use "and", otherwise "or"
            use_and = (curr.dest == dest)
            part = curr.to_string(dest, inv, rev)

            # Add parentheses if needed
            if curr.is_chain and self.parent:
                part = f"({part})"

            parts.append(part)
            curr = curr.next

        # Join with and/or
        connector = " and " if len(parts) > 1 else " or "
        return connector.join(parts)


class BooleanBuilder:
    """
    Builds boolean expressions from comparison sequences.

    Accumulates BoolOp entries and constructs a LogicExp tree
    when the expression is complete.
    """

    def __init__(self):
        self.ops: List[BoolOp] = []

    def add(self, op: BoolOp) -> None:
        """Add a comparison/test to the pending list."""
        self.ops.append(op)

    def clear(self) -> None:
        """Clear the pending list."""
        self.ops.clear()

    def is_empty(self) -> bool:
        """Check if there are pending operations."""
        return len(self.ops) == 0

    def build(self, then_addr: int, endif_addr: int) -> Tuple[Optional[LogicExp], int, int]:
        """
        Build a LogicExp tree from accumulated BoolOps.

        Returns (expression, then_addr, endif_addr).
        """
        if not self.ops:
            return None, then_addr, endif_addr

        # Simple case: single operation
        if len(self.ops) == 1:
            exp = LogicExp.from_bool_op(self.ops[0])
            self.clear()
            return exp, then_addr, endif_addr

        # Complex case: multiple operations forming and/or chain
        # This is a simplified version - the full algorithm is complex
        exp = self._build_chain()
        self.clear()
        return exp, then_addr, endif_addr

    def _build_chain(self) -> LogicExp:
        """Build a chain expression from multiple ops."""
        # Create chain root
        root = LogicExp.make_chain(self.ops[-1].dest)

        # Add all operations as children
        prev_child = None
        for bop in self.ops:
            child = LogicExp.from_bool_op(bop)
            child.parent = root

            if prev_child:
                prev_child.next = child
                child.prev = prev_child
            else:
                root.subexp = child

            prev_child = child

        return root


def make_boolean(ops: List[BoolOp]) -> Tuple[Optional[LogicExp], int, int]:
    """
    Build a LogicExp tree from boolean operations.

    This implements the full MakeBoolean algorithm from the original luadec.

    Returns (expression, then_addr, endif).
    """
    if not ops:
        return None, 0, 0

    first = ops[0]
    last = ops[-1]

    # Compute addresses
    first_addr = first.pc + 2
    then_addr = last.pc + 2
    else_addr = last.dest
    endif = 0

    # Find the actual last operation based on jump destinations
    # This handles cases where conditions jump past each other
    for op in reversed(ops):
        dest = op.dest
        if else_addr > then_addr:
            is_test = op.op in (OpCode.TEST, OpCode.TESTSET)
            if (dest > else_addr + 1) if is_test else (dest > else_addr):
                last = op
                then_addr = op.pc + 2
                else_addr = dest

    # Build expression tree
    curr_exp = LogicExp.from_bool_op(first)
    dest = first.dest

    if dest > first_addr and dest <= then_addr:
        first_exp = LogicExp.make_chain(dest)
        _tie_as_subexp(first_exp, curr_exp)
    else:
        first_exp = curr_exp
        endif = dest

    # Process remaining operations
    for i, op in enumerate(ops[1:], 1):
        at = op.pc
        dest = op.dest

        exp = LogicExp.from_bool_op(op)

        if dest < first_addr:
            # Jump to loop in a while
            _tie_as_next(curr_exp, exp)
            curr_exp = exp
            endif = dest
        elif dest > then_addr:
            # Jump to "else"
            _tie_as_next(curr_exp, exp)
            curr_exp = exp
            if op.op not in (OpCode.TEST, OpCode.TESTSET):
                if endif != 0 and endif != dest:
                    pass  # Unhandled construct
            endif = dest
        elif dest == curr_exp.dest:
            # Within current chain
            _tie_as_next(curr_exp, exp)
            curr_exp = exp
        elif dest > curr_exp.dest:
            if curr_exp.parent is None or dest < curr_exp.parent.dest:
                # Creating a new level
                subexp = LogicExp.make_chain(dest)
                _tie_as_next(curr_exp, exp)
                curr_exp = exp
                if curr_exp.parent is None:
                    _tie_as_subexp(subexp, first_exp)
                    first_exp = subexp
            elif dest > curr_exp.parent.dest:
                # Start a new chain
                _tie_as_next(curr_exp, exp)
                curr_exp = curr_exp.parent
                if not curr_exp.is_chain:
                    return None, then_addr, endif
                prev_parent = curr_exp.parent
                chain = LogicExp.make_chain(dest)
                _untie(curr_exp)
                if prev_parent and prev_parent.is_chain:
                    prev_parent = prev_parent.subexp
                _tie_as_subexp(chain, curr_exp)
                if prev_parent is None:
                    first_exp = chain
                else:
                    _tie_as_next(prev_parent, chain)
        elif dest > first_addr and dest < curr_exp.dest:
            # Start a new chain
            subexp = LogicExp.make_chain(dest)
            _tie_as_subexp(subexp, exp)
            _tie_as_next(curr_exp, subexp)
            curr_exp = exp

        # Check if we need to promote the parent
        if curr_exp.parent and at + 3 > curr_exp.parent.dest:
            curr_exp.parent.dest = curr_exp.dest
            if op != last:
                chain = LogicExp.make_chain(curr_exp.dest)
                _tie_as_subexp(chain, first_exp)
                first_exp = chain
            curr_exp = curr_exp.parent

    # Simplify if root is a chain
    if first_exp.is_chain and first_exp.subexp:
        first_exp = first_exp.subexp
        first_exp.parent = None

    if endif == 0:
        endif = then_addr

    return first_exp, then_addr, endif


def _tie_as_next(curr: LogicExp, item: LogicExp) -> None:
    """Link item as the next sibling of curr."""
    curr.next = item
    item.prev = curr
    item.parent = curr.parent


def _tie_as_subexp(parent: LogicExp, item: LogicExp) -> None:
    """Link item as a sub-expression of parent."""
    parent.subexp = item
    node = item
    while node:
        node.parent = parent
        node = node.next


def _untie(curr: LogicExp) -> None:
    """Unlink curr from its previous sibling."""
    if curr.prev:
        curr.prev.next = None
    curr.prev = None
    curr.parent = None


def write_boolean(exp: Optional[LogicExp], then_addr: int, inv: bool = False, rev: bool = False) -> str:
    """
    Convert a LogicExp tree to a Lua string.

    Args:
        exp: The expression tree root
        then_addr: The then block address (determines and/or)
        inv: Invert the entire expression
        rev: Reverse comparison order
    """
    if exp is None:
        return "true"

    return _print_logic_exp(exp, then_addr, inv, rev)


def _print_logic_exp(exp: LogicExp, dest: int, inv: bool, rev: bool) -> str:
    """Recursively print a logic expression."""
    parts = []
    node = exp

    while node:
        # Determine and/or based on jump destination
        cond = node.dest > dest
        node_inv = not inv if cond else inv

        part = _print_logic_item(node, node_inv, rev)
        parts.append(part)

        if node.next:
            # Determine connector
            use_cond = cond
            if inv:
                use_cond = not use_cond
            if rev:
                use_cond = not use_cond
            connector = "and" if use_cond else "or"
            parts.append(f" {connector} ")

        node = node.next

    return "".join(parts)


def _print_logic_item(exp: LogicExp, inv: bool, rev: bool) -> str:
    """Print a single logic item (leaf or subexpression)."""
    if exp.subexp:
        inner = _print_logic_exp(exp.subexp, exp.dest, inv, rev)
        return f"({inner})"

    # Leaf node
    cond = exp.neg
    if inv:
        cond = not cond
    if rev:
        cond = not cond

    if exp.op in (OpCode.TEST, OpCode.TESTSET):
        if cond:
            return f"not {exp.op2 or exp.op1}"
        return exp.op2 or exp.op1

    if exp.op in COMPARISON_OPERATORS:
        op_str = INVERTED_COMPARISON_OPERATORS[exp.op] if cond else COMPARISON_OPERATORS[exp.op]
        return f"{exp.op1} {op_str} {exp.op2}"

    return exp.op1 or "true"


def make_boolean_string(ops: List[BoolOp], then_addr: int, else_addr: int) -> str:
    """
    Convert a list of boolean operations to a Lua expression string.

    This implements the full MakeBoolean algorithm from the original luadec.
    """
    if not ops:
        return "true"

    if len(ops) == 1:
        return _single_op_to_string(ops[0], invert_for_if=False)

    # Check for simple AND chain (all ops jump to same destination = else_addr)
    # In AND chains, all conditions failing jump to the else/end of if
    first_dest = ops[0].dest
    all_same_dest = all(op.dest == first_dest for op in ops)

    if all_same_dest:
        # Simple AND chain - all conditions must be true to reach the body
        # Each condition jumps to else_addr if it fails
        parts = [_single_op_to_string(op, invert_for_if=False) for op in ops]
        return " and ".join(parts)

    # Check for simple OR chain pattern
    # In OR chains: early conditions jump to then_addr if true (short-circuit success)
    # Only the last condition jumps to else_addr if false
    or_pattern = True
    for i, op in enumerate(ops[:-1]):
        # All but the last should jump to an earlier address (the body)
        if op.dest >= else_addr:
            or_pattern = False
            break

    if or_pattern and ops[-1].dest == else_addr:
        # OR chain - any condition being true jumps to body
        parts = [_single_op_to_string(op, invert_for_if=False) for op in ops]
        return " or ".join(parts)

    # More complex case (mixed and/or) - use full algorithm
    exp, computed_then, endif = make_boolean(ops)
    if exp:
        return write_boolean(exp, computed_then, inv=False, rev=False)

    # Fallback to simple AND joining
    parts = [_single_op_to_string(op, invert_for_if=False) for op in ops]
    return " and ".join(parts)


def make_boolean_string_simple(ops: List[BoolOp]) -> str:
    """Simple version for single conditions or basic chains."""
    if not ops:
        return "true"

    if len(ops) == 1:
        return _single_op_to_string(ops[0], invert_for_if=True)

    # Check if all ops have the same destination (simple and/or chain)
    first_dest = ops[0].dest
    all_same = all(op.dest == first_dest for op in ops)

    parts = [_single_op_to_string(op, invert_for_if=True) for op in ops]

    if all_same:
        # All jump to same place - likely AND chain
        return " and ".join(parts)
    else:
        # Mixed destinations - need more analysis
        return " and ".join(parts)


def _single_op_to_string(op: BoolOp, invert_for_if: bool = False) -> str:
    """
    Convert a single BoolOp to string.

    Args:
        op: The boolean operation
        invert_for_if: If True, invert the condition logic
    """
    effective_neg = op.neg
    if invert_for_if:
        effective_neg = not effective_neg

    if op.op in (OpCode.TEST, OpCode.TESTSET):
        if effective_neg:
            return f"not {op.op1}"
        return op.op1

    if op.op in COMPARISON_OPERATORS:
        op_str = INVERTED_COMPARISON_OPERATORS[op.op] if effective_neg else COMPARISON_OPERATORS[op.op]
        return f"{op.op1} {op_str} {op.op2}"

    return op.op1 or "true"


def _group_to_string(ops: List[BoolOp], connector: str) -> str:
    """Convert a group of ops to string."""
    parts = [_single_op_to_string(op, invert_for_if=True) for op in ops]

    if len(parts) == 1:
        return parts[0]

    result = f" {connector} ".join(parts)

    # Add parentheses if needed
    if connector == "or" and len(ops) > 1:
        return f"({result})"

    return result


def analyze_if_else_structure(code: List[int], start_pc: int, end_pc: int) -> List[IfBlock]:
    """
    Analyze bytecode to detect if/then/else structures.

    Returns a list of IfBlock structures describing the control flow.
    """
    from ..bytecode.instruction import Instruction
    from ..bytecode.opcodes import OpCode

    blocks = []
    pc = start_pc

    while pc < end_pc:
        inst = Instruction.decode(code[pc])

        # Look for comparison or test followed by JMP
        if inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
            if pc + 1 < end_pc:
                next_inst = Instruction.decode(code[pc + 1])
                if next_inst.op == OpCode.JMP:
                    # Found a conditional - analyze structure
                    jmp_dest = pc + 2 + next_inst.sbx

                    # Create if block
                    block = IfBlock(
                        condition_start=pc,
                        condition_end=pc + 2,
                        then_start=pc + 2,
                        then_end=jmp_dest,
                        endif=jmp_dest
                    )

                    # Check if there's an else branch
                    # The then block ends with a JMP that skips the else
                    if jmp_dest - 1 > pc + 2:
                        possible_else_jmp_pc = jmp_dest - 1
                        if possible_else_jmp_pc < end_pc:
                            else_jmp = Instruction.decode(code[possible_else_jmp_pc])
                            if else_jmp.op == OpCode.JMP and else_jmp.sbx > 0:
                                # There's an else block
                                else_end = possible_else_jmp_pc + 1 + else_jmp.sbx
                                block.then_end = possible_else_jmp_pc
                                block.else_start = jmp_dest
                                block.else_end = else_end
                                block.endif = else_end

                    blocks.append(block)
                    pc = block.endif
                    continue

        pc += 1

    return blocks
