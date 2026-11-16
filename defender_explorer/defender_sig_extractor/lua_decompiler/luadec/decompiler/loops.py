"""
Loop detection and loop tree management.

The decompiler uses a tree structure to track nested loops.
During the backward pass, loops are detected and added to the tree.
During the forward pass, the tree is used to determine loop boundaries.
"""

from dataclasses import dataclass, field
from typing import Optional, List, TYPE_CHECKING

from ..ast.statements import AstStatement, StatementType

if TYPE_CHECKING:
    from ..bytecode.proto import Proto


@dataclass
class LoopItem:
    """
    Loop structure node representing a single loop or the function root.

    The loop tree is built during backward scan and used during forward scan
    to track loop boundaries and generate proper control flow statements.
    """
    # Tree structure
    parent: Optional['LoopItem'] = None
    child: Optional['LoopItem'] = None
    prev: Optional['LoopItem'] = None
    next: Optional['LoopItem'] = None

    # Loop type
    type: StatementType = StatementType.FUNCTION_STMT

    # PC boundaries
    prep: int = -1    # Preparation instruction (FORPREP)
    start: int = 0    # First instruction in loop
    body: int = 0     # First instruction of body (after condition)
    end: int = 0      # Last instruction in loop
    out: int = 0      # First instruction after loop

    # Indentation level
    indent: int = 0

    # Associated AST block
    block: Optional[AstStatement] = None

    @classmethod
    def create_function_root(cls, sizecode: int) -> 'LoopItem':
        """Create the root loop item for the entire function."""
        item = cls(
            type=StatementType.FUNCTION_STMT,
            prep=-1,
            start=0,
            body=0,
            end=sizecode - 1,
            out=sizecode,
            indent=0
        )
        return item

    @classmethod
    def create_while(cls, start: int, end: int, out: int) -> 'LoopItem':
        """Create a while loop item."""
        return cls(
            type=StatementType.WHILE_STMT,
            prep=start,
            start=start,
            body=start,
            end=end,
            out=out
        )

    @classmethod
    def create_repeat(cls, start: int, end: int, out: int) -> 'LoopItem':
        """Create a repeat-until loop item."""
        return cls(
            type=StatementType.REPEAT_STMT,
            prep=start,
            start=start,
            body=start,
            end=end,
            out=out
        )

    @classmethod
    def create_for(cls, prep: int, start: int, end: int, out: int) -> 'LoopItem':
        """Create a numeric for loop item."""
        return cls(
            type=StatementType.FORLOOP_STMT,
            prep=prep,
            start=start,
            body=start,
            end=end,
            out=out
        )

    @classmethod
    def create_tfor(cls, prep: int, start: int, end: int, out: int) -> 'LoopItem':
        """Create a generic for loop item."""
        return cls(
            type=StatementType.TFORLOOP_STMT,
            prep=prep,
            start=start,
            body=start,
            end=end,
            out=out
        )

    def contains_pc(self, pc: int) -> bool:
        """Check if this loop contains the given PC."""
        return self.start <= pc <= self.end

    def is_function_root(self) -> bool:
        """Check if this is the function root."""
        return self.type == StatementType.FUNCTION_STMT


class LoopTree:
    """
    Manages the loop detection tree.

    The tree tracks all loops in a function, with the function itself
    as the root. Nested loops are children of their parent loops.
    """

    def __init__(self, sizecode: int):
        """Initialize with a function root."""
        self.root = LoopItem.create_function_root(sizecode)
        self.current = self.root

    def add_loop(self, item: LoopItem) -> bool:
        """
        Add a loop item to the tree in the correct position.

        Returns True if the loop was added successfully.
        """
        # Find the correct parent
        while self.current:
            if self._should_be_child(item, self.current):
                # Found parent, insert as first child
                self._insert_as_child(item, self.current)
                self.current = item
                return True
            else:
                # Move up to parent
                self.current = self.current.parent

        return False

    def _should_be_child(self, item: LoopItem, parent: LoopItem) -> bool:
        """Check if item should be a child of parent."""
        return item.start >= parent.start and item.end < parent.end

    def _insert_as_child(self, item: LoopItem, parent: LoopItem) -> None:
        """Insert item as the first child of parent."""
        item.parent = parent
        item.next = parent.child
        item.prev = None
        item.indent = parent.indent + 1

        if parent.child:
            parent.child.prev = item
        parent.child = item

    def reset(self) -> None:
        """Reset current pointer to root for forward pass."""
        self.current = self.root

    def move_to_child(self) -> bool:
        """Move current to first child if exists."""
        if self.current and self.current.child:
            self.current = self.current.child
            return True
        return False

    def move_to_next(self) -> bool:
        """Move current to next sibling if exists."""
        if self.current and self.current.next:
            self.current = self.current.next
            return True
        return False

    def move_to_parent(self) -> bool:
        """Move current to parent if exists."""
        if self.current and self.current.parent:
            self.current = self.current.parent
            return True
        return False

    def find_loop_at_pc(self, pc: int) -> Optional[LoopItem]:
        """Find the innermost loop containing the given PC."""
        result = None
        item = self.root

        while item:
            if item.contains_pc(pc):
                result = item
                item = item.child
            else:
                item = item.next

        return result

    def get_loop_for_break(self, pc: int) -> Optional[LoopItem]:
        """Find the loop that a break at pc should exit."""
        item = self.find_loop_at_pc(pc)
        while item:
            if item.type in (StatementType.WHILE_STMT, StatementType.REPEAT_STMT,
                            StatementType.FORLOOP_STMT, StatementType.TFORLOOP_STMT):
                return item
            item = item.parent
        return None


def detect_loops(proto: 'Proto') -> LoopTree:
    """
    Detect all loops in a function prototype.

    This performs a backward scan through the bytecode to identify:
    - FORLOOP instructions (numeric for loops)
    - TFORLOOP instructions (generic for loops)
    - JMP instructions with backward targets (while/repeat loops)

    Returns a LoopTree containing all detected loops.
    """
    from ..bytecode.instruction import Instruction
    from ..bytecode.opcodes import OpCode

    tree = LoopTree(proto.sizecode)
    code = proto.code

    # Track JMPs that are part of FORLOOP/TFORLOOP to avoid double-detection
    skip_jmp = set()

    # Backward scan
    for pc in range(proto.sizecode - 1, -1, -1):
        inst = Instruction.decode(code[pc])

        # FORLOOP - numeric for loop
        if inst.op == OpCode.FORLOOP:
            dest = inst.sbx + pc + 1
            item = LoopItem.create_for(
                prep=dest - 1,
                start=dest,
                end=pc,
                out=pc + 1
            )
            tree.add_loop(item)
            continue

        # TFORLOOP followed by JMP - generic for loop
        if inst.op == OpCode.TFORLOOP and pc + 1 < proto.sizecode:
            next_inst = Instruction.decode(code[pc + 1])
            if next_inst.op == OpCode.JMP:
                dest = next_inst.sbx + pc + 2
                item = LoopItem.create_tfor(
                    prep=dest - 1,
                    start=dest,
                    end=pc + 1,
                    out=pc + 2
                )
                tree.add_loop(item)
                # Mark the JMP as part of this TFORLOOP so we don't detect it again
                skip_jmp.add(pc + 1)
                continue

        # JMP - potential while/repeat loop
        if inst.op == OpCode.JMP and pc > 0:
            # Skip if this JMP is part of a FORLOOP/TFORLOOP
            if pc in skip_jmp:
                continue

            dest = inst.sbx + pc + 1

            # Check if it's a backward jump (loop)
            if dest <= pc:
                # Check previous instruction for loop type
                prev_inst = Instruction.decode(code[pc - 1])

                # Check if previous is a test instruction
                is_test = prev_inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE,
                                           OpCode.TEST, OpCode.TESTSET)

                # Also check if previous is TFORLOOP - if so, skip (already handled)
                if prev_inst.op == OpCode.TFORLOOP:
                    continue

                if is_test:
                    # REPEAT-UNTIL (backward conditional jump)
                    item = LoopItem.create_repeat(
                        start=dest,
                        end=pc,
                        out=pc + 1
                    )
                else:
                    # WHILE loop (backward unconditional jump)
                    item = LoopItem.create_while(
                        start=dest,
                        end=pc,
                        out=pc + 1
                    )
                tree.add_loop(item)

    # Reset for forward pass
    tree.reset()
    return tree
