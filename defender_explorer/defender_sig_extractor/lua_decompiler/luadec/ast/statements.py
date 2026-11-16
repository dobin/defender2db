"""
AST statement nodes for Lua decompilation.

Represents the hierarchical structure of Lua statements including
control flow constructs (if/while/for/repeat), function definitions,
and simple statements.
"""

from enum import IntEnum, auto
from typing import List, Optional, TYPE_CHECKING
from io import StringIO


class StatementType(IntEnum):
    """Types of AST statement nodes."""
    SIMPLE_STMT = 0      # Simple statement (assignment, call, etc.)
    BREAK_STMT = auto()  # break
    RETURN_STMT = auto() # return [values]
    FUNCTION_STMT = auto()  # function definition
    DO_STMT = auto()     # do ... end
    WHILE_STMT = auto()  # while ... do ... end
    REPEAT_STMT = auto() # repeat ... until ...
    FORLOOP_STMT = auto()   # for i = a, b, c do ... end
    TFORLOOP_STMT = auto()  # for k, v in ... do ... end
    IF_STMT = auto()     # if ... then ... [else ...] end
    IF_THEN_STMT = auto()   # then branch of if
    IF_ELSE_STMT = auto()   # else branch of if
    JMP_DEST_STMT = auto()  # Jump destination (for goto in 5.2+)


# Statement type names for debugging
STATEMENT_TYPE_NAMES = {
    StatementType.SIMPLE_STMT: "SIMPLE_STMT",
    StatementType.BREAK_STMT: "BREAK_STMT",
    StatementType.RETURN_STMT: "RETURN_STMT",
    StatementType.FUNCTION_STMT: "FUNCTION_STMT",
    StatementType.DO_STMT: "DO_STMT",
    StatementType.WHILE_STMT: "WHILE_STMT",
    StatementType.REPEAT_STMT: "REPEAT_STMT",
    StatementType.FORLOOP_STMT: "FORLOOP_STMT",
    StatementType.TFORLOOP_STMT: "TFORLOOP_STMT",
    StatementType.IF_STMT: "IF_STMT",
    StatementType.IF_THEN_STMT: "IF_THEN_STMT",
    StatementType.IF_ELSE_STMT: "IF_ELSE_STMT",
    StatementType.JMP_DEST_STMT: "JMP_DEST_STMT",
}


class AstStatement:
    """
    AST node for a Lua statement.

    Can represent simple statements (with code string) or block statements
    (with sub-statements list).
    """

    def __init__(self, stmt_type: StatementType, code: Optional[str] = None):
        self.type = stmt_type
        self.code = code
        self.sub: List['AstStatement'] = []
        self.parent: Optional['AstStatement'] = None
        self.line: int = 0
        self._sub_print_count: int = 0
        self._comment_print_count: int = 0

    @classmethod
    def make_simple(cls, code: str) -> 'AstStatement':
        """Create a simple statement with code."""
        return cls(StatementType.SIMPLE_STMT, code)

    @classmethod
    def make_block(cls, stmt_type: StatementType, code: Optional[str] = None) -> 'AstStatement':
        """Create a block statement that can contain sub-statements."""
        stmt = cls(stmt_type, code)
        return stmt

    @classmethod
    def make_if(cls, test: str) -> 'AstStatement':
        """Create an if statement with then and else branches."""
        stmt = cls.make_block(StatementType.IF_STMT, test)
        stmt.add_child(cls.make_block(StatementType.IF_THEN_STMT))
        stmt.add_child(cls.make_block(StatementType.IF_ELSE_STMT))
        return stmt

    @classmethod
    def make_while(cls, test: str) -> 'AstStatement':
        """Create a while statement."""
        return cls.make_block(StatementType.WHILE_STMT, test)

    @classmethod
    def make_repeat(cls, test: str) -> 'AstStatement':
        """Create a repeat-until statement."""
        return cls.make_block(StatementType.REPEAT_STMT, test)

    @classmethod
    def make_for(cls, header: str) -> 'AstStatement':
        """Create a numeric for statement."""
        return cls.make_block(StatementType.FORLOOP_STMT, header)

    @classmethod
    def make_tfor(cls, header: str) -> 'AstStatement':
        """Create a generic for statement."""
        return cls.make_block(StatementType.TFORLOOP_STMT, header)

    @classmethod
    def make_do(cls) -> 'AstStatement':
        """Create a do-end block."""
        return cls.make_block(StatementType.DO_STMT)

    @classmethod
    def make_function(cls, params: str) -> 'AstStatement':
        """Create a function statement."""
        return cls.make_block(StatementType.FUNCTION_STMT, params)

    @classmethod
    def make_break(cls) -> 'AstStatement':
        """Create a break statement."""
        return cls(StatementType.BREAK_STMT, "")

    @classmethod
    def make_return(cls, values: str = "") -> 'AstStatement':
        """Create a return statement."""
        return cls(StatementType.RETURN_STMT, values)

    @property
    def then_stmt(self) -> Optional['AstStatement']:
        """Get the 'then' branch of an if statement."""
        if self.type == StatementType.IF_STMT and len(self.sub) >= 1:
            return self.sub[0]
        return None

    @property
    def else_stmt(self) -> Optional['AstStatement']:
        """Get the 'else' branch of an if statement."""
        if self.type == StatementType.IF_STMT and len(self.sub) >= 2:
            return self.sub[1]
        return None

    def add_child(self, child: 'AstStatement') -> None:
        """Add a child statement."""
        child.parent = self
        self.sub.append(child)

    def clear(self) -> None:
        """Clear this statement."""
        self.type = StatementType.SIMPLE_STMT
        self.code = None
        self.line = 0
        for child in self.sub:
            child.clear()
        self.sub.clear()
        self._sub_print_count = 0
        self._comment_print_count = 0

    def to_lua(self, indent: int = 0, debug: bool = False) -> str:
        """Convert this AST node to Lua source code."""
        output = StringIO()
        self._print(output, indent, debug)
        return output.getvalue()

    def _print(self, output: StringIO, indent: int, debug: bool = False) -> None:
        """Print this statement to output."""
        if self.type == StatementType.SIMPLE_STMT:
            self._print_simple(output, indent)
        elif self.type == StatementType.BREAK_STMT:
            self._print_break(output, indent)
        elif self.type == StatementType.RETURN_STMT:
            self._print_return(output, indent)
        elif self.type in (StatementType.DO_STMT, StatementType.FUNCTION_STMT,
                          StatementType.WHILE_STMT, StatementType.REPEAT_STMT,
                          StatementType.FORLOOP_STMT, StatementType.TFORLOOP_STMT):
            self._print_block(output, indent, debug)
        elif self.type == StatementType.IF_STMT:
            self._print_if(output, indent, False, debug)
        elif self.type in (StatementType.IF_THEN_STMT, StatementType.IF_ELSE_STMT):
            self._print_indent(output, indent)
            output.write(f"-- DECOMPILER ERROR: unexpected statement {STATEMENT_TYPE_NAMES[self.type]}\n")
        elif self.type == StatementType.JMP_DEST_STMT:
            self._print_jmp_dest(output, indent, debug)

    def _print_indent(self, output: StringIO, indent: int) -> None:
        """Print indentation."""
        output.write("  " * indent)

    def _print_sub(self, output: StringIO, indent: int, debug: bool = False) -> None:
        """Print all sub-statements."""
        self._sub_print_count = 0
        self._comment_print_count = 0
        for child in self.sub:
            child._print(output, indent, debug)
            self._sub_print_count += 1
            # Track comments
            if child.code and child.code.startswith("--"):
                self._sub_print_count -= 1
                self._comment_print_count += 1

    def _print_simple(self, output: StringIO, indent: int) -> None:
        """Print a simple statement."""
        if self.parent and self._is_first_with_paren():
            self._print_indent(output, indent)
            output.write(";\n")
        self._print_indent(output, indent)
        output.write(f"{self.code}\n")

    def _is_first_with_paren(self) -> bool:
        """Check if this is a statement starting with '(' that needs semicolon."""
        if self.parent and self.parent._sub_print_count > 0 and self.code:
            return self.code.startswith('(')
        return False

    def _print_break(self, output: StringIO, indent: int) -> None:
        """Print a break statement."""
        # If break is not the last statement, wrap in do block
        if self.parent and not self._is_last_in_block():
            self._print_indent(output, indent)
            output.write("do break end\n")
        else:
            self._print_indent(output, indent)
            output.write("break\n")

    def _print_return(self, output: StringIO, indent: int) -> None:
        """Print a return statement."""
        # If return is not the last statement, wrap in do block
        if self.parent and not self._is_last_in_block():
            self._print_indent(output, indent)
            if self.code:
                output.write(f"do return {self.code} end\n")
            else:
                output.write("do return end\n")
        else:
            self._print_indent(output, indent)
            if self.code:
                output.write(f"return {self.code}\n")
            else:
                output.write("return\n")

    def _is_last_in_block(self) -> bool:
        """Check if this is the last statement in parent block."""
        if not self.parent:
            return True
        total = self.parent._sub_print_count + self.parent._comment_print_count + 1
        return total >= len(self.parent.sub)

    def _print_block(self, output: StringIO, indent: int, debug: bool = False) -> None:
        """Print a block statement (do, while, for, etc.)."""
        start_code = ""
        end_code = ""

        if self.type == StatementType.DO_STMT:
            start_code = "do"
            end_code = "end"
        elif self.type == StatementType.FUNCTION_STMT:
            start_code = f"function({self.code or ''})"
            end_code = "end"
        elif self.type == StatementType.WHILE_STMT:
            start_code = f"while {self.code} do"
            end_code = "end"
        elif self.type == StatementType.REPEAT_STMT:
            start_code = "repeat"
            end_code = f"until {self.code}"
        elif self.type == StatementType.FORLOOP_STMT:
            start_code = f"for {self.code} do"
            end_code = "end"
        elif self.type == StatementType.TFORLOOP_STMT:
            start_code = f"for {self.code} do"
            end_code = "end"
        else:
            self._print_indent(output, indent)
            output.write(f"-- DECOMPILER ERROR: unexpected statement {STATEMENT_TYPE_NAMES[self.type]}\n")
            return

        self._print_indent(output, indent)
        output.write(f"{start_code}\n")
        self._print_sub(output, indent + 1, debug)
        self._print_indent(output, indent)
        output.write(f"{end_code}\n")

    def _print_if(self, output: StringIO, indent: int, is_elseif: bool, debug: bool = False) -> None:
        """Print an if statement."""
        then_stmt = self.then_stmt
        else_stmt = self.else_stmt

        if not then_stmt or not else_stmt:
            self._print_indent(output, indent)
            output.write("-- DECOMPILER ERROR: malformed if statement\n")
            return

        # Print if/elseif
        self._print_indent(output, indent)
        if is_elseif:
            output.write(f"elseif {self.code} then\n")
        else:
            output.write(f"if {self.code} then\n")

        # Print then block
        if debug:
            self._print_indent(output, indent + 1)
            output.write(f"-- AstStatement type=IF_THEN_STMT line={then_stmt.line} size={len(then_stmt.sub)}\n")
        then_stmt._print_sub(output, indent + 1, debug)

        # Print else block
        else_size = len(else_stmt.sub)
        if else_size == 0:
            # No else branch
            self._print_indent(output, indent)
            output.write("end\n")
        elif else_size == 1 and else_stmt.sub[0].type == StatementType.IF_STMT:
            # elseif chain
            else_stmt.sub[0]._print_if(output, indent, True, debug)
        else:
            # Regular else
            self._print_indent(output, indent)
            output.write("else\n")
            if debug:
                self._print_indent(output, indent + 1)
                output.write(f"-- AstStatement type=IF_ELSE_STMT line={else_stmt.line} size={else_size}\n")
            else_stmt._print_sub(output, indent + 1, debug)
            self._print_indent(output, indent)
            output.write("end\n")

    def _print_jmp_dest(self, output: StringIO, indent: int, debug: bool = False) -> None:
        """Print a jump destination (for goto labels)."""
        if debug:
            self._print_indent(output, indent)
            jump_lines = " ".join(str(s.line) for s in self.sub)
            output.write(f"-- JMP destination in line {self.line}, jump from line {jump_lines}\n")
        # Labels are Lua 5.2+ feature, not needed for 5.1

    def __repr__(self) -> str:
        return f"AstStatement({STATEMENT_TYPE_NAMES[self.type]}, code={self.code!r}, children={len(self.sub)})"

    def try_optimize_while_if(self) -> bool:
        """
        Try to optimize 'while 1 do if test then body else break end end' to 'while test do body end'.

        This is a common pattern in compiled Lua code.

        Returns True if optimization was applied.
        """
        # Must be a while statement with code "1" or "true"
        if self.type != StatementType.WHILE_STMT:
            return False
        if self.code not in ("1", "true"):
            return False

        # Must have exactly one child which is an if statement
        if len(self.sub) != 1:
            return False
        if_stmt = self.sub[0]
        if if_stmt.type != StatementType.IF_STMT:
            return False

        # The if must have then and else branches
        then_stmt = if_stmt.then_stmt
        else_stmt = if_stmt.else_stmt
        if not then_stmt or not else_stmt:
            return False

        # The else branch must contain only a break
        if len(else_stmt.sub) != 1:
            return False
        else_child = else_stmt.sub[0]
        if else_child.type != StatementType.BREAK_STMT:
            return False

        # Optimization is possible!
        # Convert: while 1 do if X then Y else break end end
        # To: while X do Y end

        # Update the while condition
        self.code = if_stmt.code

        # Replace while's children with the then block's children
        self.sub.clear()
        for child in then_stmt.sub:
            child.parent = self
            self.sub.append(child)

        return True

    def try_optimize_inverted_while_if(self) -> bool:
        """
        Try to optimize 'while 1 do if not test then break end body end' to 'while test do body end'.

        This is the inverted version of the while-if pattern.

        Returns True if optimization was applied.
        """
        # Must be a while statement with code "1" or "true"
        if self.type != StatementType.WHILE_STMT:
            return False
        if self.code not in ("1", "true"):
            return False

        # Must have at least one child, first being an if statement
        if len(self.sub) < 1:
            return False
        if_stmt = self.sub[0]
        if if_stmt.type != StatementType.IF_STMT:
            return False

        # The if must have then and else branches
        then_stmt = if_stmt.then_stmt
        else_stmt = if_stmt.else_stmt
        if not then_stmt or not else_stmt:
            return False

        # The then branch must contain only a break
        if len(then_stmt.sub) != 1:
            return False
        then_child = then_stmt.sub[0]
        if then_child.type != StatementType.BREAK_STMT:
            return False

        # The else branch must be empty
        if len(else_stmt.sub) != 0:
            return False

        # Optimization is possible!
        # Convert: while 1 do if not X then break end body end
        # To: while X do body end

        # Invert the condition
        condition = if_stmt.code
        if condition.startswith("not "):
            # Remove the "not " prefix
            condition = condition[4:]
        else:
            # Add "not" or invert comparison
            if " == " in condition:
                condition = condition.replace(" == ", " ~= ", 1)
            elif " ~= " in condition:
                condition = condition.replace(" ~= ", " == ", 1)
            elif " < " in condition:
                condition = condition.replace(" < ", " >= ", 1)
            elif " <= " in condition:
                condition = condition.replace(" <= ", " > ", 1)
            elif " > " in condition:
                condition = condition.replace(" > ", " <= ", 1)
            elif " >= " in condition:
                condition = condition.replace(" >= ", " < ", 1)
            else:
                condition = f"not ({condition})" if " " in condition else f"not {condition}"

        self.code = condition

        # Remove the if statement and keep the rest of the body
        rest_of_body = self.sub[1:]
        self.sub.clear()
        for child in rest_of_body:
            child.parent = self
            self.sub.append(child)

        return True
