"""
Main decompilation engine.

Implements the two-pass decompilation algorithm:
1. Backward pass: Detect loop structures and control flow
2. Forward pass: Process instructions and generate Lua source
"""

from typing import Optional, List, Tuple, Dict, Any, Set

from ..bytecode.proto import Proto, format_constant, is_identifier
from ..bytecode.instruction import Instruction, is_k, index_k
from ..bytecode.opcodes import (
    OpCode, OpMode, OPCODE_INFO, BINARY_OPERATORS, UNARY_OPERATORS,
    COMPARISON_OPERATORS, INVERTED_COMPARISON_OPERATORS, OPERATOR_PRIORITY,
    LFIELDS_PER_FLUSH, is_test_opcode
)
from ..ast.statements import AstStatement, StatementType
from .function import DecompilerState, VarListItem, RegisterInfo
from .loops import LoopTree, LoopItem, detect_loops
from .booleans import BoolOp, make_boolean_string, IfBlock, analyze_if_else_structure
from .guess import NameGuesser, improve_temp_name


class Decompiler:
    """
    Main decompilation engine.

    Converts Lua 5.1 bytecode (Proto) to Lua source code.
    """

    def __init__(self, debug: bool = False):
        self.debug = debug
        self.process_sub = True
        self.reached_terminal = False  # Track if we've hit unreachable code

    def decompile(self, proto: Proto, funcnumstr: str = "0") -> str:
        """
        Decompile a Proto to Lua source.

        Args:
            proto: The function prototype to decompile
            funcnumstr: Function number string for nested functions

        Returns:
            Decompiled Lua source code
        """
        # Initialize state
        state = DecompilerState(proto=proto, funcnumstr=funcnumstr)

        # Set up name guesser for better variable names
        self.name_guesser = NameGuesser(proto)
        self.guessed_names = self.name_guesser.guess_all_locals()

        # Set up loop tree via backward pass
        state.loop_tree = detect_loops(proto)
        state.loop_ptr = state.loop_tree.root

        # Analyze control flow (if/else structures)
        self._analyze_control_flow(state)

        # Set up function block AST
        state.func_block = AstStatement.make_block(StatementType.FUNCTION_STMT, "")
        state.loop_tree.root.block = state.func_block
        state.curr_stmt = state.func_block

        # Initialize parameters with guessed or debug info names
        params = []
        for i in range(proto.numparams):
            # First try debug info
            name = self._get_local_name_at_pc(proto, i, 0)
            if not name:
                # Try guessed name
                name = self.guessed_names.get(i)
            if not name:
                # Fallback
                name = f"a{i}"
            params.append(name)
            state.declare_local(name, i)

        # Handle vararg
        if proto.is_vararg >= 2:
            params.append("...")

        state.func_block.code = ", ".join(params)
        state.free_local = proto.numparams

        # Process instructions (forward pass)
        self._process_code(state)

        # Generate output
        return self._generate_output(state)

    def _analyze_control_flow(self, state: DecompilerState) -> None:
        """
        Analyze control flow to detect if/else structures.

        This pre-pass identifies:
        - Conditional jumps that form if/else
        - Boolean expression chains
        - Break statements
        - Else branches
        - do/end blocks from CLOSE opcode
        """
        proto = state.proto
        code = proto.code
        n = proto.sizecode

        # Track jump destinations
        jump_targets: Dict[int, List[int]] = {}  # dest -> [source_pcs]

        # Track if/else structures
        self.if_blocks: Dict[int, IfBlock] = {}  # condition_start -> IfBlock
        self.else_starts: Set[int] = set()  # PCs where else blocks start
        self.endif_pcs: Set[int] = set()  # PCs where if statements end

        # Track do/end blocks from CLOSE opcode
        # In Lua 5.1, CLOSE R(A) closes upvalues >= R(A)
        # This indicates a block scope ending
        for pc in range(n - 1, -1, -1):
            inst = Instruction.decode(code[pc])

            # Detect do/end blocks from CLOSE opcode
            if inst.op == OpCode.CLOSE:
                start_reg = inst.a
                # Find local variables that start at this register
                for locvar in proto.locvars:
                    if locvar.startpc <= pc < locvar.endpc:
                        # This locvar is active at this CLOSE
                        # Mark block boundaries
                        state.do_opens.add(locvar.startpc)
                        state.do_closes.add(locvar.endpc)

            if inst.op == OpCode.JMP:
                dest = pc + inst.sbx + 1

                # Track this jump
                if dest not in jump_targets:
                    jump_targets[dest] = []
                jump_targets[dest].append(pc)

                # Check if this is a break (jumps to loop exit)
                loop = state.loop_tree.find_loop_at_pc(pc) if state.loop_tree else None
                if loop and dest == loop.out:
                    state.breaks.add(pc)

        # Detect if/else structures
        # First pass: identify condition chains and their boundaries
        # A chain is a sequence of TEST/CMP+JMP where each JMP is followed by another condition
        pc = 0
        while pc < n:
            inst = Instruction.decode(code[pc])

            # Look for comparison/test followed by JMP
            if inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
                if pc + 1 < n:
                    next_inst = Instruction.decode(code[pc + 1])
                    if next_inst.op == OpCode.JMP:
                        jmp_dest = pc + 2 + next_inst.sbx

                        # Skip boolean expression patterns (comparison -> result stored)
                        # Pattern: CMP + JMP -> LOADBOOL with skip -> LOADBOOL
                        if pc + 2 < n:
                            lb_inst = Instruction.decode(code[pc + 2])
                            if lb_inst.op == OpCode.LOADBOOL and lb_inst.c == 1:
                                # This is a boolean expression, not an if statement
                                pc += 1
                                continue

                        # Check if this is the START of a condition chain
                        # Find the end of the chain by looking for the last condition
                        # with the SAME or COMPATIBLE destination (for AND chains)
                        chain_start = pc
                        chain_end_pc = pc
                        final_dest = jmp_dest
                        first_dest = jmp_dest  # Track original destination for chain matching

                        # Walk through consecutive conditions
                        scan_pc = pc + 2  # After first condition+JMP
                        while scan_pc < n:
                            scan_inst = Instruction.decode(code[scan_pc])
                            if scan_inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
                                if scan_pc + 1 < n:
                                    scan_jmp = Instruction.decode(code[scan_pc + 1])
                                    if scan_jmp.op == OpCode.JMP:
                                        next_dest = scan_pc + 2 + scan_jmp.sbx

                                        # Only include in chain if destination matches
                                        # (same dest = AND chain with same else target)
                                        if next_dest == first_dest:
                                            chain_end_pc = scan_pc
                                            final_dest = next_dest
                                            scan_pc += 2
                                            continue
                                        # Different destination breaks the chain
                                        break
                            break

                        # Skip if destination is a LOADBOOL (boolean expression)
                        if final_dest < n:
                            dest_inst = Instruction.decode(code[final_dest])
                            if dest_inst.op == OpCode.LOADBOOL:
                                pc = chain_end_pc + 2
                                continue

                        # Create if block for the entire chain
                        then_start = chain_end_pc + 2  # Body starts after last condition+JMP
                        block = IfBlock(
                            condition_start=chain_start,
                            condition_end=then_start,
                            then_start=then_start,
                            then_end=final_dest,
                            endif=final_dest
                        )

                        # Check for else branch: look for JMP at end of then block
                        then_end_pc = final_dest - 1
                        if then_end_pc > then_start and then_end_pc < n:
                            maybe_else_jmp = Instruction.decode(code[then_end_pc])
                            if maybe_else_jmp.op == OpCode.JMP and maybe_else_jmp.sbx > 0:
                                else_end = then_end_pc + 1 + maybe_else_jmp.sbx

                                # Don't treat as else if the "else body" starts with
                                # another conditional (it's probably elseif)
                                first_else_inst = Instruction.decode(code[final_dest]) if final_dest < n else None
                                if first_else_inst and first_else_inst.op in (OpCode.LOADK, OpCode.LOADBOOL):
                                    # Not an else - it's a value expression
                                    pass
                                elif first_else_inst and first_else_inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
                                    # Could be elseif - let it be handled as separate if
                                    pass
                                else:
                                    # Looks like a real else block
                                    block.then_end = then_end_pc
                                    block.else_start = final_dest
                                    block.else_end = else_end
                                    block.endif = else_end
                                    self.else_starts.add(final_dest)

                        self.if_blocks[chain_start] = block
                        self.endif_pcs.add(block.endif)

                        # Skip past the entire chain
                        pc = chain_end_pc + 2
                        continue

            pc += 1

        # Second pass: fix problematic nested blocks
        sorted_blocks = sorted(self.if_blocks.items(), key=lambda x: x[0])
        for i, (pc, block) in enumerate(sorted_blocks):
            # Fix overlapping else blocks
            if block.else_start > 0:
                # Check if this else_start falls within an outer if's then block
                for j, (outer_pc, outer_block) in enumerate(sorted_blocks):
                    if outer_pc < pc:  # outer_block is an outer if
                        if outer_block.then_start <= block.else_start < outer_block.then_end:
                            # The else of inner block is inside outer's then
                            # This is not a real else - it's just sequential code
                            block.else_start = -1
                            block.else_end = -1
                            self.else_starts.discard(block.then_end)

            # Handle guard clause pattern: inner if whose then_end goes past outer's then_end
            for j, (outer_pc, outer_block) in enumerate(sorted_blocks):
                if outer_pc < pc and outer_block.then_start <= pc < outer_block.then_end:
                    # This block is inside outer's then block
                    if block.then_end > outer_block.then_end:
                        # Inner if extends past outer's then - this is a guard clause
                        # Limit inner block's then_end to outer's then_end
                        block.then_end = outer_block.then_end
                        block.else_start = -1
                        block.else_end = -1
                        block.endif = outer_block.then_end

        state.jmpdests = {pc: None for pc in jump_targets.keys()}

    def _process_code(self, state: DecompilerState) -> None:
        """Process all bytecode instructions."""
        proto = state.proto
        code = proto.code
        n = proto.sizecode
        skip_next = 0
        self.reached_terminal = False

        # Nil optimization: check first instruction to determine registers needing nil
        self._handle_nil_optimization(state)

        # Output nil initialization statement if needed
        if hasattr(state, '_nil_init_regs') and state._nil_init_regs:
            names = [name for _, name in state._nil_init_regs]
            state.add_statement(f"local {', '.join(names)}")
            state._nil_init_regs = []

        for pc in range(n):
            if skip_next > 0:
                skip_next -= 1
                continue

            # Skip unreachable code after TAILCALL
            if self.reached_terminal:
                continue

            state.pc = pc

            # Check for pending if/else transitions
            self._check_if_transitions(state, pc)

            # Handle do/end block opens
            if pc in state.do_opens:
                state.do_opens.discard(pc)
                do_stmt = AstStatement.make_do()
                state.enter_block(do_stmt)

            inst = Instruction.decode(code[pc])

            # Update local variable scope
            self._update_locals(state, pc)

            # Handle loop/block transitions
            self._handle_block_transitions(state, pc)

            # Process instruction
            skip = self._process_instruction(state, inst)
            if skip:
                skip_next = skip

            # Handle do/end block closes
            if pc + 1 in state.do_closes:
                state.do_closes.discard(pc + 1)
                if state.curr_stmt and state.curr_stmt.type == StatementType.DO_STMT:
                    state.leave_block()

    def _handle_nil_optimization(self, state: DecompilerState) -> None:
        """
        Handle nil optimization at function start (Lua 5.1 feature).

        When the first instruction uses registers that haven't been initialized
        (i.e., registers beyond numparams), those registers need to be declared
        as nil locals first.
        """
        proto = state.proto
        if proto.sizecode == 0:
            return

        first_inst = Instruction.decode(proto.code[0])
        op = first_inst.op
        a = first_inst.a
        b = first_inst.b
        c = first_inst.c

        # Determine the highest register that needs nil initialization
        num_nil = -1

        if op == OpCode.SETGLOBAL:
            # SETGLOBAL reads from register A
            num_nil = a
        elif op == OpCode.SETUPVAL:
            # SETUPVAL reads from register A
            num_nil = a
        elif op == OpCode.JMP:
            # JMP doesn't use any registers
            num_nil = -1
        elif op == OpCode.SETTABLE:
            # SETTABLE reads from A (table), and possibly B and C if not constants
            num_nil = a
            if not is_k(b):
                num_nil = max(num_nil, b)
            if not is_k(c):
                num_nil = max(num_nil, c)
        elif op == OpCode.GETTABLE:
            # GETTABLE writes to A, reads from B and possibly C
            num_nil = a - 1
            if b > num_nil:
                num_nil = b
            if not is_k(c) and c > num_nil:
                num_nil = c
        elif op in (OpCode.EQ, OpCode.LT, OpCode.LE):
            # Comparisons read from B and C (if not constants)
            if not is_k(b):
                num_nil = max(num_nil, b)
            if not is_k(c):
                num_nil = max(num_nil, c)
        elif op == OpCode.TEST:
            # TEST reads from A
            num_nil = a
        elif op == OpCode.TESTSET:
            # TESTSET reads from B, writes to A
            num_nil = max(a - 1, b)
        elif op == OpCode.RETURN:
            # RETURN reads from A onwards
            if first_inst.b > 1:
                num_nil = a + first_inst.b - 2
            elif first_inst.b == 0:
                num_nil = a
        elif op == OpCode.CALL or op == OpCode.TAILCALL:
            # CALL reads function from A and args from A+1 onwards
            num_nil = a
            if first_inst.b > 1:
                num_nil = a + first_inst.b - 1
        else:
            # Most instructions write to A, so A-1 registers need to be nil
            num_nil = a - 1

        # Initialize registers from numparams to num_nil with nil
        free_local = proto.numparams

        if num_nil >= free_local:
            # Collect register names that need nil initialization
            nil_regs = []
            for r in range(free_local, num_nil + 1):
                # Check if there's a local variable name for this register
                name = self._get_local_name_at_pc(proto, r, 0)
                if not name:
                    name = self.guessed_names.get(r)
                if not name:
                    name = f"l_{r}"

                nil_regs.append((r, name))

                # Set up the register
                state.registers[r].value = name
                state.registers[r].local_idx = r
                state.registers[r].is_pending = False

            # If we have nil registers to declare, we'll do it lazily
            # Store them for output when appropriate
            if nil_regs:
                state._nil_init_regs = nil_regs

    def _check_if_transitions(self, state: DecompilerState, pc: int) -> None:
        """Check and handle if/else block transitions."""
        # First, close any if statements that have ended
        while state.if_stack:
            then_end, else_end, if_stmt = state.if_stack[-1]

            if else_end > then_end:
                # Has else block
                if pc >= else_end:
                    # Flush pending assignments before closing block
                    state.flush_pending_assignments()
                    # Past the end of else block - close this if
                    state.if_stack.pop()
                    # Navigate directly to the if_stmt's parent
                    if if_stmt.parent:
                        state.curr_stmt = if_stmt.parent
                    continue
                elif pc >= then_end and pc < else_end:
                    # Transitioning to else block - flush first
                    state.flush_pending_assignments()
                    # Inside else block - make sure we're in else_stmt
                    if if_stmt.else_stmt and state.curr_stmt != if_stmt.else_stmt:
                        state.curr_stmt = if_stmt.else_stmt
                    break
                else:
                    # Still in then block
                    break
            else:
                # No else block
                if pc >= then_end:
                    # Flush pending assignments before closing block
                    state.flush_pending_assignments()
                    # Past the end of then block - close this if
                    state.if_stack.pop()
                    # Navigate directly to the if_stmt's parent
                    if if_stmt.parent:
                        state.curr_stmt = if_stmt.parent
                    continue
                else:
                    break

        # Check if we're at an else block start
        if hasattr(self, 'else_starts') and pc in self.else_starts:
            # Find the if statement whose else block starts here
            for i in range(len(state.if_stack) - 1, -1, -1):
                then_end, else_end, if_stmt = state.if_stack[i]
                if then_end == pc and else_end > then_end:
                    # This if's else block starts at pc
                    if if_stmt.else_stmt:
                        state.curr_stmt = if_stmt.else_stmt
                    break

    def _update_locals(self, state: DecompilerState, pc: int) -> None:
        """Update local variable declarations and releases."""
        proto = state.proto

        # Flush any pending local declarations
        if state.local_pending:
            state.flush_local_declarations()

        # Check for new locals starting at this PC
        new_locals = []
        for i, locvar in enumerate(proto.locvars):
            if locvar.startpc == pc and not state.ignore_for_variables:
                reg = self._count_active_locals_before(proto, i, pc)
                if reg >= 0 and not state.is_local(reg):
                    new_locals.append((reg, locvar.varname))

        # Declare new locals
        for reg, name in new_locals:
            # Get pending value if any
            info = state.registers[reg]
            pending_val = info.value if info.is_pending else None
            state.declare_local(name, reg, pending_val)

        # Check for locals ending at this PC
        for i, locvar in enumerate(proto.locvars):
            if locvar.endpc == pc:
                reg = self._count_active_locals_at(proto, i, pc - 1)
                if reg >= 0:
                    state.release_local(reg)

    def _count_active_locals_before(self, proto: Proto, target_idx: int, pc: int) -> int:
        """Count active locals before the target local at pc."""
        count = 0
        for i, locvar in enumerate(proto.locvars):
            if i == target_idx:
                return count
            if locvar.startpc <= pc < locvar.endpc:
                count += 1
        return -1

    def _count_active_locals_at(self, proto: Proto, target_idx: int, pc: int) -> int:
        """Count active locals at pc to find register for target local."""
        count = 0
        for i, locvar in enumerate(proto.locvars):
            if i == target_idx:
                return count
            if locvar.startpc <= pc < locvar.endpc:
                count += 1
        return -1

    def _get_local_name_at_pc(self, proto: Proto, reg: int, pc: int) -> Optional[str]:
        """Get local variable name for register at pc."""
        idx = 0
        for locvar in proto.locvars:
            if locvar.startpc <= pc < locvar.endpc:
                if idx == reg:
                    return locvar.varname
                idx += 1
        return None

    def _get_local_starting_at_pc(self, proto: Proto, reg: int, pc: int) -> Optional[str]:
        """
        Get local variable name that starts at exactly this PC for this register.

        This is used to detect when a multi-value return will create new locals.
        """
        # First, count how many locals are already active before this PC
        # (locals that started before pc and haven't ended yet)
        base_reg = 0
        for locvar in proto.locvars:
            if locvar.startpc < pc and locvar.endpc > pc:
                base_reg += 1

        # Now look for locals that start at exactly this PC
        # and find the one that will occupy the target register
        current_reg = base_reg
        for locvar in proto.locvars:
            if locvar.startpc == pc:
                if current_reg == reg:
                    return locvar.varname
                current_reg += 1

        return None

    def _handle_block_transitions(self, state: DecompilerState, pc: int) -> None:
        """Handle loop and block entry/exit."""
        loop_ptr = state.loop_ptr

        if not loop_ptr:
            return

        # Check if we're entering a child loop
        child = loop_ptr.child
        while child:
            if child.start == pc:
                self._enter_loop(state, child)
                state.loop_ptr = child
                loop_ptr = child
                child = child.child
            else:
                child = child.next

        # Check if we're exiting current loop
        while loop_ptr and loop_ptr.parent:
            if pc > loop_ptr.end:
                self._exit_loop(state, loop_ptr)
                state.loop_ptr = loop_ptr.parent
                loop_ptr = loop_ptr.parent
            else:
                break

    def _enter_loop(self, state: DecompilerState, loop: LoopItem) -> None:
        """Handle entering a loop."""
        if loop.type == StatementType.WHILE_STMT:
            stmt = AstStatement.make_while("true")
            loop.block = stmt
            state.enter_block(stmt)
        elif loop.type == StatementType.REPEAT_STMT:
            stmt = AstStatement.make_repeat("true")
            loop.block = stmt
            state.enter_block(stmt)
        elif loop.type == StatementType.FORLOOP_STMT:
            stmt = AstStatement.make_for("")
            loop.block = stmt
            state.enter_block(stmt)
        elif loop.type == StatementType.TFORLOOP_STMT:
            stmt = AstStatement.make_tfor("")
            loop.block = stmt
            state.enter_block(stmt)
            # Pre-initialize loop variables - find the TFORLOOP instruction
            self._init_tfor_variables(state, loop)

    def _is_in_loop(self, state: DecompilerState) -> bool:
        """Check if currently inside a loop (not the function root)."""
        if not state.loop_ptr:
            return False
        return state.loop_ptr.type in (
            StatementType.WHILE_STMT, StatementType.REPEAT_STMT,
            StatementType.FORLOOP_STMT, StatementType.TFORLOOP_STMT
        )

    def _init_tfor_variables(self, state: DecompilerState, loop: LoopItem) -> None:
        """Initialize loop variables for a TFORLOOP before processing the body."""
        # Find the TFORLOOP instruction to get register info
        # TFORLOOP is at loop.end - 1 (JMP is at loop.end)
        tfor_pc = loop.end - 1
        if tfor_pc < 0 or tfor_pc >= state.proto.sizecode:
            return

        inst = Instruction.decode(state.proto.code[tfor_pc])
        if inst.op != OpCode.TFORLOOP:
            return

        # TFORLOOP R(A) puts loop variables at R(A+3), R(A+4), etc.
        # C field tells how many variables
        base_reg = inst.a + 3

        for i in range(inst.c):
            # Get variable name from debug info
            name = self._get_local_name_at_pc(state.proto, base_reg + i, loop.start)
            if not name:
                name = f"v{i}"

            # Set the register to the variable name
            state.registers[base_reg + i].value = name
            state.registers[base_reg + i].local_idx = base_reg + i
            state.registers[base_reg + i].is_pending = False

    def _exit_loop(self, state: DecompilerState, loop: LoopItem) -> None:
        """Handle exiting a loop."""
        # Try to optimize while 1 do if -> while before leaving
        if loop.type == StatementType.WHILE_STMT and loop.block:
            if loop.block.try_optimize_while_if():
                pass  # Optimization applied
            elif loop.block.try_optimize_inverted_while_if():
                pass  # Inverted optimization applied

        state.leave_block()

    def _process_instruction(self, state: DecompilerState, inst: Instruction) -> int:
        """
        Process a single instruction.

        Returns number of instructions to skip.
        """
        handlers = {
            OpCode.MOVE: self._handle_move,
            OpCode.LOADK: self._handle_loadk,
            OpCode.LOADBOOL: self._handle_loadbool,
            OpCode.LOADNIL: self._handle_loadnil,
            OpCode.GETUPVAL: self._handle_getupval,
            OpCode.GETGLOBAL: self._handle_getglobal,
            OpCode.GETTABLE: self._handle_gettable,
            OpCode.SETGLOBAL: self._handle_setglobal,
            OpCode.SETUPVAL: self._handle_setupval,
            OpCode.SETTABLE: self._handle_settable,
            OpCode.NEWTABLE: self._handle_newtable,
            OpCode.SELF: self._handle_self,
            OpCode.ADD: self._handle_binary,
            OpCode.SUB: self._handle_binary,
            OpCode.MUL: self._handle_binary,
            OpCode.DIV: self._handle_binary,
            OpCode.MOD: self._handle_binary,
            OpCode.POW: self._handle_binary,
            OpCode.UNM: self._handle_unary,
            OpCode.NOT: self._handle_unary,
            OpCode.LEN: self._handle_unary,
            OpCode.CONCAT: self._handle_concat,
            OpCode.JMP: self._handle_jmp,
            OpCode.EQ: self._handle_comparison,
            OpCode.LT: self._handle_comparison,
            OpCode.LE: self._handle_comparison,
            OpCode.TEST: self._handle_test,
            OpCode.TESTSET: self._handle_testset,
            OpCode.CALL: self._handle_call,
            OpCode.TAILCALL: self._handle_tailcall,
            OpCode.RETURN: self._handle_return,
            OpCode.FORLOOP: self._handle_forloop,
            OpCode.FORPREP: self._handle_forprep,
            OpCode.TFORLOOP: self._handle_tforloop,
            OpCode.SETLIST: self._handle_setlist,
            OpCode.CLOSE: self._handle_close,
            OpCode.CLOSURE: self._handle_closure,
            OpCode.VARARG: self._handle_vararg,
        }

        handler = handlers.get(inst.op)
        if handler:
            return handler(state, inst) or 0
        return 0

    # Instruction handlers

    def _handle_move(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := R(B)"""
        # Get source value without consuming if it's a local
        src_info = state.registers[inst.b]
        if src_info.local_idx >= 0:
            # Moving from a local - just reference by name
            value = state.peek_register(inst.b)
        else:
            value = state.get_register(inst.b)

        dest_info = state.registers[inst.a]

        # Check if we're assigning to a temp register inside a loop with a significant value
        # In this case, we should emit a local variable assignment
        if dest_info.local_idx < 0 and self._is_in_loop(state):
            # Check if value is significant (table constructor, call, etc.)
            if value.startswith('{') or '(' in value:
                # Emit as local variable with contextual name
                if value.startswith('{'):
                    temp_name = "result"
                else:
                    temp_name = "item"
                state.add_statement(f"local {temp_name} = {value}")
                state.registers[inst.a].value = temp_name
                state.registers[inst.a].temp_name = temp_name
                return

        state.set_register(inst.a, value, state.Rprio[inst.b])

    def _handle_loadk(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := Kst(Bx)"""
        const = state.get_constant(inst.bx)
        value = format_constant(const)

        # Check if this register will be used as an accumulator (modified in-place)
        # If so, declare a synthetic local now to ensure proper scoping
        dest_reg = inst.a
        if dest_reg >= state.free_local and self._is_accumulator_init(state, dest_reg):
            temp_name = f"l_{dest_reg}_{state.pc}"
            state.add_statement(f"local {temp_name} = {value}")
            info = state.registers[dest_reg]
            info.temp_name = temp_name
            info.local_idx = dest_reg
            info.value = temp_name
            info.set_pc = state.pc
            state._sync_register_info(dest_reg)
            return

        state.set_register(inst.a, value)

    def _is_accumulator_init(self, state: DecompilerState, reg: int) -> bool:
        """Check if this register initialization is for an accumulator variable.

        An accumulator is a register that is modified in-place later, e.g.:
            LOADK R[1] = 0
            ...
            ADD R[1] = R[1] + 2
        """
        proto = state.proto
        code = proto.code
        n = proto.sizecode

        # Scan forward from current PC to find binary ops that modify this reg in-place
        for pc in range(state.pc + 1, n):
            inst = Instruction.decode(code[pc])

            # Check for binary ops where dest == source
            if inst.op in (OpCode.ADD, OpCode.SUB, OpCode.MUL, OpCode.DIV, OpCode.MOD, OpCode.POW):
                if inst.a == reg:
                    # This op writes to our register
                    if inst.b == reg or (inst.c < 256 and inst.c == reg):
                        # And also reads from it - this is an accumulator pattern
                        return True
                    # If it just overwrites without reading, stop searching
                    break

            # If register is overwritten by something else, stop
            if inst.op in (OpCode.LOADK, OpCode.LOADNIL, OpCode.LOADBOOL, OpCode.MOVE,
                          OpCode.GETGLOBAL, OpCode.GETTABLE, OpCode.GETUPVAL,
                          OpCode.NEWTABLE, OpCode.CALL, OpCode.CLOSURE):
                if inst.op == OpCode.CALL:
                    # CALL writes to A through A+C-2
                    if inst.a <= reg < inst.a + max(1, inst.c - 1):
                        break
                elif inst.op == OpCode.LOADNIL:
                    if inst.a <= reg <= inst.b:
                        break
                elif inst.a == reg:
                    break

            # Stop at return/end of function
            if inst.op == OpCode.RETURN:
                break

        return False

    def _handle_loadbool(self, state: DecompilerState, inst: Instruction) -> int:
        """R(A) := (Bool)B; if (C) pc++"""
        value = "true" if inst.b else "false"
        state.set_register(inst.a, value)

        if inst.c:
            # Skip next instruction (typically used in boolean expressions)
            return 1
        return 0

    def _handle_loadnil(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := ... := R(B) := nil"""
        for r in range(inst.a, inst.b + 1):
            state.set_register(r, "nil")

    def _handle_getupval(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := UpValue[B]"""
        name = state.get_upvalue_name(inst.b)
        state.set_register(inst.a, name)

    def _handle_getglobal(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := Gbl[Kst(Bx)]"""
        const = state.get_constant(inst.bx)
        name = str(const) if const else f"_G[{inst.bx}]"
        state.set_register(inst.a, name)

    def _handle_gettable(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := R(B)[RK(C)]"""
        table = state.get_register(inst.b)
        key = self._get_rk(state, inst.c)
        value = self._format_table_access(table, key)
        state.set_register(inst.a, value)

    def _handle_setglobal(self, state: DecompilerState, inst: Instruction) -> None:
        """Gbl[Kst(Bx)] := R(A)"""
        const = state.get_constant(inst.bx)
        name = str(const) if const else f"_G[{inst.bx}]"
        value = state.get_register(inst.a)
        state.add_statement(f"{name} = {value}")

    def _handle_setupval(self, state: DecompilerState, inst: Instruction) -> None:
        """UpValue[B] := R(A)"""
        name = state.get_upvalue_name(inst.b)
        value = state.get_register(inst.a)
        state.add_statement(f"{name} = {value}")

    def _handle_settable(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A)[RK(B)] := RK(C)"""
        # Check if setting on a table under construction
        if state.registers[inst.a].is_table:
            table = state.tables.get_table(inst.a)
            if table:
                key = self._get_rk(state, inst.b)
                value = self._get_rk(state, inst.c)
                table.add_keyed_item(key, value)
                return

        table = state.get_register(inst.a)
        key = self._get_rk(state, inst.b)
        value = self._get_rk(state, inst.c)
        access = self._format_table_access(table, key)
        state.add_statement(f"{access} = {value}")

    def _handle_newtable(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := {} (size = B,C)"""
        array_size = self._fb2int(inst.b)
        hash_size = self._fb2int(inst.c)
        state.start_table(inst.a, array_size, hash_size)

    def _fb2int(self, x: int) -> int:
        """Convert floating point byte to integer."""
        if x < 8:
            return x
        return ((x & 7) + 8) << ((x >> 3) - 1)

    def _handle_self(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A+1) := R(B); R(A) := R(B)[RK(C)]"""
        table = state.get_register(inst.b)
        key = self._get_rk(state, inst.c)

        # Store table reference for method call (will be implicit self)
        state.set_register(inst.a + 1, table)

        # Format as method reference
        method = self._format_method_access(table, key)
        state.set_register(inst.a, method)
        # Mark as method call so CALL knows to skip the implicit self arg
        state.registers[inst.a].is_method = True

    def _handle_binary(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := RK(B) op RK(C)"""
        left = self._get_rk(state, inst.b)
        right = self._get_rk(state, inst.c)
        op_str = BINARY_OPERATORS.get(inst.op, "?")
        prio = OPERATOR_PRIORITY.get(inst.op, 10)

        # Add parentheses if needed based on priority
        left_prio = state.Rprio[inst.b] if not is_k(inst.b) else 0
        right_prio = state.Rprio[inst.c] if not is_k(inst.c) else 0

        if left_prio > prio:
            left = f"({left})"
        if right_prio >= prio:
            right = f"({right})"

        value = f"{left} {op_str} {right}"
        state.set_register(inst.a, value, prio)

    def _handle_unary(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := op R(B)"""
        operand = state.get_register(inst.b)
        op_str = UNARY_OPERATORS.get(inst.op, "?")
        prio = OPERATOR_PRIORITY.get(inst.op, 2)

        if state.Rprio[inst.b] > prio:
            operand = f"({operand})"

        value = f"{op_str}{operand}"
        state.set_register(inst.a, value, prio)

    def _handle_concat(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A) := R(B).. ... ..R(C)"""
        parts = []
        for r in range(inst.b, inst.c + 1):
            part = state.get_register(r)
            if state.Rprio[r] > 5:
                part = f"({part})"
            parts.append(part)

        value = " .. ".join(parts)
        state.set_register(inst.a, value, 5)

    def _handle_jmp(self, state: DecompilerState, inst: Instruction) -> int:
        """pc += sBx"""
        dest = state.pc + inst.sbx + 1

        # Check if this is a break
        if state.pc in state.breaks:
            state.bools.clear()
            state.add_block_statement(AstStatement.make_break())
            return 0

        # Check if this is a backward jump (loop continuation)
        if dest <= state.pc:
            # Loop back edge - handled by loop structure
            state.bools.clear()
            return 0

        # Check if we have pending boolean operations
        if state.bools:
            # KEY FIX: Check if there's another condition coming that's part of this chain
            # Look ahead to find the next comparison/test instruction
            # If it jumps to the same destination, it's part of the same AND chain
            if self._has_more_conditions_in_chain(state, dest):
                # More conditions coming - don't create if statement yet
                return 0

            # Check if this is part of a conditional expression chain
            # (a chain that leads to value assignment, not statement blocks)
            if self._is_conditional_expression_chain(state, dest):
                # Don't create if statement - let the chain continue
                # The expression will be resolved when we hit the final assignment
                return 0

            # This JMP completes a boolean condition for an if statement
            # Now we have all conditions accumulated - build combined condition
            condition = self._build_condition(state, dest)
            if condition:
                # For combined chains (multiple bools), use dest from the last JMP
                # as then_end, not the pre-analyzed if_block which may have wrong boundaries
                # The pre-analyzed blocks don't handle complex OR chains correctly
                if len(state.bools) > 1:
                    # Multiple conditions combined - use runtime dest
                    self._create_if_statement(state, condition, dest)
                else:
                    # Single condition - can use pre-analyzed block if available
                    cond_start = state.bools[0].pc if state.bools else state.pc - 1
                    if_block = self.if_blocks.get(cond_start) if hasattr(self, 'if_blocks') else None

                    if if_block:
                        self._create_if_statement_from_block(state, condition, if_block)
                    else:
                        self._create_if_statement(state, condition, dest)
                state.bools.clear()
            return 0

        # Forward jump at end of then block - skip (else handling done elsewhere)
        if state.if_stack:
            then_end, else_end, if_stmt = state.if_stack[-1]
            if state.pc == then_end - 1 and else_end > then_end:
                # This JMP skips the else block - don't process as separate statement
                return 0

        return 0

    def _has_more_conditions_in_chain(self, state: DecompilerState, current_dest: int) -> bool:
        """
        Check if there are more conditions in this AND/OR chain.

        Scans forward from the current JMP to find the next condition (TEST/CMP).
        If found and it jumps to a compatible destination, it's part of the same chain.

        For AND chains: all conditions jump to the same else_addr (skip on failure)
        For OR chains: conditions may jump to body (short-circuit on success)

        CALLs are allowed if their result is used in the next condition (e.g., function()
        returns a value that is immediately tested). CALLs that are NOT used in conditions
        break the chain.
        """
        proto = state.proto
        code = proto.code
        n = proto.sizecode

        # Scan forward from after the JMP to find the next condition
        scan_pc = state.pc + 1
        max_scan = min(state.pc + 30, n)  # Don't scan too far

        last_call_result_reg = -1  # Track the result register of the last CALL

        while scan_pc < max_scan:
            inst = Instruction.decode(code[scan_pc])

            # Found another condition
            if inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
                # Check if this condition uses the CALL result (if there was a call)
                # For TEST/TESTSET, the tested value is in register A
                # For EQ/LT/LE, the values are in B and C (potentially RK)
                condition_uses_call_result = False
                if last_call_result_reg >= 0:
                    if inst.op in (OpCode.TEST, OpCode.TESTSET):
                        condition_uses_call_result = (inst.a == last_call_result_reg)
                    else:
                        # EQ/LT/LE compare B and C
                        if not is_k(inst.b) and inst.b == last_call_result_reg:
                            condition_uses_call_result = True
                        if not is_k(inst.c) and inst.c == last_call_result_reg:
                            condition_uses_call_result = True

                # If there was a CALL but the condition doesn't use its result,
                # the CALL is a side-effect and breaks the chain
                if last_call_result_reg >= 0 and not condition_uses_call_result:
                    return False

                # Check if it has a JMP following it
                if scan_pc + 1 < n:
                    jmp_inst = Instruction.decode(code[scan_pc + 1])
                    if jmp_inst.op == OpCode.JMP:
                        next_dest = scan_pc + 2 + jmp_inst.sbx

                        # Same destination = AND chain
                        if next_dest == current_dest:
                            return True

                        # Next dest is current_dest or past it = compatible chain
                        # (might be complex and/or)
                        if next_dest >= current_dest:
                            return True

                        # For OR patterns: if current jumps to body (short-circuit success)
                        # and next jumps to else, they form an OR chain
                        # This is detected when current_dest < next_dest
                        # and current_dest is between current position and next_dest
                        if current_dest > state.pc + 2 and current_dest < next_dest:
                            return True

                return False

            # Skip over value-loading instructions (these don't break the chain)
            if inst.op in (OpCode.GETGLOBAL, OpCode.GETTABLE, OpCode.GETUPVAL,
                          OpCode.MOVE, OpCode.LOADK, OpCode.LOADNIL, OpCode.LOADBOOL):
                scan_pc += 1
                continue

            # Hit a CALL - track its result register
            # If the result is used in the next condition, it's part of the chain
            if inst.op == OpCode.CALL:
                # Track the result register (CALL stores result in A)
                if inst.c >= 2:  # Has at least one return value
                    last_call_result_reg = inst.a
                else:
                    # Statement call (no returns) - this breaks the chain
                    return False
                scan_pc += 1
                continue

            # Past current_dest means we're looking at the body code
            # which should not be in the condition chain
            if scan_pc >= current_dest:
                return False

            # Any other instruction breaks the chain
            break

        return False

    def _is_conditional_expression_chain(self, state: DecompilerState, dest: int) -> bool:
        """
        Check if this JMP is part of a conditional expression chain (and/or).

        Returns True if the jump leads to:
        - Another comparison/test (chain continues)
        - A LOADK followed by TEST (value in and/or expression)
        - A pattern that will result in a single value assignment

        When True is returned, we skip creating an if statement and let the
        chain continue building. The bools will be cleared when we detect
        that the pattern ends with a simple assignment.
        """
        proto = state.proto
        code = proto.code
        n = proto.sizecode

        if dest >= n:
            return False

        dest_inst = Instruction.decode(code[dest])

        # Jump to another comparison - definitely part of a chain
        if dest_inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
            return True

        # Jump to LOADBOOL - end of boolean expression
        if dest_inst.op == OpCode.LOADBOOL:
            return True

        # Jump to LOADK - might be part of and/or value expression
        # Check if followed by TEST (a and b pattern) or if it leads to assignment
        if dest_inst.op == OpCode.LOADK:
            # Check next instruction
            if dest + 1 < n:
                next_inst = Instruction.decode(code[dest + 1])
                # LOADK followed by TEST is "value and next_condition" pattern
                if next_inst.op == OpCode.TEST:
                    return True
                # LOADK followed by JMP might be skipping to else value
                if next_inst.op == OpCode.JMP:
                    return True
                # LOADK followed by SETGLOBAL/SETTABLE is final value -
                # clear bools and let normal processing continue
                if next_inst.op in (OpCode.SETGLOBAL, OpCode.SETTABLE, OpCode.SETUPVAL):
                    # This is the end of a conditional expression chain
                    # Clear bools so we don't create spurious if statements
                    state.bools.clear()
                    return True

        # Jump to GETGLOBAL/GETTABLE followed by comparison - chain continues
        if dest_inst.op in (OpCode.GETGLOBAL, OpCode.GETTABLE, OpCode.GETUPVAL):
            if dest + 1 < n:
                next_inst = Instruction.decode(code[dest + 1])
                if next_inst.op in (OpCode.EQ, OpCode.LT, OpCode.LE, OpCode.TEST, OpCode.TESTSET):
                    return True

        # Jump directly to SETGLOBAL/SETTABLE - end of conditional expression
        # This happens when skipping over an alternative value in and/or expressions
        if dest_inst.op in (OpCode.SETGLOBAL, OpCode.SETTABLE, OpCode.SETUPVAL):
            # This is the end of a conditional expression chain
            # Clear bools so we don't create spurious if statements
            state.bools.clear()
            return True

        return False

    def _handle_comparison(self, state: DecompilerState, inst: Instruction) -> int:
        """if ((RK(B) op RK(C)) ~= A) then pc++"""
        left = self._get_rk(state, inst.b)
        right = self._get_rk(state, inst.c)

        # Get jump destination from next instruction
        next_pc = state.pc + 1
        if next_pc >= state.proto.sizecode:
            return 0

        next_inst = Instruction.decode(state.proto.code[next_pc])
        if next_inst.op != OpCode.JMP:
            return 0

        dest = next_pc + next_inst.sbx + 1

        # Check if this is a boolean expression pattern (comparison -> JMP -> LOADBOOL)
        # This pattern converts a comparison result to a boolean value
        if self._is_boolean_expression_pattern(state, dest):
            # Handle as expression, not control flow
            return self._handle_boolean_expression(state, inst, left, right, dest)

        # Add to boolean operations for if statement
        bop = BoolOp(
            op1=left,
            op2=right,
            op=inst.op,
            neg=(inst.a != 0),
            pc=state.pc,
            dest=dest
        )
        state.bools.append(bop)

        return 0

    def _is_boolean_expression_pattern(self, state: DecompilerState, jmp_dest: int) -> bool:
        """
        Check if this comparison is part of a boolean expression pattern.

        Pattern: CMP + JMP -> LOADBOOL false, skip -> LOADBOOL true
        """
        proto = state.proto
        pc = state.pc

        # Check for LOADBOOL at pc+2 (between JMP and dest)
        if pc + 2 < proto.sizecode:
            lb1 = Instruction.decode(proto.code[pc + 2])
            if lb1.op == OpCode.LOADBOOL and lb1.c == 1:  # Has skip
                # Check for another LOADBOOL at jmp_dest
                if jmp_dest < proto.sizecode:
                    lb2 = Instruction.decode(proto.code[jmp_dest])
                    if lb2.op == OpCode.LOADBOOL and lb2.c == 0:  # No skip
                        return True
        return False

    def _handle_boolean_expression(self, state: DecompilerState, inst: Instruction,
                                   left: str, right: str, dest: int) -> int:
        """Handle a comparison used as a boolean expression."""
        # The comparison result goes into the register from the LOADBOOL
        pc = state.pc
        lb1 = Instruction.decode(state.proto.code[pc + 2])
        target_reg = lb1.a

        # Build the boolean expression
        op_str = COMPARISON_OPERATORS[inst.op] if inst.a else INVERTED_COMPARISON_OPERATORS[inst.op]
        expr = f"{left} {op_str} {right}"

        state.set_register(target_reg, expr)

        # Skip the JMP and both LOADBOOLs
        return 3

    def _handle_test(self, state: DecompilerState, inst: Instruction) -> int:
        """if not (R(A) <=> C) then pc++"""
        value = state.get_register(inst.a, consume=False)

        next_pc = state.pc + 1
        if next_pc >= state.proto.sizecode:
            return 0

        next_inst = Instruction.decode(state.proto.code[next_pc])
        if next_inst.op != OpCode.JMP:
            return 0

        dest = next_pc + next_inst.sbx + 1

        # Check for boolean expression pattern
        if self._is_boolean_expression_pattern(state, dest):
            return self._handle_test_boolean_expression(state, inst, value, dest)

        # Determine negation based on context:
        # For AND chains: C=0 means "if falsy, skip to else" -> display value as-is
        #                 C=1 means "if truthy, skip to else" -> display "not value"
        # For OR chains (short-circuit to body):
        #                 C=1 means "if truthy, go to body" -> display value as-is (no negation!)
        #
        # We detect OR short-circuit by checking if dest is NOT the else address
        # (i.e., dest < the final else address, meaning it jumps to body for short-circuit)
        neg = (inst.c != 0)

        # Check if this is an OR short-circuit (jump to body, not to else)
        # For OR: TEST C=1 + JMP to body means "if truthy, short-circuit to body"
        # In this case, the condition displayed should be the value itself, not negated
        if inst.c == 1:
            # Save PC, temporarily advance past the JMP to scan for more conditions
            orig_pc = state.pc
            state.pc = next_pc  # Now pointing at JMP
            if self._has_more_conditions_in_chain(state, dest):
                # This is first part of OR chain jumping to body - don't negate
                neg = False
            state.pc = orig_pc

        bop = BoolOp(
            op1=value,
            op2="",
            op=inst.op,
            neg=neg,
            pc=state.pc,
            dest=dest
        )
        state.bools.append(bop)

        return 0

    def _handle_test_boolean_expression(self, state: DecompilerState, inst: Instruction,
                                        value: str, dest: int) -> int:
        """Handle a TEST used as a boolean expression."""
        pc = state.pc
        lb1 = Instruction.decode(state.proto.code[pc + 2])
        target_reg = lb1.a

        # Build the boolean expression
        if inst.c:
            expr = f"not {value}"
        else:
            expr = value

        state.set_register(target_reg, expr)
        return 3

    def _handle_testset(self, state: DecompilerState, inst: Instruction) -> int:
        """if (R(B) <=> C) then R(A) := R(B) else pc++"""
        value = state.get_register(inst.b, consume=False)

        next_pc = state.pc + 1
        if next_pc >= state.proto.sizecode:
            return 0

        next_inst = Instruction.decode(state.proto.code[next_pc])
        if next_inst.op != OpCode.JMP:
            return 0

        dest = next_pc + next_inst.sbx + 1

        bop = BoolOp(
            op1=value,
            op2="",
            op=inst.op,
            neg=(inst.c == 0),
            pc=state.pc,
            dest=dest
        )
        state.bools.append(bop)

        # Also handle the assignment
        state.set_register(inst.a, value)

        return 0

    def _handle_call(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A), ... ,R(A+C-2) := R(A)(R(A+1), ... ,R(A+B-1))"""
        func_info = state.registers[inst.a]
        is_method = func_info.is_method
        func = state.get_register(inst.a)

        # For method calls (:), the first argument is implicit self, skip it
        arg_start = inst.a + 2 if is_method else inst.a + 1

        # Gather arguments
        args = []
        if inst.b == 0:
            # Variable arguments (from previous call with variable returns)
            start, end = state.get_call_results_range()
            if start >= 0:
                for r in range(arg_start, min(end + 1, inst.a + 10)):
                    args.append(state.get_register(r))
            else:
                for r in range(arg_start, state.last_call + 1):
                    args.append(state.get_register(r))
        elif inst.b > 1:
            for r in range(arg_start, inst.a + inst.b):
                args.append(state.get_register(r))

        call_str = f"{func}({', '.join(args)})"

        # Handle return values
        if inst.c == 0:
            # Variable returns
            state.set_register(inst.a, call_str)
            state.mark_call_result(inst.a, 0)
            state.registers[inst.a].is_call_result = True
            state.registers[inst.a].original_call_expr = call_str
        elif inst.c == 1:
            # No returns (statement call)
            state.add_statement(call_str)
        elif inst.c == 2:
            # Single return
            # Check if this result will be used in a nil comparison AND used later
            # If so, emit as a local declaration like C luadec does
            if self._should_emit_call_as_local(state, inst.a):
                # Generate a meaningful temp name based on the call
                temp_name = self._generate_call_local_name(state, func, inst.a)
                state.add_statement(f"local {temp_name} = {call_str}")
                state.registers[inst.a].temp_name = temp_name
                state.registers[inst.a].value = temp_name
                state.registers[inst.a].local_idx = inst.a  # Mark as local so assignments work
                state.registers[inst.a].is_call_result = True
                state.registers[inst.a].original_call_expr = call_str
                state.mark_call_result(inst.a, 1)
            else:
                state.set_register(inst.a, call_str)
                state.mark_call_result(inst.a, 1)
                state.registers[inst.a].is_call_result = True
                state.registers[inst.a].original_call_expr = call_str
                # Check if this result will be used multiple times
                if self._register_used_multiple_times(state, inst.a):
                    # Generate a meaningful temp name based on the call
                    temp_name = self._generate_temp_name(func, inst.a)
                    state.add_statement(f"local {temp_name} = {call_str}")
                    state.registers[inst.a].temp_name = temp_name
                    state.registers[inst.a].value = temp_name
        else:
            # Multiple returns - values go to A, A+1, ..., A+C-2
            num_returns = inst.c - 1

            # Check if these registers will become locals at this PC
            local_names = []
            for i in range(num_returns):
                reg = inst.a + i
                name = self._get_local_starting_at_pc(state.proto, reg, state.pc + 1)
                if name:
                    local_names.append(name)
                else:
                    local_names.append(None)

            # If all returns become locals, output a multi-variable declaration
            if all(local_names):
                state.add_statement(f"local {', '.join(local_names)} = {call_str}")
                # Mark these registers as locals
                for i, name in enumerate(local_names):
                    reg = inst.a + i
                    state.registers[reg].value = name
                    state.registers[reg].local_idx = reg
                    state.registers[reg].is_pending = False
                    state.registers[reg].temp_name = None
            else:
                # Not all become locals - just set the first register
                state.set_register(inst.a, call_str)
                state.mark_call_result(inst.a, num_returns)
                state.registers[inst.a].is_call_result = True
                state.registers[inst.a].original_call_expr = call_str

                # Mark additional registers with placeholder values
                for i in range(1, num_returns):
                    reg = inst.a + i
                    # Use a descriptive placeholder
                    if local_names[i]:
                        state.registers[reg].value = local_names[i]
                    else:
                        state.registers[reg].value = f"_ret{i}"
                    state.registers[reg].is_call_result = True
                    state.registers[reg].temp_name = None
                    state.registers[reg].original_call_expr = call_str

    def _handle_tailcall(self, state: DecompilerState, inst: Instruction) -> None:
        """return R(A)(R(A+1), ... ,R(A+B-1))"""
        func = state.get_register(inst.a)

        args = []
        if inst.b == 0:
            for r in range(inst.a + 1, state.last_call + 1):
                args.append(state.get_register(r))
        elif inst.b > 1:
            for r in range(inst.a + 1, inst.a + inst.b):
                args.append(state.get_register(r))

        call_str = f"{func}({', '.join(args)})"
        state.add_block_statement(AstStatement.make_return(call_str))

        # Mark that we've reached a terminal instruction
        self.reached_terminal = True

    def _handle_return(self, state: DecompilerState, inst: Instruction) -> None:
        """return R(A), ... ,R(A+B-2)"""
        # Don't output return at end of function (implicit)
        if state.pc == state.proto.sizecode - 1 and inst.b == 1:
            return

        values = []
        if inst.b == 0:
            for r in range(inst.a, state.last_call + 1):
                values.append(state.get_register(r))
        elif inst.b > 1:
            for r in range(inst.a, inst.a + inst.b - 1):
                values.append(state.get_register(r))

        stmt = AstStatement.make_return(", ".join(values) if values else "")
        state.add_block_statement(stmt)

    def _handle_forloop(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A)+=R(A+2); if R(A) <?= R(A+1) then { pc+=sBx; R(A+3)=R(A) }"""
        # Loop iteration - handled by loop structure
        pass

    def _handle_forprep(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A)-=R(A+2); pc+=sBx"""
        # Get loop variable name
        var_name = self._get_local_name_at_pc(state.proto, inst.a + 3, state.pc + 1)
        if not var_name:
            var_name = "i"

        init = state.get_register(inst.a)
        limit = state.get_register(inst.a + 1)
        step = state.get_register(inst.a + 2)

        # Build for header
        if step == "1":
            header = f"{var_name} = {init}, {limit}"
        else:
            header = f"{var_name} = {init}, {limit}, {step}"

        # Update loop block code
        if state.loop_ptr and state.loop_ptr.block:
            state.loop_ptr.block.code = header

        # Mark internal registers
        for r in range(inst.a, inst.a + 4):
            state.registers[r].is_internal = True

    def _handle_tforloop(self, state: DecompilerState, inst: Instruction) -> None:
        """Generic for iterator call."""
        # Get variable names
        var_names = []
        for i in range(inst.c):
            name = self._get_local_name_at_pc(state.proto, inst.a + 3 + i, state.pc + 1)
            if name:
                var_names.append(name)
            else:
                var_names.append(f"v{i}")

        # Get the iterator expression
        # If the iterator came from a call with multiple returns, just use the call
        iter_func = state.get_register(inst.a)
        iter_info = state.registers[inst.a]

        # Check if this is a call that returns multiple values (the iterator triple)
        # In that case, the call expression already represents the full iterator
        if iter_info.call_returns > 1 or (iter_info.value and '(' in str(iter_info.value)):
            # Just use the call expression directly
            header = f"{', '.join(var_names)} in {iter_func}"
        else:
            # Need all three parts (rare case)
            iter_state = state.get_register(inst.a + 1)
            iter_var = state.get_register(inst.a + 2)
            header = f"{', '.join(var_names)} in {iter_func}, {iter_state}, {iter_var}"

        if state.loop_ptr and state.loop_ptr.block:
            state.loop_ptr.block.code = header

    def _handle_setlist(self, state: DecompilerState, inst: Instruction) -> int:
        """R(A)[(C-1)*FPF+i] := R(A+i), 1 <= i <= B"""
        skip = 0
        c = inst.c

        if c == 0:
            next_inst = Instruction.decode(state.proto.code[state.pc + 1])
            c = next_inst.raw
            skip = 1

        start_index = (c - 1) * LFIELDS_PER_FLUSH + 1

        # Gather values
        values = []
        if inst.b == 0:
            for r in range(inst.a + 1, state.last_call + 1):
                values.append(state.get_register(r))
        else:
            for r in range(inst.a + 1, inst.a + inst.b + 1):
                values.append(state.get_register(r))

        # Add to table
        table = state.tables.get_table(inst.a)
        if table:
            table.add_array_items(values, start_index)

        return skip

    def _handle_close(self, state: DecompilerState, inst: Instruction) -> None:
        """close all variables >= R(A)"""
        pass

    def _handle_closure(self, state: DecompilerState, inst: Instruction) -> int:
        """R(A) := closure(KPROTO[Bx])"""
        child_proto = state.proto.p[inst.bx] if inst.bx < len(state.proto.p) else None

        if not child_proto:
            state.set_register(inst.a, f"function() --[[func {inst.bx}]] end")
            return 0

        # In Lua 5.1, upvalues are determined by the next N instructions after CLOSURE
        # MOVE: upvalue comes from local variable
        # GETUPVAL: upvalue comes from parent's upvalue
        num_upvalues = child_proto.nups
        skip_count = 0

        if num_upvalues > 0:
            # Extract upvalue names from following instructions
            upvalue_names = []
            for i in range(num_upvalues):
                upval_pc = state.pc + 1 + i
                if upval_pc < state.proto.sizecode:
                    upval_inst = Instruction.decode(state.proto.code[upval_pc])
                    skip_count += 1

                    if upval_inst.op == OpCode.MOVE:
                        # Upvalue from local variable
                        local_name = self._get_local_name_at_pc(state.proto, upval_inst.b, state.pc)
                        if local_name:
                            upvalue_names.append(local_name)
                        else:
                            reg_val = state.peek_register(upval_inst.b)
                            if reg_val and reg_val not in ("nil", "true", "false") and not reg_val.startswith("TEMP_"):
                                upvalue_names.append(reg_val)
                            else:
                                upvalue_names.append(f"upval_{i}")
                    elif upval_inst.op == OpCode.GETUPVAL:
                        # Upvalue from parent's upvalue
                        parent_upval_name = state.get_upvalue_name(upval_inst.b)
                        upvalue_names.append(parent_upval_name)
                    else:
                        upvalue_names.append(f"upval_{i}")
                else:
                    upvalue_names.append(f"upval_{i}")

            # Store upvalue names in child proto for decompilation
            child_proto.upvalues = upvalue_names

        if self.process_sub:
            child_num = f"{state.funcnumstr}_{inst.bx}"
            child_code = self.decompile(child_proto, child_num)
            state.set_register(inst.a, child_code.strip())
        else:
            state.set_register(inst.a, f"function() --[[func {inst.bx}]] end")

        return skip_count

    def _handle_vararg(self, state: DecompilerState, inst: Instruction) -> None:
        """R(A), R(A+1), ..., R(A+B-2) = vararg"""
        if inst.b == 0:
            state.set_register(inst.a, "...")
            state.mark_call_result(inst.a, 0)
        elif inst.b >= 2:
            state.set_register(inst.a, "...")

    # Helper methods

    def _should_emit_call_as_local(self, state: DecompilerState, reg: int) -> bool:
        """
        Check if a call result should be emitted as a local declaration.

        This matches C luadec behavior: when a call result is:
        1. Compared against nil (or in a condition)
        2. AND used again later in the code

        The call should be emitted as:
            local varname = call()
            if varname ~= nil then

        Rather than:
            if call() ~= nil then
        """
        proto = state.proto
        code = proto.code
        n = proto.sizecode

        # Look ahead to find uses of this register
        scan_pc = state.pc + 1
        max_scan = min(state.pc + 30, n)

        found_comparison = False
        found_later_use = False

        while scan_pc < max_scan:
            inst = Instruction.decode(code[scan_pc])

            # Check if this register is used in a comparison against nil
            if inst.op == OpCode.EQ:
                # EQ compares B with C
                if not is_k(inst.b) and inst.b == reg:
                    # Check if comparing with nil (K260 in test file)
                    if is_k(inst.c):
                        const = state.get_constant(index_k(inst.c))
                        if const is None:  # nil constant
                            found_comparison = True
                            scan_pc += 2  # Skip past EQ + JMP
                            continue

            # Check if this register is written to (invalidates it)
            if self._instruction_writes_to(inst, reg):
                # If we haven't found comparison yet, can't use this pattern
                if not found_comparison:
                    return False
                break

            # Check if this register is read (used)
            reads = self._instruction_reads_from(inst, reg)
            if reads > 0:
                if found_comparison:
                    # Found use after comparison - should emit as local
                    found_later_use = True
                    break

            scan_pc += 1

        return found_comparison and found_later_use

    def _generate_call_local_name(self, state: DecompilerState, func_expr: str, reg: int) -> str:
        """Generate a local variable name for a call result (C luadec style)."""
        # Use function number and register number like C luadec
        return f"l_{state.funcnumstr}_{reg}"

    def _register_used_multiple_times(self, state: DecompilerState, reg: int) -> bool:
        """Check if a register will be read multiple times before being overwritten."""
        proto = state.proto
        code = proto.code
        n = proto.sizecode
        pc = state.pc + 1
        use_count = 0

        while pc < n:
            inst = Instruction.decode(code[pc])

            # Check if instruction writes to this register
            if self._instruction_writes_to(inst, reg):
                break

            # Count reads from this register
            reads = self._instruction_reads_from(inst, reg)
            use_count += reads

            if use_count >= 2:
                return True

            pc += 1

        return False

    def _instruction_writes_to(self, inst: Instruction, reg: int) -> bool:
        """Check if instruction writes to a register."""
        # Most instructions write to A
        if inst.op in (OpCode.MOVE, OpCode.LOADK, OpCode.LOADBOOL, OpCode.LOADNIL,
                       OpCode.GETUPVAL, OpCode.GETGLOBAL, OpCode.GETTABLE,
                       OpCode.NEWTABLE, OpCode.SELF, OpCode.ADD, OpCode.SUB,
                       OpCode.MUL, OpCode.DIV, OpCode.MOD, OpCode.POW,
                       OpCode.UNM, OpCode.NOT, OpCode.LEN, OpCode.CONCAT,
                       OpCode.CLOSURE, OpCode.VARARG):
            if inst.a == reg:
                return True
            # LOADNIL writes to range A to B
            if inst.op == OpCode.LOADNIL and inst.a <= reg <= inst.b:
                return True
            # SELF writes to A and A+1
            if inst.op == OpCode.SELF and inst.a + 1 == reg:
                return True

        # CALL/TAILCALL can write to A
        if inst.op in (OpCode.CALL, OpCode.TAILCALL):
            if inst.a == reg:
                return True

        return False

    def _instruction_reads_from(self, inst: Instruction, reg: int) -> int:
        """Count how many times an instruction reads from a register."""
        count = 0

        # SELF reads from B
        if inst.op == OpCode.SELF:
            if inst.b == reg:
                count += 1

        # GETTABLE reads from B
        if inst.op == OpCode.GETTABLE:
            if inst.b == reg:
                count += 1
            if not is_k(inst.c) and inst.c == reg:
                count += 1

        # Binary ops read from B and C (if not constants)
        if inst.op in BINARY_OPERATORS:
            if not is_k(inst.b) and inst.b == reg:
                count += 1
            if not is_k(inst.c) and inst.c == reg:
                count += 1

        # Unary ops read from B
        if inst.op in UNARY_OPERATORS:
            if inst.b == reg:
                count += 1

        # MOVE reads from B
        if inst.op == OpCode.MOVE:
            if inst.b == reg:
                count += 1

        # SETTABLE reads from A, and B/C if not constants
        if inst.op == OpCode.SETTABLE:
            if inst.a == reg:
                count += 1
            if not is_k(inst.b) and inst.b == reg:
                count += 1
            if not is_k(inst.c) and inst.c == reg:
                count += 1

        # CALL reads function from A and args from A+1 onwards
        if inst.op in (OpCode.CALL, OpCode.TAILCALL):
            if inst.a == reg:
                count += 1
            if inst.b > 1:
                if inst.a + 1 <= reg < inst.a + inst.b:
                    count += 1
            elif inst.b == 0:
                if reg >= inst.a + 1:
                    count += 1

        # RETURN reads from A onwards
        if inst.op == OpCode.RETURN:
            if inst.b > 1:
                if inst.a <= reg < inst.a + inst.b - 1:
                    count += 1
            elif inst.b == 0:
                if reg >= inst.a:
                    count += 1

        # CONCAT reads from B to C
        if inst.op == OpCode.CONCAT:
            if inst.b <= reg <= inst.c:
                count += 1

        # TEST reads from A
        if inst.op == OpCode.TEST:
            if inst.a == reg:
                count += 1

        # TESTSET reads from B
        if inst.op == OpCode.TESTSET:
            if inst.b == reg:
                count += 1

        # SETGLOBAL and SETUPVAL read from A
        if inst.op in (OpCode.SETGLOBAL, OpCode.SETUPVAL):
            if inst.a == reg:
                count += 1

        return count

    def _generate_temp_name(self, func_expr: str, reg: int) -> str:
        """Generate a meaningful temp variable name based on context."""
        # Extract the function/method name for hints
        func_lower = func_expr.lower()

        # Map common patterns to variable names
        if ':prepare' in func_lower or '.prepare' in func_lower:
            return "stmt"
        elif ':open' in func_lower or '.open' in func_lower:
            if 'sqlite' in func_lower or 'db' in func_lower:
                return "db"
            return "handle"
        elif ':read' in func_lower or '.read' in func_lower:
            return "data"
        elif ':write' in func_lower or '.write' in func_lower:
            return "result"
        elif 'pairs' in func_lower:
            return "iter"
        elif 'ipairs' in func_lower:
            return "iter"
        elif ':query' in func_lower or '.query' in func_lower:
            return "result"
        elif ':execute' in func_lower or '.execute' in func_lower:
            return "result"
        elif ':nrows' in func_lower or '.nrows' in func_lower:
            return "rows"
        elif ':create' in func_lower or '.create' in func_lower:
            return "obj"
        elif ':new' in func_lower or '.new' in func_lower:
            return "obj"
        elif 'string.' in func_lower:
            return "str"
        elif 'table.' in func_lower:
            return "tbl"
        elif 'math.' in func_lower:
            return "val"
        elif 'io.' in func_lower:
            return "file"

        # Default: use a short prefix with register number
        return f"tmp{reg}"

    def _get_rk(self, state: DecompilerState, rk: int) -> str:
        """Get value from register or constant."""
        if is_k(rk):
            const = state.get_constant(index_k(rk))
            return format_constant(const)
        else:
            return state.get_register(rk)

    def _format_table_access(self, table: str, key: str) -> str:
        """Format table[key] access."""
        if key.startswith('"') or key.startswith("'"):
            inner = key[1:-1]
            if is_identifier(inner):
                return f"{table}.{inner}"
        return f"{table}[{key}]"

    def _format_method_access(self, table: str, key: str) -> str:
        """Format table:method access."""
        if key.startswith('"') or key.startswith("'"):
            inner = key[1:-1]
            if is_identifier(inner):
                return f"{table}:{inner}"
        return f"{table}[{key}]"

    def _build_condition(self, state: DecompilerState, else_dest: int) -> Optional[str]:
        """Build a condition string from pending boolean operations."""
        if not state.bools:
            return None

        # Simple case: single condition
        if len(state.bools) == 1:
            bop = state.bools[0]
            # No inversion needed - bytecode condition is already for the then block
            return self._format_boolop(bop, invert=False)

        # Complex case: multiple conditions with and/or
        # then_addr is where execution goes if condition is true (right after JMP)
        then_addr = state.pc + 2
        return make_boolean_string(state.bools, then_addr, else_dest)

    def _format_boolop(self, bop: BoolOp, invert: bool = False) -> str:
        """
        Format a single boolean operation.

        Args:
            bop: The boolean operation
            invert: If True, invert the condition for if statement display
        """
        # Determine effective negation
        effective_neg = bop.neg
        if invert:
            effective_neg = not effective_neg

        if bop.op in (OpCode.TEST, OpCode.TESTSET):
            if effective_neg:
                return f"not {bop.op1}"
            return bop.op1
        elif bop.op in COMPARISON_OPERATORS:
            op_str = INVERTED_COMPARISON_OPERATORS[bop.op] if effective_neg else COMPARISON_OPERATORS[bop.op]
            return f"{bop.op1} {op_str} {bop.op2}"
        return bop.op1

    def _create_if_statement(self, state: DecompilerState, condition: str, else_dest: int) -> None:
        """Create an if statement with the given condition."""
        if_stmt = AstStatement.make_if(condition)

        # Calculate then and else end positions
        then_end = else_dest
        else_end = else_dest  # Will be updated if there's an else branch

        state.enter_block(if_stmt)
        state.curr_stmt = if_stmt.then_stmt
        state.if_stack.append((then_end, else_end, if_stmt))

    def _create_if_statement_from_block(self, state: DecompilerState, condition: str, block: IfBlock) -> None:
        """Create an if statement using pre-analyzed block info."""
        if_stmt = AstStatement.make_if(condition)

        # Use the analyzed block boundaries
        then_end = block.then_end
        else_end = block.else_end if block.else_start >= 0 else block.then_end

        state.enter_block(if_stmt)
        state.curr_stmt = if_stmt.then_stmt
        state.if_stack.append((then_end, else_end, if_stmt))

    def _generate_output(self, state: DecompilerState) -> str:
        """Generate final Lua source from AST."""
        if state.func_block:
            return state.func_block.to_lua(0, self.debug)
        return ""


def decompile(proto: Proto, funcnumstr: str = "0",
              process_sub: bool = True, debug: bool = False) -> str:
    """
    Decompile a Proto to Lua source code.

    Args:
        proto: Function prototype to decompile
        funcnumstr: Function number string for nested functions
        process_sub: Whether to decompile nested functions
        debug: Enable debug output

    Returns:
        Decompiled Lua source code
    """
    dec = Decompiler(debug=debug)
    dec.process_sub = process_sub
    return dec.decompile(proto, funcnumstr)
