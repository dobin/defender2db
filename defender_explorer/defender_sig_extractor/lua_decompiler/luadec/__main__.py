#!/usr/bin/env python3
"""
LuaDec Python - Lua 5.1 Decompiler

Command-line interface for decompiling Lua 5.1 bytecode.

Usage:
    python -m luadec_py [options] <input.luac>

Examples:
    python -m luadec_py test.luac              # Decompile
    python -m luadec_py -dis test.luac         # Disassemble only
    python -m luadec_py -pn test.luac          # Print function numbers
    python -m luadec_py -f 0_1 test.luac       # Decompile specific function
"""

import argparse
import sys
from typing import Optional

from .bytecode.loader import load_chunk, LoaderError
from .bytecode.proto import Proto
from .decompiler.engine import decompile, Decompiler
from .disassembler import disassemble, print_function_tree


def find_sub_function(proto: Proto, funcnumstr: str) -> tuple:
    """
    Find a sub-function by its number string.

    Args:
        proto: Root prototype
        funcnumstr: Function number string (e.g., "0_1_2")

    Returns:
        (found_proto, real_funcnumstr) or (None, None) if not found
    """
    if not funcnumstr or funcnumstr == "0":
        return proto, "0"

    parts = funcnumstr.split("_")
    current = proto
    path = []

    for part in parts:
        if part == "0" and not path:
            path.append("0")
            continue

        try:
            idx = int(part)
        except ValueError:
            return None, None

        if idx < 0 or idx >= len(current.p):
            return None, None

        current = current.p[idx]
        path.append(str(idx))

    return current, "_".join(path) if path else "0"


def main(args: Optional[list] = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="luadec_py",
        description="LuaDec Python - Lua 5.1 Decompiler",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  luadec_py test.luac              Decompile bytecode file
  luadec_py -dis test.luac         Disassemble only
  luadec_py -pn test.luac          Print function numbers
  luadec_py -f 0_1 test.luac       Decompile function 0_1
  luadec_py -ns test.luac          Don't process sub-functions
"""
    )

    parser.add_argument(
        "input",
        nargs="?",
        help="Input .luac bytecode file (or stdin if not specified)"
    )

    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output file (default: stdout)"
    )

    parser.add_argument(
        "-dis", "--disassemble",
        action="store_true",
        help="Disassemble only (no decompilation)"
    )

    parser.add_argument(
        "-pn", "--print-numbers",
        action="store_true",
        help="Print function numbers and exit"
    )

    parser.add_argument(
        "-f", "--function",
        metavar="NUM",
        help="Decompile specific function (e.g., 0_1)"
    )

    parser.add_argument(
        "-ns", "--no-sub",
        action="store_true",
        help="Do not process sub-functions"
    )

    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable debug output"
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version="%(prog)s 1.0.0 (Python port of luadec)"
    )

    parsed = parser.parse_args(args)

    # Load bytecode
    try:
        if parsed.input:
            proto = load_chunk(parsed.input, parsed.input)
        else:
            # Read from stdin
            data = sys.stdin.buffer.read()
            proto = load_chunk(data, "stdin")
    except LoaderError as e:
        print(f"Error loading bytecode: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(f"Error: File not found: {parsed.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Handle function selection
    target_proto = proto
    funcnumstr = "0"
    if parsed.function:
        target_proto, funcnumstr = find_sub_function(proto, parsed.function)
        if target_proto is None:
            print(f"Error: No such sub function: {parsed.function}", file=sys.stderr)
            print("Use -pn option to see available function numbers.", file=sys.stderr)
            return 1

    # Execute requested operation
    try:
        if parsed.print_numbers:
            result = print_function_tree(proto)
        elif parsed.disassemble:
            result = disassemble(
                target_proto,
                name=funcnumstr,
                process_sub=not parsed.no_sub
            )
        else:
            result = decompile(
                target_proto,
                funcnumstr=funcnumstr,
                process_sub=not parsed.no_sub,
                debug=parsed.debug
            )
    except Exception as e:
        if parsed.debug:
            import traceback
            traceback.print_exc()
        print(f"Error during processing: {e}", file=sys.stderr)
        return 1

    # Output result
    if parsed.output:
        try:
            with open(parsed.output, 'w') as f:
                f.write(result)
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            return 1
    else:
        print(result, end='')

    return 0


if __name__ == "__main__":
    sys.exit(main())
