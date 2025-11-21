import struct
import argparse
import sys
import io
import subprocess

import logging

logger = logging.getLogger(__package__)


def lua_decompile(filepath) -> bytes:
    result = subprocess.run(["./luadec", filepath], capture_output=True)

    if result.returncode == 0:
        return result.stdout
    else:
        logger.error("Decompilation failed with error code:", result.returncode)
        logger.error("Error message:", result.stderr)
        return None
    

def lua_disassemble(filepath) -> bytes:
    result = subprocess.run(["./luadec", "-dis", filepath], capture_output=True)

    if result.returncode == 0:
        return result.stdout
    else:
        logger.error("Disassembly failed with error code:", result.returncode)
        logger.error("Error message:", result.stderr)
        return None


# copy of https://raw.githubusercontent.com/commial/experiments/refs/heads/master/windows-defender/lua/parse.py

def fixup_lua_data(data: bytes) -> tuple[bytes | None, str | None]:
    """Fix up Lua data and return (fixed_data, error_message).
    Returns (bytes, None) on success, (None, error_str) on failure.
    """
    #fdesc = open(options.target, "rb")
    fdesc = io.BytesIO(data)

    # Header + some info hardcoded (int size, endianess, etc.)
    # MpEngine actually checks that these values are always the same
    header = fdesc.read(12)
    if header != b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01':
        return None, f"Invalid Lua header: {header.hex()}"
    #assert header == b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01'

    func = LuaFunc(fdesc)
    success, error = func.init()
    if not success:
        return None, error if error else "Failed to initialize Lua function"
    
    export = None
    try:
        export = func.export(root=True)
    except Exception as e:
        return None, f"Exception when converting lua: {e}"
    
    return export, None


class LuaConst(object):
    "Stand for Lua constants"
    def __init__(self, value):
        self.value = value

    def __repr__(self):
        return "<%s %s>" % (self.__class__, self.value)

class LuaConstNil(LuaConst):
    pass

class LuaConstByte(LuaConst):
    pass

class LuaConstNumber(LuaConst):
    pass

class LuaConstString(LuaConst):
    pass


class LuaFunc(object):
    "Converter"

    def read_byte(self):
        return struct.unpack("B", self.stream.read(1))[0]

    def read_int(self):
        return struct.unpack("<I", self.stream.read(4))[0]
    
    def __init__(self, stream):
        """
        @stream: I/O like object
        """
        self.stream = stream

    def init(self):
        """Initialize Lua function. Returns (success, error_message)."""
        src_name = self.stream.read(4)
        if src_name != b"\x00" * 4:
            return False, "Invalid Lua source name"
        #assert src_name == b"\x00" * 4
        line_def = self.stream.read(4)
        if line_def != b"\x00" * 4:
            return False, "Invalid Lua line definition"
        #assert line_def == b"\x00" * 4
        lastline_def = self.stream.read(4)
        if lastline_def != b"\x00" * 4:
            return False, "Invalid Lua last line definition"
        #assert lastline_def == b"\x00" * 4

        self.nb_upvalues = self.read_byte()
        self.nb_params = self.read_byte()
        self.is_vararg = self.read_byte()
        self.max_stacksize = self.read_byte()

        self.nb_instr = self.read_int()

        self.instrs = self.stream.read(4 * self.nb_instr)

        self.nb_const = self.read_int()

        self.consts = []
        i = 0
        for i in range(self.nb_const):
            cst_type = self.read_byte()
            if cst_type == 4:
                # String
                length = self.read_int()
                self.consts.append(LuaConstString(self.stream.read(length)))
            elif cst_type == 3:
                # Int
                self.consts.append(LuaConstNumber(struct.unpack("<q", self.stream.read(8))[0]))
            elif cst_type == 1:
                # Byte
                self.consts.append(LuaConstByte(self.read_byte()))
            elif cst_type == 0:
                # NIL
                self.consts.append(LuaConstNil(0))
            else:
                raise RuntimeError("Unimplemented")

        nb_func = self.read_int()

        self.funcs = []
        for i in range(nb_func):
            f = LuaFunc(self.stream)
            success, error = f.init()
            if not success:
                return False, error if error else f"Failed to init nested function {i}"
            self.funcs.append(f)

        src_line_positions = self.read_int()
        if src_line_positions != 0:
            return False, "Invalid Lua source line positions"
        #assert src_line_positions == 0
        nb_locals = self.read_int()
        if nb_locals != 0:
            return False, "Invalid Lua locals"
        #assert nb_locals == 0
        nb_upvalues = self.read_int()
        if nb_upvalues != 0:
            return False, "Invalid Lua upvalues"
        #assert nb_upvalues == 0

        return True, None

    def export(self, root=False):
        """
        Returns the bytes of the newly created Lua precompiled script
        If @root is set, prepend a Lua header
        """
        out = []
        if root:
            out.append(b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x00')
        out.append(b"\x00" * 0x10)
        out.append(struct.pack("BBBB", self.nb_upvalues, self.nb_params, self.is_vararg, self.max_stacksize))
        out.append(struct.pack("<I", self.nb_instr))
        out.append(self.instrs)
        out.append(struct.pack("<I", self.nb_const))
        for cst in self.consts:
            if isinstance(cst, LuaConstNil):
                out.append(struct.pack("B", 0))
            elif isinstance(cst, LuaConstByte):
                out.append(struct.pack("BB", 1, cst.value))
            elif isinstance(cst, LuaConstNumber):
                out.append(struct.pack("<B", 3))
                
                # HACK-ISH
                # Convert int to double for decompiler
                out.append(struct.pack("<d", cst.value))
            else:
                assert isinstance(cst, LuaConstString)
                out.append(struct.pack("<BQ", 4, len(cst.value)))
                out.append(cst.value)

        out.append(struct.pack("<I", len(self.funcs)))
        for func in self.funcs:
            out.append(func.export(root=False))
        
        # No debug info
        out.append(struct.pack("<III", 0, 0, 0))

        return b"".join(out)


def main():
    parser = argparse.ArgumentParser(description="Lua precompiled script fixer")
    parser.add_argument("target", type=str, help="Target Lua precompiled script file")
    args = parser.parse_args()

    print(f"Fixing up Lua precompiled script: {args.target}")
    with open(args.target, "rb") as fdesc:
        data = fdesc.read()

    fixed_data, error = fixup_lua_data(data)
    if fixed_data is None:
        print(f"Error: {error}")
        sys.exit(1)

    print(f"Resulting fixed Lua precompiled script: {args.target}.fixed")
    with open(args.target + ".fixed", "wb") as fdesc:
        fdesc.write(fixed_data)


if __name__ == "__main__":
    main()