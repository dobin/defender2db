"""Adapter for Defender Explorer's pure-Python Lua implementation.

Load only its Lua package: importing defender_sig_extractor itself also imports
unrelated downloaders and analysis services. No native executable is invoked.
"""

from functools import lru_cache
import importlib.util
from pathlib import Path
import sys


@lru_cache(maxsize=1)
def load_lua_backend():
    # Both source checkouts and wheels place these packages under the same root.
    root = Path(__file__).resolve().parents[2] / "defender_explorer" / "defender_sig_extractor"
    package = root / "lua_decompiler"
    if not (package / "__init__.py").is_file():
        raise RuntimeError(
            "The bundled Python Lua backend is missing from "
            f"{package}. Restore defender_explorer/defender_sig_extractor "
            "or reinstall defender2db."
        )

    name = "_defender2db_explorer_lua"
    spec = importlib.util.spec_from_file_location(
        name, package / "__init__.py", submodule_search_locations=[str(package)]
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Python Lua backend from {package}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        for key in list(sys.modules):
            if key == name or key.startswith(name + "."):
                del sys.modules[key]
        raise
    return module


def decompile_data(data: bytes, *, disassemble: bool = False) -> bytes:
    """Accept original MpLua or standard Lua 5.1, preserving integer constants."""
    backend = load_lua_backend()
    if data[:12] == b'\x1bLuaQ\x00\x01\x04\x08\x04\x08\x01':
        # Explorer's converter writes int64 constants as doubles. Build its
        # Python Proto model directly instead, retaining exact integer values.
        from io import BytesIO
        from .luaparse import LuaFunc, LuaConstNil, LuaConstByte, LuaConstString

        stream = BytesIO(data[12:])
        function = LuaFunc(stream)
        success, error = function.init()
        if not success:
            raise ValueError(error)

        def to_proto(function):
            proto = backend.luadec.bytecode.proto.Proto()
            proto.source = "MpLua"
            proto.nups = function.nb_upvalues
            proto.numparams = function.nb_params
            proto.is_vararg = function.is_vararg
            proto.maxstacksize = function.max_stacksize
            import struct
            proto.code = list(struct.unpack(f"<{function.nb_instr}I", function.instrs))
            proto.k = []
            for constant in function.consts:
                if isinstance(constant, LuaConstNil):
                    value = None
                elif isinstance(constant, LuaConstByte):
                    value = bool(constant.value)
                elif isinstance(constant, LuaConstString):
                    value = constant.value.removesuffix(b'\0').decode('latin-1')
                else:
                    value = constant.value
                proto.k.append(value)
            proto.p = [to_proto(child) for child in function.funcs]
            return proto

        proto = to_proto(function)
        source = backend.luadec.disassemble(proto) if disassemble else backend.luadec.decompile(proto)
        return source.encode("utf-8")
    if disassemble:
        source = backend.luadec.disassemble(backend.load_chunk_auto(data))
    else:
        source = backend.decompile_bytecode(data)
    return source.encode("utf-8")