import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


LUA_HEADER = b'\x1bLuaQ'
# A second, headerless Lua variant used by a small number of shared
# infrastructure records.  Its body starts with this marker followed by a
# normal MpLua function prototype (12 zero debug bytes and then the function
# header).  The instruction set of that variant is not Lua 5.1, so the body is
# retained as raw data but cannot be decompiled.
HEADERLESS_LUA_MARKER = b'\x01' + b'\x00' * 11


def _printable_strings(data: bytes) -> tuple[list[str], bytes]:
    """Split a leading run of printable NUL-terminated strings from *data*."""
    strings = []
    pos = 0
    while pos < len(data):
        end = data.find(b'\0', pos)
        if end < 0:
            break
        item = data[pos:end]
        if not item or not all(32 <= byte < 127 for byte in item):
            break
        strings.append(item.decode('utf-8', 'replace'))
        pos = end + 1
    return strings, data[pos:]


class LuaSig(BaseSig):
    """SIGNATURE_TYPE_LUASTANDALONE (0xBD) — a standalone script body.

    Layout::

        u8   name_length         length of the script name including its NUL
        u8   script_type         engine script kind/flags
        u16  attributes_length
        u32  body_length
        u8   name[name_length]
        u8   attributes[attributes_length]
        u8   body[body_length]

    The body normally starts with the MpLua header (``\\x1bLuaQ``).  A few
    infrastructure records use a headerless variant whose instruction set is
    not supported by the bundled decompiler; they are kept as raw data and
    reported as partially decoded.  Attributes are a NUL-separated key/value
    list (for example ``Includes\\0BMLuaLib\\0``), optionally followed by
    binary attribute data for ``ObMpAttributes`` records.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0xBD]

        if len(self.sig_data) < 8:
            raise ValueError(
                f"Truncated {self.sig_type} header: {len(self.sig_data)} bytes"
            )

        self.name_length = self.sig_data[0]
        self.script_type = self.sig_data[1]
        self.attributes_length = struct.unpack_from("<H", self.sig_data, 2)[0]
        self.body_length = struct.unpack_from("<I", self.sig_data, 4)[0]

        expected_size = 8 + self.name_length + self.attributes_length + self.body_length
        if expected_size != len(self.sig_data):
            raise ValueError(
                f"Invalid {self.sig_type} lengths: expected {expected_size} bytes, "
                f"got {len(self.sig_data)}"
            )

        body_offset = 8 + self.name_length + self.attributes_length
        self.name_raw = self.sig_data[8:8 + self.name_length]
        self.name = self.name_raw.rstrip(b'\0').decode('utf-8', 'replace')
        self.attributes_raw = self.sig_data[
            8 + self.name_length:8 + self.name_length + self.attributes_length
        ]
        self.body = self.sig_data[body_offset:body_offset + self.body_length]

        if self.body.startswith(LUA_HEADER):
            self.body_format = "lua"
        elif self.body.startswith(HEADERLESS_LUA_MARKER):
            self.body_format = "mplua_headerless"
        else:
            self.body_format = "unknown"
        self.lua_bytecode = self.body if self.body_format == "lua" else None

        self.attribute_strings, self.attribute_data = _printable_strings(
            self.attributes_raw
        )

        self.decode_warnings = []
        if self.body_format == "mplua_headerless":
            self.decode_warnings.append(
                "Headerless MpLua body uses an unsupported instruction set"
            )
        elif self.body_format == "unknown":
            self.decode_warnings.append("Unrecognized Lua script body")

    def to_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "script_type": self.script_type,
            "attributes": list(self.attribute_strings),
            "attribute_data_hex": (
                self.attribute_data.hex() if self.attribute_data else None
            ),
            "body_size": self.body_length,
            "body_format": self.body_format,
            "has_lua_bytecode": self.lua_bytecode is not None,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = f"LUA {self.name or '(unnamed)'} type={self.script_type} body={self.body_format}"
        if self.attribute_strings:
            text += f" attributes={'/'.join(self.attribute_strings)}"
        text += f" size={self.body_length}"
        return text
