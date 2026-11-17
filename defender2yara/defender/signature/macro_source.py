"""SIGNATURE_TYPE_MACRO_SOURCE (0x43) — macro/VBA source routine signature.

The ``macro`` module (``FUN_180a50370``) registers this type with
``FUN_1801d35d0``.  A record describes an **ordered sequence of normalised
macro-source routines** plus the kind of macro stream it applies to.

Layout::

    u8   name_length       0..0x3f (0 = no inline name)
    u8   name[name_length]
    u32  header            bits 0..5 = routine count, bits 6+ = source kind
    u32  hash_low[count]
    u32  hash_high[count]  optional; absent means every high dword is 0

Each ``(hash_low[i], hash_high[i])`` pair is one 64-bit routine key.  The
``hash_high`` array is stored after the whole ``hash_low`` array (not
interleaved).  Word 6 / Excel 5 records usually omit it; VBA and Excel-formula
records normally include it.

The source kind is not a bitmask in this format: the loader compares it for
equality against the stream that produced the keys (``FUN_18024dc90``):

| header >> 6 | engine stream | meaning |
|------------:|---------------|---------|
| 0 | kinds 0/1 (`+0x5040`, `+0x6048`) | Word 6 / Excel 5 macro source |
| 2 | kind 2 (`+0x8048`) | Excel formula stream |
| 4 | kind 3 (`+0xa048`, `+0xb050`) | VBA source + VBA p-code |
| 8 | kind 4 (`+0x2da70`) | Excel formula routines (`xfcrcs`) |

At scan time ``FUN_1802f81bc`` receives the runtime list of 8-byte routine keys
and looks each one up in a global map; a matching entry points at the records
that need it.  ``FUN_18024dc90`` then walks the record's key vector in order and
requires every key to occur (in sequence) in the stream.  This is why the type
is a structural malware signature but not a byte pattern: the actual matched
text has already been reduced to routine hashes.
"""

import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


MACRO_SOURCE_SIG = "SIGNATURE_TYPE_MACRO_SOURCE"

# Source kinds are compared for equality, not OR-ed (FUN_18024dc90).  Values
# come from the diagnostics in FUN_1802f7e98 ("MpWord6Routines",
# "MpExcelFormulaRoutines", "MpVBASourceRoutines", "MpVBAPCodeRoutines", ...
# and the "xfcrcs" dump used for the Excel-formula routine stream).
MACRO_SOURCE_KINDS = {
    0x0: "word6_excel5_macro_source",
    0x2: "excel_formula",
    0x4: "vba_source",
    0x8: "excel_formula_routines",
}

MAX_ROUTINES = 0x3F


class MacroSourceSig(BaseSig):
    """A macro-source routine sequence signature."""

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0x43]

        if not self.sig_data:
            raise ValueError("Empty MACRO_SOURCE payload")
        name_length = self.sig_data[0]
        if name_length > 0x3F:
            raise ValueError(f"Invalid MACRO_SOURCE name length {name_length}")
        offset = 1 + name_length
        if len(self.sig_data) < offset + 4:
            raise ValueError(
                f"Truncated {self.sig_type} header: {len(self.sig_data)} bytes"
            )

        self.name_raw = bytes(self.sig_data[1:offset])
        self.name = self.name_raw.decode("utf-8", "replace")
        self.name_length = name_length

        self.header = struct.unpack_from("<I", self.sig_data, offset)[0]
        offset += 4
        self.routine_count = self.header & MAX_ROUTINES
        self.source_kind = self.header >> 6
        self.source_kind_label = MACRO_SOURCE_KINDS.get(
            self.source_kind, f"unknown_0x{self.source_kind:x}"
        )

        low_end = offset + 4 * self.routine_count
        if low_end > len(self.sig_data):
            raise ValueError(
                f"Truncated {self.sig_type} routine table: "
                f"{len(self.sig_data)} bytes for {self.routine_count} routines"
            )
        self.hash_low = list(struct.unpack_from(
            f"<{self.routine_count}I", self.sig_data, offset
        ))
        self.has_second_hash_array = len(self.sig_data) == low_end + 4 * self.routine_count
        if self.has_second_hash_array:
            self.hash_high = list(struct.unpack_from(
                f"<{self.routine_count}I", self.sig_data, low_end
            ))
        else:
            self.hash_high = [0] * self.routine_count

        self.routine_keys = [
            (high << 32) | low for low, high in zip(self.hash_low, self.hash_high)
        ]
        self.routine_keys_hex = [f"{key:016x}" for key in self.routine_keys]
        self.expected_size = low_end + (4 * self.routine_count
                                        if self.has_second_hash_array else 0)

        self.decode_warnings = []
        if self.routine_count == 0:
            self.decode_warnings.append("MACRO_SOURCE record has no routine keys")
        if self.expected_size != len(self.sig_data):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(self.sig_data) - self.expected_size} bytes"
            )

    def to_details(self) -> dict:
        return {
            "record_name": self.name,
            "has_name": self.name_length > 0,
            "source_kind": self.source_kind,
            "source_kind_label": self.source_kind_label,
            "routine_count": self.routine_count,
            "routine_keys": list(self.routine_keys_hex),
            "has_second_hash_array": self.has_second_hash_array,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = (
            f"MACRO_SOURCE {self.source_kind_label} "
            f"routines={self.routine_count} keys={','.join(self.routine_keys_hex)}"
        )
        if self.name_length:
            text += f" name={self.name!r}"
        return text
