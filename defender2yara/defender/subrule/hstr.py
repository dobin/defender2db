import struct
# from defender2yara.utils import hexdump


class HStrSubRule:
    def to_details(self) -> dict:
        from defender2yara.defender.signature.sigtree import decode_tree_pattern

        rule_bytes = getattr(self, "rule_bytes", b"")
        return {
            "rule_weight": self.rule_weight,
            "rule_size": getattr(self, "rule_size", 0),
            "rule_bytes_hex": rule_bytes.hex(),
            "text": decode_tree_pattern(rule_bytes),
        }

    def __init__(self,data:bytes,ptr:int) -> None:
        if len(data[ptr:]) < 3:
            self.rule_weight = 0
            return

        self.rule_weight = struct.unpack('<h',data[ptr+0:ptr+2])[0] # rule weight contains negative numbers

        if self.rule_weight == 0:
            return
        self.rule_size = data[ptr+2]
        self.rule_bytes = data[ptr+3:ptr+3+self.rule_size]

        # Convert rule_bytes to YARA strings.
        # self.yara_str, self.yara_str_type, self.yara_str_inaccurate = rule_bytes_to_yara_string(self.rule_bytes)


class HStrExtSubRule:
    """One weighted ``*HSTR_EXT`` sub-rule.

    On-disk layout (confirmed by ``FUN_180182d14`` in mpengine)::

        i16  weight
        u8   size
        u8   flags       bit 0 case-sensitive, bit 1 wildcard pattern,
                         bit 7 extended header
        u8   extra       only when flags & 0x80
        u8   bytes[size]

    The engine parses the flags as follows (``FUN_180183298``):

    * ``flags & 0x01``: keep the pattern case-sensitive.  When clear the
      engine lower-cases every byte (wildcard-aware when ``0x02`` is set).
    * ``flags & 0x02``: the pattern contains ``0x90``/HSTR wildcard opcodes.
      Such patterns must end with ``90 00``; the engine validates every
      opcode against its 50-entry table at ``0x180c94d50``.
    * ``flags & 0x80``: an ``extra`` byte precedes the pattern.  Bit 0 of
      ``extra`` makes the engine register a second, terminator-less variant of
      the pattern (stored with internal flag ``0x400``).  Only ``extra == 1``
      is observed in the shipped database.
    """

    def to_details(self, include_text: bool = True) -> dict:
        rule_bytes = getattr(self, "rule_bytes", b"")
        details = {
            "rule_weight": self.rule_weight,
            "rule_size": getattr(self, "rule_size", 0),
            "unknown_u8_1": getattr(self, "unknown_u8_1", None),
            "flags": getattr(self, "flags", getattr(self, "unknown_u8_1", None)),
            "case_sensitive": getattr(self, "case_sensitive", False),
            "wildcard": getattr(self, "wildcard", False),
            "extended": getattr(self, "extended", False),
            "extra": getattr(self, "extra", None),
            "variant": getattr(self, "variant", False),
            "rule_bytes_hex": rule_bytes.hex(),
        }
        if include_text:
            text, encoding = self.decoded
            details["text"] = text
            details["encoding"] = encoding
        return details

    @property
    def entry_size(self) -> int:
        """Total number of bytes this sub-rule occupies."""
        return 4 + getattr(self, "rule_size", 0) + (1 if getattr(self, "extended", False) else 0)

    @property
    def decoded(self):
        if getattr(self, "_decoded", None) is None:
            from defender2yara.defender.signature.hstr import decode_hstr_pattern

            self._decoded = decode_hstr_pattern(self.rule_bytes)
        return self._decoded

    @property
    def pattern_text(self) -> str:
        return self.decoded[0]

    @property
    def encoding(self) -> str:
        return self.decoded[1]

    def __init__(self,data:bytes,ptr:int) -> None:
        self.rule_weight = 0
        self.rule_size = 0
        self.rule_bytes = b""
        self.unknown_u8_1 = 0
        self.flags = 0
        self.extended = False
        self.extra = None
        self.case_sensitive = False
        self.wildcard = False
        self.variant = False

        if len(data[ptr:]) < 4:
            self.rule_weight = 0
            return

        self.rule_weight = struct.unpack('<h',data[ptr+0:ptr+2])[0] # rule weight contains negative numbers

        if self.rule_weight == 0:
            return

        self.rule_size = data[ptr+2]
        self.flags = data[ptr+3]
        self.unknown_u8_1 = self.flags

        body_pos = ptr + 4
        if self.flags & 0x80:
            self.extended = True
            if body_pos < len(data):
                self.extra = data[body_pos]
                body_pos += 1
            self.variant = bool((self.extra or 0) & 0x01)

        self.case_sensitive = bool(self.flags & 0x01)
        self.wildcard = bool(self.flags & 0x02)

        self.rule_bytes = data[body_pos:body_pos+self.rule_size]

        # Convert rule_bytes to YARA strings.
        # self.yara_str, self.yara_str_type, self.yara_str_inaccurate = rule_bytes_to_yara_string(self.rule_bytes)
