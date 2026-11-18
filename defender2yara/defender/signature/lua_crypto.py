"""Instruction-word cipher used by *headerless* MpLua chunks.

The 154 headerless ``SIGNATURE_TYPE_LUASTANDALONE`` records in the shipped
database store their Lua 5.1 ``code`` arrays with a byte-wise chained
substitution instead of plain instruction words.  The 256-byte table is the
engine's table at ``0x180dc18a0`` (``mpengine.dll`` 1.1.26100.4), the same one
that ``Ob*``-attribute obfuscation uses (``FUN_1805afc44``).

Every 32-bit little-endian word is transformed independently; the feedback for
byte ``i`` is the *ciphertext* byte ``i-1`` and the chain restarts at zero for
each word::

    p0 = TABLE[c0]
    p1 = TABLE[c1] ^ c0
    p2 = TABLE[c2] ^ c1
    p3 = TABLE[c3] ^ c2

``TABLE`` is a permutation of 0..255 but not an involution, so encoding uses
its inverse permutation.  Only the ``code`` arrays are encoded: constants,
nested prototypes, debug sections and the wrapper stay plain.

The constants below were recovered from cross-version plaintext pairs and
validated against all 32,042 instructions of the shipped headerless records
(0 invalid opcodes after decoding, 144/154 scripts decompile cleanly).  See
``cache/luastandalone_headerless_reversing.md`` for the full analysis.
"""

#: Substitution table from ``mpengine.dll`` ``0x180dc18a0``.
INSTRUCTION_TABLE = bytes.fromhex(
    "00baa3c0464384eda8973f7217adef54ddf9216442f18c49687677fc11b274d3"
    "dc040996d40df619fb357e9fd1e19dccdb63f53094407cf35dc7aae4e614676e"
    "d837a2b056a651dfb98539159e8d3e22cefe7a0ac17d9c93b313082a0c3d0682"
    "609bbd05c4241e50e5014f1cf48a982ccd3c5e6d328f2b472f1da5bb25b8d7b1"
    "659158c9be92e88b3355128eeaabf8261f711b52cbe2e786ae6231fdaf02d20e"
    "b7e3834816cfd579030fdab56f4d7bde079ad9a0c827a1d0c310bff76118eb38"
    "28a95f66c50b95535b4bf07f81f26ad678731aac89a4fa4436b475c223bc59e9"
    "29ca5a416b34704ceeb66c873a5780a799ec69ffe0c64a3b4e205c2d45882e90"
)


def _invert(table: bytes) -> bytes:
    inverse = bytearray(256)
    for index, value in enumerate(table):
        inverse[value] = index
    return bytes(inverse)


INVERSE_INSTRUCTION_TABLE = _invert(INSTRUCTION_TABLE)


def decode_word(word: int) -> int:
    """Decode one stored 32-bit word to a Lua 5.1 instruction word."""
    b0 = word & 0xFF
    b1 = (word >> 8) & 0xFF
    b2 = (word >> 16) & 0xFF
    b3 = (word >> 24) & 0xFF
    p0 = INSTRUCTION_TABLE[b0]
    p1 = INSTRUCTION_TABLE[b1] ^ b0
    p2 = INSTRUCTION_TABLE[b2] ^ b1
    p3 = INSTRUCTION_TABLE[b3] ^ b2
    return p0 | p1 << 8 | p2 << 16 | p3 << 24


def encode_word(word: int) -> int:
    """Encode one Lua 5.1 instruction word into its stored form."""
    p0 = word & 0xFF
    p1 = (word >> 8) & 0xFF
    p2 = (word >> 16) & 0xFF
    p3 = (word >> 24) & 0xFF
    c0 = INVERSE_INSTRUCTION_TABLE[p0]
    c1 = INVERSE_INSTRUCTION_TABLE[p1 ^ c0]
    c2 = INVERSE_INSTRUCTION_TABLE[p2 ^ c1]
    c3 = INVERSE_INSTRUCTION_TABLE[p3 ^ c2]
    return c0 | c1 << 8 | c2 << 16 | c3 << 24
