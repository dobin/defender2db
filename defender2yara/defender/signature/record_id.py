"""Engine record ids shared by the STATIC builder and reference records.

mpengine identifies a record by ``crc32(payload) | type << 32 | size << 40``
(``FUN_180b5589c`` / ``FUN_180b558fc``).  The same packing is used for NID/NID64
ids and for STATIC record ids, so a NID64 key that has this layout can be
resolved back to the record it points at.
"""

import zlib

RECORD_ID_SIG_TYPE_SHIFT = 32
RECORD_ID_SIZE_SHIFT = 40


def defender_crc32(data: bytes) -> int:
    """CRC-32 as used by mpengine: reflected, init 0xffffffff, no final xor."""
    return zlib.crc32(data) & 0xFFFFFFFF ^ 0xFFFFFFFF


def packed_record_id(payload: bytes, sig_type_id: int) -> int:
    """Return the engine record id for ``payload`` of type ``sig_type_id``."""
    return (
        defender_crc32(payload)
        | sig_type_id << RECORD_ID_SIG_TYPE_SHIFT
        | len(payload) << RECORD_ID_SIZE_SHIFT
    )
