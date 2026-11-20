"""Hosts-file entry conditions: ``SIGNATURE_TYPE_HOSTSENTRY`` (``0x64``).

A ``HOSTSENTRY`` record is one line of a Windows ``hosts`` file: a mapped
address followed by the host name.  The engine evaluates it against the parsed
``hosts`` file (the ``VFS:hosts`` scan), which is how the
``SettingsModifier:Win32/HostsFileHijack`` family detects entries such as
``NULL microsoft.com`` or ``127.0.0.1 update.microsoft.com``.

On-disk payload (x64 build 1.1.26100.4, parser ``FUN_180474f90``)::

    u8   address_length       includes the trailing NUL, must be > 1
    u8   address[address_length]
    u8   host_length          includes the trailing NUL, must be > 1
    u8   host[host_length]

Both strings are NUL-terminated and the NUL is counted in the length.  The
parser requires the exact payload length and a final NUL in both fields.  The
record id is ``crc32(payload) | 0x64 << 32 | size << 40``.

Matching (``FUN_180448360``):

* the host is hashed (``FUN_180676364``) and looked up in the sorted exact
  table ``DAT_1811231d8``; a hit requires the stored address hash to equal the
  hash of the address in the hosts line, or the special ``NULL`` sentinel;
* hosts whose name starts with ``*.`` are stored in the wildcard table
  ``DAT_1811231e0`` and matched by suffix/extension (``FUN_180925328`` +
  lower-cased suffix comparison).  No shipped record uses a wildcard, but the
  engine supports it;
* a match reports the condition id in the caller-provided structure and
  returns feature code ``0x29``.

Registration: the ``kcrce`` module init ``FUN_180927150`` registers
``0x64`` -> ``FUN_180474f90`` next to the KCRCE/KCRCEX contexts.

Database coverage (``cache/threats.db``): 204 records, all owned by
``SettingsModifier:Win32/HostsFileHijack`` (149) or
``SettingsModifier:Win32/PossibleHostsFileHijack`` (55).  Addresses are
``NULL`` (195), ``0.0.0.0`` (6) and ``127.0.0.1`` (3); 71 distinct hosts.
"""

from typing import List, Tuple

from .base import BaseSig
from .record_id import packed_record_id
from defender2yara.defender.constant import SIG_TYPES


HOSTSENTRY_SIG = "SIGNATURE_TYPE_HOSTSENTRY"
HOSTSENTRY_TYPE_ID = 0x64
NULL_ADDRESS = "NULL"


def _read_entry(payload: bytes, offset: int) -> Tuple[bytes, str, int]:
    """Read one ``u8 length + NUL-terminated string`` field."""
    if offset >= len(payload):
        raise ValueError("Truncated HOSTSENTRY string length")
    length = payload[offset]
    end = offset + 1 + length
    if end > len(payload):
        raise ValueError(
            f"Truncated HOSTSENTRY string: {length} bytes at offset {offset}"
        )
    raw = bytes(payload[offset + 1:end])
    if not raw or raw[-1] != 0:
        raise ValueError(
            f"HOSTSENTRY string at offset {offset} is not NUL terminated"
        )
    return raw, raw[:-1].decode("utf-8", "replace"), end


class HostsEntrySig(BaseSig):
    """``SIGNATURE_TYPE_HOSTSENTRY`` (``0x64``) - hosts-file line condition."""

    layout = "hostsentry"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[HOSTSENTRY_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 4:
            raise ValueError(
                f"Truncated HOSTSENTRY payload: {len(payload)} bytes"
            )

        self.address_raw, self.address, offset = _read_entry(payload, 0)
        self.host_raw, self.host, offset = _read_entry(payload, offset)
        self.address_length = len(self.address_raw)
        self.host_length = len(self.host_raw)

        self.is_null_address = self.address == NULL_ADDRESS
        self.host_wildcard = self.host.startswith("*.")
        self.host_suffix = self.host[2:] if self.host_wildcard else ""

        self.decode_warnings: List[str] = []
        if offset != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: {len(payload) - offset} bytes"
            )
        if not self.address:
            self.decode_warnings.append("Empty address field")
        if not self.host:
            self.decode_warnings.append("Empty host field")

        self.packed_record_id = packed_record_id(payload, HOSTSENTRY_TYPE_ID)

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "address": self.address,
            "address_length": self.address_length,
            "is_null_address": self.is_null_address,
            "host": self.host,
            "host_length": self.host_length,
            "host_wildcard": self.host_wildcard,
            "host_suffix": self.host_suffix,
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        return f"HOSTSENTRY {self.address} {self.host}"
