"""Registry key/value signatures: ``SIGNATURE_TYPE_REGKEY`` (0x63).

A ``REGKEY`` record is a **registry condition**, not a file pattern.  It names
a registry key (optionally one value below it) and, optionally, the expected
value data.  The resource manager evaluates these records while scanning the
live registry and while analysing registry-related detections (startup keys,
shell extensions, proxy settings, ...).

On-disk payload::

    u16 hive / root id     1 = HKEY_CLASSES_ROOT, 2 = HKEY_CURRENT_USER,
                           3 = HKEY_LOCAL_MACHINE, 4 = HKEY_USERS (unused)
    u16 key_length
    u8  key[key_length]    case-insensitive registry path; the literal
                           sequence ``\\\\`` separates the key from the value
                           name below it
    u16 value_length
    u8  value[value_length]  expected value data (empty = key existence only)

The engine requires ``hive`` to be 1..4; anything else is ignored.  The key
string is stored relative to the hive, i.e. ``SOFTWARE\\...`` rather than
``HKLM\\SOFTWARE\\...``.  An empty ``value`` means "the key exists"; a
non-empty ``value`` is compared against the registry value data.  When the key
contains ``\\\\``, the text before it is the key path and the text after it is
the value name, so the record can pin a specific value.

Engine notes (x64 build 1.1.26100.4; see ``cache/functions_vdm.md`` section
21):

* ``FUN_1809382c0`` - resmgr module init; registers the ``0x63`` handler
  (``FUN_1802b27c0``) next to FILEPATH / FOLDERNAME / ASEP paths.
* ``FUN_1802b27c0`` - record parser.  It validates the hive and both string
  lengths, splits the key at the first ``\\\\`` with ``FUN_18070d75c``
  (``strstr`` against ``"\\\\\\\\"``), interns the value data and registers the
  condition (``FUN_180186b84``).  Records with no value name but non-empty
  value data go to a second "value only" table.
* ``FUN_1802b34f4`` - strips one of eleven well-known path prefixes
  (``software\\microsoft\\windows\\currentversion\\run``, ``software\\classes``,
  ``system\\currentcontrolset`` ...).  The remainder is stored to save space.
* ``FUN_1803c3420`` / ``FUN_18041fb20`` - case-insensitive comparators
  (hive, prefix id, key path, value name).
* ``FUN_1802b2d84`` / ``FUN_1802b31a8`` - runtime lookups over the collected
  registry path / value data; the value data is fetched with
  ``FUN_1801f6f60`` and compared by ``FUN_18093a800``.

Database coverage (``cache/threats.db``): 3,911 records used by 542 threats.
Hive ids: 2,526 HKLM, 1,310 HKCU, 74 HKCR and one invalid ``0xffff`` that the
engine skips.  476 records pin a value name (72 with an empty name, e.g.
``.z\\\\``) and 269 carry expected value data.
"""

import struct
from typing import List, Optional, Tuple

from .base import BaseSig
from .record_id import packed_record_id
from defender2yara.defender.constant import SIG_TYPES


REGKEY_SIG = "SIGNATURE_TYPE_REGKEY"
REGKEY_TYPE_ID = 0x63
VALUE_SEPARATOR = "\\\\"

# Inferred from the key content: HKCR holds the extension/ProgID records
# (``.z``, ``IEWarning.WarningBHO``), HKCU the per-user software keys and HKLM
# the SYSTEM / machine-wide keys.
REGKEY_HIVES = {
    1: "HKEY_CLASSES_ROOT",
    2: "HKEY_CURRENT_USER",
    3: "HKEY_LOCAL_MACHINE",
    4: "HKEY_USERS",
}

# ``FUN_1802b34f4`` / table at ``0x180d82b50``: the eleven key prefixes that the
# parser strips before storing the remainder.  The order matters: the first
# logical prefix wins, and ``software\\classes\\`` (17 bytes) is tested before
# the shorter ``software\\classes``.
REGKEY_PREFIXES = (
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\explorer",
    "software\\microsoft\\windows\\currentversion",
    "software\\microsoft\\",
    "software\\classes\\clsid",
    "software\\classes\\interface",
    "software\\classes\\typelib",
    "software\\classes\\software\\microsoft\\windows\\currentversion\\explorer",
    "software\\classes",
    "software",
    "system\\currentcontrolset",
)


def match_regkey_prefix(key: str) -> Tuple[Optional[int], Optional[str]]:
    """Return the engine prefix table index/prefix for *key*, if any.

    Mirrors ``FUN_1802b34f4``: case-insensitive, the prefix must be followed by
    a path separator (or end the key), except when the prefix itself ends in a
    separator.
    """
    folded = key.lower()
    for index, prefix in enumerate(REGKEY_PREFIXES):
        if len(folded) < len(prefix) or folded[:len(prefix)] != prefix:
            continue
        if (
            len(folded) == len(prefix)
            or folded[len(prefix)] == "\\"
            or prefix.endswith("\\")
        ):
            return index, prefix
    return None, None


class RegKeySig(BaseSig):
    """SIGNATURE_TYPE_REGKEY (0x63) - registry key/value condition."""

    layout = "regkey"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[REGKEY_TYPE_ID]

        payload = self.sig_data
        if len(payload) < 4:
            raise ValueError(
                f"Truncated REGKEY signature: {len(payload)} bytes"
            )

        self.hive_id, key_length = struct.unpack_from("<HH", payload)
        key_end = 4 + key_length
        if key_end + 2 > len(payload):
            raise ValueError(
                f"Truncated REGKEY key: {key_length} bytes at offset 4"
            )
        key_raw = bytes(payload[4:key_end])
        value_length = struct.unpack_from("<H", payload, key_end)[0]
        value_end = key_end + 2 + value_length
        if value_end > len(payload):
            raise ValueError(
                f"Truncated REGKEY value: {value_length} bytes at offset "
                f"{key_end + 2}"
            )
        self.key_raw = key_raw
        self.value_raw = bytes(payload[key_end + 2:value_end])
        self.key = key_raw.decode("utf-8", "replace")
        self.value_data = self.value_raw.decode("utf-8", "replace")
        self.expected_size = value_end
        self.hive = REGKEY_HIVES.get(self.hive_id)

        self.key_path, self.value_name = self._split_key(self.key)
        self.has_value_separator = self.value_name is not None
        self.value_is_empty = not self.value_data

        self.packed_record_id = packed_record_id(payload, REGKEY_TYPE_ID)

        self.prefix_index, self.prefix = match_regkey_prefix(self.key)
        if self.prefix is None:
            self.key_suffix = self.key
        else:
            self.key_suffix = self.key[len(self.prefix):]

        self.decode_warnings: List[str] = []
        if self.hive is None:
            self.decode_warnings.append(
                f"Hive id 0x{self.hive_id:04x} is outside 1..4; "
                "the engine ignores this record"
            )
        if not self.key:
            self.decode_warnings.append("Empty registry key path")
        if self.expected_size != len(payload):
            self.decode_warnings.append(
                f"Unexpected trailing data: "
                f"{len(payload) - self.expected_size} bytes"
            )

    @staticmethod
    def _split_key(key: str) -> Tuple[str, Optional[str]]:
        index = key.find(VALUE_SEPARATOR)
        if index < 0:
            return key, None
        return key[:index], key[index + len(VALUE_SEPARATOR):]

    @property
    def key_existence_only(self) -> bool:
        """True when the record only requires the key to exist."""
        return self.value_is_empty

    @property
    def full_key(self) -> str:
        hive = self.hive or f"hive:{self.hive_id}"
        if not self.key_path:
            return hive
        separator = "" if self.key_path.startswith("\\") else "\\"
        return f"{hive}{separator}{self.key_path}"

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "hive_id": self.hive_id,
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "value_data": self.value_data,
            "has_value_separator": self.has_value_separator,
            "key_existence_only": self.value_is_empty,
            "prefix_index": self.prefix_index,
            "prefix": self.prefix,
            "key_suffix": self.key_suffix,
            "full_key": self.full_key,
            "packed_record_id_hex": f"{self.packed_record_id:016x}",
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        text = self.full_key
        if self.value_name is not None:
            text += f"\\\\{self.value_name}"
        if self.value_data:
            text += f" = {self.value_data!r}"
        else:
            text += " (exists)"
        return text
