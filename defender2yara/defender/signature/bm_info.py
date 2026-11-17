import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


# Behaviour-monitoring action/telemetry bits.  Name -> bit, taken from the
# mpengine string dispatcher ``FUN_18055c56c`` (the lookup is case-insensitive,
# see ``FUN_180719580``; the database contains e.g. both ``SmsScan`` and
# ``SMSScan``).
BM_ACTION_BITS = {
    "EventLog": 0x00000001,
    "Telemetry": 0x00000002,
    "UI": 0x00000004,
    "RemediateProcess": 0x00000008,
    "RemediateBaseFile": 0x00000010,
    "AlwaysSendSamples": 0x00000020,
    "SendModules": 0x00000040,
    "SingleProcessScan": 0x00000080,
    "AllProcessScan": 0x00000100,
    "EmsScan": 0x00001000,
    "RegKeyValueScan": 0x00004000,
    "TurnNriOn": 0x00010000,
    "BootScan": 0x00020000,
    "DriverScan": 0x00040000,
    "WMIScan": 0x00080000,
    "FastRemediation": 0x00100000,
    "RemediateMultiProcess": 0x00200000,
    "InformCamp": 0x00800000,
    "MonitorEop": 0x01000000,
    "MonitorProcTreeEop": 0x02000000,
    "SetProcessTainted": 0x04000000,
    "SmsScan": 0x08000000,
    "FdrProcess": 0x10000000,
    "FdrFile": 0x20000000,
    "ParentInfo": 0x40000000,
    "SmsAsyncScanEvent": 0x80000000,
    "EmsMappedScan": 0x100000000,
    "SenseETW": 0x200000000,
    "BootBackup": 0x400000000,
    "BootRestore": 0x800000000,
    "MemoryQuery": 0x1000000000,
    "PurgeClipboardContent": 0x2000000000,
}

BM_ACTION_BITS_CASEFOLDED = {name.lower(): bit for name, bit in BM_ACTION_BITS.items()}

# ``BmDetectionDetails`` keeps one action mask per severity (object +0x20,
# +0x28, +0x30).  Unknown levels fall back to the raw text only.
BM_LEVELS = ("Low", "Medium", "High")
BM_LEVEL_KEYS = {level.lower(): level for level in BM_LEVELS}

# Per-scope signature id overrides understood by ``FUN_180bd13dc``.
BM_SCOPES = {
    "packed": "Packed",
    "system32": "System32",
}

# The engine stores the second word at ``BmDetectionDetails+0x14`` and rejects
# values >= 0x1000 (``FUN_1804424d4``).
BM_FLAGS_LIMIT = 0x1000


def bits_to_names(mask: int) -> list:
    """Expand an action mask into ``BM_ACTION_BITS`` names (bit order)."""
    return [name for name, bit in BM_ACTION_BITS.items() if mask & bit]


def names_to_bits(names) -> int:
    """Fold case-insensitive action names into a bit mask."""
    mask = 0
    for name in names:
        mask |= BM_ACTION_BITS_CASEFOLDED.get(name.lower(), 0)
    return mask


def _read_cstring(payload: bytes, pos: int, length: int, label: str,
                  warnings: list):
    """Read a length-prefixed, NUL-terminated engine string."""
    if length == 0:
        return "", pos
    if pos + length > len(payload):
        warnings.append(f"Truncated {label}")
        raw = payload[pos:]
        return raw.split(b"\0")[0].decode("utf-8", "replace"), len(payload)
    raw = payload[pos:pos + length]
    if not raw.endswith(b"\0"):
        warnings.append(f"{label} is not NUL terminated")
    return raw.split(b"\0")[0].decode("utf-8", "replace"), pos + length


class BmInfoSig(BaseSig):
    """
    SIGNATURE_TYPE_BM_INFO (0xa8) — behaviour-monitoring detection metadata.

    mpengine builds this record in ``FUN_1803859d0`` and decodes it into a
    ``BmDetectionDetails`` object (``FUN_180385ce4`` -> ``FUN_1804424d4``).
    It is not a detection by itself: it attaches the reporting policy to a
    behaviour signature id.  Layout (all lengths include the trailing NUL)::

        u16 group_len            0 in every shipped record
        u8  group[group_len]     optional NUL-terminated group/list name
        u16 flags                option word, engine requires < 0x1000
        u16 id_spec_len
        u8  id_spec[id_spec_len] NUL-terminated "<id>[,<id>+<scope>...]"
        u16 tags_len
        u8  tags[tags_len]       NUL-terminated "<level>:<tag>[+<tag>...],..."

    ``id_spec`` is the lookup key: a default numeric id followed by optional
    per-context overrides.  ``FUN_180442588`` parses the default id and then
    feeds the remaining ``<id>+<scope>`` items to ``FUN_180bd13dc``, which only
    accepts the scopes ``Packed`` and ``System32``.  Example:

    .. code-block:: text

        33,33+Packed,33+System32

    ``tags`` is a comma separated list of ``<level>:<action>[+<action>...]``
    items.  ``FUN_1804426c0`` -> ``FUN_180442794`` stores a separate action
    bit mask per severity (Low/Medium/High) and
    ``FUN_18055c56c`` maps each action name to its bit (``BM_ACTION_BITS``).
    The action names are matched case-insensitively, which is why the shipped
    database contains variants such as ``SMSScan`` and ``Smsscan``.

    In the shipped database all 4,192 records use ``group_len == 0``, 4,117
    use the plain id ``33`` and the most common tag set is
    ``Low:Telemetry`` (3,224 records).  The record consumes its payload
    exactly for every record, so the layout above is complete.

    This is reporting/telemetry policy, not a file pattern, so no YARA rule is
    generated from it.
    """

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[0xA8]

        payload = self.sig_data
        self.decode_warnings = []
        if len(payload) < 6:
            raise ValueError(
                f"Truncated BM_INFO signature: {len(payload)} bytes"
            )

        pos = 0
        group_len = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
        self.group, pos = _read_cstring(payload, pos, group_len, "BM_INFO group",
                                       self.decode_warnings)

        if pos + 2 > len(payload):
            raise ValueError("Truncated BM_INFO flags")
        self.flags = struct.unpack_from("<H", payload, pos)[0]
        pos += 2

        if pos + 2 > len(payload):
            raise ValueError("Truncated BM_INFO id spec length")
        id_spec_len = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
        self.id_spec, pos = _read_cstring(payload, pos, id_spec_len,
                                         "BM_INFO id spec", self.decode_warnings)

        if pos + 2 > len(payload):
            raise ValueError("Truncated BM_INFO tags length")
        tags_len = struct.unpack_from("<H", payload, pos)[0]
        pos += 2
        self.tags, pos = _read_cstring(payload, pos, tags_len,
                                      "BM_INFO tags", self.decode_warnings)

        self.trailing = payload[pos:]
        if self.trailing:
            self.decode_warnings.append(
                f"Unexpected trailing bytes after BM_INFO payload: {len(self.trailing)}"
            )

        self.default_signature_id, self.scope_ids = self._parse_id_spec()
        self.levels = self._parse_tags()

    def _parse_id_spec(self):
        if not self.id_spec:
            self.decode_warnings.append("Empty BM_INFO id spec")
            return None, {}
        items = [item.strip() for item in self.id_spec.split(",") if item.strip()]
        default_id = self._parse_int(items[0], "BM_INFO signature id")
        scope_ids = {}
        for item in items[1:]:
            value, _, scope = item.partition("+")
            value = value.strip()
            scope_key = scope.strip().lower()
            if not scope:
                self.decode_warnings.append(
                    f"BM_INFO id override without scope: {item!r}"
                )
                continue
            if scope_key not in BM_SCOPES:
                self.decode_warnings.append(
                    f"Unknown BM_INFO id scope: {scope!r}"
                )
                continue
            parsed = self._parse_int(value, "BM_INFO scoped signature id")
            if parsed is not None:
                scope_ids[scope_key] = parsed
        return default_id, scope_ids

    def _parse_int(self, text: str, label: str):
        try:
            return int(text, 10)
        except (TypeError, ValueError):
            self.decode_warnings.append(f"Invalid {label}: {text!r}")
            return None

    def _parse_tags(self):
        levels = {}
        if not self.tags:
            self.decode_warnings.append("Empty BM_INFO tag list")
            return levels
        for item in [part.strip() for part in self.tags.split(",") if part.strip()]:
            level_text, sep, actions = item.partition(":")
            level_key = level_text.strip().lower()
            if not sep:
                self.decode_warnings.append(
                    f"BM_INFO tag without level: {item!r}"
                )
                continue
            level = BM_LEVEL_KEYS.get(level_key)
            if level is None:
                self.decode_warnings.append(
                    f"Unknown BM_INFO tag level: {level_text!r}"
                )
                continue
            action_names = [a.strip() for a in actions.split("+") if a.strip()]
            mask = 0
            for name in action_names:
                bit = BM_ACTION_BITS_CASEFOLDED.get(name.lower())
                if bit is None:
                    self.decode_warnings.append(
                        f"Unknown BM_INFO action tag: {name!r}"
                    )
                    continue
                mask |= bit
            entry = levels.setdefault(level, {"tags": [], "mask": 0})
            entry["tags"].extend(action_names)
            entry["mask"] |= mask
        return levels

    def to_details(self) -> dict:
        return {
            "decode_warnings": list(self.decode_warnings),
            "group": self.group or None,
            "flags": self.flags,
            "flags_in_range": self.flags < BM_FLAGS_LIMIT,
            "id_spec": self.id_spec,
            "default_signature_id": self.default_signature_id,
            "scope_ids": dict(sorted(self.scope_ids.items())),
            "tags": self.tags,
            "levels": [
                {
                    "level": level,
                    "tags": self.levels[level]["tags"],
                    "mask": self.levels[level]["mask"],
                }
                for level in BM_LEVELS
                if level in self.levels
            ],
            "action_mask": self.action_mask,
            "action_names": bits_to_names(self.action_mask),
            "summary": self.describe(),
        }

    @property
    def action_mask(self) -> int:
        """Union of the per-level action masks."""
        mask = 0
        for entry in self.levels.values():
            mask |= entry["mask"]
        return mask

    @property
    def level_masks(self) -> dict:
        return {level: self.levels[level]["mask"] for level in self.levels}

    def describe(self) -> str:
        text = f"{self.sig_type} flags=0x{self.flags:04x}"
        if self.default_signature_id is not None:
            text += f" id={self.default_signature_id}"
        if self.scope_ids:
            text += " scoped=" + ",".join(
                f"{scope}:{value}" for scope, value in sorted(self.scope_ids.items())
            )
        if self.tags:
            text += f" tags={self.tags}"
        if self.group:
            text += f" group={self.group!r}"
        return text
