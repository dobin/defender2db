"""Generic brute-force signatures: BRUTE (0xd0).

``SIGNATURE_TYPE_BRUTE`` uses the **same payload layout as**
``SIGNATURE_TYPE_NSCRIPT_BRUTE`` (``0x29``): a normalised script-text pattern
with the engine's ``0x90`` wildcard opcodes, a script-kind byte and a search
mode.  The difference is ownership and matching:

* ``0x29`` records are parsed by the ``nscript`` module and matched by the
  script ring-buffer / hash driver.
* ``0xd0`` records are registered by the **kcrce module** (``FUN_180927150`` ->
  ``FUN_180927754``) with parser ``FUN_1801828c0``, table tag ``brut``
  (``0x62727574``) and commit callback ``FUN_180517e50``.  The parser builds a
  0x18-byte entry ``{pattern ptr, condition id, ..., any_length, pattern_length,
  mode, kind, variant, high_flag}`` and the commit callback builds a dedicated
  Aho-Corasick matcher (``DAT_1811152c8``) over the literal prefix of each
  pattern.

All ``0xd0`` records shipped in database 1.463.330.0 use script kind **0
("any")**, i.e. the pattern is not restricted to JS/VBS/PowerShell.  They are
the patterns behind the ``BRUTE:JS:Feature:`` / ``BRUTE:VBS:Feature:`` /
``BRUTE:PDF:Feature:`` feature names and the ``mp.GetBruteMatchData()`` /
``mp.ReadBruteMatchBuffer()`` Lua API.  The optional inline name is a feed
label (``!#BRUTE:...``, ``!#SCPT:...``), never a threat name.

Engine notes (x64 build 1.1.26100.4, see ``cache/functions_vdm.md`` section 22):
``FUN_180927754`` registration, ``FUN_1801828c0`` parser,
``FUN_1801836c8`` packed record id, ``FUN_180517e50`` commit/build matcher,
``FUN_180517568`` matcher driver, ``FUN_18015dde0`` hit reporting.
"""

from .nscript import NscriptBruteSig
from defender2yara.defender.constant import SIG_TYPES


BRUTE_SIG = "SIGNATURE_TYPE_BRUTE"


class BruteSig(NscriptBruteSig):
    """SIGNATURE_TYPE_BRUTE (0xd0) - generic (script-type agnostic) brute pattern."""

    SIG_TYPE_ID = 0xD0
    SHORT_NAME = "BRUTE"

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        super().__init__(data, ptr)
        assert self.sig_type == SIG_TYPES[0xD0]

    def to_details(self) -> dict:
        details = super().to_details()
        details["layout"] = "brute"
        details["parser"] = "FUN_1801828c0"
        details["table_tag"] = "brut"
        return details
