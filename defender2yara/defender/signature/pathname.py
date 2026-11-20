"""Path-name signatures: FILEPATH (``0x5f``), FOLDERNAME (``0x60``) and ASEP.

All four record types are literal *path patterns*, not hashes and not byte
patterns.  A record stores a 16-bit **root id** followed by the path relative to
that root::

    u16  root_id      known-folder / special-folder id (CSIDL-style)
    u8   pattern[]    relative path or glob pattern, no NUL terminator

``FILEPATH`` and ``ASEP_FILEPATH`` (``0x71``) share the same payload and the
same parser (``FUN_1802b378c``); only the record type id differs.  The engine
registers both in the resmgr plugin (``FUN_180939aa0``), building the record id
as ``crc32(payload) | type << 32 | size << 40``.  ``ASEP_FILEPATH`` is used in
the auto-start extensibility point (ASEP) checks, where the same path is
evaluated in the context of a registered startup location.  ``FOLDERNAME`` and
``ASEP_FOLDERNAME`` (``0x75``) are the directory counterparts; the ASEP variants
use the same payload in the ASEP context.

The root id is a Windows `CSIDL` value in the range `0x00`..`0x3d`.  The
shipped records confirm the mapping: `0x25` (`CSIDL_SYSTEM`) is used for
`\\System32` files, `0x26` (`CSIDL_PROGRAM_FILES`) for
`\\Internet Explorer\\...`, `0x1a` (`CSIDL_APPDATA`) for roaming-profile
drops, `0x02` (`CSIDL_PROGRAMS`) for Start-menu shortcuts, and so on.

The high ids are engine pseudo-folders rather than CSIDL values.  Their meaning
is taken from the engine's path-macro table at ``0x180c72c60`` and confirmed by
the shipped record suffixes:

======  ==================  =================================================
id      macro               meaning
======  ==================  =================================================
0xfffa  ``%username%``      current user name (not seen in the database)
0xfffb  ``%systemdrive%``   drive root, e.g. ``C:\\``
0xfffc  ``%CommonProgramFiles%``  ``C:\\Program Files\\Common Files``
0xfffd  ``%allusersprofile%``    ``C:\\ProgramData`` on modern Windows
0xfffe  ``%temp%``          per-user temporary directory
0xffff  (none)              suffix is already an absolute path
======  ==================  =================================================

Examples from ``cache/threats.db``::

    5f 0d 0000 2500 "\\gedzac.reg"              -> %SystemRoot%\\System32\\gedzac.reg
    5f 08 0000 feff "\\s.cmd"                   -> %temp%\\s.cmd
    5f 23 0000 fcff "\\microsoft shared\\greenav20??.exe"
                                                 -> %CommonProgramFiles%\\microsoft shared\\greenav20??.exe
    5f 0a 0000 ffff "c:\\a.bat"                 -> c:\\a.bat
    60 14 0000 2600 "\\common files\\kuum"      -> %ProgramFiles%\\common files\\kuum

``?`` and ``*`` are glob wildcards (``\\msg1*.dll``, ``\\SOEasy.?``), and the
comparison is case-insensitive.  ``FILEPATH`` matches a file path, ``FOLDERNAME``
a directory path; apart from the object kind they have the same payload.

Engine anchors (x64 build 1.1.26100.4): the path-macro table at
``0x180c72c60`` (stride ``0x50``; ``{func, id, names, ...}`` entries) holds the
``%...%`` expansion macros and resolvers ``0x1802911a0``/``0x18028f4d0``/
``0x18028daf0``.  Its numeric ids are not a reliable direct index (it contains
duplicate/shifted entries, e.g. two ``0x23`` entries), so the normal path roots
in this record field are decoded as standard CSIDL, which is what the suffixes
in the database show.  The high pseudo-ids above are taken from that table and
corroborated by the shipped paths.
"""

import struct
from typing import Optional

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES


FILEPATH_SIG = "SIGNATURE_TYPE_FILEPATH"
FOLDERNAME_SIG = "SIGNATURE_TYPE_FOLDERNAME"
ASEP_FILEPATH_SIG = "SIGNATURE_TYPE_ASEP_FILEPATH"
ASEP_FOLDERNAME_SIG = "SIGNATURE_TYPE_ASEP_FOLDERNAME"
PATHNAME_SIGS = (
    FILEPATH_SIG,
    FOLDERNAME_SIG,
    ASEP_FILEPATH_SIG,
    ASEP_FOLDERNAME_SIG,
)

# id -> (CSIDL/engine name, rendering macro)
#
# The names follow the Windows CSIDL constants; the macros come from the
# engine's known-folder table.  Only ids observed in the shipped database are
# given a macro, the rest are named for completeness.
PATH_ROOTS = {
    0x00: ("DESKTOP", "%Desktop%"),
    0x01: ("INTERNET", None),
    0x02: ("PROGRAMS", "%Programs%"),
    0x03: ("CONTROLS", None),
    0x04: ("PRINTERS", None),
    0x05: ("PERSONAL", "%Personal%"),
    0x06: ("FAVORITES", "%Favorites%"),
    0x07: ("STARTUP", "%Startup%"),
    0x08: ("RECENT", "%Recent%"),
    0x09: ("SENDTO", "%SendTo%"),
    0x0A: ("BITBUCKET", None),
    0x0B: ("STARTMENU", "%StartMenu%"),
    0x0C: ("MYDOCUMENTS", "%MyDocuments%"),
    0x0D: ("MYMUSIC", "%MyMusic%"),
    0x0E: ("MYVIDEO", "%MyVideo%"),
    0x0F: ("MYCOMPUTER", None),
    0x10: ("DESKTOPDIRECTORY", "%Desktop%"),
    0x11: ("DRIVES", None),
    0x12: ("NETWORK", None),
    0x13: ("NETHOOD", "%NetHood%"),
    0x14: ("FONTS", "%Fonts%"),
    0x15: ("TEMPLATES", "%Templates%"),
    0x16: ("COMMON_STARTMENU", "%CommonStartMenu%"),
    0x17: ("COMMON_PROGRAMS", "%CommonPrograms%"),
    0x18: ("COMMON_STARTUP", "%CommonStartup%"),
    0x19: ("COMMON_DESKTOPDIRECTORY", "%CommonDesktop%"),
    0x1A: ("APPDATA", "%AppData%"),
    0x1B: ("PRINTHOOD", "%PrintHood%"),
    0x1C: ("LOCAL_APPDATA", "%LocalAppData%"),
    0x1D: ("ALTSTARTUP", "%AltStartup%"),
    0x1E: ("COMMON_ALTSTARTUP", "%CommonAltStartup%"),
    0x1F: ("COMMON_FAVORITES", "%CommonFavorites%"),
    0x20: ("INTERNET_CACHE", "%InternetCache%"),
    0x21: ("COOKIES", "%Cookies%"),
    0x22: ("HISTORY", "%History%"),
    0x23: ("COMMON_APPDATA", "%CommonAppData%"),
    0x24: ("WINDOWS", "%windir%"),
    0x25: ("SYSTEM", "%SystemRoot%\\System32"),
    0x26: ("PROGRAM_FILES", "%ProgramFiles%"),
    0x27: ("MYPICTURES", "%MyPictures%"),
    0x28: ("PROFILE", "%UserProfile%"),
    0x29: ("SYSTEMX86", "%SystemRoot%\\SysWOW64"),
    0x2A: ("PROGRAM_FILESX86", "%ProgramFiles(x86)%"),
    0x2B: ("PROGRAM_FILES_COMMON", "%CommonProgramFiles%"),
    0x2C: ("PROGRAM_FILES_COMMONX86", "%CommonProgramFiles(x86)%"),
    0x2D: ("COMMON_TEMPLATES", "%CommonTemplates%"),
    0x2E: ("COMMON_DOCUMENTS", "%CommonDocuments%"),
    0x2F: ("COMMON_ADMINTOOLS", "%CommonAdminTools%"),
    0x30: ("ADMINTOOLS", "%AdminTools%"),
    0x31: ("CONNECTIONS", "%Connections%"),
    0x35: ("COMMON_MUSIC", "%CommonMusic%"),
    0x36: ("COMMON_PICTURES", "%CommonPictures%"),
    0x37: ("COMMON_VIDEO", "%CommonVideo%"),
    0x38: ("RESOURCES", "%CSIDLResources%"),
    0x39: ("RESOURCES_LOCALIZED", "%CSIDLResourcesLocalized%"),
    0x3A: ("COMMON_OEM_LINKS", "%CommonOemLinks%"),
    0x3B: ("CDBURN_AREA", "%CD Burning%"),
    0x3C: ("COMPUTERSNEARME", None),
    0x3D: ("COMPUTERSNEARME", None),
    # Engine pseudo-folders (not CSIDL values).
    0xFFFA: ("USERNAME", "%username%"),
    0xFFFB: ("SYSTEMDRIVE", "%systemdrive%"),
    0xFFFC: ("COMMONFILES", "%CommonProgramFiles%"),
    0xFFFD: ("ALLUSERSPROFILE", "%allusersprofile%"),
    0xFFFE: ("TEMP", "%temp%"),
    0xFFFF: ("ABSOLUTE", None),
}

WILDCARD_CHARS = "*?"


def decode_path_text(raw: bytes) -> str:
    """Decode a path pattern (UTF-8, with a latin-1 fallback)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


class PathNameSig(BaseSig):
    """Shared decoder for ``FILEPATH``, ``FOLDERNAME`` and their ASEP forms."""

    SIG_TYPE_ID: int = 0
    layout = "pathname"
    SHORT_NAME = "PATH"
    ASEP = False

    def __init__(self, data: bytes, ptr: int = 0) -> None:
        self.parse_common_header(data, ptr)
        assert self.sig_type == SIG_TYPES[self.SIG_TYPE_ID]

        if len(self.sig_data) < 2:
            raise ValueError(
                f"Truncated {self.sig_type} payload: {len(self.sig_data)} bytes"
            )

        self.root_id = struct.unpack_from("<H", self.sig_data, 0)[0]
        root = PATH_ROOTS.get(self.root_id)
        if root is None:
            self.root_name = f"UNKNOWN(0x{self.root_id:04x})"
            self.root_macro: Optional[str] = None
        else:
            self.root_name, self.root_macro = root

        self.is_absolute = self.root_id == 0xFFFF
        self.raw_pattern = bytes(self.sig_data[2:])
        self.pattern = decode_path_text(self.raw_pattern)

        self.decode_warnings = []
        if root is None:
            self.decode_warnings.append(
                f"Unknown path root id 0x{self.root_id:04x}"
            )
        if not self.raw_pattern:
            self.decode_warnings.append("Empty path pattern")

    @property
    def is_wildcard(self) -> bool:
        return any(char in self.pattern for char in WILDCARD_CHARS)

    @property
    def rendering(self) -> str:
        """Path with the root macro expanded symbolically."""
        if self.is_absolute or self.root_macro is None:
            return self.pattern
        return f"{self.root_macro}{self.pattern}"

    # ``path`` is the friendlier alias used by the API/UI.
    @property
    def path(self) -> str:
        return self.pattern

    def to_details(self) -> dict:
        return {
            "layout": self.layout,
            "root_id": self.root_id,
            "root_id_hex": f"0x{self.root_id:04x}",
            "root_name": self.root_name,
            "root_macro": self.root_macro,
            "is_absolute": self.is_absolute,
            "is_asep": self.ASEP,
            "pattern": self.pattern,
            "is_wildcard": self.is_wildcard,
            "rendered": self.rendering,
            "decode_warnings": list(self.decode_warnings),
            "summary": self.describe(),
        }

    def describe(self) -> str:
        return f"{self.SHORT_NAME} {self.rendering}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(root=0x{self.root_id:04x}, "
            f"pattern={self.pattern!r})"
        )


class FilePathSig(PathNameSig):
    """``SIGNATURE_TYPE_FILEPATH`` (``0x5f``) - file path/glob signature."""

    SIG_TYPE_ID = 0x5F
    layout = "filepath"
    SHORT_NAME = "FILEPATH"


class FolderNameSig(PathNameSig):
    """``SIGNATURE_TYPE_FOLDERNAME`` (``0x60``) - directory path/glob signature."""

    SIG_TYPE_ID = 0x60
    layout = "foldername"
    SHORT_NAME = "FOLDERNAME"


class AsepFilePathSig(PathNameSig):
    """``SIGNATURE_TYPE_ASEP_FILEPATH`` (``0x71``).

    Same payload as :class:`FilePathSig`, evaluated at an auto-start
    extensibility point (Run key, startup folder, service, ...).
    """

    SIG_TYPE_ID = 0x71
    layout = "asep_filepath"
    SHORT_NAME = "ASEP_FILEPATH"
    ASEP = True


class AsepFolderNameSig(PathNameSig):
    """``SIGNATURE_TYPE_ASEP_FOLDERNAME`` (``0x75``).

    Same payload as :class:`FolderNameSig`, evaluated at an auto-start
    extensibility point.
    """

    SIG_TYPE_ID = 0x75
    layout = "asep_foldername"
    SHORT_NAME = "ASEP_FOLDERNAME"
    ASEP = True
