from defender2yara.defender.signature.base import BaseSig
from defender2yara.defender.signature.hstr import (
    HStrSig,
    HStrExtSig,
    DexHStrExtSig,
    CmdHStrExtSig,
    HSTR_EXT_SIGS,
    TEXTUAL_HSTR_SIGS,
    decode_hstr_pattern,
)
from defender2yara.defender.signature.threat import ThreatBeginSig, ThreatEndSig
from defender2yara.defender.signature.lua import LuaSig
from defender2yara.defender.signature.static import StaticSig
from defender2yara.defender.signature.kcrce import KcrceSig
from defender2yara.defender.signature.snid import SnidSig
from defender2yara.defender.signature.nid import NidSig, Nid64Sig
from defender2yara.defender.signature.sigtree import SigTreeSig, SIGTREE_SIGS
from defender2yara.defender.signature.pestatic import PestaticSig, PESTATIC_SIGS
from defender2yara.defender.signature.bm_info import BmInfoSig
from defender2yara.defender.signature.nscript import (
    NscriptBruteSig, NscriptNormalSig, NscriptSpSig,
)
from defender2yara.defender.signature.macro_source import MacroSourceSig
from defender2yara.defender.signature.macro_pcode import (
    MACRO_PCODE_SIGS, MacroPcodeSig,
)
from defender2yara.defender.signature.cksimplerec import (
    CkOldRecSig, CkSimpleRecSig,
)
from defender2yara.defender.signature.aggregator import (
    AaAggregatorExSig, AaAggregatorSig,
)
from defender2yara.defender.signature.pathname import (
    FilePathSig, FolderNameSig,
)
from defender2yara.defender.signature.versioncheck import VersionCheckSig
from defender2yara.defender.signature.kpat import (
    KPAT_SIGS, KpatExSig, KpatSig,
)
from defender2yara.defender.signature.vdll import VDLL_SIGS, VdllSig
from defender2yara.defender.signature.kvir32 import Kvir32Sig
from defender2yara.defender.signature.regkey import RegKeySig
from defender2yara.defender.signature.ndat import NdatSig
from defender2yara.defender.signature.boot import BootSig
from defender2yara.defender.signature.brute import BruteSig
