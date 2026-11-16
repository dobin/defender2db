from peewee import Model, CharField, SqliteDatabase, BlobField, IntegerField, DateTimeField
from defender2yara.defender.threat import Threat
from defender2yara.defender.signature.base import BaseSig
from defender2yara.defender.signature.hstr import DexHStrExtSig, HStrExtSig
from defender2yara.defender.signature.aggregator import AaAggregatorExSig
from defender2yara.defender.signature.versioncheck import VersionCheckSig
from defender2yara.defender.signature.sigtree import SigTreeSig
from defender2yara.defender.signature.nid import NidSig
import logging
import struct


db = SqliteDatabase('cache/threats.db')

class BaseModel(Model):
    class Meta:
        database = db

class DbThreat(BaseModel):
    name = CharField()
    sigs = CharField()
    sigcount = IntegerField()
    threatObject = BlobField()

class DbMetadata(BaseModel):
    signature_version = CharField()
    engine_version = CharField()
    conversion_datetime = DateTimeField()


class NiceThreat:
    def __init__(self, threat: Threat) -> None:
        self.name: str = threat.threat_name
        self.id: int = threat.threat_id
        self.category: int = threat.category_id
        self.severity: str | int | None = threat.severity
        self.type: str = threat.threat_type
        self.platform: str = threat.threat_platform
        self.family: str = threat.threat_family
        self.variant: str = threat.threat_variant
        self.suffixes: list[str] = threat.threat_suffixes

        self.signatures: list[BaseSig] = threat.signatures
        self.lua_scripts: list[bytes] = []
        self.yara_rules: list[str] = []
        self._populate_signature_data()

    def _populate_signature_data(self, reparse: bool = False) -> None:
        self.dexhstr_signatures: list[DexHStrExtSig] = []
        self.aggregator_signatures: list[AaAggregatorExSig] = []
        self.version_checks: list[VersionCheckSig] = []
        self.behavior_signatures: list[SigTreeSig] = []
        self.nid_signatures: list[NidSig] = []
        self.pehstr_signatures: list[HStrExtSig] = []
        self.revoked_certs: list[str] = []

        for sig in self.signatures:
            if sig.sig_type == "SIGNATURE_TYPE_REVOKED_CERTIFICATE":
                self.revoked_certs.append(sig.sig_data[3:23].hex())
                continue
            if sig.sig_type not in {
                "SIGNATURE_TYPE_DEXHSTR_EXT", "SIGNATURE_TYPE_AAGGREGATOREX",
                "SIGNATURE_TYPE_VERSIONCHECK", "SIGNATURE_TYPE_SIGTREE_BM",
                "SIGNATURE_TYPE_NID", "SIGNATURE_TYPE_PEHSTR_EXT",
            }:
                continue
            try:
                # Old pickles may contain BaseSig instances from before parser support.
                data = bytes([sig.sig_type_id]) + b"\xff\xff\xff" + len(sig.sig_data).to_bytes(4, "little") + sig.sig_data
                if sig.sig_type == "SIGNATURE_TYPE_DEXHSTR_EXT":
                    self.dexhstr_signatures.append(sig if not reparse and isinstance(sig, DexHStrExtSig) else DexHStrExtSig(data))
                elif sig.sig_type == "SIGNATURE_TYPE_AAGGREGATOREX":
                    self.aggregator_signatures.append(sig if not reparse and isinstance(sig, AaAggregatorExSig) else AaAggregatorExSig(data))
                elif sig.sig_type == "SIGNATURE_TYPE_VERSIONCHECK":
                    self.version_checks.append(sig if not reparse and isinstance(sig, VersionCheckSig) else VersionCheckSig(data))
                elif sig.sig_type == "SIGNATURE_TYPE_SIGTREE_BM":
                    self.behavior_signatures.append(sig if not reparse and isinstance(sig, SigTreeSig) else SigTreeSig(data))
                elif sig.sig_type == "SIGNATURE_TYPE_NID":
                    self.nid_signatures.append(sig if not reparse and isinstance(sig, NidSig) else NidSig(data))
                elif sig.sig_type == "SIGNATURE_TYPE_PEHSTR_EXT":
                    self.pehstr_signatures.append(sig if not reparse and isinstance(sig, HStrExtSig) else HStrExtSig(data))
            except (ValueError, AssertionError, IndexError, struct.error) as error:
                logging.getLogger(__name__).warning(
                    "Could not decode %s for %s: %s", sig.sig_type, self.name, error
                )

    def __setstate__(self, state: dict[str, object]) -> None:
        self.__dict__.update(state)
        if "dexhstr_signatures" not in state:
            self._populate_signature_data(reparse=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.id}) - {self.type} {self.platform} {self.family} {self.variant}"

