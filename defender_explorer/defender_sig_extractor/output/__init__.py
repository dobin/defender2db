"""
Output writers for extracted Defender signatures.

Formats:
- threats: C-like organized by threat category
- yara: YARA rules from PEHSTR signatures
- asr: ASR rules organized by GUID
- iocs: Extracted IOCs (hashes, URLs, etc.)
- lolbin: LOLBin detection rules
- standalone: Standalone signatures (not mapped to threats)
"""

from .threat_writer import ThreatWriter, write_threats_organized
from .yara_writer import YaraWriter, write_yara_rules
from .asr_writer import ASRWriter, write_asr_rules, ASR_RULES, list_asr_rules
from .ioc_writer import IOCWriter, write_iocs
from .lolbin_writer import LOLBinWriter, write_lolbin_detections
from .standalone_writer import write_standalone_signatures, StandaloneWriterStats
