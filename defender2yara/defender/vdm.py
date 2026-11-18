from typing import List, Tuple
import os
import struct
import time
import zlib
from collections import defaultdict
import exiftool

from defender2yara.defender.constant import SIG_TYPES
from defender2yara.defender.signature import *
from defender2yara.defender.threat import Threat

from defender2yara.util.utils import hexdump
from defender2yara.util.pe import parse_pe_meta_info

import logging
from tqdm import tqdm

logger = logging.getLogger(__package__)

class Vdm:
    def __init__(self,base_path:str):
        self.base_path = base_path
        self.delta_path = ""

        self.signatures:List[BaseSig] = []
        self.threats:List[Threat] = []

        self.delta_filename:str = ""
        self.version:str = ""
        self.vdm_type:str = ""

        filename, self.version = self.get_meta_info(base_path)

        if filename not in ['mpavbase.vdm','mpasbase.vdm']:
            raise ValueError("Invalid vdm file. Please use mpa(s|v)base.vdm file.")

        if filename.startswith("mpav"):
            self.vdm_type = "anti-virus"
        elif filename.startswith("mpas"):
            self.vdm_type = "anti-spyware"

        self.major_version = ".".join(self.version.split(".")[0:2])
        self.minor_version = ".".join(self.version.split(".")[2:4])

        self.raw_data:bytes = self.extract_vdm_data(base_path)


    def apply_delta_vdm(self,vdm_path):
        delta_filename, version = self.get_meta_info(vdm_path)
        # Validation
        if delta_filename not in ['mpavdlta.vdm','mpasdlta.vdm']:
            raise ValueError(f"Invalid vdm file. Please use mpa(s|v)dlta.vdm file:{delta_filename}")
        
        vdm_type:str = ""
        if delta_filename.startswith("mpav"):
            vdm_type = "anti-virus"
        elif delta_filename.startswith("mpas"):
            vdm_type = "anti-spyware"

        if vdm_type != self.vdm_type:
            raise ValueError(f"Vdm file type miss match: Base->{self.vdm_type}, Delta->{vdm_type}")

        major_version = ".".join(version.split(".")[0:2])
        minor_version = ".".join(version.split(".")[2:4])
        
        if major_version != self.major_version:
            raise ValueError(f"The major version of vdm miss matched: Base->{self.major_version}, Delta:{major_version}")

        self.delta_path = vdm_path
        self.version = ".".join([self.major_version,minor_version])
        self.minor_version = minor_version
    
        delta_raw_data = self.extract_vdm_data(vdm_path)
        delta_signatures = self.parse_database(delta_raw_data)

        if len(delta_signatures) != 2:
            raise ValueError(f"Unexpected signature count for delta vdm: {len(delta_signatures)}")

        delta_blob = delta_signatures[1].sig_data
        self.raw_data = self.apply_delta_patch(delta_blob,self.raw_data)
    

    def parse_files(self):
        self.signatures = self.parse_database(self.raw_data)
        self.threats = self.parse_threats(self.signatures)

    def get_threats(self) -> List[Threat]:
        return self.threats
    
    def get_signatures(self) -> List[BaseSig]:
        return self.signatures
    
    # Raw data -> self.signatures
    @staticmethod
    def parse_database(data:bytes) -> List[BaseSig]:
        counter = defaultdict(int)
        ptr:int = 0
        entry:BaseSig
        database:List[BaseSig] = []

        start_time = time.perf_counter()
        progress_bar = tqdm(
                total=len(data),
                unit='bytes',
                bar_format='{l_bar}{bar:20}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {postfix}]',
                colour='green',
                desc="Parsing database",
                postfix="0.00 MB/s",
                leave=False)

        next_progress = 1_000_000
        # parse
        while ptr < len(data):
            if ptr + 4 > len(data):
                raise ValueError(f"Truncated signature header at offset {ptr}")
            try:
                entry = Vdm.decode_record(data, ptr)
            except (ValueError, AssertionError, IndexError, struct.error, UnicodeError) as error:
                # Validate framing on the failure path, not twice for every record.
                framed = BaseSig(data, ptr)
                if framed.sig_type in ('SIGNATURE_TYPE_THREAT_BEGIN', 'SIGNATURE_TYPE_THREAT_END'):
                    raise ValueError(f'Invalid threat boundary at offset {ptr}: {error}') from error
                entry = framed
                entry.decode_error = str(error)
            database.append(entry)
            counter[entry.sig_type] += 1
            ptr += entry.record_size
            progress_bar.update(entry.record_size)
            if ptr >= next_progress:
                next_progress = ptr + 1_000_000
                elapsed = time.perf_counter() - start_time
                throughput_mb_s = ptr / elapsed / 1_000_000 if elapsed else 0
                progress_bar.set_postfix_str(f"{throughput_mb_s:.2f} MB/s", refresh=False)

        progress_bar.close()
        elapsed = time.perf_counter() - start_time
        logger.info('Parsed %.2f MB in %.2f seconds (%.2f MB/s)',
                    len(data) / 1_000_000, elapsed,
                    len(data) / elapsed / 1_000_000 if elapsed else 0)
        return database

    @staticmethod
    def decode_record(data: bytes, ptr: int = 0) -> BaseSig:
        sig_type = SIG_TYPES[data[ptr]]
        if sig_type == "SIGNATURE_TYPE_THREAT_BEGIN":
            entry = ThreatBeginSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_THREAT_END":
            entry = ThreatEndSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_PEHSTR":
            entry = HStrSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_DEXHSTR_EXT":
            entry = DexHStrExtSig(data,ptr)
        elif sig_type in HSTR_EXT_SIGS:
            entry = HStrExtSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_LUASTANDALONE":
            entry = LuaSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_STATIC":
            entry = StaticSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_KCRCE":
            entry = KcrceSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_SNID":
            entry = SnidSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_NID":
            entry = NidSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_NID64":
            entry = Nid64Sig(data,ptr)
        elif sig_type in SIGTREE_SIGS:
            entry = SigTreeSig(data,ptr)
        elif sig_type in PESTATIC_SIGS:
            entry = PestaticSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_BM_INFO":
            entry = BmInfoSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_NSCRIPT_NORMAL":
            entry = NscriptNormalSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_NSCRIPT_SP":
            entry = NscriptSpSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_NSCRIPT_BRUTE":
            entry = NscriptBruteSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_MACRO_SOURCE":
            entry = MacroSourceSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_CKSIMPLEREC":
            entry = CkSimpleRecSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_CKOLDREC":
            entry = CkOldRecSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_AAGGREGATOREX":
            entry = AaAggregatorExSig(data,ptr)
        elif sig_type == "SIGNATURE_TYPE_VERSIONCHECK":
            entry = VersionCheckSig(data,ptr)
        else:
            entry = BaseSig(data,ptr)
        return entry

    @staticmethod
    def parse_threats(database:List[BaseSig]) -> List[Threat]:
        # init threats
        threats = []
        threat = None
        # parse
        # progress bar setup
        progress_bar = tqdm(
                total=len(database),
                unit='threats',
                bar_format='{l_bar}{bar:20}{r_bar}',
                colour='green',
                desc="Parsing threats",
                leave=False)

        for sig in database:
            if sig.sig_type == "SIGNATURE_TYPE_THREAT_BEGIN":
                if threat is not None:
                    logger.warning("Nested threat BEGIN; discarding incomplete threat")
                threat = Threat(sig)
                continue
            elif sig.sig_type == "SIGNATURE_TYPE_THREAT_END":
                if threat is not None:
                    threat.threat_end_sig = sig
                    threats.append(threat)
                else:
                    logger.warning("Orphan threat END")
                threat = None
            if threat:
                threat.add_signature(sig)

            progress_bar.update(1)

        progress_bar.close()

        return threats

    @staticmethod
    def get_meta_info(path) -> Tuple[str,str]:
        try:
            with exiftool.ExifToolHelper() as ef:
                metadata = ef.get_metadata(path)[0]
                return metadata['EXE:OriginalFileName'],metadata['EXE:ProductVersion']
        except:
            # use pefile if exiftool is not present or available on the system 
            return parse_pe_meta_info(path)

    @staticmethod
    def extract_vdm_data(filepath) -> bytes:
        """
        Extracts VDM data from the given file.

        Args:
            filepath (str): The path to the file from which to extract VDM data.

        Returns:
            bytes: The decompressed VDM data.

        Raises:
            ValueError: If the file does not contain the expected resource signature or if the file format is invalid.
            FileNotFoundError: If the file does not exist.
            AssertionError: If the decompressed data size does not match the expected size.
        """
        if os.path.exists(filepath):
            with open(filepath, "rb") as stream:
                data = stream.read()
        else:
            raise FileNotFoundError(filepath)

        base = data.find(b"RMDX") # Look for resource signature
        if base < 0 or base + 0x20 > len(data):
            raise ValueError(f"Invalid file format. {filepath}")
        
        offset, size = struct.unpack("<II", data[base + 0x18: base + 0x20])
        if base + offset + 8 >= len(data):
            raise ValueError(f"Invalid compressed resource offset. {filepath}")
        decompressed_data = zlib.decompress(data[base + offset + 8:], -15)
        if len(decompressed_data) != size:
            raise ValueError(f"VDM decompressed size mismatch: expected {size}, got {len(decompressed_data)}")
        return decompressed_data

    @staticmethod
    def apply_delta_patch(delta_blob:bytes, base_data:bytes)->bytes:
        results:List[bytes] = []

        ptr = 0
        unknown_dword1,unknown_dword2 = struct.unpack("II", delta_blob[ptr:ptr+8])
        ptr += 8

        while ptr < len(delta_blob):
            info = struct.unpack("H", delta_blob[ptr:ptr+2])[0]
            ptr += 2
            if info & 0x7fff == info:
                # append from delta 
                results.append(delta_blob[ptr:ptr+info])
                ptr += info
            else:
                # append from base
                base_offset = struct.unpack("I", delta_blob[ptr:ptr+4])[0]
                ptr += 4
                size = (info & 0x7fff) + 6
                results.append(base_data[base_offset:base_offset+size])
        return b"".join(results) # optimization / using "+=" for large bytes is too slow.  