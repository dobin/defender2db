"""
IOC (Indicators of Compromise) Extractor

Extracts actionable IOCs from Defender signatures:
- File hashes (SHA256, SHA512, MD5)
- URLs and domains
- Registry keys and values
- Mutex/Event/Pipe names
- File paths and names
- Command line patterns
- IP addresses
"""

import re
import struct
import signal
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from contextlib import contextmanager

from ..signature_extractor import (
    ThreatDefinition, TLVEntry, extract_threats, parse_tlv_stream
)


# Signature types that contain IOCs
IOC_SIG_TYPES = {
    # Hashes
    0x44: "FRIENDLY_FILE_HASH",
    0x45: "THREAT_FILE_HASH",
    0x46: "FRIENDLYHASH_SHA256",
    0x47: "FRIENDLYHASH_SHA512",
    0x48: "THREATHASH_SHA256",
    0x49: "THREATHASH_SHA512",

    # URLs/Domains
    0x28: "URLHSTR",
    0x29: "URLHSTR_EXT",

    # Registry
    0xA0: "REGKEY",
    0xA1: "REGVAL",

    # File paths
    0xA2: "FILEPATH",
    0xA3: "FILENAME",
    0x6A: "FOLDERNAME",
    0x71: "ASEP_FILEPATH",
    0x75: "ASEP_FOLDERNAME",

    # Sync objects (mutexes, events, etc.)
    0xA4: "MUTEX",
    0xA5: "EVENT",
    0xA6: "SEMAPHORE",
    0xA9: "PIPE",
    0xAA: "MAILSLOT",

    # Command line
    0x24: "CMDHSTR",
    0x25: "CMDHSTR_EXT",

    # Certificates
    0x6B: "WVT_EXCEPTION",
    0x6C: "REVOKED_CERTIFICATE",
    0x70: "TRUSTED_PUBLISHER",
}

# Regex patterns for extraction - optimized to prevent catastrophic backtracking
# Limit repetitions and use more specific character classes
URL_PATTERN = re.compile(rb'https?://[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=-]{5,200}', re.IGNORECASE)
DOMAIN_PATTERN = re.compile(rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}')
IP_PATTERN = re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
# Email pattern - use atomic grouping via non-overlapping character classes
EMAIL_PATTERN = re.compile(rb'[a-zA-Z0-9_%+-][a-zA-Z0-9._%+-]{0,63}@[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}\.[a-zA-Z]{2,6}')

# Maximum data size to run regex on (skip very large entries to prevent hangs)
MAX_REGEX_DATA_SIZE = 10000  # 10KB limit for generic regex extraction
REGEX_TIMEOUT_SECONDS = 2  # Timeout for regex operations


class RegexTimeout(Exception):
    """Raised when regex operation times out."""
    pass


@contextmanager
def regex_timeout(seconds):
    """Context manager to timeout regex operations (Unix only)."""
    def handler(signum, frame):
        raise RegexTimeout("Regex operation timed out")

    # Only use signal on Unix systems
    if hasattr(signal, 'SIGALRM'):
        old_handler = signal.signal(signal.SIGALRM, handler)
        signal.alarm(seconds)
        try:
            yield
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # On Windows, just yield without timeout
        yield


def safe_regex_finditer(pattern, data, max_matches=1000):
    """Safely run regex with size limits and match count limits."""
    if len(data) > MAX_REGEX_DATA_SIZE:
        # Only search first portion of large data
        data = data[:MAX_REGEX_DATA_SIZE]

    matches = []
    try:
        with regex_timeout(REGEX_TIMEOUT_SECONDS):
            for i, match in enumerate(pattern.finditer(data)):
                if i >= max_matches:
                    break
                matches.append(match)
    except RegexTimeout:
        pass  # Return whatever matches we found before timeout

    return matches


@dataclass
class IOCCollection:
    """Collection of extracted IOCs."""
    sha256_hashes: Set[str] = field(default_factory=set)
    sha512_hashes: Set[str] = field(default_factory=set)
    md5_hashes: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    ips: Set[str] = field(default_factory=set)
    registry_keys: Set[str] = field(default_factory=set)
    registry_values: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    file_names: Set[str] = field(default_factory=set)
    mutexes: Set[str] = field(default_factory=set)
    pipes: Set[str] = field(default_factory=set)
    events: Set[str] = field(default_factory=set)
    command_lines: Set[str] = field(default_factory=set)
    certificates: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)

    # Threat associations
    hash_threats: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    url_threats: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract printable strings from binary data."""
    strings = []
    current = []
    for b in data:
        if 32 <= b < 127:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings


def extract_hash(data: bytes, hash_size: int) -> Optional[str]:
    """Extract a hash from data."""
    if len(data) >= hash_size:
        hash_bytes = data[:hash_size]
        if any(b != 0 for b in hash_bytes):  # Not all zeros
            return hash_bytes.hex()
    return None


def extract_hashes_from_sig(data: bytes) -> Tuple[List[str], List[str], List[str]]:
    """Extract all hashes from a hash signature."""
    sha256_list = []
    sha512_list = []
    md5_list = []

    # Try SHA256 (32 bytes)
    if len(data) % 32 == 0:
        for i in range(0, len(data), 32):
            h = extract_hash(data[i:], 32)
            if h:
                sha256_list.append(h)

    # Try SHA512 (64 bytes)
    elif len(data) % 64 == 0:
        for i in range(0, len(data), 64):
            h = extract_hash(data[i:], 64)
            if h:
                sha512_list.append(h)

    # Try MD5 (16 bytes)
    elif len(data) % 16 == 0:
        for i in range(0, len(data), 16):
            h = extract_hash(data[i:], 16)
            if h:
                md5_list.append(h)

    return sha256_list, sha512_list, md5_list


def process_entry(entry: TLVEntry, threat_name: str, iocs: IOCCollection) -> None:
    """Process a single TLV entry and extract IOCs."""
    sig_type = entry.sig_type
    data = entry.data

    # Hash signatures
    if sig_type in (0x44, 0x45, 0x46, 0x47, 0x48, 0x49):
        sha256, sha512, md5 = extract_hashes_from_sig(data)
        for h in sha256:
            iocs.sha256_hashes.add(h)
            if threat_name:
                iocs.hash_threats[h].add(threat_name)
        for h in sha512:
            iocs.sha512_hashes.add(h)
        for h in md5:
            iocs.md5_hashes.add(h)

    # URL signatures
    elif sig_type in (0x28, 0x29):
        strings = extract_strings(data, 5)
        for s in strings:
            if '.' in s and len(s) > 5:
                if s.startswith('http'):
                    iocs.urls.add(s)
                    if threat_name:
                        iocs.url_threats[s].add(threat_name)
                elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s):
                    iocs.domains.add(s)

    # Registry signatures
    elif sig_type == 0xA0:  # REGKEY
        strings = extract_strings(data, 5)
        for s in strings:
            if any(hive in s.upper() for hive in ['HKEY_', 'HKLM', 'HKCU', 'HKU', 'HKCR']):
                iocs.registry_keys.add(s)
            elif '\\' in s:
                iocs.registry_keys.add(s)

    elif sig_type == 0xA1:  # REGVAL
        strings = extract_strings(data, 3)
        iocs.registry_values.update(strings)

    # File path signatures
    elif sig_type in (0xA2, 0x71):  # FILEPATH, ASEP_FILEPATH
        strings = extract_strings(data, 3)
        for s in strings:
            if '\\' in s or '/' in s:
                iocs.file_paths.add(s)

    elif sig_type in (0xA3, 0x6A, 0x75):  # FILENAME, FOLDERNAME, ASEP_FOLDERNAME
        strings = extract_strings(data, 3)
        iocs.file_names.update(strings)

    # Sync object signatures
    elif sig_type == 0xA4:  # MUTEX
        strings = extract_strings(data, 3)
        iocs.mutexes.update(strings)

    elif sig_type == 0xA5:  # EVENT
        strings = extract_strings(data, 3)
        iocs.events.update(strings)

    elif sig_type == 0xA9:  # PIPE
        strings = extract_strings(data, 3)
        for s in strings:
            iocs.pipes.add(s)

    # Command line signatures
    elif sig_type in (0x24, 0x25):
        strings = extract_strings(data, 5)
        iocs.command_lines.update(strings)

    # Certificate signatures
    elif sig_type in (0x6B, 0x6C, 0x70):
        strings = extract_strings(data, 5)
        iocs.certificates.update(strings)

    # Generic extraction from any signature
    # Look for URLs, IPs, emails in any data (with size limits and timeout)
    for match in safe_regex_finditer(URL_PATTERN, data):
        try:
            url = match.group(0).decode('utf-8', errors='ignore')
            iocs.urls.add(url)
        except:
            pass

    for match in safe_regex_finditer(IP_PATTERN, data):
        try:
            ip = match.group(0).decode('ascii')
            iocs.ips.add(ip)
        except:
            pass

    for match in safe_regex_finditer(EMAIL_PATTERN, data):
        try:
            email = match.group(0).decode('utf-8', errors='ignore')
            iocs.emails.add(email)
        except:
            pass


class IOCWriter:
    """Writes IOCs to organized files."""

    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.iocs = IOCCollection()
        self.stats = {
            'signatures_processed': 0,
            'threats_processed': 0,
        }

    def process_threat(self, threat: ThreatDefinition) -> None:
        """Process a threat and extract IOCs."""
        self.stats['threats_processed'] += 1

        for entry in threat.signatures:
            self.stats['signatures_processed'] += 1
            process_entry(entry, threat.threat_name, self.iocs)

    def process_raw(self, vdm_data: bytes, progress_callback=None) -> None:
        """Process raw VDM data."""
        threats = list(extract_threats(vdm_data))
        for i, threat in enumerate(threats):
            self.process_threat(threat)
            if progress_callback and i % 1000 == 0:
                progress_callback(i, len(threats))

    def write_all(self) -> Dict[str, int]:
        """Write all IOCs to files."""
        ioc_dir = self.output_dir / 'iocs'
        ioc_dir.mkdir(parents=True, exist_ok=True)

        counts = {}

        # Hashes
        if self.iocs.sha256_hashes:
            path = ioc_dir / 'sha256_hashes.txt'
            with open(path, 'w') as f:
                for h in sorted(self.iocs.sha256_hashes):
                    f.write(h + '\n')
            counts['sha256'] = len(self.iocs.sha256_hashes)

        if self.iocs.sha512_hashes:
            path = ioc_dir / 'sha512_hashes.txt'
            with open(path, 'w') as f:
                for h in sorted(self.iocs.sha512_hashes):
                    f.write(h + '\n')
            counts['sha512'] = len(self.iocs.sha512_hashes)

        if self.iocs.md5_hashes:
            path = ioc_dir / 'md5_hashes.txt'
            with open(path, 'w') as f:
                for h in sorted(self.iocs.md5_hashes):
                    f.write(h + '\n')
            counts['md5'] = len(self.iocs.md5_hashes)

        # URLs and domains
        if self.iocs.urls:
            path = ioc_dir / 'urls.txt'
            with open(path, 'w') as f:
                for url in sorted(self.iocs.urls):
                    f.write(url + '\n')
            counts['urls'] = len(self.iocs.urls)

        if self.iocs.domains:
            path = ioc_dir / 'domains.txt'
            with open(path, 'w') as f:
                for domain in sorted(self.iocs.domains):
                    f.write(domain + '\n')
            counts['domains'] = len(self.iocs.domains)

        if self.iocs.ips:
            path = ioc_dir / 'ips.txt'
            with open(path, 'w') as f:
                for ip in sorted(self.iocs.ips):
                    f.write(ip + '\n')
            counts['ips'] = len(self.iocs.ips)

        # Registry
        if self.iocs.registry_keys:
            path = ioc_dir / 'registry_keys.txt'
            with open(path, 'w') as f:
                for key in sorted(self.iocs.registry_keys):
                    f.write(key + '\n')
            counts['registry_keys'] = len(self.iocs.registry_keys)

        if self.iocs.registry_values:
            path = ioc_dir / 'registry_values.txt'
            with open(path, 'w') as f:
                for val in sorted(self.iocs.registry_values):
                    f.write(val + '\n')
            counts['registry_values'] = len(self.iocs.registry_values)

        # File paths
        if self.iocs.file_paths:
            path = ioc_dir / 'file_paths.txt'
            with open(path, 'w') as f:
                for fp in sorted(self.iocs.file_paths):
                    f.write(fp + '\n')
            counts['file_paths'] = len(self.iocs.file_paths)

        if self.iocs.file_names:
            path = ioc_dir / 'file_names.txt'
            with open(path, 'w') as f:
                for fn in sorted(self.iocs.file_names):
                    f.write(fn + '\n')
            counts['file_names'] = len(self.iocs.file_names)

        # Sync objects
        if self.iocs.mutexes:
            path = ioc_dir / 'mutexes.txt'
            with open(path, 'w') as f:
                for m in sorted(self.iocs.mutexes):
                    f.write(m + '\n')
            counts['mutexes'] = len(self.iocs.mutexes)

        if self.iocs.pipes:
            path = ioc_dir / 'pipes.txt'
            with open(path, 'w') as f:
                for p in sorted(self.iocs.pipes):
                    f.write(p + '\n')
            counts['pipes'] = len(self.iocs.pipes)

        if self.iocs.events:
            path = ioc_dir / 'events.txt'
            with open(path, 'w') as f:
                for e in sorted(self.iocs.events):
                    f.write(e + '\n')
            counts['events'] = len(self.iocs.events)

        # Command lines
        if self.iocs.command_lines:
            path = ioc_dir / 'command_lines.txt'
            with open(path, 'w') as f:
                for cmd in sorted(self.iocs.command_lines):
                    f.write(cmd + '\n')
            counts['command_lines'] = len(self.iocs.command_lines)

        # Certificates
        if self.iocs.certificates:
            path = ioc_dir / 'certificates.txt'
            with open(path, 'w') as f:
                for cert in sorted(self.iocs.certificates):
                    f.write(cert + '\n')
            counts['certificates'] = len(self.iocs.certificates)

        # Emails
        if self.iocs.emails:
            path = ioc_dir / 'emails.txt'
            with open(path, 'w') as f:
                for email in sorted(self.iocs.emails):
                    f.write(email + '\n')
            counts['emails'] = len(self.iocs.emails)

        # Hash-to-threat mapping
        if self.iocs.hash_threats:
            path = ioc_dir / 'hash_threats.csv'
            with open(path, 'w') as f:
                f.write("hash,threats\n")
                for h, threats in sorted(self.iocs.hash_threats.items()):
                    f.write(f'{h},"{";".join(sorted(threats))}"\n')

        # URL-to-threat mapping
        if self.iocs.url_threats:
            path = ioc_dir / 'url_threats.csv'
            with open(path, 'w') as f:
                f.write("url,threats\n")
                for url, threats in sorted(self.iocs.url_threats.items()):
                    escaped = url.replace('"', '""')
                    f.write(f'"{escaped}","{";".join(sorted(threats))}"\n')

        # Write README
        readme_path = ioc_dir / 'README.md'
        with open(readme_path, 'w') as f:
            f.write("# Extracted IOCs from Microsoft Defender\n\n")
            f.write("## Statistics\n\n")
            f.write(f"- Threats processed: {self.stats['threats_processed']}\n")
            f.write(f"- Signatures processed: {self.stats['signatures_processed']}\n\n")
            f.write("## IOC Counts\n\n")
            f.write("| Type | Count |\n")
            f.write("|------|-------|\n")
            for ioc_type, count in sorted(counts.items()):
                f.write(f"| {ioc_type} | {count:,} |\n")
            f.write("\n## Files\n\n")
            for ioc_type in sorted(counts.keys()):
                f.write(f"- `{ioc_type}.txt`\n")

        return counts


def write_iocs(vdm_data: bytes, output_dir: str, progress_callback=None) -> Dict[str, int]:
    """
    Extract and write IOCs from VDM data.

    Returns dict of IOC type -> count
    """
    writer = IOCWriter(output_dir)
    writer.process_raw(vdm_data, progress_callback)
    return writer.write_all()
