"""
Microsoft Defender Signature Downloader

Downloads the mpam-fe.exe signature package from Microsoft.
"""

import hashlib
import ssl
from pathlib import Path
from typing import Optional, Callable
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import tempfile
import shutil

# Microsoft Defender signature download URLs
MPAM_URLS = {
    'x64': 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64',
    'x86': 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86',
    'arm64': 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=arm64',
}

# Direct CDN URLs (may change)
MPAM_CDN_URLS = {
    'x64': 'https://definitionupdates.microsoft.com/download/DefinitionUpdates/VersionedSignatures/AM/1.0.0.0/x64/mpam-fe.exe',
}

# Default user agent
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

# Chunk size for downloads
CHUNK_SIZE = 8192


class DownloadProgress:
    """Progress tracker for downloads."""

    def __init__(self, total_size: int = 0):
        self.total_size = total_size
        self.downloaded = 0
        self.callback: Optional[Callable[[int, int], None]] = None

    def update(self, chunk_size: int) -> None:
        self.downloaded += chunk_size
        if self.callback:
            self.callback(self.downloaded, self.total_size)


class Downloader:
    """Downloads Microsoft Defender signature packages."""

    def __init__(self, arch: str = 'x64'):
        """
        Initialize downloader.

        Args:
            arch: Architecture to download ('x64', 'x86', 'arm64')
        """
        self.arch = arch
        self.url = MPAM_URLS.get(arch, MPAM_URLS['x64'])

    def _create_request(self, url: str) -> Request:
        """Create HTTP request with appropriate headers."""
        req = Request(url)
        req.add_header('User-Agent', USER_AGENT)
        req.add_header('Accept', '*/*')
        return req

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for HTTPS connections."""
        ctx = ssl.create_default_context()
        return ctx

    def download(self, output_path: str,
                 progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
        """
        Download mpam-fe.exe to specified path.

        Args:
            output_path: Path to save the downloaded file
            progress_callback: Optional callback(downloaded, total) for progress

        Returns:
            Path to downloaded file
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        # Create temporary file for download
        temp_path = output.with_suffix('.tmp')

        try:
            req = self._create_request(self.url)
            ctx = self._get_ssl_context()

            with urlopen(req, context=ctx, timeout=60) as response:
                # Get file size if available
                total_size = int(response.headers.get('Content-Length', 0))

                progress = DownloadProgress(total_size)
                progress.callback = progress_callback

                with open(temp_path, 'wb') as f:
                    while True:
                        chunk = response.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        f.write(chunk)
                        progress.update(len(chunk))

            # Move to final location
            shutil.move(str(temp_path), str(output))
            return str(output)

        except (URLError, HTTPError) as e:
            if temp_path.exists():
                temp_path.unlink()
            raise DownloadError(f"Failed to download: {e}") from e

    def download_to_temp(self,
                         progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
        """
        Download mpam-fe.exe to temporary directory.

        Returns:
            Path to downloaded file
        """
        temp_dir = tempfile.mkdtemp(prefix='defender_sig_')
        output_path = Path(temp_dir) / 'mpam-fe.exe'
        return self.download(str(output_path), progress_callback)

    def get_info(self) -> dict:
        """
        Get information about the download without downloading.

        Returns:
            Dictionary with URL and size information
        """
        try:
            req = self._create_request(self.url)
            ctx = self._get_ssl_context()

            with urlopen(req, context=ctx, timeout=30) as response:
                return {
                    'url': response.url,
                    'size': int(response.headers.get('Content-Length', 0)),
                    'content_type': response.headers.get('Content-Type', ''),
                    'status': response.status,
                }
        except (URLError, HTTPError) as e:
            return {
                'error': str(e),
                'url': self.url,
            }


class DownloadError(Exception):
    """Error during download."""
    pass


def download_mpam(output_path: str, arch: str = 'x64',
                  progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
    """
    Download mpam-fe.exe signature package.

    Args:
        output_path: Path to save the downloaded file
        arch: Architecture ('x64', 'x86', 'arm64')
        progress_callback: Optional progress callback

    Returns:
        Path to downloaded file
    """
    downloader = Downloader(arch)
    return downloader.download(output_path, progress_callback)


def download_mpam_to_temp(arch: str = 'x64',
                          progress_callback: Optional[Callable[[int, int], None]] = None) -> str:
    """
    Download mpam-fe.exe to temporary directory.

    Args:
        arch: Architecture ('x64', 'x86', 'arm64')
        progress_callback: Optional progress callback

    Returns:
        Path to downloaded file
    """
    downloader = Downloader(arch)
    return downloader.download_to_temp(progress_callback)


def verify_download(file_path: str, expected_hash: Optional[str] = None) -> dict:
    """
    Verify downloaded file integrity.

    Args:
        file_path: Path to downloaded file
        expected_hash: Optional expected SHA256 hash

    Returns:
        Verification result dictionary
    """
    path = Path(file_path)
    if not path.exists():
        return {'valid': False, 'error': 'File not found'}

    # Calculate hash
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(CHUNK_SIZE):
            sha256.update(chunk)

    file_hash = sha256.hexdigest()

    result = {
        'valid': True,
        'size': path.stat().st_size,
        'sha256': file_hash,
    }

    if expected_hash:
        result['hash_match'] = file_hash.lower() == expected_hash.lower()
        result['valid'] = result['hash_match']

    # Check for PE signature
    with open(path, 'rb') as f:
        magic = f.read(2)
        result['is_pe'] = magic == b'MZ'

    return result


def print_progress(downloaded: int, total: int) -> None:
    """Simple progress printer for CLI."""
    if total > 0:
        pct = (downloaded / total) * 100
        mb_down = downloaded / (1024 * 1024)
        mb_total = total / (1024 * 1024)
        print(f"\rDownloading: {mb_down:.1f} / {mb_total:.1f} MB ({pct:.1f}%)", end='', flush=True)
    else:
        mb_down = downloaded / (1024 * 1024)
        print(f"\rDownloading: {mb_down:.1f} MB", end='', flush=True)
