"""
Lua Decompiler Backend Selection

Supports three backends (in priority order):
- luadec: Native luadec binary on PATH (fastest, best output)
- python: Pure Python implementation (always available)
- docker: Docker-based luadec 5.1 (https://github.com/viruscamp/luadec)

By default, auto-detects: uses native luadec if found on PATH,
otherwise falls back to the Python implementation with a notice.
"""

import logging
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import Optional
from enum import Enum

from .mplua_converter import is_mplua, convert_mplua_to_lua51

logger = logging.getLogger(__name__)


class DecompilerBackend(Enum):
    LUADEC = "luadec"
    PYTHON = "python"
    DOCKER = "docker"


# Global backend setting (None = auto-detect)
_current_backend: Optional[DecompilerBackend] = None
_backend_message_shown = False

# Docker image for luadec
LUADEC_DOCKER_IMAGE = "viruscamp/luadec"


def _detect_backend() -> DecompilerBackend:
    """Auto-detect the best available backend."""
    global _backend_message_shown

    if shutil.which("luadec") is not None:
        if not _backend_message_shown:
            logger.info("Using native luadec binary")
            _backend_message_shown = True
        return DecompilerBackend.LUADEC

    if not _backend_message_shown:
        logger.info(
            "Native luadec not found on PATH, using Python decompiler. "
            "For better results, install luadec: "
            "https://github.com/viruscamp/luadec"
        )
        _backend_message_shown = True
    return DecompilerBackend.PYTHON


def set_backend(backend: str) -> None:
    """Set the decompiler backend.

    Args:
        backend: 'luadec', 'python', or 'docker'
    """
    global _current_backend
    _current_backend = DecompilerBackend(backend.lower())


def get_backend() -> DecompilerBackend:
    """Get the current decompiler backend (auto-detects if not explicitly set)."""
    if _current_backend is None:
        return _detect_backend()
    return _current_backend


def _check_docker() -> None:
    """Check if Docker is installed and running."""
    if shutil.which("docker") is None:
        raise RuntimeError(
            "Docker not found. Please install Docker to use the docker backend:\n"
            "  https://docs.docker.com/get-docker/"
        )

    result = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Docker daemon is not running. Please start Docker."
        )


def _ensure_docker_image() -> None:
    """Ensure the luadec Docker image is available."""
    result = subprocess.run(
        ["docker", "images", "-q", LUADEC_DOCKER_IMAGE],
        capture_output=True,
        text=True
    )

    if not result.stdout.strip():
        print(f"[*] Pulling Docker image {LUADEC_DOCKER_IMAGE}...")
        result = subprocess.run(
            ["docker", "pull", LUADEC_DOCKER_IMAGE],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to pull Docker image: {result.stderr}")


def _decompile_with_luadec_binary(bytecode: bytes) -> str:
    """Decompile bytecode using native luadec binary on PATH."""
    if is_mplua(bytecode):
        bytecode = convert_mplua_to_lua51(bytecode)

    with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
        tmp.write(bytecode)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["luadec", tmp_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            # Retry with -s flag for stripped bytecode
            result = subprocess.run(
                ["luadec", "-s", tmp_path],
                capture_output=True,
                text=True,
                timeout=30
            )

        if result.returncode != 0:
            raise RuntimeError(f"luadec failed: {result.stderr}")

        return result.stdout

    except subprocess.TimeoutExpired:
        raise RuntimeError("luadec timed out after 30 seconds")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _decompile_with_docker(bytecode: bytes) -> str:
    """Decompile bytecode using Docker luadec."""
    _check_docker()
    _ensure_docker_image()

    if is_mplua(bytecode):
        bytecode = convert_mplua_to_lua51(bytecode)

    with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tmp:
        tmp.write(bytecode)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{tmp_path}:/input.luac:ro",
                LUADEC_DOCKER_IMAGE,
                "luadec", "/input.luac"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{tmp_path}:/input.luac:ro",
                    LUADEC_DOCKER_IMAGE,
                    "luadec", "-s", "/input.luac"
                ],
                capture_output=True,
                text=True,
                timeout=30
            )

        if result.returncode != 0:
            raise RuntimeError(f"luadec failed: {result.stderr}")

        return result.stdout

    except subprocess.TimeoutExpired:
        raise RuntimeError("luadec timed out after 30 seconds")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _decompile_with_python(bytecode: bytes) -> str:
    """Decompile bytecode using the Python implementation."""
    from . import decompile_bytecode
    return decompile_bytecode(bytecode)


def decompile(bytecode: bytes, backend: Optional[str] = None) -> str:
    """Decompile Lua bytecode using the selected backend.

    Args:
        bytecode: Raw Lua bytecode
        backend: Override the global backend setting ('luadec', 'python', or 'docker')

    Returns:
        Decompiled Lua source code
    """
    if backend is not None:
        use_backend = DecompilerBackend(backend.lower())
    else:
        use_backend = get_backend()

    if use_backend == DecompilerBackend.LUADEC:
        return _decompile_with_luadec_binary(bytecode)
    elif use_backend == DecompilerBackend.DOCKER:
        return _decompile_with_docker(bytecode)
    else:
        return _decompile_with_python(bytecode)


def check_backend_available(backend: str) -> dict:
    """Check if a backend is available.

    Returns:
        Dictionary with 'available' bool and optional 'error' message
    """
    backend_lower = backend.lower()

    if backend_lower == "python":
        return {"available": True}

    elif backend_lower == "luadec":
        if shutil.which("luadec") is not None:
            return {"available": True}
        return {
            "available": False,
            "error": "luadec binary not found on PATH. Install from https://github.com/viruscamp/luadec"
        }

    elif backend_lower == "docker":
        try:
            _check_docker()
            return {"available": True}
        except RuntimeError as e:
            return {"available": False, "error": str(e)}

    return {"available": False, "error": f"Unknown backend: {backend}"}
