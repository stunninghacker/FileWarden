"""Chunked file hashing utilities (SHA-256 by default, MD5 optional).

The helpers here are defensive: unreadable / vanished files never raise, they
return ``None`` so callers (monitor, integrity checker) can degrade gracefully.
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional

SUPPORTED_ALGORITHMS = ("sha256", "md5")

#: Read files in 1 MiB chunks - keeps memory flat for multi-GB files.
DEFAULT_CHUNK_SIZE = 1024 * 1024


def get_hasher(algorithm: str = "sha256"):
    """Return a fresh :class:`hashlib` hasher for *algorithm*.

    Raises
    ------
    ValueError
        If the algorithm is not one of :data:`SUPPORTED_ALGORITHMS`.
    """
    algorithm = (algorithm or "sha256").lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported hash algorithm {algorithm!r}; choose from {SUPPORTED_ALGORITHMS}"
        )
    return hashlib.new(algorithm)


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Return the hex digest of an in-memory byte string."""
    hasher = get_hasher(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_file(
    path: str | os.PathLike[str],
    algorithm: str = "sha256",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Optional[str]:
    """Return the hex digest of a file, or ``None`` if it cannot be read.

    The file is streamed in *chunk_size* byte blocks so arbitrarily large
    files can be hashed without exhausting memory.
    """
    # Validate the algorithm outside the try so a bad value is a clear error,
    # while unreadable files still degrade gracefully to None.
    hasher = get_hasher(algorithm)
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (OSError, PermissionError):
        return None


def file_size(path: str | os.PathLike[str]) -> Optional[int]:
    """Return the size of *path* in bytes, or ``None`` if it is unavailable."""
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def hashes_match(path: str, expected: str, algorithm: str = "sha256") -> Optional[bool]:
    """Compare the current hash of *path* against *expected*.

    Returns ``None`` when the file cannot be hashed (deleted / locked).
    """
    current = hash_file(path, algorithm)
    if current is None:
        return None
    return current == expected
