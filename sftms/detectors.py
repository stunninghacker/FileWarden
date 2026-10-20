"""Destination classification: removable media, network shares, cloud folders.

Classification is layered so it works everywhere:

1. Explicit, case-insensitive path patterns (``cloud_folder_patterns`` etc.)
   - deterministic and used for demos/tests on machines without real hardware.
2. ``psutil.disk_partitions`` mount information (filesystem type + mount point).
3. On Windows, the native ``GetDriveTypeW`` API (via ``ctypes``) to recognise
   ``DRIVE_REMOVABLE`` / ``DRIVE_REMOTE`` letters. This call is guarded so the
   module imports and runs unchanged on Linux.
"""

from __future__ import annotations

import os
import sys
from enum import Enum
from fnmatch import fnmatch
from typing import Iterable, List, Optional, Tuple

try:  # psutil is a hard dependency, but keep the import defensive.
    import psutil
except Exception:  # pragma: no cover - only if psutil is missing/broken
    psutil = None  # type: ignore[assignment]


class DriveClass(str, Enum):
    """Where a destination path physically lives."""

    LOCAL = "local"
    REMOVABLE = "removable"
    NETWORK = "network"
    CLOUD = "cloud"
    UNKNOWN = "unknown"

    @property
    def is_external(self) -> bool:
        """True when the destination is outside the local fixed disk."""
        return self in (DriveClass.REMOVABLE, DriveClass.NETWORK, DriveClass.CLOUD)


#: Filesystem types that indicate a network mount on Linux/Unix.
_NETWORK_FSTYPES = {
    "cifs", "smbfs", "smb", "nfs", "nfs4", "sshfs", "fuse.sshfs",
    "afpfs", "davfs", "fuse.davfs", "webdav",
}

#: Mount-point fragments that commonly hold removable media on Linux.
_REMOVABLE_MOUNTS = ("/media/", "/run/media/", "/mnt/usb", "/mnt/removable")

# Windows GetDriveTypeW return values (see winbase.h).
_DRIVE_REMOVABLE = 2
_DRIVE_FIXED = 3
_DRIVE_REMOTE = 4
_DRIVE_CDROM = 5


def _norm(path: str) -> str:
    """Normalise a path for case-insensitive, slash-agnostic pattern matching."""
    return os.path.normpath(os.path.abspath(path)).replace("\\", "/").lower()


def _matches_any(normalised_path: str, patterns: Iterable[str]) -> Optional[str]:
    """Return the first pattern matching *normalised_path*, else ``None``."""
    for pattern in patterns or ():
        pat = str(pattern).replace("\\", "/").lower()
        if fnmatch(normalised_path, pat) or fnmatch(os.path.basename(normalised_path), pat):
            return pattern
    return None


def get_mounts() -> List[Tuple[str, str, str]]:
    """Return ``(mountpoint, device, fstype)`` tuples from psutil."""
    if psutil is None:
        return []
    mounts: List[Tuple[str, str, str]] = []
    try:
        for part in psutil.disk_partitions(all=True):
            mounts.append((part.mountpoint, part.device, (part.fstype or "").lower()))
    except Exception:  # pragma: no cover - defensive
        return mounts
    return mounts


def _win_drive_type(path: str) -> Optional[int]:
    """Return the Windows drive type for *path* or ``None`` on non-Windows.

    Uses ``ctypes.windll.kernel32.GetDriveTypeW`` - no third-party dependency
    and fully guarded so Linux import is unaffected.
    """
    if not sys.platform.startswith("win"):
        return None
    try:  # pragma: no cover - Windows only
        import ctypes

        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if not drive:
            return None
        root = drive + "\\"
        return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)))
    except Exception:
        return None


def _mount_for(path: str) -> Optional[Tuple[str, str, str]]:
    """Return the longest mountpoint containing *path* (or ``None``)."""
    target = os.path.normcase(os.path.abspath(path))
    best: Optional[Tuple[str, str, str]] = None
    best_len = -1
    for mountpoint, device, fstype in get_mounts():
        mp = os.path.normcase(os.path.abspath(mountpoint))
        if target == mp or target.startswith(mp.rstrip(os.sep) + os.sep):
            if len(mp) > best_len:
                best, best_len = (mountpoint, device, fstype), len(mp)
    return best


def classify_destination(
    path: Optional[str],
    cloud_patterns: Iterable[str] = (),
    removable_patterns: Iterable[str] = (),
    network_patterns: Iterable[str] = (),
) -> DriveClass:
    """Classify *path* as local / removable / network / cloud.

    Pattern matches take priority (they are deterministic and used for demos),
    then psutil mount information, then the Windows drive-type API.
    """
    if not path:
        return DriveClass.UNKNOWN

    norm = _norm(path)

    if _matches_any(norm, cloud_patterns):
        return DriveClass.CLOUD
    if _matches_any(norm, removable_patterns):
        return DriveClass.REMOVABLE
    if _matches_any(norm, network_patterns):
        return DriveClass.NETWORK

    # Windows UNC path (\server\share) - treat as network.
    if norm.startswith("//") and not norm.startswith("///"):
        return DriveClass.NETWORK

    mount = _mount_for(path)
    if mount:
        mountpoint, device, fstype = mount
        if fstype in _NETWORK_FSTYPES or device.startswith("//"):
            return DriveClass.NETWORK
        mp_norm = mountpoint.replace("\\", "/").lower()
        if any(frag in mp_norm for frag in _REMOVABLE_MOUNTS):
            return DriveClass.REMOVABLE

    drive_type = _win_drive_type(path)
    if drive_type == _DRIVE_REMOVABLE:
        return DriveClass.REMOVABLE
    if drive_type == _DRIVE_REMOTE:
        return DriveClass.NETWORK
    if drive_type in (_DRIVE_FIXED, _DRIVE_CDROM):
        return DriveClass.LOCAL

    return DriveClass.LOCAL


def is_external_destination(path: Optional[str], **kwargs) -> bool:
    """Convenience wrapper: True if *path* is removable/network/cloud."""
    return classify_destination(path, **kwargs).is_external
