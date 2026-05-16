"""Filesystem permission helpers for ARGUS checks."""

import stat
from pathlib import Path

UNSAFE_WRITABLE_BITS = stat.S_IWGRP | stat.S_IWOTH


def unsafe_writable_bits(path: str | Path) -> int:
    """Return group/other writable mode bits set on a path."""
    try:
        mode = Path(path).stat().st_mode
    except OSError:
        return 0
    return mode & UNSAFE_WRITABLE_BITS


def is_group_writable(path: str | Path) -> bool:
    """Return True when the group writable mode bit is set."""
    return bool(unsafe_writable_bits(path) & stat.S_IWGRP)


def is_world_writable(path: str | Path) -> bool:
    """Return True when the other writable mode bit is set."""
    return bool(unsafe_writable_bits(path) & stat.S_IWOTH)


def is_group_or_world_writable(path: str | Path) -> bool:
    """Return True when a path is writable by group or other users.

    This checks filesystem mode bits, not whether the current ARGUS process can write
    to the path. That avoids false positives when ARGUS runs as root.
    """
    return bool(unsafe_writable_bits(path))
