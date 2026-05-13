"""Filesystem permission helpers for ARGUS checks."""

import stat
from pathlib import Path


def is_group_or_world_writable(path: str | Path) -> bool:
    """Return True when a path is writable by group or other users.

    This checks filesystem mode bits, not whether the current ARGUS process can write
    to the path. That avoids false positives when ARGUS runs as root.
    """
    try:
        mode = Path(path).stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
