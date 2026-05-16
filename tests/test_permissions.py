"""Permission helper and unsafe writable path tests."""

import stat
from pathlib import Path

from argus.analyzers.cron import CronAnalyzer
from argus.collectors import persistence as persistence_module
from argus.collectors import sudo as sudo_module
from argus.collectors.persistence import PersistenceCollector
from argus.collectors.sudo import SudoCollector
from argus.collectors.systemd import SystemdCollector
from argus.models import CronEntry
from argus.permissions import (
    is_group_or_world_writable,
    is_group_writable,
    is_world_writable,
    unsafe_writable_bits,
)


def _write_file(path: Path, mode: int, content: str = "test") -> Path:
    path.write_text(content)
    path.chmod(mode)
    return path


def test_permission_helper_ignores_owner_writable_file(tmp_path: Path) -> None:
    """Owner-writable files should not be reported as unsafe writable paths."""
    path = _write_file(tmp_path / "safe.conf", 0o600)

    assert not is_group_or_world_writable(path)


def test_permission_helper_detects_group_writable_file(tmp_path: Path) -> None:
    """Group-writable files should be reported as unsafe writable paths."""
    path = _write_file(tmp_path / "group.conf", 0o620)

    assert is_group_or_world_writable(path)


def test_permission_helper_detects_world_writable_file(tmp_path: Path) -> None:
    """World-writable files should be reported as unsafe writable paths."""
    path = _write_file(tmp_path / "world.conf", 0o602)

    assert is_group_or_world_writable(path)


def test_permission_helper_returns_unsafe_writable_bits(tmp_path: Path) -> None:
    """Unsafe mode bit reporting should ignore owner-only write access."""
    path = _write_file(tmp_path / "mixed.conf", 0o622)

    assert unsafe_writable_bits(path) == stat.S_IWGRP | stat.S_IWOTH


def test_permission_helper_distinguishes_group_and_world_bits(
    tmp_path: Path,
) -> None:
    """Callers should be able to distinguish group from world writable paths."""
    group_path = _write_file(tmp_path / "group.conf", 0o620)
    world_path = _write_file(tmp_path / "world.conf", 0o602)

    assert is_group_writable(group_path)
    assert not is_world_writable(group_path)
    assert not is_group_writable(world_path)
    assert is_world_writable(world_path)


def test_permission_helper_treats_missing_paths_as_safe(tmp_path: Path) -> None:
    """Missing paths should not produce unsafe writable false positives."""
    missing_path = tmp_path / "missing.conf"

    assert unsafe_writable_bits(missing_path) == 0
    assert not is_group_or_world_writable(missing_path)


def test_permission_helper_detects_world_writable_directory(tmp_path: Path) -> None:
    """Directory mode bits should be checked the same way as files."""
    directory = tmp_path / "profile.d"
    directory.mkdir()
    directory.chmod(0o777)

    assert is_group_or_world_writable(directory)
    assert is_group_writable(directory)
    assert is_world_writable(directory)


def test_cron_analyzer_ignores_owner_writable_script(tmp_path: Path) -> None:
    """Cron analyzer should not flag scripts that are only owner-writable."""
    script = _write_file(tmp_path / "job.sh", 0o700)

    findings = CronAnalyzer().analyze([
        CronEntry(user="root", schedule="* * * * *", command=str(script)),
    ])

    assert not [finding for finding in findings if finding.id.startswith("ARGUS-CRON-003")]


def test_cron_analyzer_flags_group_writable_script(tmp_path: Path) -> None:
    """Cron analyzer should flag scripts writable by group users."""
    script = _write_file(tmp_path / "job.sh", 0o720)

    findings = CronAnalyzer().analyze([
        CronEntry(user="root", schedule="* * * * *", command=str(script)),
    ])

    assert [finding for finding in findings if finding.id.startswith("ARGUS-CRON-003")]


def test_systemd_collector_marks_only_unsafe_unit_modes(tmp_path: Path) -> None:
    """Systemd unit writability should come from mode bits."""
    safe_unit = _write_file(
        tmp_path / "safe.service",
        0o644,
        "[Unit]\nDescription=Safe\n[Service]\nExecStart=/bin/true\n",
    )
    unsafe_unit = _write_file(
        tmp_path / "unsafe.service",
        0o664,
        "[Unit]\nDescription=Unsafe\n[Service]\nExecStart=/bin/true\n",
    )
    collector = SystemdCollector()

    assert collector._parse_unit_file(safe_unit).writable is False
    assert collector._parse_unit_file(unsafe_unit).writable is True


def test_sudo_collector_reports_group_writable_include_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Sudo collector should report unsafe sudoers include file mode bits."""
    safe_file = _write_file(tmp_path / "safe", 0o440)
    unsafe_file = _write_file(tmp_path / "unsafe", 0o460)
    monkeypatch.setattr(sudo_module, "SUDOERS_DIR", str(tmp_path))

    writable = SudoCollector().get_writable_sudoers_files()

    assert str(safe_file) not in writable
    assert str(unsafe_file) in writable


def test_persistence_collector_uses_mode_bits_for_writable_files(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Persistence collector should not mark owner-writable files as unsafe."""
    safe_file = _write_file(tmp_path / "safe-profile", 0o600)
    unsafe_file = _write_file(tmp_path / "unsafe-profile", 0o606)
    monkeypatch.setattr(
        persistence_module,
        "PERSISTENCE_PATHS",
        [str(safe_file), str(unsafe_file)],
    )

    findings: list[str] = []
    PersistenceCollector()._check_persistence_files(findings)

    assert f"exists:{safe_file}" in findings
    assert f"writable:{unsafe_file}" in findings


def test_persistence_collector_reports_writable_directories(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Persistence directories should be checked for unsafe writable mode bits."""
    unsafe_dir = tmp_path / "profile.d"
    unsafe_dir.mkdir()
    unsafe_dir.chmod(0o775)
    monkeypatch.setattr(persistence_module, "PERSISTENCE_PATHS", [str(unsafe_dir)])

    findings: list[str] = []
    PersistenceCollector()._check_persistence_files(findings)

    assert findings == [f"writable:{unsafe_dir}"]


def test_persistence_collector_uses_mode_bits_for_startup_scripts(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Startup script discovery should depend on executable mode bits."""
    startup_dir = tmp_path / "init.d"
    startup_dir.mkdir()
    executable = _write_file(startup_dir / "boot", 0o755)
    non_executable = _write_file(startup_dir / "note.sh", 0o644)
    monkeypatch.setattr(persistence_module, "STARTUP_SCRIPT_DIRS", [str(startup_dir)])

    findings: list[str] = []
    PersistenceCollector()._scan_startup_directories(findings)

    assert f"startup_script:{executable}" in findings
    assert f"startup_script:{non_executable}" not in findings
