"""Log collector tests — plain files, gzip, rotated archives, line limits."""

import gzip
from pathlib import Path

from argus.collectors.logs import LogCollector


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


def _write_gz(path: Path, content: str) -> Path:
    with gzip.open(path, "wt") as f:
        f.write(content)
    return path


# ── safe_read_lines ──────────────────────────────────────────────

# LogCollector does not define its own safe_read_lines — it inherits
# the implementation from BaseCollector.
_collector = LogCollector()


def test_safe_read_lines_plain(tmp_path: Path) -> None:
    path = _write(tmp_path / "auth.log", "line1\nline2\n\nline3\n")
    result = _collector.safe_read_lines(str(path))
    assert result == ["line1", "line2", "line3"]


def test_safe_read_lines_empty(tmp_path: Path) -> None:
    path = _write(tmp_path / "empty.log", "")
    result = _collector.safe_read_lines(str(path))
    assert result == []


def test_safe_read_lines_missing(tmp_path: Path) -> None:
    result = _collector.safe_read_lines(str(tmp_path / "nope.log"))
    assert result == []


def test_safe_read_lines_gzip(tmp_path: Path) -> None:
    path = _write_gz(tmp_path / "auth.log.2.gz", "a\nb\n\nc\n")
    result = _collector.safe_read_lines(str(path))
    assert result == ["a", "b", "c"]


def test_safe_read_lines_max_lines(tmp_path: Path) -> None:
    lines = "\n".join(f"line{i}" for i in range(100)) + "\n"
    path = _write(tmp_path / "large.log", lines)
    result = _collector.safe_read_lines(str(path), max_lines=10)
    assert len(result) == 10
    assert result[0] == "line90"
    assert result[-1] == "line99"


# ── discover_rotated_paths ───────────────────────────────────────


def test_discover_rotated_paths_none(tmp_path: Path) -> None:
    _write(tmp_path / "auth.log", "data")
    found = LogCollector.discover_rotated_paths(str(tmp_path / "auth.log"))
    assert found == []


def test_discover_rotated_paths_plain(tmp_path: Path) -> None:
    _write(tmp_path / "auth.log", "current")
    p1 = _write(tmp_path / "auth.log.1", "newer")
    p2 = _write(tmp_path / "auth.log.2", "oldest")
    found = LogCollector.discover_rotated_paths(str(tmp_path / "auth.log"))
    assert found == [str(p1), str(p2)]


def test_discover_rotated_paths_gz(tmp_path: Path) -> None:
    _write(tmp_path / "auth.log", "current")
    p1 = _write_gz(tmp_path / "auth.log.1.gz", "newer")
    p2 = _write_gz(tmp_path / "auth.log.2.gz", "oldest")
    found = LogCollector.discover_rotated_paths(str(tmp_path / "auth.log"))
    assert len(found) == 2
    assert found[0] == str(p1)
    assert found[1] == str(p2)


# ── collect with discover_rotated ────────────────────────────────


def test_collect_with_rotated(tmp_path: Path) -> None:
    _write(tmp_path / "auth.log", "current\nline\n")
    _write(tmp_path / "auth.log.1", "older\nlog\n")
    _write_gz(tmp_path / "auth.log.2.gz", "oldest\nentry\n")
    collector = LogCollector()
    result = collector.collect(
        log_path=str(tmp_path / "auth.log"),
        discover_rotated=True,
    )
    assert "oldest" in result
    assert "entry" in result
    assert "older" in result
    assert "log" in result
    assert "current" in result
    assert "line" in result


def test_collect_rotated_places_current_last(tmp_path: Path) -> None:
    _write(tmp_path / "auth.log", "current")
    _write(tmp_path / "auth.log.1", "older")
    _write_gz(tmp_path / "auth.log.2.gz", "oldest")
    result = LogCollector().collect(
        log_path=str(tmp_path / "auth.log"),
        discover_rotated=True,
    )
    assert result[-1] == "current"
