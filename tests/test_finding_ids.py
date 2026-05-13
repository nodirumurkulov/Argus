"""Finding identifier regression tests."""

from argus.analyzers.cron import CronAnalyzer
from argus.analyzers.persistence import PersistenceAnalyzer
from argus.analyzers.sudo import SudoAnalyzer
from argus.models import CronEntry


def test_cron_suspicious_findings_have_unique_ids() -> None:
    """Multiple suspicious cron entries should not share the same finding ID."""
    findings = CronAnalyzer().analyze([
        CronEntry(user="root", schedule="* * * * *", command="curl http://example.test/a"),
        CronEntry(user="www-data", schedule="* * * * *", command="wget http://example.test/b"),
    ])

    ids = [finding.id for finding in findings if finding.id.startswith("ARGUS-CRON-001")]

    assert len(ids) == 2
    assert len(ids) == len(set(ids))


def test_persistence_writable_findings_have_unique_ids() -> None:
    """Multiple writable persistence paths should not share the same finding ID."""
    findings = PersistenceAnalyzer().analyze([
        "writable:/etc/rc.local",
        "writable:/etc/profile.d/example.sh",
    ])

    ids = [finding.id for finding in findings if finding.id.startswith("ARGUS-PERS-001")]

    assert len(ids) == 2
    assert len(ids) == len(set(ids))


def test_sudo_writable_findings_have_unique_ids() -> None:
    """Multiple writable sudoers files should not share the same finding ID."""
    findings = SudoAnalyzer().analyze(
        users=[],
        sudo_rules={},
        writable_files=["/etc/sudoers.d/dev", "/etc/sudoers.d/admin"],
    )

    ids = [finding.id for finding in findings if finding.id.startswith("ARGUS-SUDO-003")]

    assert len(ids) == 2
    assert len(ids) == len(set(ids))
