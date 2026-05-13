"""Package inventory collector for ARGUS."""

from argus.collectors.base import BaseCollector
from argus.models import PackageInfo


class PackageCollector(BaseCollector):
    """Collect installed package inventory using dpkg."""

    name = "packages"

    def collect(self) -> list[PackageInfo]:
        """Collect installed packages from dpkg."""
        output = self.safe_run_command(
            ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${binary:Summary}\n"]
        )
        if output is None:
            return []
        return self._parse_dpkg_output(output)

    def _parse_dpkg_output(self, output: str) -> list[PackageInfo]:
        """Parse dpkg-query output into PackageInfo models."""
        packages: list[PackageInfo] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                packages.append(PackageInfo(
                    name=parts[0],
                    version=parts[1],
                    architecture=parts[2] if len(parts) > 2 else "",
                    description=parts[3] if len(parts) > 3 else "",
                ))
        return packages

    def get_security_packages(self) -> dict[str, bool]:
        """Check for presence of security-related packages."""
        security_packages = [
            "fail2ban",
            "ufw",
            "iptables",
            "apparmor",
            "selinux-utils",
            "auditd",
            "aide",
            "rkhunter",
            "chkrootkit",
            "clamav",
            "unattended-upgrades",
            "needrestart",
            "libpam-pwquality",
        ]
        installed = {pkg.name for pkg in self.collect()}
        return {pkg: pkg in installed for pkg in security_packages}

    def get_upgradable_count(self) -> int:
        """Get count of packages with available upgrades."""
        output = self.safe_run_command(["apt", "list", "--upgradable"])
        if output is None:
            return 0
        lines = [line for line in output.splitlines() if "/" in line]
        return len(lines)
