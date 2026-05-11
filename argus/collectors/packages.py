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
