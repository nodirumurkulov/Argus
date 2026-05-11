"""Network information collector for ARGUS."""

import re

from argus.collectors.base import BaseCollector
from argus.models import NetworkConnection


class NetworkCollector(BaseCollector):
    """Collect listening network connections using ss command."""

    name = "network"

    def collect(self) -> list[NetworkConnection]:
        """Collect all listening TCP and UDP connections."""
        output = self.safe_run_command(["ss", "-tulpn"])
        if output is None:
            return []
        return self._parse_ss_output(output)

    def _parse_ss_output(self, output: str) -> list[NetworkConnection]:
        """Parse ss -tulpn output into NetworkConnection models."""
        connections: list[NetworkConnection] = []
        for line in output.splitlines()[1:]:  # skip header
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            protocol = parts[0].lower()
            local_addr = parts[4]
            conn = self._parse_address(protocol, local_addr)
            if conn is None:
                continue
            conn.state = parts[1] if len(parts) > 1 else "LISTEN"
            self._extract_process_info(parts, conn)
            connections.append(conn)
        return connections

    def _parse_address(
        self, protocol: str, addr_str: str
    ) -> NetworkConnection | None:
        """Parse address:port string into a NetworkConnection."""
        if "]:" in addr_str:
            # IPv6: [::]:port
            bracket_end = addr_str.rfind("]:")
            address = addr_str[: bracket_end + 1]
            port_str = addr_str[bracket_end + 2 :]
        elif addr_str.count(":") == 1:
            address, port_str = addr_str.rsplit(":", 1)
        else:
            return None
        try:
            port = int(port_str)
        except ValueError:
            return None
        return NetworkConnection(
            protocol=protocol,
            local_address=address,
            local_port=port,
        )

    def _extract_process_info(
        self, parts: list[str], conn: NetworkConnection
    ) -> None:
        """Extract process name and PID from ss output."""
        full_line = " ".join(parts)
        proc_match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', full_line)
        if proc_match:
            conn.process_name = proc_match.group(1)
            conn.pid = int(proc_match.group(2))

    def get_wildcard_listeners(self) -> list[NetworkConnection]:
        """Return connections listening on all interfaces (0.0.0.0 or ::)."""
        connections = self.collect()
        wildcard = []
        for conn in connections:
            addr = conn.local_address
            if addr in ("0.0.0.0", "*", "[::]", "::"):
                wildcard.append(conn)
        return wildcard

    def get_high_risk_ports(self) -> list[NetworkConnection]:
        """Return connections on commonly targeted ports."""
        risky_ports = {
            21, 23, 25, 53, 110, 135, 139, 445, 1433, 1521,
            3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
        }
        connections = self.collect()
        return [c for c in connections if c.local_port in risky_ports]
