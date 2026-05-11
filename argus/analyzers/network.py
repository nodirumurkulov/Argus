"""Network security analyzer for ARGUS."""

from argus.analyzers.base import BaseAnalyzer
from argus.models import Finding, NetworkConnection


RISKY_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    135: "MS-RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


class NetworkAnalyzer(BaseAnalyzer):
    """Analyze network connections for security issues."""

    name = "network"
    category = "network"

    def analyze(self, connections: list[NetworkConnection]) -> list[Finding]:
        """Analyze network connections and return findings."""
        findings: list[Finding] = []
        self._check_wildcard_listeners(connections, findings)
        self._check_risky_ports(connections, findings)
        self._check_database_exposure(connections, findings)
        return findings

    def _check_wildcard_listeners(
        self, connections: list[NetworkConnection], findings: list[Finding]
    ) -> None:
        """Check for services listening on all interfaces."""
        wildcards = [
            c for c in connections
            if c.local_address in ("0.0.0.0", "*", "[::]", "::")
        ]
        for conn in wildcards:
            port_name = RISKY_PORTS.get(conn.local_port, "")
            svc_desc = f" ({port_name})" if port_name else ""
            process = conn.process_name or "unknown"
            severity = "medium" if conn.local_port in RISKY_PORTS else "low"
            findings.append(self._make_finding(
                finding_id=f"ARGUS-NET-001-{conn.local_port}",
                title=f"Port {conn.local_port}{svc_desc} listening on all interfaces",
                severity=severity,
                description=(
                    f"Service '{process}' on port {conn.local_port} is bound to "
                    f"{conn.local_address}, accessible from all network interfaces."
                ),
                evidence=[
                    f"Protocol: {conn.protocol}",
                    f"Address: {conn.local_address}:{conn.local_port}",
                    f"Process: {process} (PID {conn.pid or 'unknown'})",
                ],
                recommendation=f"Bind port {conn.local_port} to localhost or specific interfaces.",
                mitre=["T1071"],
            ))

    def _check_risky_ports(
        self, connections: list[NetworkConnection], findings: list[Finding]
    ) -> None:
        """Check for commonly targeted ports that are open."""
        for conn in connections:
            if conn.local_port in RISKY_PORTS:
                port_name = RISKY_PORTS[conn.local_port]
                process = conn.process_name or "unknown"
                if conn.local_address not in ("127.0.0.1", "::1", "localhost"):
                    findings.append(self._make_finding(
                        finding_id=f"ARGUS-NET-002-{conn.local_port}",
                        title=f"High-risk port {conn.local_port} ({port_name}) is exposed",
                        severity="medium",
                        description=(
                            f"Port {conn.local_port} ({port_name}) is exposed and "
                            "commonly targeted by attackers."
                        ),
                        evidence=[
                            f"Service: {process}",
                            f"Address: {conn.local_address}:{conn.local_port}",
                        ],
                        recommendation=f"Restrict access to port {conn.local_port} via firewall.",
                        mitre=["T1071"],
                    ))

    def _check_database_exposure(
        self, connections: list[NetworkConnection], findings: list[Finding]
    ) -> None:
        """Check for database services exposed to all interfaces."""
        db_ports = {
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
            9200: "Elasticsearch",
            1433: "MSSQL",
        }
        for conn in connections:
            if (
                conn.local_port in db_ports
                and conn.local_address in ("0.0.0.0", "*", "[::]", "::")
            ):
                db_name = db_ports[conn.local_port]
                findings.append(self._make_finding(
                    finding_id=f"ARGUS-NET-003-{conn.local_port}",
                    title=f"{db_name} exposed on all interfaces",
                    severity="high",
                    description=(
                        f"{db_name} on port {conn.local_port} is listening on all "
                        "interfaces. Databases should only be accessible locally."
                    ),
                    evidence=[
                        f"Service: {db_name}",
                        f"Address: {conn.local_address}:{conn.local_port}",
                    ],
                    recommendation=f"Bind {db_name} to 127.0.0.1 and use SSH tunneling.",
                    mitre=["T1190"],
                ))
