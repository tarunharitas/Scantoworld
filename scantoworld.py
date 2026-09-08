#RUN
"""Scantoworld - a simple TCP connect port scanner (Version 1).

Scantoworld scans a fixed set of 14 well-known TCP ports on one IPv4
address and writes a plain-text report of every port that accepted a
connection.

Usage:
    python scantoworld.py 192.168.1.1    (target as an argument)
    python scantoworld.py                (you will be prompted)

Ethics:
    Use Scantoworld only on systems you own or have explicit
    permission to test. Scanning systems without authorisation may
    be illegal.

Only the Python standard library is used. IPv6, port ranges, full
0-65535 scans, and stealth techniques are intentionally unsupported
in Version 1.
"""

from __future__ import annotations

import ipaddress
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Every TCP port Version 1 is allowed to scan (and nothing else).
PORTS_TO_SCAN = (
    21, 22, 23, 25, 53, 80,
    110, 139, 143, 443, 445,
    3306, 3389, 8080,
)

# Port-number -> service-name lookup (a table, not a probe).
PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NETBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MYSQL",
    3389: "RDP",
    8080: "HTTP-ALT",
}

# Seconds to wait for each connection attempt.
SOCKET_TIMEOUT = 0.5

# Where the report is written (always in the current working directory).
REPORT_PATH = Path("scan_report.txt")

# Fail fast if the two tables above ever drift apart.
if set(PORTS_TO_SCAN) != set(PORT_SERVICES):
    raise ValueError("PORTS_TO_SCAN and PORT_SERVICES must list the same ports")


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def get_raw_target(argv: list[str]) -> str:
    """Return the target string from the command line or a prompt.

    Returns "" when there is no input at all (the user pressed Enter on
    an empty prompt, or stdin was closed with no data).
    """
    if len(argv) == 1:
        try:
            return input("Enter an IPv4 address to scan: ").strip()
        except EOFError:
            return ""
    return argv[1].strip()


def validate_ipv4(raw_target: str) -> ipaddress.IPv4Address:
    """Validate raw_target and return it as an IPv4Address object.

    Raises ValueError with a friendly message when the input is empty,
    is not an IP address, or is an IPv6 address.
    """
    if not raw_target:
        raise ValueError("No IP address was entered.")
    try:
        address = ipaddress.ip_address(raw_target)
    except ValueError:
        raise ValueError(f"'{raw_target}' is not a valid IP address.") from None
    if address.version != 4:
        raise ValueError(
            f"'{raw_target}' is an IPv6 address. "
            "Scantoworld Version 1 supports IPv4 only."
        )
    return address


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def scan_port(host: str, port: int) -> bool:
    """Attempt a single TCP connect to host:port.

    Returns True if the connection succeeded (port is open), otherwise
    False. The 'with' statement closes the socket on every path
    (success, failure, or exception), so sockets never leak.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            # connect_ex() returns 0 on success and an error code
            # otherwise, instead of raising an exception.
            return sock.connect_ex((host, port)) == 0
    except OSError:
        # Covers timeouts (socket.timeout is an OSError subclass) and
        # any other socket-level error. Treat as "not open" and move on.
        return False


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def build_report(
    target: str,
    scan_date: str,
    duration: float,
    ports_scanned: int,
    open_ports: list[tuple[int, str]],
) -> str:
    """Build and return the full text of the scan report."""
    thick = "=" * 60
    thin = "-" * 60

    lines = [
        thick,
        "SCANTOWORLD SCAN REPORT",
        thick,
        "",
        f"Target:         {target}",
        f"Scan date:      {scan_date}",
        f"Duration:       {duration:.2f} seconds",
        "",
        f"Ports scanned:  {ports_scanned}",
        f"Open ports:     {len(open_ports)}",
        "",
        thin,
        "OPEN PORTS",
        thin,
    ]

    if open_ports:
        lines.append(f"{'PORT':<10}SERVICE")
        for port, service in open_ports:
            lines.append(f"{port:<10}{service}")
    else:
        lines.append("No open ports were found.")

    lines.extend([
        "",
        thin,
        "NOTES",
        thin,
        "- Service names are inferred from the port number only; no",
        "  banner or protocol inspection is performed.",
        "- A timeout or absent result does not prove a port is closed;",
        "  a firewall may be filtering traffic.",
        f"- Scan type: TCP connect scan, {SOCKET_TIMEOUT}s timeout.",
        "",
        f"Generated by Scantoworld v{__version__}",
    ])
    return "\n".join(lines) + "\n"


def save_report(report_text: str, path: Path) -> bool:
    """Write the report to path and return True on success.

    Permission problems and other I/O errors are reported as short,
    friendly messages; False is returned instead of raising.
    """
    try:
        path.write_text(report_text, encoding="utf-8")
    except PermissionError:
        print(f"Error: permission denied while writing '{path}'.", file=sys.stderr)
        return False
    except OSError as exc:
        print(f"Error: could not write '{path}': {exc}", file=sys.stderr)
        return False
    return True


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def main() -> int:
    """Run one scan and return the process exit code."""
    if len(sys.argv) > 2:
        print("Error: too many arguments.", file=sys.stderr)
        print("Usage: python scantoworld.py <IPv4 address>")
        return 2
    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0

    print(f"Scantoworld {__version__} - TCP port scanner")
    print("-" * 40)

    try:
        target = validate_ipv4(get_raw_target(sys.argv))
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    host = str(target)

    print(f"Target:     {host}")
    print(f"Ports:      {len(PORTS_TO_SCAN)} TCP ports "
          f"(connect scan, {SOCKET_TIMEOUT}s timeout each)")
    print()
    print(f"Scanning {host} ...")

    open_ports: list[tuple[int, str]] = []
    start = time.perf_counter()
    for port in PORTS_TO_SCAN:
        if scan_port(host, port):
            service = PORT_SERVICES.get(port, "Unknown")
            open_ports.append((port, service))
            print(f"  [+] Port {port:<6} open   {service}")
    duration = time.perf_counter() - start

    print()
    print("Scan finished.")
    print(f"  Ports scanned: 14")
    print(f"  Open ports:    {len(open_ports)}")
    print(f"  Duration:      {duration:.2f} seconds")

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_text = build_report(
        target=host,
        scan_date=scan_date,
        duration=duration,
        ports_scanned=len(PORTS_TO_SCAN),
        open_ports=open_ports,
    )
    if not save_report(report_text, REPORT_PATH):
        return 1

    print()
    print(f"Report saved to: {REPORT_PATH.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nScan cancelled by user (Ctrl+C). "
              "The scan did not finish; no complete report was written.")
        sys.exit(130)