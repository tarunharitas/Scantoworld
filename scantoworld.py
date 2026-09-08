#!/usr/bin/env python3
"""Scantoworld - a simple TCP connect port scanner (Version 1).

Scantoworld scans a fixed set of 14 common TCP ports on one IPv4
address. It displays every port that accepts a connection and creates
a plain-text scan report.

Usage:
    python scantoworld.py 192.168.1.1
    python scantoworld.py

Ethical use:
    Use Scantoworld only on systems you own or have explicit permission
    to test. Unauthorized network scanning may violate applicable laws,
    agreements, or network policies.

Scantoworld Version 1 uses only the Python standard library. IPv6,
custom port ranges, full-port scans, and stealth-scanning techniques
are intentionally unsupported.
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

PORTS_TO_SCAN = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    139,
    143,
    443,
    445,
    3306,
    3389,
    8080,
)

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

SOCKET_TIMEOUT = 0.5
REPORT_PATH = Path("scan_report.txt")


# Check that every configured port has a service mapping.
if set(PORTS_TO_SCAN) != set(PORT_SERVICES):
    raise ValueError(
        "PORTS_TO_SCAN and PORT_SERVICES must contain the same ports."
    )


# ---------------------------------------------------------------------------
# Input handling
# ---------------------------------------------------------------------------

def get_raw_target(argv: list[str]) -> str:
    """Return the target from a command-line argument or user prompt."""
    if len(argv) == 1:
        try:
            return input("Enter an IPv4 address to scan: ").strip()
        except EOFError:
            return ""

    return argv[1].strip()


def validate_ipv4(raw_target: str) -> ipaddress.IPv4Address:
    """Validate the target and return a valid IPv4Address object."""
    if not raw_target:
        raise ValueError("No IP address was entered.")

    try:
        address = ipaddress.ip_address(raw_target)
    except ValueError:
        raise ValueError(
            f"'{raw_target}' is not a valid IP address."
        ) from None

    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError(
            f"'{raw_target}' is an IPv6 address. "
            "Scantoworld Version 1 supports IPv4 only."
        )

    return address


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------

def scan_port(host: str, port: int) -> bool:
    """Return True when a TCP connection to the specified port succeeds."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            return sock.connect_ex((host, port)) == 0

    except OSError:
        # A timeout, rejected connection, or network error means that
        # the port was not detected as open during this scan.
        return False


def scan_target(host: str) -> tuple[list[tuple[int, str]], float]:
    """Scan configured ports and return open ports and scan duration."""
    open_ports: list[tuple[int, str]] = []

    print()
    print(f"Scanning {host} ...")

    start_time = time.perf_counter()

    for port in PORTS_TO_SCAN:
        if scan_port(host, port):
            service = PORT_SERVICES.get(port, "Unknown")
            open_ports.append((port, service))
            print(f"  [+] Port {port:<6} open   {service}")

    duration = time.perf_counter() - start_time
    return open_ports, duration


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    target: str,
    scan_date: str,
    duration: float,
    open_ports: list[tuple[int, str]],
) -> str:
    """Build and return the complete plain-text scan report."""
    thick_line = "=" * 60
    thin_line = "-" * 60

    lines = [
        thick_line,
        "SCANTOWORLD SCAN REPORT",
        thick_line,
        "",
        f"Target:         {target}",
        f"Scan date:      {scan_date}",
        f"Duration:       {duration:.2f} seconds",
        "",
        f"Ports scanned:  {len(PORTS_TO_SCAN)}",
        f"Open ports:     {len(open_ports)}",
        "",
        thin_line,
        "OPEN PORTS",
        thin_line,
    ]

    if open_ports:
        lines.append(f"{'PORT':<10}SERVICE")

        for port, service in open_ports:
            lines.append(f"{port:<10}{service}")
    else:
        lines.append(
            "No open ports were found in the configured port list."
        )

    lines.extend(
        [
            "",
            thin_line,
            "NOTES",
            thin_line,
            "- Service names are inferred from port numbers only.",
            "- No banner or protocol inspection is performed.",
            "- A timeout or absent result does not prove that a port",
            "  is closed because a firewall may be filtering traffic.",
            (
                f"- Scan type: TCP connect scan with a "
                f"{SOCKET_TIMEOUT}-second timeout."
            ),
            "",
            "For authorized security testing only.",
            f"Generated by Scantoworld v{__version__}",
        ]
    )

    return "\n".join(lines) + "\n"


def save_report(report_text: str, path: Path) -> bool:
    """Save the report and return True when writing succeeds."""
    try:
        path.write_text(report_text, encoding="utf-8")
        return True

    except PermissionError:
        print(
            f"Error: permission denied while writing '{path}'.",
            file=sys.stderr,
        )
        return False

    except OSError as error:
        print(
            f"Error: could not write '{path}': {error}",
            file=sys.stderr,
        )
        return False


# ---------------------------------------------------------------------------
# Main program
# ---------------------------------------------------------------------------

def main() -> int:
    """Run one authorized scan and return the process exit code."""
    if len(sys.argv) > 2:
        print("Error: too many arguments.", file=sys.stderr)
        print(
            "Usage: python scantoworld.py <IPv4 address>",
            file=sys.stderr,
        )
        return 2

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0

    print("=" * 50)
    print(f"Scantoworld v{__version__} - TCP Port Scanner")
    print("=" * 50)

    try:
        raw_target = get_raw_target(sys.argv)
        target = validate_ipv4(raw_target)

    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    host = str(target)

    print()
    print(f"Target:  {host}")
    print(f"Ports:   {len(PORTS_TO_SCAN)} TCP ports")
    print(f"Timeout: {SOCKET_TIMEOUT} seconds per port")

    open_ports, duration = scan_target(host)

    print()
    print("Scan finished.")
    print(f"  Ports scanned: {len(PORTS_TO_SCAN)}")
    print(f"  Open ports:    {len(open_ports)}")
    print(f"  Duration:      {duration:.2f} seconds")

    if not open_ports:
        print("  No open ports found in the configured port list.")

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_text = build_report(
        target=host,
        scan_date=scan_date,
        duration=duration,
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
        print()
        print(
            "Scan cancelled by user (Ctrl+C). "
            "No complete report was written."
        )
        sys.exit(130)
