# Scantoworld

Scantoworld is a small, beginner-friendly TCP port scanner written in pure Python. It checks a fixed list of 14 well-known TCP ports on one IPv4 address, displays the ports that accept a connection, and saves a plain-text scan report.

Scantoworld uses only the Python standard library. No third-party packages are required.

> **Important:** Use Scantoworld only on systems you own or have explicit permission to test. Scanning systems or networks without authorization may violate applicable laws, agreements, or network usage policies.

## Features

- IPv4 address validation
- TCP connect port scanning
- Scanning of 14 common TCP ports
- Port-based service mapping
- Command-line argument and interactive input support
- Configurable socket timeout
- Scan-duration measurement
- Plain-text report generation
- Friendly error handling
- Clean cancellation with `Ctrl+C`
- No external dependencies

## How It Works

1. The user provides an IPv4 address as a command-line argument or through the interactive prompt.
2. The address is validated using Python's `ipaddress` module.
3. Scantoworld attempts a normal TCP connection to each configured port.
4. Every connection uses a timeout of 0.5 seconds.
5. Ports that accept a connection are displayed as open.
6. The service name is inferred using a fixed port-to-service mapping.
7. The completed scan is saved to `scan_report.txt`.

## Requirements

- Python 3.8 or newer
- Windows, macOS, or Linux
- No third-party packages

Check the installed Python version:

```bash
python --version
```

On some Linux and macOS systems:

```bash
python3 --version
```

## Installation

Clone the repository:

```bash
git clone https://github.com/tarunharitas/Scantoworld.git
```

Open the project folder:

```bash
cd Scantoworld
```


You can also download the repository as a ZIP file and extract it.

## Usage

### Provide the target as an argument

```bash
python scantoworld.py 192.168.1.1
```

### Enter the target interactively

```bash
python scantoworld.py
```

The program will prompt:

```text
Enter an IPv4 address to scan:
```

On some Linux and macOS systems, use `python3`:

```bash
python3 scantoworld.py 192.168.1.1
```

### Display help

```bash
python scantoworld.py --help
```

## Example Output

```text
Scantoworld 1.0.0 - TCP port scanner
----------------------------------------
Target:     192.168.1.10
Ports:      14 TCP ports (connect scan, 0.5s timeout each)

Scanning 192.168.1.10 ...
  [+] Port 22     open   SSH
  [+] Port 80     open   HTTP
  [+] Port 443    open   HTTPS

Scan finished.
  Ports scanned: 14
  Open ports:     3
  Duration:       0.44 seconds

Report saved to: /home/you/Scantoworld/scan_report.txt
```

The output shown above is an example. Actual results depend on the target system, active services, network configuration, and firewall rules.

## Ports Scanned

Scantoworld Version 1 scans the following TCP ports:

| Port | Mapped Service |
|---:|:---|
| 21 | FTP |
| 22 | SSH |
| 23 | TELNET |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 139 | NETBIOS |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3306 | MYSQL |
| 3389 | RDP |
| 8080 | HTTP-ALT |

## Scan Report

Every completed scan creates or overwrites:

```text
scan_report.txt
```

The report contains:

- Target IPv4 address
- Scan date and time
- Scan duration
- Number of ports scanned
- Number of open ports detected
- Open-port numbers
- Mapped service names
- Scan notes and limitations

The report is created in the directory from which the program is run. Its absolute path is displayed after the file is saved.

The repository can include `sample_report.txt` as an example. The generated `scan_report.txt` should be excluded from Git using `.gitignore`.

## Service Mapping Notice

Scantoworld Version 1 does not perform banner grabbing or protocol inspection.

Service names are inferred only from commonly associated port numbers. For example, port `22` is mapped to SSH and port `80` is mapped to HTTP.

This mapping does not confirm which service or software is actually running. A service may use a non-standard port, and an unexpected service may run on a commonly associated port.

## Limitations

- IPv4 addresses only
- Fixed list of 14 TCP ports
- No custom port ranges
- No multithreading
- No banner grabbing
- No service-version detection
- No operating-system detection
- No vulnerability detection
- No stealth or SYN scanning

A timeout or absent response does not prove that a port is closed. A firewall or network device may silently filter the connection attempt.

Because ports are scanned sequentially, a target that silently filters every connection can take approximately seven seconds with the default timeout:

```text
14 ports × 0.5 seconds = approximately 7 seconds
```

## Error Handling

| Situation | Program Behaviour |
|:---|:---|
| Empty IP address | Displays a friendly error and exits |
| Invalid IP address | Displays a friendly error and exits |
| IPv6 address | Explains that Version 1 supports IPv4 only |
| Socket error or timeout | Treats the port as not detected as open and continues |
| Report permission failure | Displays a report-writing error |
| Too many arguments | Displays the correct usage |
| `
