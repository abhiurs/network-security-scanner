import socket
import sys
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import time
from nmap_detector import detect_services
from risk_analyzer import analyze_risk
from report_generator import save_json, save_csv, generate_risk_summary
import argparse


def scan_port(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return "OPEN"
        else:
            return "CLOSED"

    except socket.timeout:
        return "FILTERED"

    except socket.error:
        return "ERROR"

    finally:
        sock.close()


def scan_single_port(target, port, timeout):
    state = scan_port(target, port, timeout)

    return port, state


parser = argparse.ArgumentParser(
    description="Network Security Scanner - TCP Port and Service Scanner"
)

parser.add_argument("--target", required=True, help="Target IPv4 address to scan")

parser.add_argument(
    "--ports", required=True, help="Port or port range to scan (example: 80 or 1-1000)"
)

parser.add_argument(
    "--threads",
    type=int,
    default=100,
    help="Number of concurrent scanning threads (default: 50)",
)

parser.add_argument(
    "--timeout",
    type=float,
    default=0.5,
    help="Socket connection timeout in seconds (default: 0.5)",
)


args = parser.parse_args()

target = args.target
port_range = args.ports
threads = args.threads
timeout = args.timeout


if threads < 1:
    print("Invalid thread count.")
    print("Threads must be at least 1.")
    sys.exit(1)

if timeout <= 0:
    print("Invalid timeout.")
    print("Timeout must be greater than 0.")
    sys.exit(1)


try:
    parsed_ip = ipaddress.ip_address(target)

    if parsed_ip.version != 4:
        print("Invalid target: Only IPv4 addresses are supported.")
        sys.exit(1)

except ValueError:
    print(f"Invalid IP address: {target}")
    sys.exit(1)


try:
    if "-" in port_range:
        start_port, end_port = map(int, port_range.split("-"))
    else:
        start_port = end_port = int(port_range)

except ValueError:
    print("Invalid port specification.")
    print("Examples:")
    print("  python scanner.py --target 127.0.0.1 --ports 80")
    print("  python scanner.py --target 127.0.0.1 --ports 1-1000")
    sys.exit(1)


if start_port < 1 or end_port > 65535 or start_port > end_port:
    print("Invalid port range.")
    print("Ports must be between 1 and 65535.")
    sys.exit(1)


print("=" * 50)
print("          NETWORK SECURITY SCANNER")
print("=" * 50)

print(f"\nTarget : {target}")
print(f"Range  : {start_port}-{end_port}")

print("\n[+] Starting scan...\n")

start_time = time.perf_counter()

open_ports = []
scan_results = []

ports = range(start_port, end_port + 1)

with ThreadPoolExecutor(max_workers=threads) as executor:

    results = executor.map(lambda port: scan_single_port(target, port, timeout), ports)

    for port, state in results:

        scan_results.append({"port": port, "state": state})

        if state == "OPEN":
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)

print("\n[+] Detecting services and versions...\n")

try:
    service_results = detect_services(target, open_ports)

except RuntimeError as error:
    print(f"\n[ERROR] {error}")
    print("Service detection failed. Scan reports were not generated.")
    sys.exit(1)

if service_results:
    print("Service Detection Results:")
    print("-" * 100)

    for result in service_results:

        risk = analyze_risk(result)

        result["risk_level"] = risk["risk_level"]
        result["risk_reason"] = risk["reason"]

        print(
            f"Port {result['port']}/{result['protocol']} | "
            f"State: {result['state']} | "
            f"Service: {result['service']} | "
            f"Product: {result['product']} | "
            f"Version: {result['version']} | "
            f"Risk: {result['risk_level']}"
        )

else:
    print("No open ports available for service detection.")

print("\n" + "=" * 50)
print("              SCAN COMPLETE")
print("=" * 50)

end_time = time.perf_counter()
scan_duration = end_time - start_time

save_json(
    target,
    f"{start_port}-{end_port}",
    end_port - start_port + 1,
    service_results,
    scan_duration,
    "outputs/scan_report.json",
)

save_csv(service_results, "outputs/scan_report.csv")

print(f"\nPorts scanned : {end_port - start_port + 1}")
print(f"Open ports   : {len(open_ports)}")
print(f"Scan duration : {scan_duration:.2f} seconds")

if open_ports:
    print("\nOpen ports:")
    for port in open_ports:
        print(f"  - {port}")
else:
    print("\nNo open ports found.")

risk_summary = generate_risk_summary(service_results)

print("\nRisk Summary:")
print("-" * 30)
print(f"HIGH   : {risk_summary['HIGH']}")
print(f"MEDIUM : {risk_summary['MEDIUM']}")
print(f"LOW    : {risk_summary['LOW']}")
print(f"INFO   : {risk_summary['INFO']}")
