import csv
import json


def generate_risk_summary(service_results):
    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for result in service_results:
        risk_level = result.get("risk_level", "INFO")

        if risk_level in summary:
            summary[risk_level] += 1

    return summary


def save_json(
    target, port_range, ports_scanned, service_results, scan_duration, filename
):
    risk_summary = generate_risk_summary(service_results)

    report = {
        "target": target,
        "port_range": port_range,
        "ports_scanned": ports_scanned,
        "open_ports": len(service_results),
        "scan_duration_seconds": round(scan_duration, 2),
        "risk_summary": risk_summary,
        "results": service_results,
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"[+] JSON report saved: {filename}")


def save_csv(service_results, filename):
    fieldnames = [
        "port",
        "protocol",
        "state",
        "service",
        "product",
        "version",
        "risk_level",
        "risk_reason",
    ]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        writer.writeheader()
        writer.writerows(service_results)

    print(f"[+] CSV report saved: {filename}")
