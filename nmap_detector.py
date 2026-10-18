import subprocess
import xml.etree.ElementTree as ET


def detect_services(target, open_ports):
    if not open_ports:
        return []

    ports = ",".join(str(port) for port in open_ports)

    command = ["nmap", "-sV", "-p", ports, "-oX", "-", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)

    except FileNotFoundError as error:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and verify that it is in PATH."
        ) from error

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "Nmap service detection timed out after 120 seconds."
        ) from error

    except OSError as error:
        raise RuntimeError(f"Unable to execute Nmap: {error}") from error

    if result.returncode != 0:
        message = result.stderr.strip() or "No error details provided."
        raise RuntimeError(f"Nmap scan failed: {message}")

    try:
        root = ET.fromstring(result.stdout)
    except ET.ParseError as error:
        raise RuntimeError("Nmap returned invalid XML output.") from error

    services = []

    for port in root.findall(".//port"):
        port_number = int(port.get("portid"))
        protocol = port.get("protocol")

        state_element = port.find("state")
        service_element = port.find("service")

        state = state_element.get("state") if state_element is not None else "unknown"

        service_name = (
            service_element.get("name") if service_element is not None else "unknown"
        )

        product = (
            service_element.get("product", "") if service_element is not None else ""
        )

        version = (
            service_element.get("version", "") if service_element is not None else ""
        )

        services.append(
            {
                "port": port_number,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version,
            }
        )

    return services


if __name__ == "__main__":
    target = "127.0.0.1"
    open_ports = [135, 445, 902, 912]

    try:
        results = detect_services(target, open_ports)

        for result in results:
            print(result)

    except RuntimeError as error:
        print(f"[ERROR] {error}")
