import subprocess
import xml.etree.ElementTree as ET


def scan_host(ip_address):
    """
    Scan the top 100 TCP ports of one host.

    Also performs basic service/version detection.

    Returns:
        A list of dictionaries containing information
        about each open TCP port.
    """

    result = subprocess.run(
        [
            "nmap",
            "-sV",
            "--top-ports",
            "100",
            "-oX",
            "-",
            ip_address
        ],
        capture_output=True,
        text=True,
        check=True
    )

    root = ET.fromstring(result.stdout)

    open_ports = []

    for host in root.findall("host"):
        ports = host.find("ports")

        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")

            if state is None:
                continue

            if state.get("state") != "open":
                continue

            port_number = port.get("portid")
            protocol = port.get("protocol")

            service = port.find("service")

            if service is not None:
                service_name = service.get("name", "Unknown")
                product = service.get("product", "Unknown")
                version = service.get("version", "Unknown")
            else:
                service_name = "Unknown"
                product = "Unknown"
                version = "Unknown"

            open_ports.append({
                "port": port_number,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version
            })

    return open_ports


if __name__ == "__main__":
    ip_address = input("Enter IP address to scan: ")

    ports = scan_host(ip_address)

    print("\nOpen ports found:")

    if not ports:
        print("No open ports found in the top 100 TCP ports.")

    for port in ports:
        print(
            f'{port["port"]}/{port["protocol"]}',
            "-",
            port["service"],
            "-",
            port["product"],
            "-",
            port["version"]
        )
