import subprocess


def parse_arp_scan_output(output):
    """
    Parse arp-scan output into a dictionary
    indexed by IPv4 address.

    Example output line:

        192.168.1.10    AA:BB:CC:DD:EE:FF    Vendor Name

    Returned structure:

        {
            "192.168.1.10": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "vendor": "Vendor Name"
            }
        }
    """

    devices = {}

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        parts = line.split("\t")

        if len(parts) < 2:
            continue

        ip_address = parts[0].strip()
        mac_address = parts[1].strip()

        vendor = "Unknown"

        if len(parts) >= 3:
            vendor_text = parts[2].strip()

            if vendor_text:
                vendor = vendor_text

        # arp-scan also prints summary/header lines.
        # A valid device line should contain an IPv4
        # style address and a MAC address.
        if ip_address.count(".") != 3:
            continue

        if ":" not in mac_address:
            continue

        devices[ip_address] = {
            "mac": mac_address,
            "vendor": vendor
        }

    return devices


def discover_arp_devices(interface=None):
    """
    Use arp-scan to discover local IPv4 devices.

    This is useful for obtaining:
        IP address
        MAC address
        MAC vendor

    arp-scan requires elevated privileges on
    most Linux systems.

    If an interface is supplied, arp-scan will
    use that specific network interface.
    """

    command = [
        "arp-scan",
        "--localnet"
    ]

    if interface:
        command.extend([
            "--interface",
            interface
        ])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

    except FileNotFoundError:
        print(
            "[!] arp-scan is not installed."
        )

        return {}

    except subprocess.CalledProcessError as error:

        print(
            "[!] arp-scan could not run."
        )

        if error.stderr:
            print(
                error.stderr.strip()
            )

        print(
            "[!] Try running the program "
            "with sudo."
        )

        return {}

    return parse_arp_scan_output(
        result.stdout
    )


if __name__ == "__main__":

    devices = discover_arp_devices()

    if not devices:
        print(
            "No ARP devices discovered."
        )

    for ip_address, info in devices.items():

        print(
            "IP Address :",
            ip_address
        )

        print(
            "MAC Address:",
            info["mac"]
        )

        print(
            "Vendor     :",
            info["vendor"]
        )

        print("-" * 50)
