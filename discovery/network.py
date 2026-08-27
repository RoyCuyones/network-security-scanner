import subprocess
import ipaddress


def get_default_route():
    """
    Get the default gateway, active interface,
    and local IPv4 address from Linux.
    """

    result = subprocess.run(
        ["ip", "-4", "route", "show", "default"],
        capture_output=True,
        text=True,
        check=True
    )

    line = result.stdout.strip()

    parts = line.split()

    gateway = None
    interface = None
    local_ip = None

    if "via" in parts:
        gateway = parts[parts.index("via") + 1]

    if "dev" in parts:
        interface = parts[parts.index("dev") + 1]

    if "src" in parts:
        local_ip = parts[parts.index("src") + 1]

    return gateway, interface, local_ip


def get_prefix_length(interface, local_ip):
    """
    Get the CIDR prefix length assigned to the local IPv4 address.
    """

    result = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True
    )

    for line in result.stdout.splitlines():
        line = line.strip()

        if line.startswith("inet "):
            address_with_prefix = line.split()[1]

            address, prefix = address_with_prefix.split("/")

            if address == local_ip:
                return int(prefix)

    return None

def calculate_subnet(local_ip, prefix):
    """
    Calculate the network address from an IP and prefix.
    """

    network = ipaddress.ip_network(
        f"{local_ip}/{prefix}",
        strict=False
    )

    return str(network)


def detect_network():
    """
    Detect the current active IPv4 network information.
    """

    gateway, interface, local_ip = get_default_route()

    prefix = get_prefix_length(interface, local_ip)

    if prefix is None:
        raise RuntimeError("Unable to determine IPv4 prefix length.")

    subnet = calculate_subnet(local_ip, prefix)

    return {
        "interface": interface,
        "ip": local_ip,
        "prefix": prefix,
        "subnet": subnet,
        "gateway": gateway
    }


if __name__ == "__main__":
    network = detect_network()

    print("Interface:", network["interface"])
    print("Local IP:", network["ip"])
    print("Prefix:", f'/{network["prefix"]}')
    print("Subnet:", network["subnet"])
    print("Gateway:", network["gateway"])
