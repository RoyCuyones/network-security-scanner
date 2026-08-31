import subprocess
import xml.etree.ElementTree as ET

from discovery.network import detect_network
from discovery.hostname import resolve_hostname
from discovery.ssdp import discover_ssdp_devices
from discovery.arp import discover_arp_devices

from enrichment.mac_info import (
    get_mac_type,
    normalize_vendor
)

from integrations.dhcp_clients import get_dhcp_clients

def normalize_mac_address(mac):
    """
    Convert MAC addresses into one consistent format.

    Examples:
        AA:BB:CC:DD:EE:FF
        aa-bb-cc-dd-ee-ff

    become:

        aa:bb:cc:dd:ee:ff
    """

    if not mac or mac == "Unknown":
        return None

    return mac.strip().replace("-", ":").lower()


def build_router_client_lookup(clients):
    """
    Build a MAC-address lookup table from the Huawei
    DHCP/client table.

    Example:

        {
            "9a:9d:08:34:7e:03": {
                "hostname": "POCO-X3-GT",
                "ip": "192.168.254.145",
                "mac": "9a:9d:08:34:7e:03"
            }
        }

    MAC address is used instead of IP because DHCP
    addresses can change.
    """

    lookup = {}

    for client in clients:

        mac = normalize_mac_address(
            client.get("mac")
        )

        if not mac:
            continue

        lookup[mac] = client

    return lookup


def discover_hosts(
    subnet, 
    interface=None,
    router_ip=None,
    dhcp_provider=None
):

    ssdp_devices = discover_ssdp_devices()

    arp_devices = discover_arp_devices(
        interface
    )

    # -----------------------------------------
    # HUAWEI DHCP CLIENT TABLE
    # -----------------------------------------

    router_clients_by_mac = {}
    router_clients_by_ip = {}

    if router_ip:
        try:
            router_clients = get_dhcp_clients(
		dhcp_provider,
                router_ip
            )

            router_clients_by_mac = (
                build_router_client_lookup(
                    router_clients
                )
            )

            router_clients_by_ip = {
                client["ip"]: client
                for client in router_clients
                if client.get("ip")
            }

        except Exception:
            pass

    # -----------------------------------------
    # NMAP HOST DISCOVERY
    # -----------------------------------------

    result = subprocess.run(
        [
            "nmap",
            "-sn",
            "-oX",
            "-",
            subnet
        ],
        capture_output=True,
        text=True,
        check=True
    )

    root = ET.fromstring(
        result.stdout
    )

    live_hosts = []

    # -----------------------------------------
    # PROCESS DISCOVERED HOSTS
    # -----------------------------------------

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        # -----------------------------------------
        # IP ADDRESS
        # -----------------------------------------

        ipv4_address = host.find(
            "address[@addrtype='ipv4']"
        )

        if ipv4_address is None:
            continue

        ip_address = ipv4_address.get(
            "addr"
        )

        # -----------------------------------------
        # SSDP INFORMATION
        # -----------------------------------------

        ssdp_info = ssdp_devices.get(
            ip_address,
            {}
        )

        ssdp_name = ssdp_info.get(
            "friendly_name"
        )

        # -----------------------------------------
        # MAC ADDRESS + VENDOR
        # -----------------------------------------

        mac = "Unknown"
        vendor = "Unknown"

        # First try the MAC returned by Nmap.
        mac_address = host.find(
            "address[@addrtype='mac']"
        )

        if mac_address is not None:

            mac = mac_address.get(
                "addr",
                "Unknown"
            )

            vendor = mac_address.get(
                "vendor",
                "Unknown"
            )

        # Then try ARP information when Nmap
        # did not provide a MAC/vendor.
        arp_info = arp_devices.get(
            ip_address
        )

        if arp_info:

            if mac == "Unknown":
                mac = arp_info.get(
                    "mac",
                    "Unknown"
                )

            if vendor == "Unknown":
                vendor = arp_info.get(
                    "vendor",
                    "Unknown"
                )

        # -----------------------------------------
        # DHCP CLIENT MATCHING
        # -----------------------------------------

        router_client = None

        # First try matching the existing MAC
        # against the router DHCP table.
        normalized_mac = normalize_mac_address(
            mac
        )

        if normalized_mac:
            router_client = (
                router_clients_by_mac.get(
                    normalized_mac
                )
            )

        # If no MAC match is available, fall
        # back to matching by IP address.
        if router_client is None:
            router_client = (
                router_clients_by_ip.get(
                    ip_address
                )
            )

        # If Nmap and ARP could not provide a
        # MAC address, use the MAC recorded by
        # the router DHCP client table.
        if (
            mac == "Unknown"
            and router_client
        ):

            router_mac = router_client.get(
                "mac"
            )

            if router_mac:
                mac = router_mac.upper()

        # -----------------------------------------
        # MAC TYPE
        # -----------------------------------------

        # Determine MAC type only AFTER all
        # available MAC sources have been tried.
        mac_type = get_mac_type(
            mac
        )

        vendor = normalize_vendor(
            vendor,
            mac_type
        )

        # -----------------------------------------
        # DEVICE NAME
        # -----------------------------------------

        hostname = "Unknown"
        hostname_source = None

        # 1. Prefer the hostname from the router
        # DHCP table when available.
        if router_client:

            router_hostname = router_client.get(
                "hostname"
            )

            if router_hostname:

                router_hostname = (
                    router_hostname.strip()
                )

                if router_hostname:
                    hostname = router_hostname
                    hostname_source = "dhcp"

        # 2. If DHCP did not provide a hostname,
        # try local hostname-resolution methods.
        if hostname == "Unknown":

            hostname_result = resolve_hostname(
                ip_address
            )

            hostname = hostname_result.get(
                "hostname",
                "Unknown"
            )

            hostname_source = hostname_result.get(
                "source"
            )

        # 3. Fall back to SSDP friendly name.
        if (
            hostname == "Unknown"
            and ssdp_name
        ):

            hostname = ssdp_name
            hostname_source = "ssdp"

        # -----------------------------------------
        # FINAL DEVICE RECORD
        # -----------------------------------------

        live_hosts.append({
            "hostname": hostname,
            "hostname_source": hostname_source,
            "ip": ip_address,
        })

    return live_hosts


if __name__ == "__main__":

    network = detect_network()

    print(
        "Detected subnet:",
        network["subnet"]
    )

    hosts = discover_hosts(
        network["subnet"],
        network["interface"],
	network["gateway"]
    )

    print("\nLive hosts found:\n")

    for host in hosts:

        print(
            "Device Name :",
            host["hostname"]
        )

        print(
            "IP Address  :",
            host["ip"]
        )

        print(
            "MAC Address :",
            host["mac"]
        )

        print(
            "MAC Type    :",
            host["mac_type"]
        )

        print(
            "Vendor      :",
            host["vendor"]
        )

        print(
            "Status      :",
            host["status"]
        )

        print("-" * 50)
