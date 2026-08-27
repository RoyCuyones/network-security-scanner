import subprocess
import xml.etree.ElementTree as ET

from discovery.network import detect_network
from discovery.hostname import resolve_hostname
from discovery.ssdp import discover_ssdp_devices
from discovery.arp import discover_arp_devices

from enrichment.device_type import classify_device
from enrichment.mac_info import (
    get_mac_type,
    normalize_vendor
)


def discover_hosts(subnet, interface=None):
    """
    Discover live devices on the local subnet.

    Information collected:
        Device Name
        Category
        Device Type
        IP Address
        MAC Address
        MAC Type
        Vendor
        Status
    """

    # Discover SSDP/UPnP information once
    # for the whole local network.
    ssdp_devices = discover_ssdp_devices()

    # Discover local IP/MAC/vendor information
    # using ARP.
    arp_devices = discover_arp_devices(
        interface
    )

    # Nmap host discovery.
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

    for host in root.findall("host"):

        status = host.find("status")

        if status is None:
            continue

        if status.get("state") != "up":
            continue

        ipv4_address = host.find(
            "address[@addrtype='ipv4']"
        )

        if ipv4_address is None:
            continue

        ip_address = ipv4_address.get(
            "addr"
        )

        # -----------------------------------------
        # DEVICE NAME
        # -----------------------------------------

        hostname = resolve_hostname(
            ip_address
        )

        ssdp_info = ssdp_devices.get(
            ip_address,
            {}
        )

        ssdp_name = ssdp_info.get(
            "friendly_name"
        )

        # Use SSDP friendly name only when
        # our normal hostname resolver failed.
        if (
            hostname == "Unknown"
            and ssdp_name
        ):
            hostname = ssdp_name

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

        # Then use ARP information as another source.
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
        # MAC TYPE
        # -----------------------------------------

        mac_type = get_mac_type(
            mac
        )

        # Clean arp-scan messages such as:
        #
        # Unknown: locally administered
        #
        # into something easier for the final report.
        vendor = normalize_vendor(
            vendor,
            mac_type
        )

        # -----------------------------------------
        # CATEGORY + DEVICE TYPE
        # -----------------------------------------

        classification = classify_device(
            hostname=hostname,
            vendor=vendor,
            ssdp_info=ssdp_info
        )

        category = classification[
            "category"
        ]

        device_type = classification[
            "device_type"
        ]

        # -----------------------------------------
        # FINAL DEVICE RECORD
        # -----------------------------------------

        live_hosts.append({
            "hostname": hostname,
            "category": category,
            "device_type": device_type,
            "ip": ip_address,
            "mac": mac,
            "mac_type": mac_type,
            "vendor": vendor,
            "status": "Online",

        # Internal enrichment data.
        # This is not shown in the normal output.
            "_ssdp_info": ssdp_info
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
        network["interface"]
    )

    print("\nLive hosts found:\n")

    for host in hosts:

        print(
            "Device Name :",
            host["hostname"]
        )

        print(
            "Category    :",
            host["category"]
        )

        print(
            "Device Type :",
            host["device_type"]
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
