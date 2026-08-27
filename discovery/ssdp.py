import socket
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse


SSDP_ADDRESS = "239.255.255.250"
SSDP_PORT = 1900


def get_xml_text(root, tag_name):
    """
    Search a UPnP XML document for a tag.

    UPnP XML commonly uses namespaces such as:
        {urn:schemas-upnp-org:device-1-0}friendlyName

    Using endswith() lets us find the tag without
    having to know the namespace ahead of time.
    """

    if root is None:
        return None

    for element in root.iter():
        if element.tag.endswith(tag_name):
            if element.text:
                return element.text.strip()

    return None


def fetch_device_description(location, expected_ip):
    """
    Download a UPnP device-description XML file.

    We only accept a LOCATION URL whose hostname
    matches the IP that sent the SSDP response.

    This prevents the scanner from following an
    arbitrary URL advertised by another device.
    """

    try:
        parsed = urlparse(location)

        if parsed.scheme not in ("http", "https"):
            return {}

        if parsed.hostname != expected_ip:
            return {}

        request = urllib.request.Request(
            location,
            headers={
                "User-Agent": "LocalNetworkAuditor/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=2
        ) as response:

            # Limit how much XML we accept from a device.
            xml_data = response.read(262144)

        root = ET.fromstring(xml_data)

        return {
            "friendly_name": get_xml_text(
                root,
                "friendlyName"
            ),
            "manufacturer": get_xml_text(
                root,
                "manufacturer"
            ),
            "model_name": get_xml_text(
                root,
                "modelName"
            ),
            "device_type_raw": get_xml_text(
                root,
                "deviceType"
            )
        }

    except (
        urllib.error.URLError,
        TimeoutError,
        ET.ParseError,
        ValueError
    ):
        return {}

    except Exception:
        return {}


def parse_ssdp_headers(data):
    """
    Convert an SSDP response into a dictionary.

    Example header:

        LOCATION: http://192.168.1.20/device.xml

    becomes:

        {
            "location":
            "http://192.168.1.20/device.xml"
        }
    """

    text = data.decode(
        errors="ignore"
    )

    headers = {}

    lines = text.split("\r\n")

    for line in lines[1:]:
        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        headers[
            key.strip().lower()
        ] = value.strip()

    return headers


def discover_ssdp_devices(timeout=3):
    """
    Search the local network for SSDP/UPnP devices.

    Returns a dictionary indexed by IPv4 address.

    Example:

        {
            "192.168.1.50": {
                "friendly_name": "Living Room TV",
                "manufacturer": "Samsung",
                "model_name": "Smart TV",
                "device_type_raw":
                    "urn:schemas-upnp-org:device:MediaRenderer:1"
            }
        }
    """

    message = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDRESS}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP
    )

    sock.settimeout(timeout)

    devices = {}

    try:
        sock.sendto(
            message.encode(),
            (
                SSDP_ADDRESS,
                SSDP_PORT
            )
        )

        while True:
            try:
                data, sender = sock.recvfrom(
                    65535
                )

            except socket.timeout:
                break

            ip_address = sender[0]

            headers = parse_ssdp_headers(
                data
            )

            location = headers.get(
                "location"
            )

            if not location:
                continue

            info = fetch_device_description(
                location,
                ip_address
            )

            if ip_address not in devices:
                devices[ip_address] = {}

            for key, value in info.items():
                if (
                    value
                    and not devices[
                        ip_address
                    ].get(key)
                ):
                    devices[
                        ip_address
                    ][key] = value

    finally:
        sock.close()

    return devices


if __name__ == "__main__":
    devices = discover_ssdp_devices()

    if not devices:
        print(
            "No SSDP/UPnP devices discovered."
        )

    for ip_address, info in devices.items():

        print("\nIP:", ip_address)

        print(
            "Friendly Name:",
            info.get(
                "friendly_name",
                "Unknown"
            )
        )

        print(
            "Manufacturer:",
            info.get(
                "manufacturer",
                "Unknown"
            )
        )

        print(
            "Model:",
            info.get(
                "model_name",
                "Unknown"
            )
        )

        print(
            "Device Type:",
            info.get(
                "device_type_raw",
                "Unknown"
            )
        )
