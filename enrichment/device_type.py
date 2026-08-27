def normalize_text(value):
    """
    Convert a value into lowercase searchable text.
    """

    if not value:
        return ""

    return str(value).strip().lower()


def contains_any(text, keywords):
    """
    Return True if any keyword exists in text.
    """

    return any(
        keyword in text
        for keyword in keywords
    )


def build_service_text(ports):
    """
    Convert Nmap port/service results into one
    searchable text string.

    Example input:

        [
            {
                "port": "22",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.6"
            }
        ]

    becomes something similar to:

        "22 ssh openssh 9.6"
    """

    if not ports:
        return ""

    values = []

    for port in ports:

        values.append(
            normalize_text(
                port.get("port")
            )
        )

        values.append(
            normalize_text(
                port.get("service")
            )
        )

        values.append(
            normalize_text(
                port.get("product")
            )
        )

        values.append(
            normalize_text(
                port.get("version")
            )
        )

    return " ".join(values)


def get_open_port_numbers(ports):
    """
    Return a set containing detected open
    TCP port numbers.

    Example:

        {"22", "80", "443"}
    """

    if not ports:
        return set()

    return {
        str(port.get("port"))
        for port in ports
        if port.get("port")
    }


def classify_device(
    hostname="Unknown",
    vendor="Unknown",
    ssdp_info=None,
    ports=None
):
    """
    Estimate the device's category and type.

    Evidence currently includes:

        hostname
        MAC vendor
        SSDP/UPnP metadata
        Nmap ports
        Nmap services/products

    This is best-effort fingerprinting and
    should not be treated as guaranteed identity.
    """

    if ssdp_info is None:
        ssdp_info = {}

    if ports is None:
        ports = []

    hostname_text = normalize_text(
        hostname
    )

    vendor_text = normalize_text(
        vendor
    )

    friendly_name = normalize_text(
        ssdp_info.get("friendly_name")
    )

    manufacturer = normalize_text(
        ssdp_info.get("manufacturer")
    )

    model_name = normalize_text(
        ssdp_info.get("model_name")
    )

    device_type_raw = normalize_text(
        ssdp_info.get("device_type_raw")
    )

    service_text = build_service_text(
        ports
    )

    open_ports = get_open_port_numbers(
        ports
    )

    combined = " ".join([
        hostname_text,
        vendor_text,
        friendly_name,
        manufacturer,
        model_name,
        device_type_raw,
        service_text
    ])

    # =================================================
    # PRINTER
    # =================================================

    if (
        "9100" in open_ports
        or "631" in open_ports
        or contains_any(
            combined,
            [
                "printer",
                "laserjet",
                "officejet",
                "deskjet",
                "jetdirect",
                "ipp"
            ]
        )
    ):
        return {
            "category": "Printer",
            "device_type": "Network Printer"
        }

    # =================================================
    # DOMAIN CONTROLLER
    # =================================================

    domain_controller_ports = {
        "53",
        "88",
        "389",
        "445"
    }

    if domain_controller_ports.issubset(
        open_ports
    ):
        return {
            "category": "Server",
            "device_type": "Possible Domain Controller"
        }

    # =================================================
    # DATABASE SERVER
    # =================================================

    if (
        "3306" in open_ports
        or "5432" in open_ports
        or "1433" in open_ports
        or "1521" in open_ports
        or contains_any(
            service_text,
            [
                "mysql",
                "postgresql",
                "microsoft sql",
                "oracle"
            ]
        )
    ):
        return {
            "category": "Server",
            "device_type": "Database Server"
        }

    # =================================================
    # FILE SERVER / NAS
    # =================================================

    if contains_any(
        combined,
        [
            "synology",
            "qnap",
            "nas"
        ]
    ):
        return {
            "category": "Storage",
            "device_type": "NAS"
        }

    if (
        "445" in open_ports
        and contains_any(
            service_text,
            [
                "smb",
                "microsoft-ds",
                "samba"
            ]
        )
    ):
        return {
            "category": "Server",
            "device_type": "Possible File Server"
        }

    # =================================================
    # WEB SERVER
    # =================================================

    web_ports = {
        "80",
        "443",
        "8080",
        "8443"
    }

    if (
        open_ports.intersection(
            web_ports
        )
        and contains_any(
            service_text,
            [
                "apache",
                "nginx",
                "httpd",
                "iis"
            ]
        )
    ):
        return {
            "category": "Server",
            "device_type": "Web Server"
        }

    # =================================================
    # NETWORK INFRASTRUCTURE
    # =================================================

    if contains_any(
        combined,
        [
            "firewall",
            "pfsense",
            "opnsense",
            "fortigate",
            "fortinet",
            "sophos firewall"
        ]
    ):
        return {
            "category": "Network Infrastructure",
            "device_type": "Firewall"
        }

    if contains_any(
        combined,
        [
            "access point",
            "wireless ap",
            "wifi ap",
            "wi-fi ap"
        ]
    ):
        return {
            "category": "Network Infrastructure",
            "device_type": "Wireless Access Point"
        }

    if contains_any(
        combined,
        [
            "switch",
            "catalyst"
        ]
    ):
        return {
            "category": "Network Infrastructure",
            "device_type": "Managed Switch"
        }

    if contains_any(
        combined,
        [
            "router"
        ]
    ):
        return {
            "category": "Network Infrastructure",
            "device_type": "Router"
        }

    if contains_any(
        combined,
        [
            "gateway"
        ]
    ):
        return {
            "category": "Network Infrastructure",
            "device_type": "Gateway"
        }

    # =================================================
    # SMART TV / MEDIA
    # =================================================

    if contains_any(
        combined,
        [
            "tizen",
            "smart tv",
            "smarttv",
            "television",
            "mediarenderer"
        ]
    ):
        return {
            "category": "Media Device",
            "device_type": "Smart TV"
        }

    if contains_any(
        combined,
        [
            "chromecast",
            "roku",
            "fire tv",
            "apple tv",
            "appletv"
        ]
    ):
        return {
            "category": "Media Device",
            "device_type": "Streaming Device"
        }

    if contains_any(
        combined,
        [
            "playstation",
            "xbox",
            "nintendo"
        ]
    ):
        return {
            "category": "Media Device",
            "device_type": "Game Console"
        }

    # =================================================
    # SURVEILLANCE
    # =================================================

    if contains_any(
        combined,
        [
            "nvr"
        ]
    ):
        return {
            "category": "Security / Surveillance",
            "device_type": "NVR"
        }

    if contains_any(
        combined,
        [
            "dvr"
        ]
    ):
        return {
            "category": "Security / Surveillance",
            "device_type": "DVR"
        }

    if contains_any(
        combined,
        [
            "ip camera",
            "ipcam",
            "network camera",
            "camera"
        ]
    ):
        return {
            "category": "Security / Surveillance",
            "device_type": "IP Camera"
        }

    # =================================================
    # PHONES
    # =================================================

    if contains_any(
        combined,
        [
            "iphone"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "iPhone"
        }

    if contains_any(
        combined,
        [
            "poco",
            "redmi",
            "realme",
            "tecno",
            "android",
            "pixel"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "Android Smartphone"
        }

    # =================================================
    # TABLETS
    # =================================================

    if contains_any(
        combined,
        [
            "ipad"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "iPad"
        }

    if contains_any(
        combined,
        [
            "tablet",
            "galaxy-tab",
            "galaxy tab"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "Tablet"
        }

    # =================================================
    # WORKSTATIONS
    # =================================================

    if contains_any(
        combined,
        [
            "macbook",
            "imac"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "macOS Workstation"
        }

    if contains_any(
        combined,
        [
            "ubuntu",
            "linux workstation"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "Linux Workstation"
        }

    if contains_any(
        combined,
        [
            "windows workstation",
            "windows desktop"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "Windows Workstation"
        }

    if contains_any(
        combined,
        [
            "desktop",
            "laptop",
            "thinkpad",
            "workstation"
        ]
    ):
        return {
            "category": "Endpoint",
            "device_type": "Workstation"
        }

    # =================================================
    # GENERIC SERVER
    # =================================================

    if contains_any(
        combined,
        [
            "server",
            "-srv",
            "srv-"
        ]
    ):
        return {
            "category": "Server",
            "device_type": "General Server"
        }

    # =================================================
    # IOT
    # =================================================

    if contains_any(
        combined,
        [
            "iot",
            "smart plug",
            "smart bulb",
            "smart light",
            "smart home"
        ]
    ):
        return {
            "category": "IoT",
            "device_type": "IoT Device"
        }

    # =================================================
    # NOTHING STRONG ENOUGH
    # =================================================

    return {
        "category": "Unknown",
        "device_type": "Unknown Device"
    }
def refine_device_classification(
    device,
    ports
):
    """
    Reclassify a discovered device after an
    Nmap service scan has provided more evidence.

    The original device dictionary is updated
    with the refined category and device type.
    """

    classification = classify_device(
        hostname=device.get(
            "hostname",
            "Unknown"
        ),
        vendor=device.get(
            "vendor",
            "Unknown"
        ),
        ssdp_info=device.get(
            "_ssdp_info",
            {}
        ),
        ports=ports
    )

    device["category"] = classification[
        "category"
    ]

    device["device_type"] = classification[
        "device_type"
    ]

    return device

if __name__ == "__main__":

    tests = [
        {
            "name": "Printer example",
            "hostname": "Unknown",
            "vendor": "HP",
            "ports": [
                {
                    "port": "9100",
                    "service": "jetdirect",
                    "product": "HP JetDirect",
                    "version": "Unknown"
                }
            ]
        },
        {
            "name": "Database server example",
            "hostname": "DB01",
            "vendor": "Unknown",
            "ports": [
                {
                    "port": "3306",
                    "service": "mysql",
                    "product": "MySQL",
                    "version": "8.0"
                }
            ]
        },
        {
            "name": "Phone example",
            "hostname": "POCO-X3-GT",
            "vendor": "Not identifiable",
            "ports": []
        }
    ]

    for test in tests:

        result = classify_device(
            hostname=test["hostname"],
            vendor=test["vendor"],
            ports=test["ports"]
        )

        print(test["name"])

        print(
            "Category   :",
            result["category"]
        )

        print(
            "Device Type:",
            result["device_type"]
        )

        print("-" * 50)
