def build_device_fingerprint(
    host,
    ports=None,
    ssdp_info=None
):
    """
    Build a normalized fingerprint from factual
    network evidence.

    This function does NOT classify the device.
    It only collects and organizes evidence.
    """

    if ports is None:
        ports = []

    if ssdp_info is None:
        ssdp_info = {}

    # -----------------------------------------
    # OPEN PORTS + SERVICE EVIDENCE
    # -----------------------------------------

    open_ports = []
    services = []
    service_details = []

    for port in ports:

        port_number = port.get(
            "port"
        )

        protocol = port.get(
            "protocol"
        )

        service = port.get(
            "service"
        )

        product = port.get(
            "product"
        )

        version = port.get(
            "version"
        )

        if port_number is not None:
            open_ports.append(
                str(port_number)
            )

        if service:
            services.append(
                str(service).strip().lower()
            )

        service_details.append({
            "port": (
                str(port_number)
                if port_number is not None
                else None
            ),

            "protocol": (
                str(protocol).strip().lower()
                if protocol
                else None
            ),

            "service": (
                str(service).strip().lower()
                if service
                else None
            ),

            "product": (
                str(product).strip()
                if product
                else None
            ),

            "version": (
                str(version).strip()
                if version
                else None
            )
        })

    # -----------------------------------------
    # MDNS SERVICES
    # -----------------------------------------

    mdns_services = host.get(
        "mdns_services",
        []
    )

    normalized_mdns_services = []

    for service in mdns_services:

        if not service:
            continue

        normalized_service = (
            str(service)
            .strip()
            .lower()
        )

        if normalized_service:
            normalized_mdns_services.append(
                normalized_service
            )

    # -----------------------------------------
    # FINAL FINGERPRINT
    # -----------------------------------------

    fingerprint = {
        "hostname": host.get(
            "hostname",
            "Unknown"
        ),

        "hostname_source": host.get(
            "hostname_source"
        ),

        "mac_source": host.get(
            "mac_source"
        ),

        "mac_type": host.get(
            "mac_type",
            "Unknown"
        ),

        "vendor": host.get(
            "vendor",
            "Unknown"
        ),

        "ssdp": {
            "friendly_name": ssdp_info.get(
                "friendly_name"
            ),

            "manufacturer": ssdp_info.get(
                "manufacturer"
            ),

            "model_name": ssdp_info.get(
                "model_name"
            ),

            "device_type_raw": ssdp_info.get(
                "device_type_raw"
            )
        },

        "mdns_services": sorted(
            set(
                normalized_mdns_services
            )
        ),

        "open_ports": sorted(
            set(
                open_ports
            )
        ),

        "services": sorted(
            set(
                services
            )
        ),

        "service_details": service_details
    }

    return fingerprint
