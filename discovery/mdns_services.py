import subprocess


def discover_mdns_services():
    """
    Discover mDNS/DNS-SD services advertised
    by devices on the local network.

    Returns a dictionary grouped by IP address.

    Example:
    {
        "192.168.1.10": [
            "_airplay._tcp",
            "_raop._tcp"
        ]
    }
    """

    services_by_ip = {}

    try:
        result = subprocess.run(
            [
                "avahi-browse",
                "-art"
            ],
            capture_output=True,
            text=True,
            timeout=10
        )

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired
    ):
        return services_by_ip

    for line in result.stdout.splitlines():

        if not line.startswith("="):
            continue

        parts = line.split(";")

        if len(parts) < 9:
            continue

        service_type = parts[4].strip()
        ip_address = parts[7].strip()

        if not service_type:
            continue

        if not ip_address:
            continue

        if ip_address not in services_by_ip:
            services_by_ip[ip_address] = []

        if (
            service_type
            not in services_by_ip[ip_address]
        ):
            services_by_ip[ip_address].append(
                service_type
            )

    for ip_address in services_by_ip:

        services_by_ip[ip_address].sort()

    return services_by_ip
