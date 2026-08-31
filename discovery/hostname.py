import socket
import subprocess


def resolve_reverse_dns(ip_address):
    """
    Try reverse DNS / PTR lookup.
    """

    try:
        hostname, _, _ = socket.gethostbyaddr(
            ip_address
        )

        return hostname

    except (
        socket.herror,
        socket.gaierror
    ):
        return None


def resolve_mdns(ip_address):
    """
    Try mDNS using avahi-resolve-address.
    """

    try:
        result = subprocess.run(
            [
                "avahi-resolve-address",
                ip_address
            ],
            capture_output=True,
            text=True,
            timeout=3
        )

        if result.returncode != 0:
            return None

        output = result.stdout.strip()

        if not output:
            return None

        parts = output.split()

        if len(parts) >= 2:
            return parts[1]

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired
    ):
        pass

    return None


def resolve_netbios(ip_address):
    """
    Try NetBIOS name lookup with nmblookup.
    """

    try:
        result = subprocess.run(
            [
                "nmblookup",
                "-A",
                ip_address
            ],
            capture_output=True,
            text=True,
            timeout=3
        )

        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():

            line = line.strip()

            if (
                "<00>" in line
                and "GROUP" not in line
            ):

                parts = line.split()

                if parts:
                    return parts[0]

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired
    ):
        pass

    return None


def resolve_smb_name(ip_address):
    """
    Try to identify a Windows/SMB host using smbclient.

    We do not authenticate with credentials.
    This is only a lightweight anonymous probe.

    Some systems will reveal a useful server/computer
    name, while others will reject anonymous access.
    """

    try:
        result = subprocess.run(
            [
                "smbclient",
                "-L",
                f"//{ip_address}",
                "-N"
            ],
            capture_output=True,
            text=True,
            timeout=5
        )

        output = (
            result.stdout
            + "\n"
            + result.stderr
        )

        for line in output.splitlines():

            line = line.strip()

            # smbclient sometimes prints lines such as:
            #
            # Server               Comment
            #
            # or:
            #
            # SMB1 disabled -- no workgroup available
            #
            # This probe is intentionally conservative.
            # We only accept explicit server-name style
            # results rather than guessing.

            if line.lower().startswith(
                "server="
            ):
                name = line.split(
                    "=",
                    1
                )[1].strip()

                if name:
                    return name

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired
    ):
        pass

    return None


def clean_device_name(name):
    """
    Normalize and reject unusable device names.
    """

    if not name:
        return None

    name = name.strip()

    if name.lower().endswith(".local"):
        name = name[:-6]

    if not name:
        return None

    invalid_names = {
        "localhost",
        "localhost.localdomain",
        "unknown",
        "none"
    }

    if name.lower() in invalid_names:
        return None

    return name

def collect_hostname_candidates(ip_address):
    """
    Collect names from multiple discovery methods.

    These sources stay internal and are not required
    to appear in the normal user-facing output.
    """

    candidates = {
        "reverse_dns":
            clean_device_name(
                resolve_reverse_dns(
                    ip_address
                )
            ),

        "mdns":
            clean_device_name(
                resolve_mdns(
                    ip_address
                )
            ),

        "netbios":
            clean_device_name(
                resolve_netbios(
                    ip_address
                )
            ),

        "smb":
            clean_device_name(
                resolve_smb_name(
                    ip_address
                )
            )
    }

    return candidates


def select_best_hostname(candidates):
    """
    Choose the best available device name
    and return both the hostname and its source.

    Current priority:
        mDNS
        NetBIOS
        SMB
        Reverse DNS
    """

    priority = [
        "mdns",
        "netbios",
        "smb",
        "reverse_dns"
    ]

    for source in priority:

        hostname = candidates.get(
            source
        )

        if hostname:
            return {
                "hostname": hostname,
                "source": source
            }

    return {
        "hostname": "Unknown",
        "source": None
    }


def resolve_hostname(ip_address):
    """
    Resolve the best available hostname
    and include the discovery source.
    """

    candidates = collect_hostname_candidates(
        ip_address
    )

    return select_best_hostname(
        candidates
    )

if __name__ == "__main__":

    ip_address = input(
        "Enter IP address: "
    ).strip()

    candidates = collect_hostname_candidates(
        ip_address
    )

    print("\nHostname candidates:")

    print(
        "Reverse DNS:",
        candidates["reverse_dns"]
        or "Unknown"
    )

    print(
        "mDNS:",
        candidates["mdns"]
        or "Unknown"
    )

    print(
        "NetBIOS:",
        candidates["netbios"]
        or "Unknown"
    )

    print(
        "SMB:",
        candidates["smb"]
        or "Unknown"
    )

    print(
        "\nSelected Device Name:",
        select_best_hostname(
            candidates
        )
    )

