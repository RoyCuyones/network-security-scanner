def get_mac_type(mac_address):
    """
    Determine whether a MAC address is globally
    administered or locally administered.

    Returns:
        "Globally Administered"
        "Locally Administered / Private"
        "Unknown"
    """

    if not mac_address:
        return "Unknown"

    if mac_address == "Unknown":
        return "Unknown"

    try:
        first_octet = int(
            mac_address.split(":")[0],
            16
        )

    except (
        ValueError,
        IndexError
    ):
        return "Unknown"

    locally_administered = bool(
        first_octet & 0b00000010
    )

    if locally_administered:
        return "Locally Administered / Private"

    return "Globally Administered"


def normalize_vendor(vendor, mac_type):
    """
    Clean vendor information for display.
    """

    if not vendor:
        vendor = "Unknown"

    vendor = vendor.strip()
    vendor_lower = vendor.lower()

    if mac_type == "Locally Administered / Private":
        return "Not identifiable"

    if vendor_lower in (
        "unknown",
        "(unknown)"
    ):
        return "Not found in local OUI database"

    if "locally administered" in vendor_lower:
        return "Not identifiable"

    return vendor


if __name__ == "__main__":

    test_addresses = [
        "9A:11:22:33:44:55",
        "00:1A:2B:3C:4D:5E",
        "Unknown"
    ]

    for mac in test_addresses:

        mac_type = get_mac_type(
            mac
        )

        print(
            mac,
            "->",
            mac_type
        )
