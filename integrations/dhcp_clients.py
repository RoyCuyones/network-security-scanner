from integrations.providers.huawei_hg8145v5 import get_huawei_clients


def get_dhcp_clients(provider, router_ip):
    """
    Return DHCP/client-table entries using the selected provider.

    The rest of the scanner should call this function instead
    of importing router-specific modules directly.
    """

    if not provider:
        return []

    if not router_ip:
        return []

    if provider == "huawei_hg8145v5":
        return get_huawei_clients(router_ip)

    return []
