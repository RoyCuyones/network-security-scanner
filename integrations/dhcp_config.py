import json
import os


CONFIG_FILE = "dhcp_integration.json"


def load_dhcp_config():
    """
    Load DHCP integration settings.

    If no configuration exists, return
    a disabled default configuration.
    """

    if not os.path.exists(CONFIG_FILE):
        return {
            "enabled": False,
            "provider": None,
            "router_ip": None
        }

    try:
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)

    except (OSError, json.JSONDecodeError):
        return {
            "enabled": False,
            "provider": None,
            "router_ip": None
        }

    return {
        "enabled": config.get("enabled", False),
        "provider": config.get("provider"),
        "router_ip": config.get("router_ip")
    }

def save_dhcp_config(
    enabled,
    provider=None,
    router_ip=None
):
    """
    Save DHCP integration settings locally.
    """

    config = {
        "enabled": enabled,
        "provider": provider,
        "router_ip": router_ip
    }

    with open(CONFIG_FILE, "w") as file:
        json.dump(
            config,
            file,
            indent=4
        )
