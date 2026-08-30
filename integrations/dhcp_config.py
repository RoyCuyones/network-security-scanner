import json
import os


CONFIG_FILE = "dhcp_integration.json"


def load_dhcp_config():
    """
    Load DHCP integration settings.

    If no configuration exists or the file is invalid,
    return an unconfigured state.
    """

    if not os.path.exists(CONFIG_FILE):
        return {
            "provider": None,
            "router_ip": None
        }

    try:
        with open(CONFIG_FILE, "r") as file:
            config = json.load(file)

    except (OSError, json.JSONDecodeError):
        return {
            "provider": None,
            "router_ip": None
        }

    return {
        "provider": config.get("provider"),
        "router_ip": config.get("router_ip")
    }


def save_dhcp_config(
    provider,
    router_ip
):
    """
    Save DHCP integration settings locally.
    """

    config = {
        "provider": provider,
        "router_ip": router_ip
    }

    with open(CONFIG_FILE, "w") as file:
        json.dump(
            config,
            file,
            indent=4
        )


def remove_dhcp_config():
    """
    Remove the saved DHCP integration configuration.
    """

    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
