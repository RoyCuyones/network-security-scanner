import ipaddress
import subprocess

from rich.console import Console

from analysis.vulnerabilities import analyze_ports

from discovery.network import detect_network
from discovery.hosts import discover_hosts

from integrations.dhcp_config import (
    load_dhcp_config,
    save_dhcp_config,
    remove_dhcp_config
)

from scanning.nmap_scan import scan_host

from ui.display import (
    show_network_info,
    show_devices,
    show_scan_result
)


console = Console()


def discover_network_devices(network):
    """
    Discover live devices on the detected local subnet.
    """

    console.print(
        f'\n[bold]Discovering devices on '
        f'{network["subnet"]}...[/bold]'
    )

    dhcp_config = load_dhcp_config()

    hosts = discover_hosts(
        network["subnet"],
        network["interface"],
        dhcp_config["router_ip"],
        dhcp_config["provider"]
    )
    console.print(
        f"\n[green]{len(hosts)} live device(s) discovered.[/green]"
    )

    return hosts


def scan_specific_device(network):
    """
    Scan one user-supplied IPv4 address at a time.

    After each scan, the user can choose whether
    to scan another IP or return to the main menu.
    """

    while True:

        target_ip = input(
            "\nEnter target IP address: "
        ).strip()

        # -----------------------------------------
        # 1. VALIDATE IP ADDRESS
        # -----------------------------------------

        try:
            ip_object = ipaddress.ip_address(
                target_ip
            )

        except ValueError:
            console.print(
                "[red]Invalid IP address.[/red]"
            )

            retry = input(
                "Try another IP? [y/N]: "
            ).strip().lower()

            if retry != "y":
                return

            continue

        if ip_object.version != 4:
            console.print(
                "[red]Only IPv4 addresses are supported.[/red]"
            )

            retry = input(
                "Try another IP? [y/N]: "
            ).strip().lower()

            if retry != "y":
                return

            continue

        # -----------------------------------------
        # 2. CHECK CURRENT SUBNET
        # -----------------------------------------

        current_network = ipaddress.ip_network(
            network["subnet"],
            strict=False
        )

        if ip_object not in current_network:
            console.print(
                f"[yellow]{target_ip} is not inside "
                f"the current subnet "
                f"{network['subnet']}.[/yellow]"
            )

            retry = input(
                "Try another IP? [y/N]: "
            ).strip().lower()

            if retry != "y":
                return

            continue

        # -----------------------------------------
        # 3. CHECK WHETHER HOST APPEARS ONLINE
        # -----------------------------------------

        console.print(
            f"\nChecking {target_ip}..."
        )

        discovery = subprocess.run(
            [
                "nmap",
                "-sn",
                "-oG",
                "-",
                target_ip
            ],
            capture_output=True,
            text=True
        )

        host_is_up = (
            "Status: Up"
            in discovery.stdout
        )

        if not host_is_up:
            console.print(
                "[yellow]Host did not respond to "
                "normal discovery probes.[/yellow]"
            )

            choice = input(
                "Scan it anyway? [y/N]: "
            ).strip().lower()

            if choice != "y":

                retry = input(
                    "Try another IP? [y/N]: "
                ).strip().lower()

                if retry != "y":
                    return

                continue

        # -----------------------------------------
        # 4. BUILD HOST RECORD
        # -----------------------------------------

        host = {
            "ip": target_ip,
            "mac": "Unknown",
            "mac_type": "Unknown",
            "status": (
                "Online"
                if host_is_up
                else "Unconfirmed"
            )
        }

        # -----------------------------------------
        # 5. SCAN TARGET
        # -----------------------------------------

        console.print(
            f"\n[bold]Scanning {target_ip}...[/bold]"
        )

        ports = scan_host(
            target_ip
        )

        analyzed_ports = analyze_ports(
            ports
        )

        show_scan_result(
            host,
            analyzed_ports
        )

        # -----------------------------------------
        # 6. ASK WHETHER TO SCAN AGAIN
        # -----------------------------------------

        again = input(
            "\nScan another IP? [y/N]: "
        ).strip().lower()

        if again != "y":
            return


def scan_all_devices(network):
    """
    Perform a live network security scan.

    Devices are discovered and scanned once.
    After each scan round, the network is checked
    again for newly connected devices.
    """

    scanned_ips = set()
    results_with_open_ports = []

    # -----------------------------------------
    # INITIAL DISCOVERY
    # -----------------------------------------

    current_hosts = discover_network_devices(
        network
    )

    if not current_hosts:
        return

    console.print(
        f"\n[bold]{len(current_hosts)} live device(s) "
        "available for scanning.[/bold]"
    )

    # -----------------------------------------
    # LIVE SCAN LOOP
    # -----------------------------------------

    while True:

        for host in current_hosts:

            ip_address = host["ip"]

            # Never scan the same IP twice
            # during this scan session.
            if ip_address in scanned_ips:
                continue

            console.print(
                f"\n[bold]Scanning {ip_address}...[/bold]"
            )

            ports = scan_host(
                ip_address
            )

            # Mark it scanned even when no
            # open ports were detected.
            scanned_ips.add(
                ip_address
            )

            if not ports:
                continue

            analyzed_ports = analyze_ports(
                ports
            )

            results_with_open_ports.append(
                {
                    "host": host,
                    "analyzed_ports": analyzed_ports
                }
            )

        # -----------------------------------------
        # LOOK FOR NEW DEVICES
        # -----------------------------------------

        console.print(
            "\n[bold]"
            "Checking for newly connected devices..."
            "[/bold]"
        )

        refreshed_hosts = discover_network_devices(
            network
        )

        new_hosts = [
            host
            for host in refreshed_hosts
            if host["ip"] not in scanned_ips
        ]

        if not new_hosts:

            console.print(
                "[green]"
                "No newly connected devices found."
                "[/green]"
            )

            break

        console.print(
            f"[yellow]{len(new_hosts)} new device(s) "
            "detected. Continuing scan...[/yellow]"
        )

        current_hosts = new_hosts

    # -----------------------------------------
    # FINAL RESULTS
    # -----------------------------------------

    console.print(
        f"\n[bold]{len(scanned_ips)} total device(s) "
        "scanned.[/bold]"
    )

    console.print(
        f"[bold]{len(results_with_open_ports)} "
        "device(s) with open ports found.[/bold]"
    )

    if not results_with_open_ports:

        console.print(
            "[green]"
            "No open ports were found in the "
            "top 100 TCP ports."
            "[/green]"
        )

        return

    for result in results_with_open_ports:

        host = result["host"]

        analyzed_ports = result[
            "analyzed_ports"
        ]

        show_scan_result(
            host,
            analyzed_ports
        )

def setup_dhcp_integration(detected_gateway):
    """
    Create a new DHCP integration configuration.
    """

    console.print(
        "\n[bold]ROUTER IP CONFIGURATION[/bold]"
    )

    console.print(
        f"Detected Gateway : {detected_gateway}"
    )

    console.print(
        "\n[1] Use Detected Gateway"
    )
    console.print(
        "[2] Enter Different Router IP"
    )
    console.print(
        "[3] Back"
    )

    choice = input(
        "\nSelect an option: "
    ).strip()

    if choice == "1":

        router_ip = detected_gateway

    elif choice == "2":

        router_ip = input(
            "\nEnter Router IP address: "
        ).strip()

        try:
            ip_object = ipaddress.ip_address(
                router_ip
            )

        except ValueError:
            console.print(
                "[red]Invalid Router IP address.[/red]"
            )
            return

        if ip_object.version != 4:
            console.print(
                "[red]Only IPv4 router addresses are supported.[/red]"
            )
            return

    elif choice == "3":
        return

    else:
        console.print(
            "[red]Invalid option.[/red]"
        )
        return

    # -----------------------------------------
    # ROUTER MODEL
    # -----------------------------------------

    console.print(
        "\n[bold]SELECT ROUTER MODEL USED BY YOUR ISP[/bold]"
    )

    console.print(
        "[1] Huawei HG8145V5"
    )

    console.print(
        "[2] Back"
    )

    model_choice = input(
        "\nSelect router model: "
    ).strip()

    if model_choice == "1":

        provider = "huawei_hg8145v5"

    elif model_choice == "2":
        return

    else:
        console.print(
            "[red]Invalid router model selection.[/red]"
        )
        return

    # -----------------------------------------
    # SAVE CONFIGURATION
    # -----------------------------------------

    save_dhcp_config(
        provider,
        router_ip
    )

    console.print(
        "\n[green]"
        "DHCP integration configured successfully."
        "[/green]"
    )

def configure_dhcp_integration(network):
    """
    Configure or remove DHCP integration settings.
    """

    current = load_dhcp_config()

    provider = current.get("provider")
    router_ip = current.get("router_ip")

    is_configured = bool(
        provider and router_ip
    )

    console.print(
        "\n[bold]CONFIGURE DHCP INTEGRATION[/bold]"
    )

    console.print(
        f'Status           : '
        f'{"Configured" if is_configured else "Not Configured"}'
    )

    console.print(
        f'Router IP        : '
        f'{router_ip if router_ip else "Not configured"}'
    )

    if provider == "huawei_hg8145v5":
        model_name = "Huawei HG8145V5"
    else:
        model_name = "Not configured"

    console.print(
        f'ISP Router Model : {model_name}'
    )

    if not is_configured:

        console.print(
            "\n[1] Add DHCP Integration"
        )
        console.print(
            "[2] Back to Main Menu"
        )

        choice = input(
            "\nSelect an option: "
        ).strip()

        if choice == "1":
            setup_dhcp_integration(
                network["gateway"]
            )

        elif choice == "2":
            return

        else:
            console.print(
                "[red]Invalid option.[/red]"
            )

        return

    console.print(
        "\n[1] Remove DHCP Integration"
    )
    console.print(
        "[2] Reset Configuration"
    )
    console.print(
        "[3] Back to Main Menu"
    )

    choice = input(
        "\nSelect an option: "
    ).strip()

    if choice == "1":

        remove_dhcp_config()

        console.print(
            "[green]DHCP integration removed.[/green]"
        )

    elif choice == "2":

        remove_dhcp_config()

        setup_dhcp_integration(
            network["gateway"]
        )

    elif choice == "3":
        return

    else:
        console.print(
            "[red]Invalid option.[/red]"
        )

def show_menu():
    """
    Display the main interactive menu.
    """

    console.print(
        "\n[bold]"
        "LOCAL NETWORK SECURITY AUDITOR\n"
        "[/bold]"
    )

    console.print("[1] Discover Devices")
    console.print("[2] Scan All Devices")
    console.print("[3] Scan Specific Device")
    console.print("[4] Network Information")
    console.print("[5] DHCP Integration Settings")
    console.print("[6] Exit")


def main():
    """
    Main interactive application loop.
    """

    network = detect_network()

    while True:

        show_menu()

        choice = input(
            "\nSelect an option: "
        ).strip()

        if choice == "1":

            hosts = discover_network_devices(
                network
            )

            show_devices(
                hosts
            )

        elif choice == "2":

            scan_all_devices(
                network
            )

        elif choice == "3":

            scan_specific_device(
                network
            )

        elif choice == "4":

            show_network_info(
                network
            )

        elif choice == "5":

            configure_dhcp_integration(
                network
            )

        elif choice == "6":

            console.print(
                "\n[cyan]Exiting scanner.[/cyan]"
            )

            break

        else:

            console.print(
                "\n[red]"
                "Invalid option. "
                "Please choose 1 to 6."
                "[/red]"
            )

if __name__ == "__main__":
    main()
