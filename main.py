
from rich.console import Console

from enrichment.device_type import refine_device_classification
from analysis.vulnerabilities import analyze_ports
from discovery.network import detect_network
from discovery.hosts import discover_hosts
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

    hosts = discover_hosts(network["subnet"])

    console.print(
        f"\n[green]{len(hosts)} live device(s) discovered.[/green]"
    )

    return hosts


def scan_specific_device(network):
    """
    Discover devices, allow the user to choose one,
    and scan its top 100 TCP ports.
    """

    hosts = discover_network_devices(network)

    if not hosts:
        return

    show_devices(hosts)

    choice = input("\nSelect device number to scan: ").strip()

    try:
        device_number = int(choice)

    except ValueError:
        console.print(
            "[red]Invalid selection. Please enter a number.[/red]"
        )
        return

    if device_number < 1 or device_number > len(hosts):
        console.print("[red]Device number does not exist.[/red]")
        return

    selected_host = hosts[device_number - 1]

    console.print(
        f'\n[bold]Scanning {selected_host["hostname"]} '
        f'({selected_host["ip"]})...[/bold]'
    )

    ports = scan_host(selected_host["ip"])
    analyzed_ports = analyze_ports(ports)

    show_scan_result(
        selected_host,
        analyzed_ports
    )


def scan_all_devices(network):
    """
    Discover all live devices and scan each one.
    """

    hosts = discover_network_devices(network)

    if not hosts:
        return

    for index, host in enumerate(hosts, start=1):

        if host["ip"] == network["gateway"]:

            hostname = host.get(
                "hostname",
                "Unknown"
            )

            if hostname != "Unknown":
                display_target = (
                    f'{hostname} ({host["ip"]})'
                )
            else:
                display_target = (
                    f'Default Gateway ({host["ip"]})'
                )

        else:
            display_target = host["ip"]

        console.print(
            f'\n[bold]Scanning device {index}/{len(hosts)}: '
            f'{display_target}[/bold]'
        )

        ports = scan_host(
            host["ip"]
        )

        analyzed_ports = analyze_ports(
            ports
        )

        show_scan_result(
            host,
            analyzed_ports
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
    console.print("[5] Exit")


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

            hosts = discover_network_devices(network)

            show_devices(hosts)

        elif choice == "2":

            scan_all_devices(network)

        elif choice == "3":

            scan_specific_device(network)

        elif choice == "4":

            show_network_info(network)

        elif choice == "5":

            console.print(
                "\n[cyan]Exiting scanner.[/cyan]"
            )
            break

        else:

            console.print(
                "\n[red]Invalid option. Please choose 1 to 6.[/red]"
            )


if __name__ == "__main__":
    main()
