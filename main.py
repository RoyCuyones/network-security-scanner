import ipaddress
import subprocess

from rich.console import Console

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
    Discover all live devices, scan each one,
    and display results only for devices that
    have open ports in the top 100 TCP ports.
    """

    hosts = discover_network_devices(
        network
    )

    if not hosts:
        return

    console.print(
        f"\n[bold]{len(hosts)} live device(s) "
        "available for scanning.[/bold]"
    )

    console.print(
        "\n[bold]Scanning all devices...[/bold]"
    )

    results_with_open_ports = []

    for host in hosts:

        ports = scan_host(
            host["ip"]
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

    console.print(
        f"\n[bold]{len(results_with_open_ports)} "
        "device(s) with open ports found.[/bold]"
    )

    if not results_with_open_ports:
        console.print(
            "[green]No open ports were found "
            "on any discovered device.[/green]"
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
