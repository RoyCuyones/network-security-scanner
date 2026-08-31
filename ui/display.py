from rich.console import Console
from rich.table import Table
from rich.panel import Panel


console = Console()


def show_network_info(network):
    """
    Display local network information in a formatted table.
    """

    table = Table(title="Local Network Information")

    table.add_column("Property")
    table.add_column("Value")

    table.add_row("Interface", network["interface"])
    table.add_row("IP Address", network["ip"])
    table.add_row("Prefix", f'/{network["prefix"]}')
    table.add_row("Subnet", network["subnet"])
    table.add_row("Gateway", network["gateway"])

    console.print(table)


def show_devices(hosts):
    """
    Display discovered hosts in a numbered table.
    """

    if not hosts:
        console.print("[yellow]No live devices discovered.[/yellow]")
        return

    table = Table(title="Discovered Devices")

    table.add_column("#")
    table.add_column("Hostname")
    table.add_column("IP Address")
    table.add_column("MAC Address")
    table.add_column("MAC Type")
    table.add_column("Status")

    for index, host in enumerate(hosts, start=1):
        table.add_row(
            str(index),
            host.get("hostname", "Unknown"),
            host["ip"],
            host["mac"],
            host["mac_type"],
            host["status"]
        )

    console.print(table)


def show_scan_result(host, analyzed_ports):
    """
    Display information and possible security concerns
    for one scanned host.
    """

    hostname_source = host.get(
        "hostname_source"
    )

    if hostname_source:
        hostname_source = hostname_source.upper()
    else:
        hostname_source = "None"


    device_info = (
        f'Hostname        : {host.get("hostname", "Unknown")}\n'
        f'Hostname Source : {hostname_source}\n'
        f'IP Address      : {host["ip"]}\n'
        f'MAC Address     : {host["mac"]}\n'
        f'MAC Type        : {host["mac_type"]}\n'
        f'Status          : {host["status"]}'
    )

    console.print(
        Panel(
            device_info,
            title="Device Security Assessment"
        )
    )

    if not analyzed_ports:
        console.print(
            "[green]No open ports found in the top 100 TCP ports.[/green]"
        )
        return

    for result in analyzed_ports:
        port = result["port_info"]
        concerns = result["concerns"]

        console.print(
            f'\n[bold]PORT '
            f'{port["port"]}/{port["protocol"].upper()}[/bold]'
        )

        console.print(f'Service : {port["service"]}')
        console.print(f'Product : {port["product"]}')
        console.print(f'Version : {port["version"]}')

        console.print("\n[bold]Possible concerns:[/bold]")

        for concern in concerns:
            console.print(f"• {concern}")
