def analyze_port(port):
    """
    Analyze one open port and return possible security concerns.

    Expected input example:
    {
        "port": "22",
        "protocol": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "9.x"
    }

    Returns:
        A list of security observations.
    """

    port_number = int(port["port"])
    service = port["service"].lower()

    concerns = []

    if port_number == 21 or service == "ftp":
        concerns.append(
            "FTP may transmit credentials or data without encryption."
        )
        concerns.append(
            "Verify whether FTP is required and consider SFTP or FTPS."
        )

    elif port_number == 22 or service == "ssh":
        concerns.append(
            "Remote administration service is exposed."
        )
        concerns.append(
            "Restrict SSH access to trusted users and systems."
        )
        concerns.append(
            "Check the detected SSH product and version for known vulnerabilities."
        )

    elif port_number == 23 or service == "telnet":
        concerns.append(
            "Telnet is a clear-text remote administration protocol."
        )
        concerns.append(
            "Credentials and session data may be exposed on the network."
        )
        concerns.append(
            "Replace Telnet with SSH where possible."
        )

    elif port_number == 25 or service == "smtp":
        concerns.append(
            "SMTP service is exposed."
        )
        concerns.append(
            "Verify that relay settings and authentication are properly configured."
        )

    elif port_number == 53 or service == "domain":
        concerns.append(
            "DNS service is exposed."
        )
        concerns.append(
            "Verify that recursion and zone-transfer permissions are restricted."
        )

    elif port_number == 80 or service == "http":
        concerns.append(
            "Unencrypted HTTP service is exposed."
        )
        concerns.append(
            "Check whether HTTPS should be used instead."
        )
        concerns.append(
            "Review the detected web-server product and version for known vulnerabilities."
        )

    elif port_number == 110 or service == "pop3":
        concerns.append(
            "POP3 may transmit authentication data without encryption."
        )
        concerns.append(
            "Prefer encrypted mail access such as POP3S where appropriate."
        )

    elif port_number == 139:
        concerns.append(
            "NetBIOS file-sharing service is exposed."
        )
        concerns.append(
            "Verify that legacy Windows file-sharing services are required."
        )

    elif port_number == 143 or service == "imap":
        concerns.append(
            "IMAP service is exposed."
        )
        concerns.append(
            "Verify encrypted transport is used for authentication and mail access."
        )

    elif port_number == 445 or "microsoft-ds" in service or "smb" in service:
        concerns.append(
            "SMB file-sharing service is exposed."
        )
        concerns.append(
            "Verify SMBv1 is disabled."
        )
        concerns.append(
            "Review file-share permissions and restrict access to trusted hosts."
        )
        concerns.append(
            "Check the detected SMB implementation for known vulnerabilities."
        )

    elif port_number == 3389 or "ms-wbt-server" in service:
        concerns.append(
            "Remote Desktop service is exposed."
        )
        concerns.append(
            "Restrict RDP access to trusted systems and users."
        )
        concerns.append(
            "Use strong authentication and review the detected implementation for known vulnerabilities."
        )

    elif port_number == 5900 or "vnc" in service:
        concerns.append(
            "VNC remote desktop service is exposed."
        )
        concerns.append(
            "Verify authentication and encryption settings."
        )
        concerns.append(
            "Restrict access to trusted systems."
        )

    elif port_number == 3306 or "mysql" in service:
        concerns.append(
            "MySQL database service is exposed."
        )
        concerns.append(
            "Verify the database is not unnecessarily accessible to the whole subnet."
        )
        concerns.append(
            "Review authentication, user privileges, and detected version."
        )

    elif port_number == 5432 or "postgres" in service:
        concerns.append(
            "PostgreSQL database service is exposed."
        )
        concerns.append(
            "Restrict database access to systems that actually require it."
        )
        concerns.append(
            "Review authentication, permissions, and detected version."
        )

    elif port_number == 8080:
        concerns.append(
            "Alternate HTTP service is exposed."
        )
        concerns.append(
            "Check whether this is an administrative or development interface."
        )
        concerns.append(
            "Review the detected web application or server for known vulnerabilities."
        )

    elif port_number == 8443:
        concerns.append(
            "Alternate HTTPS service is exposed."
        )
        concerns.append(
            "Check whether this is an administrative interface."
        )
        concerns.append(
            "Review the detected service and version for known vulnerabilities."
        )

    else:
        concerns.append(
            "Open network service detected."
        )
        concerns.append(
            "Verify that this service is required and intentionally exposed."
        )

    return concerns


def analyze_ports(ports):
    """
    Analyze all open ports for one host.

    Returns:
        A list where each item contains the original
        port information plus its possible concerns.
    """

    results = []

    for port in ports:
        results.append({
            "port_info": port,
            "concerns": analyze_port(port)
        })

    return results
