import re
import requests


def decode_huawei_string(value):
    return bytes(value, "utf-8").decode("unicode_escape")


def get_huawei_clients(router_ip):
    url = f"http://{router_ip}/html/bbsp/common/GetLanUserDhcpInfo.asp"

    response = requests.post(url, timeout=5)
    response.raise_for_status()

    pattern = re.compile(
        r'new DHCPInfo\('
        r'"[^"]*",'
        r'"([^"]*)",'
        r'"([^"]*)",'
        r'"([^"]*)"'
    )

    matches = pattern.findall(response.text)

    clients = []

    for hostname, ip, mac in matches:
        hostname = decode_huawei_string(hostname)
        ip = decode_huawei_string(ip)
        mac = decode_huawei_string(mac)

        clients.append({
            "hostname": hostname or None,
            "ip": ip,
            "mac": mac.lower()
        })

    return clients
