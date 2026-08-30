from integrations.providers.huawei_hg8145v5 import get_huawei_clients


def normalize_mac(mac):
    return mac.replace("-", ":").lower()


router_ip = "192.168.254.254"

clients = get_huawei_clients(router_ip)

# Example device discovered by Nmap
device = {
    "ip": "192.168.254.145",
    "mac": "9A:9D:08:34:7E:03"
}


matched_client = None

for client in clients:
    if normalize_mac(client["mac"]) == normalize_mac(device["mac"]):
        matched_client = client
        break


if matched_client:
    print("Match found")
    print(f"Hostname: {matched_client['hostname']}")
    print(f"IP:       {matched_client['ip']}")
    print(f"MAC:      {matched_client['mac']}")
else:
    print("No matching router client found")
