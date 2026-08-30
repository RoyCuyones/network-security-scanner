from integrations.providers.huawei_hg8145v5 import get_huawei_clients


router_ip = "192.168.254.254"

clients = get_huawei_clients(router_ip)

for client in clients:
    print(client)
