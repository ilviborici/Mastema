from scapy.all import ARP, Ether, srp
from ipaddress import IPv4Network
from manuf import manuf

def get_local_ip_and_mask():
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        mask = s.getsockname()[0].split(".")
        mask[-1] = "0/24"
        mask = ".".join(mask)
    return local_ip, mask

def find_connected_devices(local_ip, mask):
    ip_range = str(IPv4Network(mask, strict=False).network_address) + "/24"
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    ans, _ = srp(arp_request, timeout=2, verbose=0)

    devices = []
    p = manuf.MacParser()
    for sent, received in ans:
        manufacturer = p.get_manuf(received.hwsrc)
        devices.append({"ip": received.psrc, "mac": received.hwsrc, "manufacturer": manufacturer})
    return devices

if __name__ == "__main__":
    local_ip, mask = get_local_ip_and_mask()
    print(f"Local IP: {local_ip}, Mask: {mask}")

    devices = find_connected_devices(local_ip, mask)
    print("Connected devices:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, Manufacturer: {device['manufacturer']}")
