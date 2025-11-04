import subprocess
import platform
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def ping(ip):
    """Ping an IP once to populate ARP table; return True if ping succeeded."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        subprocess.check_output(['ping', param, '1', ip], stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def parse_arp():
    """Parse `arp -a` output and return a list of dicts with ip and mac."""
    try:
        out = subprocess.check_output(['arp', '-a'], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return []

    devices = []
    for line in out.splitlines():
        line = line.strip()
        # Windows and many OS outputs differ; try to parse common patterns
        if not line:
            continue
        parts = line.split()
        # Windows: Interface: 192.168.1.10 --- 0x6
        # then:  192.168.1.1           00-11-22-33-44-55     dynamic
        if len(parts) >= 3 and parts[0][0].isdigit():
            ip = parts[0]
            mac = parts[1]
            devices.append({'ip': ip, 'mac': mac})
    return devices


def discover_devices(timeout=0.01, max_workers=50):
    """Discover devices on local network.
    Strategy:
      - Get local hostname IPs
      - Try pinging the /24 range of each IPv4 address to populate ARP
      - Parse arp table and return devices
    """
    devices = []
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = None

    ips_to_ping = set()
    if local_ip and local_ip.count('.') == 3:
        base = '.'.join(local_ip.split('.')[:3])
        for i in range(1, 255):
            ips_to_ping.add(f"{base}.{i}")

    # Limit number of pings to avoid long run times; we'll ping top 50 addresses randomly
    ips_to_ping = list(ips_to_ping)[:100]

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(ping, ip): ip for ip in ips_to_ping}
        for fut in as_completed(futures):
            pass  # we don't need results, just want ARP to populate

    # Parse ARP table
    raw = parse_arp()
    for d in raw:
        ip = d.get('ip')
        mac = d.get('mac')
        try:
            host = socket.gethostbyaddr(ip)[0]
        except Exception:
            host = None
        # Simple risk heuristic: common IoT/mac prefixes not available offline; mark unknown as 'unknown'
        devices.append({'ip': ip, 'mac': mac, 'hostname': host, 'risk': 'unknown'})

    return devices
