import ipaddress
import random
import socket
import time
from typing import List, Tuple

SAMPLES_PER_RANGE = 100     # چند IP از هر رنج
TIMEOUT = 0.8               # حداکثر زمان تست هر IP (ثانیه)
LATENCY_THRESHOLD = 0.20    # 200ms
TOP_CLEAN_LIMIT = 100       # حداکثر تعداد IP تمیز خروجی

CLOUDFLARE_RANGES = [
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "198.41.128.0/17",
]

def random_ips_from_cidr(cidr: str, count: int) -> List[str]:
    net = ipaddress.IPv4Network(cidr)
    ips = []
    for _ in range(count):
        offset = random.randint(1, net.num_addresses - 2)
        ip = str(net.network_address + offset)
        ips.append(ip)
    return ips

def test_ip_tcp(ip: str, port: int = 443, timeout: float = TIMEOUT) -> float:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.close()
        return time.time() - start
    except Exception:
        return 999.0

def scan_ips(ip_list: List[str]) -> List[Tuple[str, float]]:
    results: List[Tuple[str, float]] = []
    print(f"Scanning {len(ip_list)} IPs...")
    for idx, ip in enumerate(ip_list, start=1):
        t = test_ip_tcp(ip)
        if t >= 999.0:
            status = "TIMEOUT"
        elif t < LATENCY_THRESHOLD:
            status = "OK"
        else:
            status = "SLOW"
        print(f"[{idx}/{len(ip_list)}] {ip} -> {t:.3f} s [{status}]")
        results.append((ip, t))
    results.sort(key=lambda x: x[1])
    return results

if __name__ == "__main__":
    all_ips = []
    for cidr in CLOUDFLARE_RANGES:
        sample_ips = random_ips_from_cidr(cidr, SAMPLES_PER_RANGE)
        all_ips.extend(sample_ips)

    all_ips = list(dict.fromkeys(all_ips))  # حذف تکراری‌ها

    print("Total IPs to scan:", len(all_ips))

    scanned = scan_ips(all_ips)

    clean = [(ip, t) for ip, t in scanned if t < LATENCY_THRESHOLD]
    clean = clean[:TOP_CLEAN_LIMIT]

    with open("cf_clean.txt", "w", encoding="utf-8") as f:
        for ip, t in clean:
            f.write(f"{ip}\t{t:.3f}\n")

    print("Scan finished.")
    print(f"Total scanned: {len(scanned)}")
    print(f"Clean (under {int(LATENCY_THRESHOLD*1000)}ms): {len(clean)}")
    print("Results saved to cf_clean.txt")