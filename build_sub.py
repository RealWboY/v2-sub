import socket
import time
from typing import List, Tuple
from urllib.parse import urlsplit, urlunsplit

# ---------- تنظیمات ----------
TIMEOUT = 0.8
CF_CLEAN_FILE = "cf_clean.txt"
OUTPUT_FILE = "sub.txt"

# ---------- تنها کانفیگ ----------
BASE_CONFIG = (
    "vless://bd977f6e-fd3a-48b5-817a-1572571cc5a5@104.21.2.75:443"
    "?encryption=none&security=tls&sni=gwagworld.trapslifee.workers.dev"
    "&fp=random&insecure=0&allowInsecure=0&type=ws"
    "&host=gwagworld.trapslifee.workers.dev"
    "&path=%2Fdm%2Fhttp%3D1234%3A1234%4018.194.239.151%3A2080"
    "#germany"
)

def load_clean_ips_from_file(path: str) -> List[str]:
    ips: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                ip = parts[0].strip()
                if ip:
                    ips.append(ip)
    except FileNotFoundError:
        print(f"{path} not found. Run scan_cf_ips.py first.")
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

def rank_ips(ips: List[str]) -> List[Tuple[str, float]]:
    results: List[Tuple[str, float]] = []
    print("Testing clean IPs from cf_clean.txt ...")
    for ip in ips:
        latency = test_ip_tcp(ip)
        status = "OK" if latency < 999.0 else "TIMEOUT"
        print(f"{ip} -> {latency:.3f} s [{status}]")
        results.append((ip, latency))
    results.sort(key=lambda x: x[1])
    return results

def replace_ip_in_vless(config: str, new_ip: str) -> str:
    parsed = urlsplit(config)
    if "@" not in parsed.netloc:
        raise ValueError("Invalid VLESS config: missing userinfo/IP section")

    userinfo, hostport = parsed.netloc.split("@", 1)

    if ":" in hostport:
        _, port = hostport.rsplit(":", 1)
        new_netloc = f"{userinfo}@{new_ip}:{port}"
    else:
        new_netloc = f"{userinfo}@{new_ip}"

    return urlunsplit((parsed.scheme, new_netloc, parsed.path, parsed.query, parsed.fragment))

def build_sub(best_ip: str) -> str:
    return replace_ip_in_vless(BASE_CONFIG, best_ip) + "\n"

if __name__ == "__main__":
    ips = load_clean_ips_from_file(CF_CLEAN_FILE)
    if not ips:
        print("No clean IPs loaded. Make sure cf_clean.txt exists and is not empty.")
        raise SystemExit(1)

    ranked = rank_ips(ips)
    usable = [item for item in ranked if item[1] < 999.0]

    if usable:
        best_ip, best_latency = usable[0]
        print(f"Best IP: {best_ip} ({best_latency:.3f}s)")
    else:
        print("All clean IPs timed out. Using original IP from config.")
        best_ip = "104.21.2.75"

    content = build_sub(best_ip)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"{OUTPUT_FILE} built successfully.")