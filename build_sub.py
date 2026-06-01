import socket
import time
from typing import List, Tuple

# ---------- تنظیمات ----------
NODE_COUNT = 7            # چند تا کانفیگ بسازیم
TIMEOUT = 0.8             # حداکثر زمان تست هر IP (ثانیه)
LATENCY_THRESHOLD = 0.20  # 200ms

CF_CLEAN_FILE = "cf_clean.txt"

# ---------- قالب لینک‌ها ----------
BASE_LINKS = [
    # 1
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=shRILl-bAse-dB4e.TRApsliFee.woRKeRs.DeV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiOHllTWFicWk0d1NyY1YiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyI0NS4xMi4xNDMuNzMiXX0%3D%3Fed%3D2560",
    # 2
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=SHrill-base-dB4E.trAPslIfEE.WORkers.dEV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiTWRlbzVBdkJIIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDUuMTIuMTQzLjczIl19%3Fed%3D2560",
    # 3
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=sHRIll-base-DB4e.TRAPSLifEe.WoRkERS.dEv&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiVFJ1RWxBaE5FIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDYuOC42NC4yMzIiXX0%3Fed%3D2560",
    # 4
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=ShRIll-Base-db4E.TRaPsLIfeE.wOrKeRs.DEV&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoicmJwc1hvT1lkIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiMTk0LjUuOTguMTciXX0%3Fed%3D2560",
    # 5
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=Shrill-BASE-dB4e.trapsLIfeE.wOrKeRs.Dev&fp=firefox&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiU3dSdnp6cTBCcWh5ZmQiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyIxMDQuMjM4LjI0Ljk5Il19%3Fed%3D2560",
    # 6
    "vless://bd977f6e-fd3a-48b5-817a-1572571cc5a5@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=gwagworld.trapslifee.workers.dev&fp=random&insecure=0&allowInsecure=0&type=ws&host=gwagworld.trapslifee.workers.dev&path=%2Fphp%2Fproxyip%3D68.183.213.79",
    # 7: کانفیگ جدید فنلاند
    "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=SHrILL-BAse-DB4E.tRapSlifEE.WORkErS.dEV&fp=random&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoidVQzRzJDMk5zVmJJUXJCWSIsInByb3RvY29sIjoidmwiLCJtb2RlIjoicHJveHlpcCIsInBhbmVsSVBzIjpbIjIxNy42MC42MS4xMCJdfQ%3D%3D%3Fed%3D2560",
]

def load_clean_ips_from_file(path: str) -> List[str]:
    ips: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                ips.append(parts[0])
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
        t = test_ip_tcp(ip)
        if t >= 999.0:
            status = "TIMEOUT"
        elif t < LATENCY_THRESHOLD:
            status = "OK"
        else:
            status = "SLOW"
        print(f"{ip} -> {t:.3f} s [{status}]")
        results.append((ip, t))
    results.sort(key=lambda x: x[1])
    return results

def build_sub(best_ranked: List[Tuple[str, float]]) -> str:
    lines = []
    for i in range(NODE_COUNT):
        ip, latency = best_ranked[i % len(best_ranked)]
        ping_label = i + 1
        lat_ms = int(latency * 1000)
        name = f"PING {ping_label} ({lat_ms}ms) IRANCELL"
        base = BASE_LINKS[i]
        link = base.replace("IP_PLACEHOLDER", ip) + "#" + name
        lines.append(link)
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    ips = load_clean_ips_from_file(CF_CLEAN_FILE)
    if not ips:
        print("No clean IPs loaded. Make sure cf_clean.txt exists and is not empty.")
        exit(1)

    ranked = rank_ips(ips)

    usable = [item for item in ranked if item[1] < 999.0]
    if not usable:
        print("All clean IPs timed out. Using ranked list anyway.")
        usable = ranked.copy()

    best_ranked = usable[:NODE_COUNT] if len(usable) >= NODE_COUNT else usable

    content = build_sub(best_ranked)
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(content)

    print("sub.txt built from cf_clean.txt with best IPs.")