import socket
import time
from typing import List, Tuple

# ---------- Clean IPs ----------
CLEAN_IPS = [
    "162.159.194.33",
    "104.17.230.63",
    "104.24.188.206",
    "104.24.186.196",
    "104.25.199.108",
    "198.41.215.17",
    "104.24.242.191",
    "104.16.142.24",
    "172.67.64.252",
    "172.65.125.18",
    "198.41.195.194",
    "172.67.65.42",
    "190.93.245.15",
    "104.18.45.163",
    "8.39.125.112",
]

# ---------- Base nodes (without IP, name will get [PING N] suffix) ----------
NODES = [
    {
        "name": "TURKEY VIP IRANCELL IPHONE",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=shRILl-bAse-dB4e.TRApsliFee.woRKeRs.DeV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiOHllTWFicWk0d1NyY1YiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyI0NS4xMi4xNDMuNzMiXX0%3D%3Fed%3D2560",
    },
    {
        "name": "TURKEY IRANCELL IPHONE",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=SHrill-base-dB4E.trAPslIfEE.WORkers.dEV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiTWRlbzVBdkJIIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDUuMTIuMTQzLjczIl19%3Fed%3D2560",
    },
    {
        "name": "FINLAND IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=sHRIll-base-DB4e.TRAPSLifEe.WoRkERS.dEv&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiVFJ1RWxBaE5FIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDYuOC42NC4yMzIiXX0%3Fed%3D2560",
    },
    {
        "name": "NORWAY IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=ShRIll-Base-db4E.TRaPsLIfeE.wOrKeRs.DEV&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoicmJwc1hvT1lkIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiMTk0LjUuOTguMTciXX0%3Fed%3D2560",
    },
    {
        "name": "KAZAKHSTAN IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=Shrill-BASE-dB4e.trapsLIfeE.wOrkeRs.Dev&fp=firefox&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiU3dSdnp6cTBCcWh5ZmQiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyIxMDQuMjM4LjI0Ljk5Il19%3Fed%3D2560",
    },
    {
        "name": "GERMANY IRANCELL",
        "base": "vless://bd977f6e-fd3a-48b5-817a-1572571cc5a5@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=gwagworld.trapslifee.workers.dev&fp=random&insecure=0&allowInsecure=0&type=ws&host=gwagworld.trapslifee.workers.dev&path=%2Fphp%2Fproxyip%3D68.183.213.79",
    },
]

def test_ip_tcp(ip: str, port: int = 443, timeout: float = 0.8) -> float:
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
    print("Testing IPs...")
    for ip in ips:
        t = test_ip_tcp(ip)
        print(f"{ip} -> {t:.3f} s")
        results.append((ip, t))
    results.sort(key=lambda x: x[1])
    return results

def build_sub(best_ranked: List[Tuple[str, float]]) -> str:
    lines = []
    # best_ranked: لیست (IP, زمان) به ترتیب بهتر به بدتر
    # برای هر نود، IP و شماره PING مربوطه را می‌گذاریم
    for i, node in enumerate(NODES):
        ip, latency = best_ranked[i % len(best_ranked)]
        ping_label = i + 1  # PING 1، PING 2، ...
        name_with_ping = f"{node['name']} [PING {ping_label}]"
        link = node["base"].replace("IP_PLACEHOLDER", ip) + "#" + name_with_ping
        lines.append(link)
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    ranked = rank_ips(CLEAN_IPS)
    usable = [item for item in ranked if item[1] < 999.0]

    if not usable:
        print("No reachable IPs, using full list without ranking.")
        usable = [(ip, 999.0) for ip in CLEAN_IPS]
    else:
        print("Reachable IPs (best to worst):")
        for ip, t in usable:
            print(f"  {ip} -> {t:.3f} s")

    # مثلاً تا ۶ تا IP برتر را نگه می‌داریم
    best_ranked = usable[:6] if len(usable) >= 6 else usable

    content = build_sub(best_ranked)
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(content)

    print("sub.txt built with best IPs and PING labels.")