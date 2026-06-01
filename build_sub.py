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
    "172.65.125.18"
]

NODES = [
    {
        "name": "TURKEY VIP IRANCELL IPHONE",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=shRILl-bAse-dB4e.TRApsliFee.woRKeRs.DeV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiOHllTWFicWk0d1NyY1YiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyI0NS4xMi4xNDMuNzMiXX0%3D%3Fed%3D2560"
    },
    {
        "name": "TURKEY IRANCELL IPHONE",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=SHrill-base-dB4E.trAPslIfEE.WORkers.dEV&fp=safari&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiTWRlbzVBdkJIIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDUuMTIuMTQzLjczIl19%3Fed%3D2560"
    },
    {
        "name": "FINLAND IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=sHRIll-base-DB4e.TRAPSLifEe.WoRkERS.dEv&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiVFJ1RWxBaE5FIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiNDYuOC42NC4yMzIiXX0%3Fed%3D2560"
    },
    {
        "name": "NORWAY IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=ShRIll-Base-db4E.TRaPsLIfeE.wOrKeRs.DEV&fp=chrome&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoicmJwc1hvT1lkIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcm94eWlwIiwicGFuZWxJUHMiOlsiMTk0LjUuOTguMTciXX0%3Fed%3D2560"
    },
    {
        "name": "KAZAKHSTAN IRANCELL",
        "base": "vless://469c4b8e-53b4-4cac-bde7-d5408613bd02@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=Shrill-BASE-dB4e.trapsLIfeE.wOrkeRs.Dev&fp=firefox&alpn=http%2F1.1&insecure=0&allowInsecure=0&type=ws&host=shrill-base-db4e.trapslifee.workers.dev&path=%2FeyJqdW5rIjoiU3dSdnp6cTBCcWh5ZmQiLCJwcm90b2NvbCI6InZsIiwibW9kZSI6InByb3h5aXAiLCJwYW5lbElQcyI6WyIxMDQuMjM4LjI0Ljk5Il19%3Fed%3D2560"
    },
    {
        "name": "GERMANY IRANCELL",
        "base": "vless://bd977f6e-fd3a-48b5-817a-1572571cc5a5@IP_PLACEHOLDER:443?encryption=none&security=tls&sni=gwagworld.trapslifee.workers.dev&fp=random&insecure=0&allowInsecure=0&type=ws&host=gwagworld.trapslifee.workers.dev&path=%2Fphp%2Fproxyip%3D68.183.213.79"
    }
]

def pick_ip(index: int) -> str:
    # فعلاً بدون پینگ، فقط چرخش ساده روی لیست IPها بر اساس index
    length = len(CLEAN_IPS)
    idx = index % length
    return CLEAN_IPS[idx]

def build_sub() -> str:
    lines = []
    for i, node in enumerate(NODES):
        ip = pick_ip(i)
        link = node["base"].replace("IP_PLACEHOLDER", ip) + "#" + node["name"]
        lines.append(link)
    return "\n".join(lines) + "\n"

if __name__ == "__main__":
    content = build_sub()
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write(content)
    print("sub.txt ساخته شد.")