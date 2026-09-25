#!/usr/bin/env python3
"""
Собирает subscription.json для Happ из сырого списка vless:// ссылок.

Логика:
1. Скачивает SOURCE_URL — построчный список vless:// конфигов.
2. Отбрасывает конфиги с флагом RU в названии.
3. Фасует оставшиеся по GROUP_SIZE штук.
4. Для каждой группы собирает отдельный "сервер" — полноценный
   Xray-конфиг с балансировщиком (routing.balancers, strategy=leastPing)
   и observatory, который сам пингует кандидатов и живёт с самым быстрым.
5. Пишет итоговый массив таких конфигов в OUTPUT_FILE — это и есть
   подписка, которую Happ понимает "из коробки".
"""

import json
import urllib.parse
import urllib.request

SOURCE_URL = "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"
GROUP_SIZE = 10
LABEL_TEMPLATE = "🇲🇦 🗽 LTE EU | AUTO {n}"
OUTPUT_FILE = "subscription.json"

RU_FLAG = "\U0001F1F7\U0001F1FA"  # 🇷🇺


def fetch_source(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
    return [line.strip() for line in raw.splitlines() if line.strip().startswith("vless://")]


def parse_vless(line: str):
    try:
        without_scheme = line[len("vless://"):]
        main_part, _, fragment = without_scheme.partition("#")
        userinfo_host, _, query = main_part.partition("?")
        uuid, _, hostport = userinfo_host.partition("@")
        host, _, port = hostport.rpartition(":")
        params = dict(urllib.parse.parse_qsl(query, keep_blank_values=True))
        remark = urllib.parse.unquote(fragment) if fragment else host
        return {
            "uuid": uuid,
            "host": host,
            "port": int(port),
            "params": params,
            "remark": remark,
        }
    except Exception:
        return None


def is_russian(remark: str) -> bool:
    return RU_FLAG in remark


def build_outbound(tag: str, cfg: dict) -> dict:
    p = cfg["params"]

    user = {"id": cfg["uuid"], "encryption": p.get("encryption", "none")}
    flow = p.get("flow")
    if flow:
        user["flow"] = flow

    outbound = {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {"address": cfg["host"], "port": cfg["port"], "users": [user]}
            ]
        },
    }

    network = p.get("type", "tcp")
    if network == "raw":
        network = "tcp"
    stream = {"network": network}

    security = p.get("security", "none")
    if security and security != "none":
        stream["security"] = security

    if security == "reality":
        reality = {
            "serverName": p.get("sni", ""),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "fingerprint": p.get("fp", "chrome"),
            "show": False,
        }
        if p.get("spx"):
            reality["spiderX"] = p["spx"]
        stream["realitySettings"] = reality
    elif security == "tls":
        tls = {
            "serverName": p.get("sni", cfg["host"]),
            "fingerprint": p.get("fp", "chrome"),
            "show": False,
        }
        if p.get("alpn"):
            tls["alpn"] = p["alpn"].split(",")
        stream["tlsSettings"] = tls

    if network == "tcp":
        stream["tcpSettings"] = {}
    elif network == "ws":
        ws = {"path": p.get("path", "/")}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc = {
            "serviceName": p.get("serviceName", ""),
            "multiMode": p.get("mode") == "multi",
        }
        if p.get("authority"):
            grpc["authority"] = p["authority"]
        stream["grpcSettings"] = grpc
    elif network == "xhttp":
        xhttp = {"path": p.get("path", "/"), "mode": p.get("mode", "auto")}
        if p.get("host"):
            xhttp["host"] = p["host"]
        if p.get("extra"):
            try:
                xhttp["extra"] = json.loads(p["extra"])
            except Exception:
                pass
        stream["xhttpSettings"] = xhttp

    outbound["streamSettings"] = stream
    return outbound


def build_group_config(group: list, index: int) -> dict:
    tags = [f"cand-{i + 1:02d}" for i in range(len(group))]
    outbounds = [build_outbound(tag, cfg) for tag, cfg in zip(tags, group)]
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    return {
        "remarks": LABEL_TEMPLATE.format(n=index),
        "dns": {
            "servers": [
                "https://8.8.8.8/dns-query",
                "https://1.1.1.1/dns-query",
            ],
            "queryStrategy": "UseIP",
        },
        "inbounds": [
            {
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http",
                "port": 10809,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {"allowTransparent": False},
                "sniffing": {
                    "enabled": True,
                    "routeOnly": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
        ],
        "log": {"loglevel": "warning"},
        "outbounds": outbounds,
        "routing": {
            "domainMatcher": "hybrid",
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "protocol": ["bittorrent"],
                    "outboundTag": "direct",
                },
                {
                    "type": "field",
                    "inboundTag": ["socks", "http"],
                    "network": "tcp,udp",
                    "balancerTag": "best_ping_balancer",
                },
            ],
            "balancers": [
                {
                    "tag": "best_ping_balancer",
                    "selector": tags,
                    "strategy": {"type": "leastPing"},
                }
            ],
        },
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "1m",
            "probeUrl": "https://www.google.com/generate_204",
            "subjectSelector": tags,
        },
    }


def main():
    lines = fetch_source(SOURCE_URL)

    parsed = []
    for line in lines:
        cfg = parse_vless(line)
        if cfg is None:
            continue
        if is_russian(cfg["remark"]):
            continue
        parsed.append(cfg)

    groups = [parsed[i:i + GROUP_SIZE] for i in range(0, len(parsed), GROUP_SIZE)]
    result = [build_group_config(g, idx + 1) for idx, g in enumerate(groups) if g]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"OK: {len(parsed)} серверов (без RU) -> {len(result)} групп по {GROUP_SIZE} -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
