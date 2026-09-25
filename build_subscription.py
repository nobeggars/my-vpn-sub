#!/usr/bin/env python3
"""
Собирает subscription.json для Happ из сырого списка vless:// ссылок.

Логика:
1. Скачивает SOURCE_URL — построчный список vless:// конфигов.
2. Отбрасывает конфиги с флагом RU в названии.
3. Фасует оставшиеся по GROUP_SIZE штук -> балансировщики AUTO N.
4. Дополнительно: через каждый кандидат поднимает временный SOCKS
   (xray-core) и проверяет, открывается ли через него Gemini.
   Все прошедшие проверку уходят одним отдельным сервером в конец
   подписки — с балансировщиком внутри (тоже leastPing).
"""

import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCE_URL = "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"
GROUP_SIZE = 10
LABEL_TEMPLATE = "🇲🇦 🗽 LTE EU | AUTO {n}"
OUTPUT_FILE = "subscription.json"

RU_FLAG = "\U0001F1F7\U0001F1FA"  # 🇷🇺

# --- Gemini-проверка ---
CHECK_GEMINI = True
GEMINI_LABEL = "🇲🇦 ⭐ LTE Gemini | Auto"
GEMINI_TEST_URL = "https://gemini.google.com/app"
GEMINI_TIMEOUT = 8          # сек на один тест
GEMINI_MAX_WORKERS = 8      # сколько кандидатов проверяем параллельно
GEMINI_BASE_PORT = 20000
XRAY_BIN = shutil.which(os.environ.get("XRAY_BIN", "xray"))


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


def build_group_config(group: list, index: int, label: str = None) -> dict:
    tags = [f"cand-{i + 1:02d}" for i in range(len(group))]
    outbounds = [build_outbound(tag, cfg) for tag, cfg in zip(tags, group)]
    outbounds.append({"tag": "direct", "protocol": "freedom"})
    outbounds.append({"tag": "block", "protocol": "blackhole"})

    return {
        "remarks": label if label else LABEL_TEMPLATE.format(n=index),
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


def test_gemini(cfg: dict, port: int) -> bool:
    """Поднимает временный SOCKS через кандидата и проверяет доступ к Gemini."""
    single_conf = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "socks",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
            }
        ],
        "outbounds": [build_outbound("proxy", cfg)],
    }

    conf_fd, conf_path = tempfile.mkstemp(suffix=".json")
    body_fd, body_path = tempfile.mkstemp(suffix=".html")
    proc = None
    try:
        with os.fdopen(conf_fd, "w", encoding="utf-8") as f:
            json.dump(single_conf, f)

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", conf_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        result = subprocess.run(
            [
                "curl", "-s", "-o", body_path, "-w", "%{http_code}",
                "--max-time", str(GEMINI_TIMEOUT),
                "--socks5-hostname", f"127.0.0.1:{port}",
                GEMINI_TEST_URL,
            ],
            capture_output=True, text=True, timeout=GEMINI_TIMEOUT + 5,
        )
        code = result.stdout.strip()
        if code != "200":
            return False

        try:
            with open(body_path, "r", encoding="utf-8", errors="ignore") as f:
                body = f.read().lower()
        except Exception:
            body = ""
        if "not available in your country" in body or "isn't available" in body:
            return False
        return True
    except Exception:
        return False
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        for path in (conf_path, body_path):
            try:
                os.unlink(path)
            except Exception:
                pass


def find_gemini_servers(parsed: list) -> list:
    if not CHECK_GEMINI:
        return []
    if not XRAY_BIN:
        print("xray не найден в PATH — пропускаю проверку Gemini")
        return []

    print(f"Проверяю доступ к Gemini через {len(parsed)} серверов...")
    working = []
    with ThreadPoolExecutor(max_workers=GEMINI_MAX_WORKERS) as ex:
        futures = {
            ex.submit(test_gemini, cfg, GEMINI_BASE_PORT + i): cfg
            for i, cfg in enumerate(parsed)
        }
        for fut in as_completed(futures):
            cfg = futures[fut]
            try:
                if fut.result():
                    working.append(cfg)
            except Exception:
                pass

    print(f"Gemini доступен через {len(working)} серверов")
    return working


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

    gemini_ok = find_gemini_servers(parsed)
    if gemini_ok:
        result.append(build_group_config(gemini_ok, index=0, label=GEMINI_LABEL))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"OK: {len(parsed)} серверов (без RU) -> {len(result)} групп -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
