#!/usr/bin/env python3
"""
Собирает subscription.json для Happ из сырого списка vless:// ссылок.

Логика:
1. Скачивает SOURCE_URL — построчный список vless:// конфигов.
2. Отбрасывает конфиги с флагом RU в названии.
3. Фасует оставшиеся по GROUP_SIZE штук -> балансировщики AUTO N.
4. Для Gemini:
   а) через ip-api.com узнаёт тип каждого IP (mobile/hosting/proxy) —
      отсеивает явные датацентры, оставляет похожих на мобильных/
      резидентных операторов (как в платных LTE-VPN);
   б) по оставшимся — реальная проверка через xray-core: поднимает
      временный SOCKS и стучится в Gemini.
   Все прошедшие уходят одним отдельным сервером в конец подписки.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
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

# --- Предфильтр по типу IP (мобильный/резидентный vs датацентр) ---
# Если True — берём в проверку ТОЛЬКО то, что ip-api явно пометил как mobile.
# Если False (по умолчанию) — берём всё, что НЕ датацентр и НЕ прокси
# (шире охват: некоторые мобильные операторы не всегда помечены mobile=true).
GEMINI_REQUIRE_MOBILE_FLAG = False
IPAPI_BATCH_URL = "http://ip-api.com/batch?fields=status,query,mobile,hosting,proxy"
IPAPI_CHUNK = 100
IPAPI_SLEEP_BETWEEN_CHUNKS = 2  # сек, чтобы не упереться в рейт-лимит


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
                    "protocol": ["quic"],
                    "outboundTag": "block",
                },
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


# ---------- Предфильтр по типу IP ----------

def fetch_ip_info(ips: list) -> dict:
    """Спрашивает ip-api.com: для каждого IP — mobile / hosting / proxy."""
    info = {}
    unique_ips = list(dict.fromkeys(ips))  # без дублей, сохраняя порядок
    for i in range(0, len(unique_ips), IPAPI_CHUNK):
        chunk = unique_ips[i:i + IPAPI_CHUNK]
        payload = json.dumps(chunk).encode("utf-8")
        req = urllib.request.Request(
            IPAPI_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            for item in data:
                if item.get("status") == "success" and item.get("query"):
                    info[item["query"]] = item
        except Exception as e:
            print("ip-api batch error:", e)
        if i + IPAPI_CHUNK < len(unique_ips):
            time.sleep(IPAPI_SLEEP_BETWEEN_CHUNKS)
    return info


def filter_likely_mobile(parsed: list) -> list:
    """Отсеивает явные датацентры/прокси, оставляет похожих на мобильных/резидентных."""
    ips = [cfg["host"] for cfg in parsed]
    info = fetch_ip_info(ips)

    likely = []
    for cfg in parsed:
        meta = info.get(cfg["host"])
        if meta is None:
            continue  # нет данных по IP — пропускаем, не тратим время xray

        if meta.get("hosting") or meta.get("proxy"):
            continue  # явный датацентр или известный прокси — почти наверняка забанен

        if GEMINI_REQUIRE_MOBILE_FLAG and not meta.get("mobile"):
            continue

        likely.append(cfg)

    print(f"Предфильтр по IP: {len(parsed)} -> {len(likely)} похожих на мобильные/резидентные")
    return likely


# ---------- Реальная проверка Gemini через xray ----------

def test_gemini(cfg: dict, port: int) -> bool:
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


def find_gemini_servers(candidates: list) -> list:
    if not CHECK_GEMINI:
        return []
    if not XRAY_BIN:
        print("xray не найден в PATH — пропускаю проверку Gemini")
        return []
    if not candidates:
        return []

    print(f"Проверяю доступ к Gemini через {len(candidates)} серверов...")
    working = []
    with ThreadPoolExecutor(max_workers=GEMINI_MAX_WORKERS) as ex:
        futures = {
            ex.submit(test_gemini, cfg, GEMINI_BASE_PORT + i): cfg
            for i, cfg in enumerate(candidates)
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

    mobile_like = filter_likely_mobile(parsed)
    gemini_ok = find_gemini_servers(mobile_like)
    if gemini_ok:
        result.append(build_group_config(gemini_ok, index=0, label=GEMINI_LABEL))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    print(f"OK: {len(parsed)} серверов (без RU) -> {len(result)} групп -> {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
