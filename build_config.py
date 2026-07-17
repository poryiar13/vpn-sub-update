#!/usr/bin/env python3
"""
Telegram -> Xray balancer config builder
------------------------------------------
Fetches the last N posts from a public Telegram channel, extracts VPN
configs (vless / vmess / trojan / ss links), converts each into an
Xray-core outbound, and assembles ONE config.json that contains:

  - all outbounds (tagged proxy-0, proxy-1, ...)
  - an "observatory" block that continuously health-checks every
    outbound (probeInterval below controls how often - default 4m,
    i.e. every 3-5 minutes as requested)
  - a "balancer" with strategy "leastPing" that always routes traffic
    through whichever outbound currently has the lowest latency

This ping-testing and switching happens live, on the device actually
running Xray (e.g. inside v2rayNG as a "custom config" profile) - not
inside GitHub Actions. This script's only job is to rebuild config.json
with a fresh set of servers on a schedule.

Output: config.json
"""

import re
import json
import base64
from urllib.parse import urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

CHANNEL = "SOSkeyNET"
MESSAGE_COUNT = 10
PROBE_INTERVAL = "4m"          # how often Xray re-tests all servers (3-5 min range)
PROBE_URL = "https://www.gstatic.com/generate_204"
SOCKS_PORT = 10808
HTTP_PORT = 10809

CONFIG_RE = re.compile(r'(?:vless|vmess|trojan|ss)://[^\s<>"\']+')


# ------------------------------------------------------------- fetching

def fetch_last_messages(channel: str, count: int) -> list:
    url = f"https://t.me/s/{channel}"
    resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    message_divs = soup.find_all("div", class_="tgme_widget_message_text")
    texts = [m.get_text("\n") for m in message_divs]
    return texts[-count:] if len(texts) > count else texts


def extract_configs(texts: list) -> list:
    configs = []
    for t in texts:
        configs.extend(CONFIG_RE.findall(t))
    seen = set()
    unique = []
    for c in configs:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


# ------------------------------------------------------- link -> outbound

def build_stream_settings(qs, sni_default=""):
    network = qs.get("type", ["tcp"])[0]
    security = qs.get("security", ["none"])[0]
    host_header = qs.get("host", [""])[0]
    path = qs.get("path", ["/"])[0]
    sni = qs.get("sni", [sni_default])[0] or sni_default
    fp = qs.get("fp", ["chrome"])[0]
    alpn_raw = qs.get("alpn", [""])[0]
    alpn_list = [a for a in alpn_raw.split(",") if a]

    stream = {"network": "xhttp" if network in ("xhttp", "splithttp") else network}
    if security in ("tls", "reality"):
        stream["security"] = security

    if security == "tls":
        tls = {"serverName": sni, "fingerprint": fp}
        if qs.get("allowInsecure", ["0"])[0] in ("1", "true") or qs.get("insecure", ["0"])[0] in ("1", "true"):
            tls["allowInsecure"] = True
        if alpn_list:
            tls["alpn"] = alpn_list
        stream["tlsSettings"] = tls
    elif security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": qs.get("pbk", [""])[0],
            "shortId": qs.get("sid", [""])[0],
            "spiderX": qs.get("spx", ["/"])[0],
        }

    if network == "ws":
        stream["wsSettings"] = {"path": path or "/", "headers": {"Host": host_header} if host_header else {}}
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": qs.get("serviceName", [""])[0],
            "multiMode": qs.get("mode", [""])[0] == "multi",
        }
    elif network in ("xhttp", "splithttp"):
        stream["xhttpSettings"] = {"host": host_header or "", "path": path or "/", "mode": qs.get("mode", ["auto"])[0]}
    elif network == "tcp":
        if qs.get("headerType", ["none"])[0] == "http":
            stream["tcpSettings"] = {
                "header": {"type": "http", "request": {"path": [path or "/"], "headers": {"Host": [host_header]} if host_header else {}}}
            }
    return stream


def parse_vless(link):
    parsed = urlparse(link)
    uuid, host, port = parsed.username, parsed.hostname, parsed.port
    if not (uuid and host and port):
        return None
    qs = parse_qs(parsed.query)
    stream = build_stream_settings(qs, sni_default=host)
    flow = qs.get("flow", [""])[0]
    user = {"id": uuid, "encryption": qs.get("encryption", ["none"])[0], "level": 8}
    if flow:
        user["flow"] = flow
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream,
        "mux": {"enabled": False},
    }, host


def parse_trojan(link):
    parsed = urlparse(link)
    password, host, port = parsed.username, parsed.hostname, parsed.port
    if not (password and host and port):
        return None
    qs = parse_qs(parsed.query)
    if "security" not in qs:
        qs["security"] = ["tls"]
    stream = build_stream_settings(qs, sni_default=host)
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": host, "port": port, "password": password, "level": 8}]},
        "streamSettings": stream,
        "mux": {"enabled": False},
    }, host


def parse_vmess(link):
    payload = link[len("vmess://"):]
    payload += "=" * (-len(payload) % 4)
    try:
        data = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
    except Exception:
        return None
    host, uuid = data.get("add"), data.get("id")
    try:
        port = int(data.get("port", 0))
    except Exception:
        return None
    if not (host and port and uuid):
        return None
    net = data.get("net", "tcp") or "tcp"
    tls_on = data.get("tls", "") == "tls"
    sni = data.get("sni") or data.get("host") or host
    path = data.get("path", "/") or "/"
    host_header = data.get("host", "") or ""
    fp = data.get("fp", "chrome") or "chrome"

    stream = {"network": net}
    if tls_on:
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp}
    if net == "ws":
        stream["wsSettings"] = {"path": path, "headers": {"Host": host_header} if host_header else {}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": path}

    return {
        "protocol": "vmess",
        "settings": {"vnext": [{
            "address": host, "port": port,
            "users": [{"id": uuid, "alterId": int(data.get("aid", 0) or 0), "security": data.get("scy", "auto") or "auto", "level": 8}],
        }]},
        "streamSettings": stream,
        "mux": {"enabled": False},
    }, host


def parse_ss(link):
    body = link[len("ss://"):].split("#")[0]
    try:
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            try:
                decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode("utf-8")
                method, password = decoded.split(":", 1)
            except Exception:
                method, password = userinfo.split(":", 1)
            hostport = hostport.split("?")[0]
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
        else:
            decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode("utf-8")
            methodpass, hostport = decoded.rsplit("@", 1)
            method, password = methodpass.split(":", 1)
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str)
    except Exception:
        return None
    return {
        "protocol": "shadowsocks",
        "settings": {"servers": [{"address": host, "port": port, "method": method, "password": password, "level": 8}]},
    }, host


def parse_config(link):
    try:
        if link.startswith("vless://"):
            return parse_vless(link)
        if link.startswith("trojan://"):
            return parse_trojan(link)
        if link.startswith("vmess://"):
            return parse_vmess(link)
        if link.startswith("ss://"):
            return parse_ss(link)
    except Exception:
        return None
    return None


# ------------------------------------------------------- full config build

def build_full_config(links):
    outbounds = []
    tags = []
    for i, link in enumerate(links):
        parsed = parse_config(link)
        if not parsed:
            continue  # unsupported combo, skip rather than guess
        outbound, host = parsed
        tag = f"proxy-{i}-{host}"[:60]
        outbound["tag"] = tag
        outbounds.append(outbound)
        tags.append(tag)

    outbounds.append({"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIPv4"}})
    outbounds.append({"tag": "block", "protocol": "blackhole", "settings": {"response": {"type": "http"}}})

    config = {
        "_comment": "Auto-generated from Telegram channel configs - leastPing balancer",
        "log": {"loglevel": "warning", "access": "none"},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
             "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http",
             "settings": {"userLevel": 8},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}},
        ],
        "outbounds": outbounds,
        "observatory": {
            "subjectSelector": tags,
            "probeUrl": PROBE_URL,
            "probeInterval": PROBE_INTERVAL,
            "enableConcurrency": True,
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [{"tag": "proxy-balancer", "selector": tags, "strategy": {"type": "leastPing"}}],
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                {"type": "field", "network": "tcp,udp", "balancerTag": "proxy-balancer"},
            ],
        },
    }
    return config, len(tags)


def main():
    print(f"[1/3] Fetching last {MESSAGE_COUNT} messages from t.me/s/{CHANNEL} ...")
    texts = fetch_last_messages(CHANNEL, MESSAGE_COUNT)
    print(f"      -> got {len(texts)} messages")

    print("[2/3] Extracting config links ...")
    links = extract_configs(texts)
    print(f"      -> found {len(links)} unique configs")

    print("[3/3] Building Xray balancer config.json ...")
    config, used = build_full_config(links)
    with open("config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    print(f"      -> config.json written with {used}/{len(links)} usable outbounds")

    if used == 0:
        print("WARNING: no supported configs found this run.")


if __name__ == "__main__":
    main()
