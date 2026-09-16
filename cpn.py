#!/usr/bin/env python3
"""cpn: safe CLI/TUI for subscription profiles and network inspection."""
from __future__ import annotations

import argparse
import base64
import curses
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

APP = "cpn"
CONFIG_DIR = Path(os.environ.get("CPN_CONFIG_DIR", Path.home() / ".config" / APP))
DATA_DIR = Path(os.environ.get("CPN_DATA_DIR", Path.home() / ".local" / "share" / APP))
STATE_FILE = CONFIG_DIR / "state.json"
# Network changes are available only through explicit `select --activate`.
NETWORK_MUTATIONS_ENABLED = False
VPN_DIR = Path("/etc/cpn")
VPN_CONFIG = VPN_DIR / "sing-box.json"
VPN_ROUTE_BACKUP = VPN_DIR / "ssh-route.json"
VPN_SERVICE = "cpn-sing-box.service"
SSH_POLICY_TABLE = "cpn_ssh"
SSH_POLICY_MARK = "0x1"
SSH_POLICY_PREF = "100"
SSH_NFT_TABLE = "cpn_ssh"
SSH_NFT_FILE = VPN_DIR / "ssh-bypass.nft"


class CpnError(Exception):
    pass


def ssh_session() -> bool:
    """Return whether cpn was launched from an SSH session."""
    return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT") or os.environ.get("SSH_TTY"))


def safety_status() -> dict[str, Any]:
    return {"ssh_session": ssh_session(), "network_mutations": NETWORK_MUTATIONS_ENABLED, "vpn_activation": "explicit --activate only", "route_changes": "SSH route pinned + policy route", "firewall_changes": "nftables SSH mark only", "dns_changes": "sing-box scoped", "profile_execution": False}


def _require_root() -> None:
    if os.geteuid() != 0: raise CpnError("Активация VPN требует root: запустите sudo cpn select <id> --activate.")


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout or "без подробностей").strip()
            raise CpnError(f"Команда {' '.join(cmd)} завершилась с кодом {result.returncode}: {detail}")
        return result
    except (OSError, subprocess.SubprocessError) as e: raise CpnError(f"Не удалось выполнить {' '.join(cmd)}: {e}")


def _ssh_route() -> dict[str, Any] | None:
    if not ssh_session(): return None
    ssh_client = os.environ.get("SSH_CLIENT", "").split()
    ssh_connection = os.environ.get("SSH_CONNECTION", "").split()
    peer = (ssh_client or ssh_connection or [""])[0]
    if not peer: return None
    prefix = f"{peer}/128" if ipaddress.ip_address(peer).version == 6 else f"{peer}/32"
    current = _run(["ip", "route", "show", "exact", prefix], check=False).stdout.strip()
    lookup = _run(["ip", "route", "get", peer], check=False).stdout.strip()
    if not lookup: raise CpnError("Не удалось определить маршрут SSH-клиента; VPN не включён.")
    parts = lookup.split(); route: dict[str, Any] = {"peer": peer, "prefix": prefix, "previous": current}
    if "via" in parts: route["via"] = parts[parts.index("via") + 1]
    if "dev" in parts: route["dev"] = parts[parts.index("dev") + 1]
    if "src" in parts: route["src"] = parts[parts.index("src") + 1]
    if "dev" not in route: raise CpnError("Не удалось определить сетевой интерфейс SSH; VPN не включён.")
    return route


def _preserve_ssh_route(route: dict[str, Any] | None) -> None:
    if not route: return
    cmd = ["ip", "route", "replace", route.get("prefix", f"{route['peer']}/32")]
    if route.get("via"): cmd += ["via", route["via"]]
    cmd += ["dev", route["dev"]]
    if route.get("src"): cmd += ["src", route["src"]]
    _run(cmd)
    VPN_DIR.mkdir(parents=True, exist_ok=True)
    VPN_ROUTE_BACKUP.write_text(json.dumps(route), encoding="utf-8")


def _ssh_route_is_pinned(route: dict[str, Any] | None) -> bool:
    if not route: return True
    lookup = _run(["ip", "route", "get", route["peer"]], check=False).stdout.split()
    return "dev" in lookup and lookup[lookup.index("dev") + 1] == route["dev"]


def _install_ssh_bypass(route: dict[str, Any] | None) -> None:
    """Keep new and existing TCP/22 flows on the original uplink."""
    if not route: return
    nft = shutil.which("nft")
    if not nft: raise CpnError("Не найден nft. Установите пакет nftables перед активацией VPN.")
    gateway = route.get("via")
    route_cmd = ["ip", "route", "replace", "default"]
    if gateway: route_cmd += ["via", gateway]
    route_cmd += ["dev", route["dev"], "table", SSH_POLICY_TABLE]
    _run(route_cmd)
    _run(["ip", "rule", "add", "pref", SSH_POLICY_PREF, "fwmark", SSH_POLICY_MARK, "lookup", SSH_POLICY_TABLE], check=False)
    VPN_DIR.mkdir(parents=True, exist_ok=True)
    SSH_NFT_FILE.write_text(
        f"table inet {SSH_NFT_TABLE} {{\n"
        " chain prerouting { type filter hook prerouting priority mangle; policy accept;\n"
        "  tcp dport 22 ct mark set 0x1\n"
        " }\n"
        " chain output { type filter hook output priority mangle; policy accept;\n"
        "  ct mark 0x1 meta mark set ct mark\n"
        " }\n"
        "}\n", encoding="utf-8")
    _run([nft, "-f", str(SSH_NFT_FILE)])


def _restore_ssh_bypass() -> None:
    nft = shutil.which("nft")
    if nft: _run([nft, "delete", "table", "inet", SSH_NFT_TABLE], check=False)
    _run(["ip", "rule", "del", "pref", SSH_POLICY_PREF, "fwmark", SSH_POLICY_MARK, "lookup", SSH_POLICY_TABLE], check=False)
    _run(["ip", "route", "flush", "table", SSH_POLICY_TABLE], check=False)
    SSH_NFT_FILE.unlink(missing_ok=True)


def _restore_ssh_route() -> None:
    _restore_ssh_bypass()
    if not VPN_ROUTE_BACKUP.exists(): return
    route = json.loads(VPN_ROUTE_BACKUP.read_text(encoding="utf-8")); peer = route["peer"]
    _run(["ip", "route", "del", route.get("prefix", f"{peer}/32")], check=False)
    if route.get("previous"):
        _run(["ip", "route", "replace"] + shlex.split(route["previous"]), check=False)
    VPN_ROUTE_BACKUP.unlink(missing_ok=True)


def _outbound_from_source(source: str) -> dict[str, Any]:
    """Convert common subscription URIs into a minimal sing-box outbound."""
    p = urllib.parse.urlparse(source); query = urllib.parse.parse_qs(p.query); tag = "proxy"
    if p.scheme == "vless":
        if not p.username or not p.hostname: raise CpnError("Некорректный VLESS-профиль.")
        out = {"type": "vless", "tag": tag, "server": p.hostname, "server_port": p.port or 443, "uuid": p.username, "tls": {"enabled": True}}
        if query.get("security", ["tls"])[0] == "none": out["tls"] = {"enabled": False}
        if query.get("sni"): out["tls"]["server_name"] = query["sni"][0]
        if query.get("flow"): out["flow"] = query["flow"][0]
        if query.get("type", ["tcp"])[0] != "tcp": out["transport"] = {"type": query["type"][0]}
        return out
    if p.scheme == "trojan":
        if not p.username or not p.hostname: raise CpnError("Некорректный Trojan-профиль.")
        return {"type": "trojan", "tag": tag, "server": p.hostname, "server_port": p.port or 443, "password": urllib.parse.unquote(p.username), "tls": {"enabled": True, "server_name": query.get("sni", [p.hostname])[0]}}
    if p.scheme == "ss":
        user = urllib.parse.unquote(p.username or "")
        if ":" not in user or not p.hostname: raise CpnError("Некорректный Shadowsocks-профиль.")
        method, password = user.split(":", 1)
        return {"type": "shadowsocks", "tag": tag, "server": p.hostname, "server_port": p.port or 443, "method": method, "password": password}
    raise CpnError(f"Пока не поддерживается активация профиля типа {p.scheme or 'unknown'}.")


def _xray_stream(stream: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert the safe, data-only subset of Xray streamSettings."""
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")
    tls = stream.get("tlsSettings", {}) or {}
    reality = stream.get("realitySettings", {}) or {}
    tls_config: dict[str, Any] = {"enabled": security in ("tls", "reality")}
    if tls.get("serverName"): tls_config["server_name"] = tls["serverName"]
    if security == "reality":
        tls_config["utls"] = {"enabled": True, "fingerprint": "chrome"}
        if reality.get("serverName"): tls_config["server_name"] = reality["serverName"]
        tls_config["reality"] = {"enabled": True, "public_key": reality.get("publicKey", ""), "short_id": reality.get("shortId", "")}
    transport: dict[str, Any] = {}
    if network == "ws":
        ws = stream.get("wsSettings", {}) or {}; transport = {"type": "ws", "path": ws.get("path", "/"), "headers": ws.get("headers", {})}
    elif network == "grpc":
        grpc = stream.get("grpcSettings", {}) or {}; transport = {"type": "grpc", "service_name": grpc.get("serviceName", "")}
    elif network == "xhttp":
        xhttp = stream.get("xhttpSettings", {}) or {}; headers = {}
        host = xhttp.get("host")
        if host: headers["Host"] = host if isinstance(host, str) else ",".join(host)
        transport = {"type": "http", "path": xhttp.get("path", "/"), "headers": headers}
    elif network not in ("tcp", "raw"):
        raise CpnError(f"JSON-профиль использует неподдерживаемый transport: {network}")
    return tls_config, transport


def _outbound_from_xray(item: dict[str, Any]) -> dict[str, Any]:
    protocol = item.get("protocol"); settings = item.get("settings", {}) or {}; stream = item.get("streamSettings", {}) or {}
    tls, transport = _xray_stream(stream); tag = str(item.get("tag") or "proxy")
    if protocol in ("freedom", "blackhole", "dns", "dokodemo-door"):
        raise CpnError("Выбран служебный Xray outbound, а не прокси.")
    if protocol in ("vless", "vmess"):
        servers = (settings.get("vnext") or [])
        if not servers: raise CpnError(f"В JSON-профиле отсутствует {protocol}.settings.vnext.")
        server = servers[0]; users = server.get("users") or []
        if not server.get("address") or not users: raise CpnError(f"В JSON-профиле отсутствуют данные {protocol}.")
        user = users[0]; out = {"type": protocol, "tag": tag, "server": server["address"], "server_port": int(server.get("port", 443)), "uuid": user.get("id", ""), "tls": tls}
        if protocol == "vmess": out["security"] = user.get("security", "auto")
        if transport: out["transport"] = transport
        if user.get("flow"): out["flow"] = user["flow"]
        return out
    if protocol == "trojan":
        servers = settings.get("servers") or []
        if not servers: raise CpnError("В JSON-профиле отсутствует trojan.settings.servers.")
        server = servers[0]; return {"type": "trojan", "tag": tag, "server": server.get("address"), "server_port": int(server.get("port", 443)), "password": server.get("password", ""), "tls": tls, **({"transport": transport} if transport else {})}
    if protocol in ("shadowsocks", "shadowsocks2022"):
        servers = settings.get("servers") or []
        if not servers: raise CpnError("В JSON-профиле отсутствует shadowsocks.settings.servers.")
        server = servers[0]; return {"type": "shadowsocks", "tag": tag, "server": server.get("address"), "server_port": int(server.get("port", 443)), "method": server.get("method", ""), "password": server.get("password", "")}
    raise CpnError(f"Пока не поддерживается JSON outbound типа {protocol!r}.")


def _outbound_from_json(source: str) -> dict[str, Any]:
    try: config = json.loads(source)
    except json.JSONDecodeError as e: raise CpnError(f"Некорректный JSON-профиль: {e.msg}")
    if not isinstance(config, dict) or not isinstance(config.get("outbounds"), list): raise CpnError("Ожидался Xray JSON с массивом outbounds.")
    candidates = [x for x in config["outbounds"] if isinstance(x, dict) and x.get("protocol") not in ("freedom", "blackhole", "dns", "dokodemo-door")]
    if not candidates: raise CpnError("В JSON-профиле не найден прокси-outbound.")
    return _outbound_from_xray(candidates[0])


def _singbox_config(profile: dict[str, Any]) -> dict[str, Any]:
    outbound = _outbound_from_json(profile["source"]) if profile.get("kind") == "xray-json" else _outbound_from_source(profile["source"])
    return {"log": {"level": "info"}, "dns": {"servers": [{"type": "https", "tag": "remote", "server": "1.1.1.1", "path": "/dns-query", "detour": "proxy"}]}, "inbounds": [{"type": "tun", "tag": "tun-in", "interface_name": "cpn0", "address": ["172.19.0.1/30"], "auto_route": True, "strict_route": True}], "outbounds": [outbound, {"type": "direct", "tag": "direct"}], "route": {"auto_detect_interface": True, "final": "proxy", "rules": [{"ip_is_private": True, "outbound": "direct"}]}}


def activate_profile(profile: dict[str, Any]) -> None:
    global NETWORK_MUTATIONS_ENABLED
    _require_root(); sing_box = shutil.which("sing-box")
    if not sing_box: raise CpnError("Не найден sing-box. Установите его и повторите активацию.")
    route = _ssh_route(); config = _singbox_config(profile)
    VPN_DIR.mkdir(parents=True, exist_ok=True); VPN_CONFIG.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    _run([sing_box, "check", "-c", str(VPN_CONFIG)])
    unit = f"[Unit]\nDescription=cpn sing-box VPN\nAfter=network-online.target\nWants=network-online.target\n[Service]\nType=simple\nExecStart={sing_box} run -c {VPN_CONFIG}\nExecStopPost=/usr/local/bin/cpn deactivate-route\nRestart=on-failure\nRestartSec=3\n[Install]\nWantedBy=multi-user.target\n"
    Path("/etc/systemd/system/cpn-sing-box.service").write_text(unit, encoding="utf-8")
    try:
        _preserve_ssh_route(route); _install_ssh_bypass(route)
        _run(["systemctl", "daemon-reload"]); _run(["systemctl", "enable", "--now", VPN_SERVICE]); time.sleep(2)
        active = _run(["systemctl", "is-active", VPN_SERVICE], check=False).stdout.strip()
        if active != "active": raise CpnError("sing-box не перешёл в active; выполнен откат SSH-маршрута.")
        if not _ssh_route_is_pinned(route): raise CpnError("Маршрут до SSH-клиента ушёл в TUN; VPN не активирован безопасно.")
    except CpnError:
        _run(["systemctl", "disable", "--now", VPN_SERVICE], check=False); _restore_ssh_route(); raise
    NETWORK_MUTATIONS_ENABLED = True


def deactivate_vpn() -> None:
    _require_root(); _run(["systemctl", "disable", "--now", VPN_SERVICE], check=False); _restore_ssh_route()


def _safe_url(url: str) -> str:
    p = urllib.parse.urlparse(url.strip())
    if p.scheme != "https" or not p.netloc:
        raise CpnError("Разрешены только корректные HTTPS-ссылки.")
    if p.username or p.password:
        raise CpnError("URL с логином и паролем запрещён.")
    return url.strip()


def load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"subscriptions": [], "profiles": [], "active_profile": None}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError
        return {"subscriptions": data.get("subscriptions", []), "profiles": data.get("profiles", []), "active_profile": data.get("active_profile")}
    except (OSError, ValueError, json.JSONDecodeError) as e:
        raise CpnError(f"Не удалось прочитать {STATE_FILE}: {e}")


def save_state(state: dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="state.", dir=CONFIG_DIR)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(name, STATE_FILE)
    except OSError as e:
        try: os.unlink(name)
        except OSError: pass
        raise CpnError(f"Не удалось сохранить состояние: {e}")


def network_status() -> dict[str, Any]:
    result = {"interface": "—", "ip": "—", "gateway": "—", "dns": [], "connected": False}
    ip_cmd = shutil.which("ip")
    if ip_cmd:
        try:
            links = subprocess.run([ip_cmd, "-o", "link", "show", "up"], capture_output=True, text=True, timeout=3, check=False)
            for line in links.stdout.splitlines():
                m = re.match(r"\d+: ([^:]+):", line)
                if m and m.group(1) != "lo": result["interface"] = m.group(1); result["connected"] = True; break
            addrs = subprocess.run([ip_cmd, "-o", "-4", "addr", "show", "scope", "global"], capture_output=True, text=True, timeout=3, check=False)
            if addrs.stdout.strip():
                parts = addrs.stdout.split(); result["interface"] = parts[1]; result["ip"] = parts[3].split("/")[0]; result["connected"] = True
            routes = subprocess.run([ip_cmd, "route", "show", "default"], capture_output=True, text=True, timeout=3, check=False)
            m = re.search(r"default via (\S+)", routes.stdout); result["gateway"] = m.group(1) if m else "—"
        except (OSError, subprocess.SubprocessError): pass
    try:
        resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8")
        result["dns"] = re.findall(r"^nameserver\s+(\S+)", resolv, re.MULTILINE)
    except OSError: pass
    return result


def _profile(name: str, source: str, kind: str = "remote") -> dict[str, str]:
    return {"id": str(uuid.uuid4())[:8], "name": name[:120] or "Без имени", "source": source, "kind": kind}


def parse_profiles(payload: bytes, source: str) -> list[dict[str, str]]:
    text = payload.decode("utf-8-sig", errors="replace").strip()
    if not text: raise CpnError("Сервер вернул пустой ответ.")
    try:
        obj = json.loads(text)
        items = obj.get("profiles", obj.get("data", obj)) if isinstance(obj, dict) else obj
        if isinstance(items, list):
            out = []
            for item in items:
                if isinstance(item, str): out.append(_profile(item.rsplit("/", 1)[-1] or item, item, "link"))
                elif isinstance(item, dict):
                    name = str(item.get("name") or item.get("title") or item.get("remarks") or item.get("tag") or item.get("id") or "JSON-профиль")
                    ref = item.get("url") or item.get("link")
                    if ref: out.append(_profile(name, str(ref), "remote"))
                    elif isinstance(item.get("outbounds"), list): out.append(_profile(name, json.dumps(item, ensure_ascii=False), "xray-json"))
            if out: return out
    except json.JSONDecodeError: pass
    # Common subscription responses: one URI per line, or base64-encoded URI list.
    candidates = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith(("#", "//"))]
    decoded = ""
    compact = "".join(candidates)
    if compact and re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact) and len(compact) >= 16:
        try: decoded = base64.b64decode(compact + "=" * (-len(compact) % 4)).decode("utf-8", errors="ignore")
        except (ValueError, UnicodeDecodeError): pass
    lines = decoded.splitlines() if decoded else candidates
    out = []
    for line in lines:
        line = line.strip()
        if re.match(r"^(ss|ssr|vmess|vless|trojan|hysteria2?|tuic)://", line): out.append(_profile(line.split("#", 1)[-1] if "#" in line else line.rsplit("/", 1)[-1], line, "link"))
        elif line and not line.startswith(("proxies:", "proxy-groups:", "port:", "mixed-port:")) and "://" in line: out.append(_profile(line.rsplit("/", 1)[-1], line, "link"))
    if not out: raise CpnError("Формат ответа не распознан: ожидается JSON или список ссылок профилей.")
    return out


def fetch_profiles(url: str, timeout: int = 15) -> list[dict[str, str]]:
    url = _safe_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": "cpn/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status != 200: raise CpnError(f"Сервер вернул HTTP {response.status}.")
            return parse_profiles(response.read(), url)
    except urllib.error.HTTPError as e: raise CpnError(f"Сервер вернул HTTP {e.code}.")
    except urllib.error.URLError as e: raise CpnError(f"Не удалось подключиться: {e.reason}")
    except TimeoutError: raise CpnError("Истекло время ожидания ответа сервера.")


def update(state: dict[str, Any], only_url: str | None = None) -> tuple[int, list[str]]:
    messages = []; total = 0
    for sub in state["subscriptions"]:
        if only_url and sub["url"] != only_url: continue
        try:
            profiles = fetch_profiles(sub["url"])
            state["profiles"] = [p for p in state["profiles"] if p.get("subscription") != sub["url"]]
            for p in profiles: p["subscription"] = sub["url"]
            state["profiles"].extend(profiles); sub["last_error"] = None; total += len(profiles); messages.append(f"{sub['url']}: загружено профилей: {len(profiles)}")
        except CpnError as e:
            sub["last_error"] = str(e); messages.append(f"{sub['url']}: ошибка: {e}")
    save_state(state); return total, messages


def print_status() -> None:
    n = network_status(); print(f"Подключение: {'да' if n['connected'] else 'нет'}\nИнтерфейс: {n['interface']}\nIP: {n['ip']}\nШлюз: {n['gateway']}\nDNS: {', '.join(n['dns']) or '—'}")


def print_safety() -> None:
    s = safety_status()
    print(f"SSH-сессия: {'да' if s['ssh_session'] else 'нет'}")
    print("Активация VPN: только через явный --activate")
    print("SSH-маршрут: закрепляется + policy route")
    print("nftables: только bypass TCP/22")
    print("DNS: внутри sing-box")
    print("Исполнение профилей: запрещено")


def print_profiles(state: dict[str, Any]) -> None:
    if not state["profiles"]: print("Профили не загружены."); return
    for p in state["profiles"]: print(f"{'*' if p['id'] == state.get('active_profile') else ' '} {p['id']}  {p['name']}  [{p.get('kind','remote')}]")


def handle(args: argparse.Namespace) -> int:
    state = load_state()
    if args.command in (None, "open"): return run_tui(state)
    if args.command == "status": print_status()
    elif args.command == "safety": print_safety()
    elif args.command == "list": print_profiles(state)
    elif args.command == "add-subscription":
        url = _safe_url(args.url)
        if not any(s["url"] == url for s in state["subscriptions"]): state["subscriptions"].append({"url": url, "last_error": None})
        save_state(state); print(f"Подписка добавлена: {url}")
        if args.fetch:
            _, msgs = update(state, url); print("\n".join(msgs)); print_profiles(state)
    elif args.command == "update":
        _, msgs = update(state); print("\n".join(msgs) or "Подписок нет.")
    elif args.command == "select":
        profile = next((p for p in state["profiles"] if p["id"] == args.profile_id), None)
        if profile is None: raise CpnError("Профиль с таким ID не найден.")
        state["active_profile"] = args.profile_id; save_state(state); print(f"Активный профиль: {args.profile_id}")
        if args.activate: activate_profile(profile); print(f"VPN активирован через {VPN_SERVICE}.")
    elif args.command == "remove":
        before = len(state["profiles"]); state["profiles"] = [p for p in state["profiles"] if p["id"] != args.profile_id]
        if before == len(state["profiles"]): raise CpnError("Профиль с таким ID не найден.")
        if state.get("active_profile") == args.profile_id: state["active_profile"] = None
        save_state(state); print("Профиль удалён.")
    elif args.command == "deactivate":
        deactivate_vpn(); print("VPN остановлен, SSH-маршрут восстановлен.")
    elif args.command == "deactivate-route":
        _restore_ssh_route()
    return 0


def run_tui(state: dict[str, Any]) -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty(): print("Интерактивный интерфейс требует терминал. Используйте cpn --help."); return 0
    def ui(stdscr: Any) -> None:
        curses.curs_set(0); selected = 0; menu = ["Сетевой статус", "Безопасность SSH/VPS", "Список профилей", "Добавить подписку", "Обновить подписки", "Выбрать профиль", "Удалить профиль", "Выход"]
        def pause(message: str) -> None:
            stdscr.addstr(10, 2, message[: max(1, curses.COLS - 4)]); stdscr.getch()
        def prompt(message: str) -> str:
            curses.echo(); stdscr.addstr(10, 2, message); value = stdscr.getstr(11, 2, max(1, curses.COLS - 4)).decode("utf-8", "replace"); curses.noecho(); return value.strip()
        def choose_profile(title: str, activate: bool = False, remove: bool = False) -> None:
            profiles = state.get("profiles", [])
            if not profiles: pause("Профили не загружены."); return
            index = next((i for i, p in enumerate(profiles) if p["id"] == state.get("active_profile")), 0)
            while True:
                stdscr.clear(); stdscr.addstr(0, 0, title, curses.A_BOLD)
                for i, profile in enumerate(profiles):
                    marker = "> " if i == index else "  "; active = " [активен]" if profile["id"] == state.get("active_profile") else ""
                    stdscr.addstr(i + 2, 2, f"{marker}{profile['name'][:50]}  ({profile['id']}){active}")
                stdscr.addstr(len(profiles) + 3, 0, "↑/↓ — выбор, Enter — подтвердить, Esc — назад")
                key = stdscr.getch()
                if key == 27: return
                if key in (curses.KEY_UP, ord("k")): index = (index - 1) % len(profiles)
                elif key in (curses.KEY_DOWN, ord("j")): index = (index + 1) % len(profiles)
                elif key in (10, 13):
                    profile = profiles[index]
                    try:
                        if remove:
                            state["profiles"] = [p for p in state["profiles"] if p["id"] != profile["id"]]
                            if state.get("active_profile") == profile["id"]: state["active_profile"] = None
                            save_state(state); pause(f"Профиль удалён: {profile['name']}")
                        else:
                            state["active_profile"] = profile["id"]; save_state(state)
                        if activate:
                            activate_profile(profile); pause(f"VPN активирован: {profile['name']}")
                        elif not remove: pause(f"Профиль выбран: {profile['name']}")
                    except CpnError as error: pause(f"Ошибка: {error}")
                    return
        while True:
            stdscr.clear(); stdscr.addstr(0, 0, "cpn — управление сетевыми профилями", curses.A_BOLD)
            for i, item in enumerate(menu): stdscr.addstr(i + 2, 2, ("> " if i == selected else "  ") + item)
            stdscr.addstr(len(menu) + 3, 0, "↑/↓ — выбор, Enter — выполнить, q — выход")
            key = stdscr.getch()
            if key in (ord("q"), 27): return
            if key in (curses.KEY_UP, ord("k")): selected = (selected - 1) % len(menu)
            elif key in (curses.KEY_DOWN, ord("j")): selected = (selected + 1) % len(menu)
            elif key in (10, 13):
                if selected == 0:
                    stdscr.clear(); stdscr.addstr(0,0,"Сетевой статус",curses.A_BOLD); n=network_status(); [stdscr.addstr(i+2,2,f"{k}: {', '.join(v) if isinstance(v,list) else v}") for i,(k,v) in enumerate(n.items())]; pause("Нажмите любую клавишу")
                elif selected == 1:
                    stdscr.clear(); stdscr.addstr(0,0,"Безопасность SSH/VPS",curses.A_BOLD); [stdscr.addstr(i+2,2,f"{k}: {'да' if v is True else 'нет' if v is False else v}") for i,(k,v) in enumerate(safety_status().items())]; pause("Нажмите любую клавишу")
                elif selected == 2:
                    stdscr.clear(); stdscr.addstr(0,0,"Профили",curses.A_BOLD); [stdscr.addstr(i+2,2,f"{'*' if p['id']==state.get('active_profile') else ' '} {p['id']} {p['name']}") for i,p in enumerate(state['profiles'])]; pause("Нажмите любую клавишу")
                elif selected == 3:
                    stdscr.clear(); stdscr.addstr(0,0,"Добавить подписку",curses.A_BOLD); url = prompt("HTTPS URL:")
                    try:
                        url = _safe_url(url)
                        if not any(s["url"] == url for s in state["subscriptions"]): state["subscriptions"].append({"url": url, "last_error": None}); save_state(state); _, msgs = update(state, url); pause(msgs[0] if msgs else "Подписка добавлена.")
                        else: pause("Такая подписка уже добавлена.")
                    except CpnError as e: pause(f"Ошибка: {e}")
                elif selected == 4:
                    _, msgs = update(state); stdscr.clear(); stdscr.addstr(0,0,"Обновление",curses.A_BOLD); [stdscr.addstr(i+2,2,m[:max(1,curses.COLS-4)]) for i,m in enumerate(msgs)]; pause("Нажмите любую клавишу")
                elif selected == 5:
                    choose_profile("Выбор и активация VPN-профиля", activate=True)
                elif selected == 6:
                    choose_profile("Удаление профиля", remove=True)
                elif selected == 7: return
    curses.wrapper(ui); return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cpn", description="Безопасное управление подписками и сетевым статусом")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("open", help="открыть TUI")
    sub.add_parser("status", help="показать сетевой статус")
    sub.add_parser("safety", help="показать гарантии SSH/VPS-безопасности")
    add = sub.add_parser("add-subscription", help="добавить HTTPS-подписку"); add.add_argument("url"); add.add_argument("--fetch", action="store_true", help="загрузить сразу")
    sub.add_parser("update", help="обновить все подписки")
    sub.add_parser("list", help="список профилей")
    sel = sub.add_parser("select", help="выбрать профиль"); sel.add_argument("profile_id"); sel.add_argument("--activate", action="store_true", help="активировать VPN через sing-box (требует root)")
    rem = sub.add_parser("remove", help="удалить профиль"); rem.add_argument("profile_id")
    sub.add_parser("deactivate", help="остановить VPN и восстановить SSH-маршрут")
    sub.add_parser("deactivate-route", help=argparse.SUPPRESS)
    return p


def main(argv: list[str] | None = None) -> int:
    try: return handle(parser().parse_args(argv))
    except CpnError as e: print(f"Ошибка: {e}", file=sys.stderr); return 2

if __name__ == "__main__": sys.exit(main())
