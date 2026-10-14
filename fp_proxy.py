"""本机梯子代理自动探测 + Clash 节点自动切换（自动换 IP）

两类能力：
1. detect_local_proxy()          探测本机梯子的代理端口（SOCKS5/HTTP）
2. Clash 控制接口联动           detect_clash_api() / rotate_clash_node()
                                每次启动自动切换节点 → 出口 IP 自动更换

前置条件（自动换 IP 需要）：
  梯子（Clash 系）开启外部控制接口 external-controller，默认 127.0.0.1:9090。
  开启方法：Clash 配置 external-controller: 127.0.0.1:9090（或客户端设置里的
  "External Controller / 外部控制" 开关），部分客户端默认开启。

用法:
    from fingerprint_browser.fp_proxy import detect_local_proxy, detect_clash_api, rotate_clash_node
    proxy = detect_local_proxy()
    api = detect_clash_api()
    if api:
        rotate_clash_node(*api)          # 自动换一个节点（IP 随之变化）
"""
from __future__ import annotations

import json
import random
import socket
import urllib.parse
import urllib.request

# 常见梯子软件默认本地代理端口（类型, 端口）
COMMON_PORTS = [
    ("socks5", 7890),   # Clash / Clash for Windows
    ("socks5", 7897),   # Clash Verge Rev
    ("socks5", 7891),
    ("socks5", 10808),  # V2RayN
    ("http", 10809),    # V2RayN http
    ("socks5", 1080),   # Shadowsocks / 通用
    ("http", 1081),
    ("http", 8888),
    ("socks5", 1088),   # 备用
]

# Clash 外部控制常见端口
CLASH_API_PORTS = (9090, 9097, 9091, 6170, 12948)


# ==================== 代理端口探测 ====================

def _connect(host: str, port: int, timeout: float):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        return s
    except OSError:
        return None


def _socks5_ok(sock) -> bool:
    """SOCKS5 握手探测：发版本协商，期望 0x05 0x00"""
    try:
        sock.sendall(b"\x05\x01\x00")
        return sock.recv(2) == b"\x05\x00"
    except OSError:
        return False


def _http_ok(sock) -> bool:
    """HTTP 代理探测：发 CONNECT 请求，期望 HTTP 响应行"""
    try:
        sock.sendall(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        data = sock.recv(32)
        return data.startswith(b"HTTP/1")
    except OSError:
        return False


def detect_local_proxy(host: str = "127.0.0.1", timeout: float = 0.5) -> str | None:
    """按常见端口探测本机代理，返回 "socks5://host:port" / "http://host:port" 或 None"""
    for kind, port in COMMON_PORTS:
        sock = _connect(host, port, timeout)
        if sock is None:
            continue
        try:
            ok = _socks5_ok(sock) if kind == "socks5" else _http_ok(sock)
            if ok:
                return f"{kind}://{host}:{port}"
        finally:
            sock.close()
    return None


# ==================== Clash 控制接口 ====================

def _clash_request(method: str, url: str, secret: str | None, timeout: float, body=None):
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status == 204:
            return None
        return json.loads(resp.read().decode("utf-8"))


def detect_clash_api(host: str = "127.0.0.1", ports: tuple = CLASH_API_PORTS,
                     timeout: float = 0.6):
    """探测 Clash 外部控制接口，返回 (host, port, secret) 或 None"""
    for port in ports:
        try:
            data = _clash_request("GET", f"http://{host}:{port}/version", None, timeout)
            if isinstance(data, dict) and data.get("version"):
                return host, port, None
        except urllib.error.HTTPError as e:
            # 401/403 说明接口存在但需要 secret
            if e.code in (401, 403):
                try:
                    body = json.loads(e.read().decode("utf-8", "ignore"))
                    return host, port, body.get("secret")
                except Exception:
                    return host, port, None
        except Exception:
            continue
    return None


def clash_real_nodes(api, timeout: float = 3.0) -> list[str]:
    """列出 Clash 中所有可用真实节点名"""
    host, port, secret = api
    proxies = _clash_request("GET", f"http://{host}:{port}/proxies", secret, timeout)
    if not proxies:
        return []
    skip = {"Direct", "Reject", "Pass", "GLOBAL", "DIRECT", "REJECT"}
    nodes = []
    for name, p in proxies.get("proxies", {}).items():
        t = p.get("type", "")
        # 真实节点：类型为协议节点且不是策略组
        if t in ("Selector", "URLTest", "Fallback", "LoadBalance", "Relay", "Direct", "Reject", "RejectDrop", "Compatible", "Pass"):
            continue
        if name in skip or "默认" in name:
            continue
        nodes.append(name)
    return nodes


def rotate_clash_node(api, exclude: list[str] | None = None, timeout: float = 3.0):
    """切换 Clash 到随机一个节点，返回 (切换前组名, 新节点名) 或 (None, None)。

    会找一个含该节点的策略组并切换选择；同时清除现有连接（connections）
    确保新请求立即走新节点。
    """
    host, port, secret = api
    nodes = [n for n in clash_real_nodes(api, timeout) if not exclude or n not in exclude]
    if not nodes:
        return None, None
    chosen = random.choice(nodes)

    proxies = _clash_request("GET", f"http://{host}:{port}/proxies", secret, timeout)
    old_group = None
    if proxies:
        for gname, g in proxies.get("proxies", {}).items():
            if g.get("type") in ("Selector", "URLTest", "Fallback") and chosen in g.get("all", []):
                if g.get("now") != chosen:
                    _clash_request("PUT", f"http://{host}:{port}/proxies/{urllib.parse.quote(gname)}",
                                   secret, timeout, {"name": chosen})
                old_group = gname
                break
    # 断开旧连接，确保下一次请求就走新节点
    try:
        _clash_request("DELETE", f"http://{host}:{port}/connections", secret, timeout)
    except Exception:
        pass
    return old_group, chosen


if __name__ == "__main__":
    r = detect_local_proxy()
    print(f"代理端口: {r}" if r else "代理端口: 未检测到（梯子未启动？）")
    api = detect_clash_api()
    if api:
        print(f"Clash 控制接口: {api[0]}:{api[1]} (secret={'有' if api[2] else '无'})")
        nodes = clash_real_nodes(api)
        print(f"可用节点数: {len(nodes)}")
        if nodes:
            group, node = rotate_clash_node(api)
            print(f"已切换: {group} -> {node}")
    else:
        print("Clash 控制接口: 未开启（自动换 IP 需在 Clash 开启 external-controller，默认 9090）")