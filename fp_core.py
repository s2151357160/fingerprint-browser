"""内置梯子内核（mihomo）管理

把 Clash 系开源内核（mihomo 单文件）打进项目，由代码直接指挥：
  - 节点来源：自动扫描本机 Clash/Verge 配置文件提取节点（零配置）
  - 启动：拉起内置 mihomo 子进程，本地代理端口 + 控制 API 端口全部自动分配
  - 换 IP：直接调内置 API 随机切换节点 —— 不依赖外置梯子软件的任何设置

用法:
    from fingerprint_browser.fp_core import Core
    core = Core()
    core.start()                       # 拉起内置内核（自动找节点）
    proxy = core.proxy_url             # 浏览器/请求走这个地址
    node = core.rotate_node()          # 随机切换节点 → 出口 IP 变化
    core.stop()
"""
from __future__ import annotations

import json
import random
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

CORE_EXE = Path(__file__).resolve().parent / "core" / "mihomo-windows-amd64.exe"
# 运行时产物（fp-core-*.yaml 含节点凭据、cache.db）放系统临时目录，项目目录保持干净
DATA_DIR = Path(tempfile.gettempdir()) / "fingerprint_browser_core"
# 配置文件名含实例 secret 前缀：多会话并行时各自独立配置，杜绝互相覆盖竞态

# 内置内核端口起始（避开外置梯子常用的 7890/7897）
MIXED_PORT_START = 7899
API_PORT_START = 19090

# 本机 Clash 系配置常见位置（按文件大小优先，越大越可能是完整订阅）
CONFIG_CANDIDATES = [
    Path.home() / ".config" / "clash-verge" / "profiles",
    Path.home() / ".config" / "clash" / "profiles",
    Path.home() / ".config" / "mihomo" / "profiles",
    Path.home() / "AppData" / "Roaming" / "io.github.clash-verge-rev.clash-verge-rev" / "profiles",
    Path.home() / "AppData" / "Roaming" / "clash-verge" / "profiles",
]

# 订阅源列表（每行一个 URL；节点合并进池，与本地 Clash 配置去重）
SUBS_FILE = Path(__file__).resolve().parent.parent / "subscriptions.txt"
# 订阅节点缓存（拉取成功即落盘；订阅临时限流/失效时用缓存兑底，节点池不抖动）
SUBS_CACHE = Path(__file__).resolve().parent.parent / "sub_nodes_cache.yaml"
# 自定义代理：用户自填的代理服务器（socks5/http/ss/vmess...），
# 注入节点池后可被绑定/选中 → 浏览器走它 → 目标网站看到该代理出口 IP。
CUSTOM_PROXIES = Path(__file__).resolve().parent.parent / "custom_proxies.json"

# 自定义代理允许的 mihomo 节点类型（其余类型字段差异大，防止配置非法导致内核启动失败）
ALLOWED_CUSTOM_TYPES = {
    "socks5", "socks4", "http", "https", "ss", "shadowsocks",
    "vmess", "vless", "trojan", "wireguard",
}


def load_custom_proxies() -> list[dict]:
    """读取 custom_proxies.json 的自定义代理节点。

    文件不存在/损坏返回空。结构：顶层对象带 proxies 数组，或直接是数组。
    仅校验基础字段（name/server/type/port），账号密码可选，
    uuid/alterId/sni 等专用字段原样透传。非法条目静默跳过。
    """
    try:
        data = json.loads(CUSTOM_PROXIES.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    if isinstance(data, dict):
        data = data.get("proxies") or []
    if not isinstance(data, list):
        return []
    out: list[dict] = []
    for p in data:
        if not (isinstance(p, dict) and p.get("name") and p.get("server")):
            continue
        t = str(p.get("type") or "socks5").lower()
        if t not in ALLOWED_CUSTOM_TYPES:
            continue
        try:
            port = int(p["port"])
        except Exception:  # noqa: BLE001
            continue
        node = {"name": p["name"], "type": t, "server": p["server"], "port": port}
        for k in ("username", "password", "uuid", "alterId", "cipher",
                  "ai", "sni", "skip-cert-verify"):
            if p.get(k) is not None:
                node[k] = p[k]
        out.append(node)
    return out


def read_subscriptions() -> list[str]:
    """读取订阅 URL 列表（空行/注释行忽略）"""
    try:
        return [ln.strip() for ln in SUBS_FILE.read_text(encoding="utf-8").splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
    except Exception:
        return []


def fetch_subscription_nodes(url: str, timeout: int = 30) -> list[dict]:
    """下载单个订阅并提取节点（Clash YAML 格式；失败返回空）

    携带 clash UA 拿 YAML；机场域名通常可直连，被墙时依次回退
    系统代理。优先走 fp_http（curl_cffi 官方 TLS 指纹，订阅接口
    对非浏览器 TLS 的拦截更友好），失败回退 urllib。
    拉取成功时写入全局缓存（多订阅合并），任一订阅临时 404/限流
    时由 load_subs_cache() 兑底。
    """
    from .fp_http import request as _http_request

    # 订阅本身是 Clash 协议：保持真实 clash UA，仅在 TLS 层做浏览器伪装
    hdrs = {"User-Agent": "clash-verge/1.7.7"}
    data = None
    for proxy in (None, "http://127.0.0.1:7897"):
        try:
            # 优先 curl_cffi（真实 TLS ClientHello），回退 urllib
            for use_cf in (True, False):
                if use_cf:
                    try:
                        from curl_cffi import requests as _cf  # noqa: N813
                        s = _cf.Session(impersonate="chrome131")
                        resp = s.get(url, headers=hdrs, timeout=timeout, verify=False,
                                     proxies={"http": proxy, "https": proxy} if proxy else None)
                        data = resp.content
                        break
                    except Exception:  # noqa: BLE001
                        continue
                import urllib.request
                req = urllib.request.Request(url, headers=hdrs)
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                    if proxy else urllib.request.ProxyHandler({}))
                with opener.open(req, timeout=timeout) as r:
                    data = r.read()
                break
            if data is not None:
                break
        except Exception:
            continue
    if not data:
        return []
    try:
        parsed = _yaml().safe_load(data.decode("utf-8", errors="ignore")) or {}
        proxies = parsed.get("proxies") or []
        if proxies:
            _save_subs_cache(url, proxies)
        return proxies
    except Exception:
        return []


def _save_subs_cache(url: str, proxies: list[dict]):
    """把拉到的订阅节点并入缓存文件（{url: 节点列表}，按 URL 分槽）"""
    try:
        cache = {}
        if SUBS_CACHE.exists():
            cache = _yaml().safe_load(SUBS_CACHE.read_text(encoding="utf-8")) or {}
        # 清洗：仅存真实节点（防占位/特殊策略项长期堆积）
        clean = [p for p in proxies
                 if isinstance(p, dict) and p.get("name") and p.get("server")
                 and p["name"].upper() not in SPECIAL_NODES
                 and not any(k in str(p["name"]) for k in PLACEHOLDER_KEYS)]
        cache[url] = clean
        SUBS_CACHE.write_text(
            _yaml().dump(cache, allow_unicode=True, sort_keys=False), encoding="utf-8")
    except Exception:
        pass


def load_subs_cache() -> list[dict]:
    """读取全部订阅的缓存节点（订阅拉取失败时的兑底）"""
    try:
        cache = _yaml().safe_load(SUBS_CACHE.read_text(encoding="utf-8")) or {}
        out: list[dict] = []
        for proxies in cache.values():
            if isinstance(proxies, list):
                out.extend(p for p in proxies if isinstance(p, dict))
        return out
    except Exception:
        return []

# 占位/信息节点关键词（"剩余流量""到期时间"等假节点）
PLACEHOLDER_KEYS = ("剩余", "到期", "过期", "套餐", "重置", "官网", "流量", "过滤")

# 特殊策略节点（非真实代理，选中会绕过代理直连 → 目标站点打不开/Turnstile 验证失败）
SPECIAL_NODES = {"DIRECT", "REJECT", "REJECT-DROP", "REJECT-DROP-ICMP", "PASS",
                "GLOBAL", "COMPATIBLE", "MATCH", "FINAL", "AUTO", "DIRECT-REJECT",
                "直连", "拒绝"}


def _yaml():
    """延迟导入 pyyaml：缺失时抛 RuntimeError 而非启动时崩溃（降级由上层处理）"""
    try:
        import yaml  # noqa: PLC0415
        return yaml
    except ImportError as e:
        raise RuntimeError("缺少 pyyaml 依赖（pip install pyyaml）") from e


def find_local_nodes() -> list[dict]:
    """扫描本机 Clash 系配置 + 订阅源，提取真实节点（按名称去重合并）"""
    try:
        y = _yaml()
    except RuntimeError:
        return []
    seen: set[str] = set()
    result: list[dict] = []

    def _safe_size(p: Path) -> int:
        try:
            return p.stat().st_size
        except OSError:
            return 0

    def _merge(proxies: list) -> None:
        for p in proxies:
            if (isinstance(p, dict) and p.get("name") and p.get("server")
                    and p["name"] not in seen
                    and p["name"].upper() not in SPECIAL_NODES
                    and not any(k in str(p["name"]) for k in PLACEHOLDER_KEYS)):
                seen.add(p["name"])
                result.append(p)

    # 0) 用户自定义代理（custom_proxies.json）：最高优先，同名不被订阅/Clash 覆盖
    _merge(load_custom_proxies())

    # 1) 订阅源（优先：节点更新、可能含住宅资源）；全部拉取失败时用缓存兜底
    sub_nodes: list[dict] = []
    for url in read_subscriptions():
        try:
            sub_nodes.extend(fetch_subscription_nodes(url))
        except Exception:
            continue
    if not sub_nodes:
        sub_nodes = load_subs_cache()
    _merge(sub_nodes)
    # 2) 本机 Clash 系配置
    for d in CONFIG_CANDIDATES:
        if not d.exists():
            continue
        for f in sorted(d.glob("*.yaml"), key=_safe_size, reverse=True):
            try:
                data = y.safe_load(f.read_text(encoding="utf-8", errors="ignore")) or {}
                _merge(data.get("proxies") or [])
            except Exception:
                continue
    return result


def _free_port(start: int, tries: int = 20) -> int:
    for port in range(start, start + tries):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"端口 {start}~{start + tries} 均被占用")


def _kill_orphan_cores():
    """清理本项目遗留的孤儿 mihomo 进程。

    孤儿定义：命令行含本项目内核配置（fp-core-*.yaml），且满足其一：
      a) 父进程不存在（控制台被强杀后残留）；
      b) "父进程"创建时间晚于内核自身（Windows PID 复用导致误判，真父早已退出）。
    父进程真实存活的不杀（避免多实例互踩）；外置梯子内核命令行不含本项目配置，不受影响。
    """
    ps_script = (
        "$targets = Get-CimInstance Win32_Process "
        "-Filter \"Name='mihomo-windows-amd64.exe'\" | "
        "Where-Object { $_.CommandLine -like '*fp-core-*.yaml*' }; "
        "foreach ($t in $targets) { "
        "$p = Get-CimInstance Win32_Process "
        "-Filter \"ProcessId=$($t.ParentProcessId)\" -ErrorAction SilentlyContinue; "
        "if ((-not $p) -or ($p.CreationDate -gt $t.CreationDate)) { "
        "Stop-Process -Id $t.ProcessId -Force } }"
    )
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps_script],
                       capture_output=True, timeout=25)
    except Exception:
        pass


def _clean_stale_core_dirs():
    """删除没有活动内核引用的实例目录。

    config.yaml 含完整节点凭据，残留即泄漏；旧版扁平文件
    （fp-core-config-*.yaml / fp-core.yaml / 共享 cache.db）一并清理。
    """
    try:
        live = []
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-CimInstance Win32_Process -Filter \"Name='mihomo-windows-amd64.exe'\" "
             "| ForEach-Object { $_.CommandLine }"],
            capture_output=True, timeout=25)
        for line in out.stdout.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if line:
                live.append(line.lower())
        if not DATA_DIR.exists():
            return
        for item in DATA_DIR.iterdir():
            keep = any(str(item).lower() in cmd for cmd in live)
            try:
                if keep:
                    continue
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink()
            except Exception:
                pass
    except Exception:
        pass


class Core:
    """内置 mihomo 内核生命周期管理"""

    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.secret = secrets.token_hex(8)
        self.port: int | None = None
        self.api_port: int | None = None
        self.nodes: list[dict] = []
        # 每实例独立数据目录：多实例并行时不共用 cache.db（并发写冲突），
        # 停止时整目录清理（config 含节点凭据，不留临时目录）
        self.data_dir = DATA_DIR / f"fp-core-{self.secret[:8]}"
        self.config_path = self.data_dir / "config.yaml"

    # ---------- 状态 ----------
    @property
    def available(self) -> bool:
        return CORE_EXE.exists()

    @property
    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    @property
    def proxy_url(self) -> str | None:
        return f"http://127.0.0.1:{self.port}" if self.port else None

    def node_names(self) -> list[str]:
        return [n["name"] for n in self.nodes]

    # ---------- API ----------
    def _api(self, method: str, path: str, body=None, timeout: float = 5):
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.api_port}{path}",
                method=method,
                headers={"Authorization": f"Bearer {self.secret}"},
                data=json.dumps(body).encode("utf-8") if body is not None else None)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                if r.status == 204:
                    return {}
                return json.loads(r.read().decode("utf-8"))
        except Exception:
            return None

    # ---------- 生命周期 ----------
    def start(self, nodes: list[dict] | None = None) -> bool:
        """拉起内置内核。返回 True；失败抛异常。"""
        if not self.available:
            raise RuntimeError(f"内核文件不存在: {CORE_EXE}")
        if self.running:
            return True

        # 孤儿清理条件化：起始端口被占才可能是上次强杀的残留，正常路径零开销
        port = _free_port(MIXED_PORT_START)
        if port != MIXED_PORT_START:
            _kill_orphan_cores()
            port = _free_port(MIXED_PORT_START)
        # 清理无活动内核引用的陈旧目录/旧版扁平文件（含凭据，不残留）
        _clean_stale_core_dirs()

        self.nodes = nodes or find_local_nodes()
        if not self.nodes:
            raise RuntimeError("未在本机找到可用节点（请提供 Clash 配置或订阅）")

        self.port = port
        self.api_port = _free_port(API_PORT_START)

        cfg = {
            "mixed-port": self.port,
            "external-controller": f"127.0.0.1:{self.api_port}",
            "secret": self.secret,
            "log-level": "warning",
            "mode": "global",
            "unified-delay": True,
            "tcp-concurrent": True,
            "ipv6": False,
            "proxies": self.nodes,
            "proxy-groups": [{
                "name": "FP-POOL",
                "type": "select",
                "proxies": self.node_names(),
            }],
            "rules": [],
        }
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            _yaml().dump(cfg, allow_unicode=True, sort_keys=False), encoding="utf-8")

        self.proc = subprocess.Popen(
            [str(CORE_EXE), "-f", str(self.config_path), "-d", str(self.data_dir)],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

        # 等待控制 API 就绪；失败路径必须回收进程，避免泄漏
        try:
            for _ in range(50):
                if self._api("GET", "/version"):
                    return True
                if not self.running:
                    raise RuntimeError("内核进程启动即退出（检查 core/fp-core.yaml 与节点配置）")
                time.sleep(0.3)
            raise RuntimeError("内核控制 API 未就绪（15s 超时）")
        except Exception:
            self.stop()
            raise

    def stop(self):
        if self.proc and self.running:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
        self.proc = None
        self.port = None
        self.api_port = None
        # 清理本实例数据目录（config 含节点凭据 + cache），不留敏感残留
        try:
            if self.data_dir.exists():
                shutil.rmtree(self.data_dir, ignore_errors=True)
        except Exception:
            pass

    # ---------- 节点切换 ----------
    def current_node(self) -> str | None:
        data = self._api("GET", "/proxies")
        if not data:
            return None
        g = data.get("proxies", {}).get("GLOBAL", {})
        return g.get("now")

    def select_node(self, name: str | None) -> bool:
        """按名称绑定节点（账号档案固定节点还原用）；节点不在池中返回 False。"""
        if not name or name not in self.node_names():
            return False
        self._api("PUT", "/proxies/GLOBAL", {"name": name}, timeout=8)
        time.sleep(0.4)
        if self.current_node() == name:
            self._api("DELETE", "/connections", timeout=5)
            return True
        return False

    def rotate_node(self, exclude_current: bool = True,
                   preferred: list[str] | None = None) -> str | None:
        """随机切换节点并断开旧连接，返回新节点名；失败返回 None。

        preferred: 信誉优先节点列表（非空时优先从中随机；列表内不含当前
        节点也无妨，exclude_current 照常生效）。无达标节点时回退全池随机。
        """
        current = self.current_node()
        names = self.node_names()
        candidates = [n for n in names if not exclude_current or n != current]
        if not candidates:
            return None
        if preferred:
            prio = [n for n in candidates if n in preferred]
            if prio:
                candidates = prio
        chosen = random.choice(candidates)
        self._api("PUT", "/proxies/GLOBAL", {"name": chosen}, timeout=8)
        time.sleep(0.4)
        if self.current_node() == chosen:
            self._api("DELETE", "/connections", timeout=5)  # 断开旧连接，新 IP 立即生效
            return chosen
        return None


if __name__ == "__main__":
    core = Core()
    print("内核文件:", "存在" if core.available else "缺失")
    nodes = find_local_nodes()
    print("本机节点数:", len(nodes))
    if nodes and core.available:
        core.start()
        print("内置内核已启动:", core.proxy_url, "| 控制 API:", core.api_port)
        print("当前节点:", core.current_node())
        print("切换到:", core.rotate_node())
        print("当前节点:", core.current_node())
        core.stop()
        print("已停止")