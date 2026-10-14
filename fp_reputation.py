"""节点信誉分级：出口 IP 类型探测 + 评分 + 缓存

风控（Cloudflare/reCAPTCHA/OpenAI 等）对出口 IP 的基础信任度：
  移动网络(4G/5G NAT) > 家宽住宅 > 未标记数据中心 > 被标记代理/VPN

实现（零依赖）：
  - 逐节点切换 → urllib 查出口 IP（复用内置内核，不影响在跑的会话）
  - ip-api.com 免费 batch 接口批量分类（hosting/proxy/mobile/ASN），
    一次请求查完整池（免费版限 45 req/min，batch 上限 100）
  - 结果缓存 7 天（node_reputation.json），过期由用户手动重扫

评分：
  3 移动  |  2 住宅  |  1 数据中心（未标记）  |  0 被标记代理/VPN
"""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path

REPUTATION_FILE = Path(__file__).resolve().parent.parent / "node_reputation.json"
TTL_SECONDS = 7 * 24 * 3600
BATCH_URL = ("http://ip-api.com/batch"
             "?fields=status,country,countryCode,regionName,city,as,isp,mobile,proxy,hosting,query")
BATCH_LIMIT = 100

TYPE_NAME = {3: "移动", 2: "住宅", 1: "数据中心", 0: "代理标记"}

# ip-api 的 hosting 标记不全（如 AS16509 Amazon 部分段漏标），ASN 关键词兑底
_CLOUD_AS_KEYS = ("amazon", "google", "microsoft", "azure", "digitalocean", "ovh",
                 "hetzner", "alibaba", "tencent", "oracle", "linode", "akamai",
                 "vultr", "choopa", "contabo", "m247", "leaseweb", "bandwagon",
                 "choopa", "zscaler", "datacamp")


def score_of(info: dict) -> int:
    if info.get("proxy"):
        return 0
    if info.get("mobile"):
        return 3
    asn = (info.get("as") or "").lower()
    if info.get("hosting") or any(k in asn for k in _CLOUD_AS_KEYS):
        return 1
    return 2   # 非 hosting 非 mobile：家庭宽带


def _probe_ip(proxy_url: str | None) -> str | None:
    """通过指定代理查出口 IP（多 URL 兜底）"""
    if not proxy_url:
        return None
    import re
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    for url in ("http://api.ipify.org", "http://ip.3322.net"):
        try:
            with opener.open(url, timeout=8) as r:
                m = re.search(r"(\d{1,3}\.){3}\d{1,3}", r.read().decode("utf-8", "ignore"))
            if m:
                return m.group(0)
        except Exception:
            continue
    return None


def classify_ips(ips: list[str]) -> dict[str, dict]:
    """批量查询 IP 类型；失败返回空（自用工具容忍降级）"""
    uniq = list(dict.fromkeys(ips))
    out: dict[str, dict] = {}
    for i in range(0, len(uniq), BATCH_LIMIT):
        chunk = uniq[i:i + BATCH_LIMIT]
        try:
            req = urllib.request.Request(
                BATCH_URL, data=json.dumps(chunk).encode("utf-8"), method="POST",
                headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as r:
                for item in json.loads(r.read().decode("utf-8")):
                    if isinstance(item, dict) and item.get("status") == "success":
                        out[item.get("query", "")] = item
        except Exception:
            continue
    return out


def scan(pool_nodes: list[dict], log=print, progress=lambda s: None) -> dict:
    """全池扫描：逐节点探出口 IP → 批量分类 → 评分。返回 {节点名: info}

    起临时内核逐节点切换，不影响在跑的会话（各会话有独立内核）。
    """
    from .fp_core import Core   # 延迟导入避免环
    results: dict[str, dict] = {}
    core = Core()
    ip_map: dict[str, tuple] = {}   # {节点名: (出口IP, 探测耗时ms)}
    try:
        core.start(nodes=pool_nodes)
        names = core.node_names()
        for i, name in enumerate(names):
            progress(f"{i + 1}/{len(names)}")
            if not core.select_node(name):
                log(f"[信誉] 节点切换失败，跳过: {name}")
                continue
            t0 = time.time()
            ip = _probe_ip(core.proxy_url)
            latency_ms = int((time.time() - t0) * 1000) if ip else None
            if ip:
                ip_map[name] = (ip, latency_ms)
        if not ip_map:
            return results
        classified = classify_ips([v[0] for v in ip_map.values()])
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for name, (ip, latency_ms) in ip_map.items():
            info = classified.get(ip) or {}
            score = score_of(info) if info else -1   # 分类失败 = -1（未知）
            results[name] = {
                "ip": ip, "score": score, "type": TYPE_NAME.get(score, "未知"),
                "country": info.get("countryCode", ""),
                "country_name": info.get("country", ""),
                "city": info.get("city", ""),
                "as": info.get("as", ""),
                "latency_ms": latency_ms,
                "flags": {"proxy": bool(info.get("proxy")),
                          "hosting": bool(info.get("hosting")),
                          "mobile": bool(info.get("mobile"))},
                "checked_at": now,
            }
    finally:
        try:
            core.stop()
        except Exception:
            pass
    return results


class ReputationStore:
    """线程安全的信誉缓存（模块级单例 store）"""

    def __init__(self, path: Path = REPUTATION_FILE):
        self._lock = threading.Lock()
        self._path = path
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self):
        try:
            self._data = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            self._data = {}

    def save(self):
        with self._lock:
            try:
                self._path.write_text(
                    json.dumps(self._data, ensure_ascii=False, indent=1), encoding="utf-8")
            except Exception:
                pass

    def update(self, results: dict):
        with self._lock:
            self._data.update(results)
        self.save()

    def get(self, name: str) -> dict | None:
        with self._lock:
            return self._data.get(name)

    def get_score(self, name: str) -> int:
        return (self.get(name) or {}).get("score", -1)

    def node_country(self, name: str) -> tuple[str | None, str | None]:
        """返回节点 (国家码, 城市)——环境人设用"""
        with self._lock:
            v = self._data.get(name) or {}
        return v.get("country") or None, v.get("city") or None

    def same_country_names(self, all_names: list[str], country: str) -> list[str]:
        """与指定国家同国的节点名（未扫描国家信息的节点排除）"""
        if not country:
            return []   # 空国家参数：不匹配任何节点（含未扫描的 country="" 节点）
        with self._lock:
            return [n for n in all_names
                    if (self._data.get(n) or {}).get("country", "").upper() == country.upper()]

    def preferred_names(self, all_names: list[str]) -> list[str]:
        """信誉达标（>=2 住宅/移动）且延迟可接受（<800ms，未测不计限制）的节点名"""
        with self._lock:
            out = []
            for n in all_names:
                v = self._data.get(n) or {}
                if v.get("score", -1) >= 2:
                    lat = v.get("latency_ms")
                    if lat is None or lat < 800:
                        out.append(n)
            return out

    def summary(self) -> dict:
        """信誉分布摘要（控制台展示）"""
        with self._lock:
            data = dict(self._data)
        dist = {"3": 0, "2": 0, "1": 0, "0": 0, "unknown": 0}
        latest = ""
        lats = []
        for v in data.values():
            s = v.get("score", -1)
            dist[str(s) if s >= 0 else "unknown"] += 1
            latest = max(latest, v.get("checked_at", ""))
            if v.get("latency_ms"):
                lats.append(v["latency_ms"])
        lat_info = {
            "avg_latency_ms": int(sum(lats) / len(lats)) if lats else None,
            "min_latency_ms": min(lats) if lats else None,
        }
        return {"count": len(data), "distribution": dist,
                "checked_at": latest, **lat_info}


store = ReputationStore()
