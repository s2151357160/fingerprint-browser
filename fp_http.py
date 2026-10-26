"""伪装 HTTP 客户端（TLS/JA3 + 完整浏览器请求头链路）

Playwright 浏览器自身走 Chromium 真实 TLS 栈，无需处理；但本项目的
非浏览器 HTTP 流量（订阅抓取、出口 IP 探测、节点信誉探测、打码回调）
默认用 urllib/requests，ClientHello(JA3/JA4) 与真实浏览器不一致，是
被抓包检测的独立盲区。本模块统一用 curl_cffi impersonate 复用官方
浏览器 TLS 指纹，并补齐浏览器式请求头链路，失败自动回退。

用法:
    from fp_http import get, post, browser_headers, best_impersonate
    html = get("https://www.example.com", impersonate="chrome")
    r = post("https://api.example.com", json={...}, impersonate="chrome")

curl_cffi 可用时：requests 风格（Cookie/代理/超时全兼容）；
不可用时：回退 requests；再回退 urllib。上层无感知。
"""
from __future__ import annotations

import json as _json
import platform as _plat

try:
    from curl_cffi import requests as _cf  # noqa: N813
    HAS_CURL_CFFI = True
except Exception:  # noqa: BLE001
    _cf = None
    HAS_CURL_CFFI = False
try:
    import requests as _req  # noqa: N812
    _HAS_REQUESTS = True
except Exception:  # noqa: BLE001
    _req = None
    _HAS_REQUESTS = False

DEFAULT_TIMEOUT = 30

# curl_cffi impersonate 目标。未命中时用最接近的可用版本。
_IMPR_MAP = {
    99: "chrome99", 100: "chrome100", 101: "chrome101", 104: "chrome104",
    107: "chrome107", 110: "chrome110", 111: "chrome111", 116: "chrome116",
    117: "chrome117", 118: "chrome118", 119: "chrome119", 120: "chrome120",
    123: "chrome123", 124: "chrome124", 131: "chrome131", 133: "chrome133",
}
_FALLBACK = "chrome131"


def best_impersonate(major: int | str | None = None, ua: str | None = None):
    """根据浏览器大版本选择最接近的 curl_cffi impersonate 目标。

    缺省无 UA/版本时返回 chrome131（现代主流）。
    """
    m = None
    if major is not None:
        try:
            m = int(str(major).split(".")[0])
        except Exception:  # noqa: BLE001
            m = None
    if m is None and ua:
        import re

        mm = re.search(r"(?:Chrome|Edg)/(\d+)", ua)
        if mm:
            m = int(mm.group(1))
    if not HAS_CURL_CFFI:
        return None
    if m is None:
        return _FALLBACK
    for ver in sorted(_IMPR_MAP, reverse=True):
        if m >= ver:
            target = _IMPR_MAP[ver]
            # 校验目标是否被当前 curl_cffi 支持；不支持则降级
            try:
                _cf.Session(impersonate=target)
            except Exception:  # noqa: BLE001
                continue
            return target
    return _FALLBACK


def browser_headers(ua: str, locale: str = "en-US", platform_name: str = "Windows",
                    major: int | str | None = None) -> dict:
    """构造与真实 Chrome/Edge 一致的完整请求头链路。

    覆盖 curl 缺省不带的 CH 头与 sec-fetch-* 系列，供非浏览器流量
    在头部层面不被一眼识破。
    """
    import json

    m = None
    try:
        m = int(str(major).split(".")[0])
    except Exception:  # noqa: BLE001
        m = None
    if m is None and ua:
        import re

        mm = re.search(r"(?:Chrome|Edg)/(\d+)", ua)
        if mm:
            m = int(mm.group(1))
    m = m or 151
    # 与 fp_browser 同源的 GREASE 品牌生成
    grease_chars = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
    gbrand = f"Not{grease_chars[m % 11]}A{grease_chars[(m + 1) % 11]}Brand"
    gver = ["8", "99", "24"][m % 3]
    main = "Microsoft Edge" if "Edg/" in ua else "Google Chrome"
    brands = [
        {"brand": gbrand, "version": gver},
        {"brand": "Chromium", "version": str(m)},
        {"brand": main, "version": str(m)},
    ]
    ch = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in brands)
    return {
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": locale,
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "sec-ch-ua": ch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{platform_name}"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": ua,
    }


def _proxy_arg(proxy: str | None):
    """把 socks5:// 或 http:// 代理转成 curl_cffi / requests 需要的代理 dict"""
    if not proxy:
        return None
    if proxy.startswith("socks5"):
        return {"http": proxy, "https": proxy}
    return {"http": proxy, "https": proxy}


def request(method: str, url: str, *, headers: dict | None = None, json=None,
            data=None, params: dict | None = None, proxy: str | None = None,
            timeout: int = DEFAULT_TIMEOUT,
            impersonate=None, ua: str | None = None, locale: str = "en-US",
            platform_name: str = "Windows", allow_redirects: bool = True):
    """发起一次伪装请求，返回 Response 兼容对象（含 .text/.json()/.status_code/.url）。

    impersonate=None 且给定 ua 时，自动按 UA 大版本选择 TLS 目标。
    """
    import urllib.parse

    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params, doseq=True)
    merge_headers = dict(headers or {})
    if ua and "User-Agent" not in merge_headers:
        merge_headers.update(
            browser_headers(ua, locale, platform_name,
                            major=None if impersonate else None))
        merge_headers.setdefault("User-Agent", ua)
    if impersonate is None and HAS_CURL_CFFI and ua:
        impersonate = best_impersonate(ua=ua)
    body = _json.dumps(json, ensure_ascii=False).encode("utf-8") if json is not None else data
    if json is not None and "Content-Type" not in merge_headers:
        merge_headers["Content-Type"] = "application/json"

    if HAS_CURL_CFFI:
        try:
            s = _cf.Session(impersonate=impersonate or _FALLBACK)
            resp = s.request(method, url, headers=merge_headers or None, data=body,
                             proxies=_proxy_arg(proxy), timeout=timeout,
                             verify=False, allow_redirects=allow_redirects)
            return _Wrap(resp)
        except Exception:  # noqa: BLE001
            pass
    if _HAS_REQUESTS:
        try:
            resp = _req.request(method, url, headers=merge_headers or None, data=body,
                                proxies=_proxy_arg(proxy), timeout=timeout,
                                verify=False, allow_redirects=allow_redirects)
            return resp
        except Exception:  # noqa: BLE001
            pass
    import urllib.request

    req = urllib.request.Request(url, data=body, headers=merge_headers or {},
                                 method=method)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(_proxy_arg(proxy)) if proxy else
        urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return _Raw(r)


class _Wrap:
    """把 curl_cffi 响应包装成 .text/.json()/.status_code 兼容对象"""

    def __init__(self, resp):
        self._resp = resp
        self.status_code = getattr(resp, "status_code", 200)
        self.url = getattr(resp, "url", "")

    @property
    def text(self):
        try:
            return self._resp.text
        except Exception:  # noqa: BLE001
            return self._resp.content.decode("utf-8", "ignore")

    def json(self):
        return _json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Raw:
    """urllib 兜底响应包装"""

    def __init__(self, r):
        self._r = r
        self.status_code = getattr(r, "status", 200)
        self.url = r.geturl()
        self._data = r.read()

    @property
    def text(self):
        return self._data.decode("utf-8", "ignore")

    def json(self):
        return _json.loads(self.text)


def get(url, **kw):
    return request("GET", url, **kw)


def post(url, **kw):
    return request("POST", url, **kw)


def put(url, **kw):
    return request("PUT", url, **kw)


if __name__ == "__main__":
    print("curl_cffi 可用:", HAS_CURL_CFFI)
    print("默认 impersonate:", best_impersonate())
    print("UA 大版本推断:", best_impersonate(ua="Mozilla/5.0 ... Chrome/150.0.0.0"))
    hdrs = browser_headers(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/151.0.0.0",
        "en-US", "Windows", 151)
    print(json_h := _json.dumps(hdrs, ensure_ascii=False, indent=2))
