"""环境人设：按出口 IP 国家生成自洽的时区/语言/地理坐标

风控会交叉校验：IP 国家 vs 时区 vs 语言 vs Geolocation。
本模块让账号档案携带"国家人设"，启动会话时覆盖指纹的环境字段，
呈现为该国的本地用户（美国 IP + America/Los_Angeles + en-US）。

原则：
  - 环境绑定账号（meta.env 国家码），不随单次换节点漂移——同一账号人设稳定
  - 随机换 IP 默认限制在同国家节点池（手动跨国家切换会提示环境不匹配）
"""
from __future__ import annotations

# 国家码 -> (时区候选, 语言, 代表城市坐标)
# 美国按城市细分时区（ip-api 返回 region/city，能对上就用当地时区）
ENV_MAP: dict[str, dict] = {
    "US": {
        "locales": ["en-US"], "langs": [["en-US", "en"]],
        "tz_by_city": {
            "los angeles": "America/Los_Angeles", "san jose": "America/Los_Angeles",
            "seattle": "America/Los_Angeles", "san francisco": "America/Los_Angeles",
            "chicago": "America/Chicago", "dallas": "America/Chicago",
            "houston": "America/Chicago", "austin": "America/Chicago",
            "new york": "America/New_York", "miami": "America/New_York",
            "atlanta": "America/New_York", "washington": "America/New_York",
            "denver": "America/Denver", "phoenix": "America/Phoenix",
        },
        "tz_default": "America/New_York",
        "geo": {"latitude": 40.71, "longitude": -74.01},   # 纽约
        "geo_by_city": {
            "los angeles": {"latitude": 34.05, "longitude": -118.24},
            "san jose": {"latitude": 37.34, "longitude": -121.89},
            "seattle": {"latitude": 47.61, "longitude": -122.33},
            "chicago": {"latitude": 41.88, "longitude": -87.63},
            "dallas": {"latitude": 32.78, "longitude": -96.80},
            "new york": {"latitude": 40.71, "longitude": -74.01},
            "miami": {"latitude": 25.76, "longitude": -80.19},
        },
    },
    "HK": {"locales": ["zh-HK", "en-HK"], "langs": [["zh-HK", "zh", "en"], ["en-HK", "en", "zh"]],
           "tz_default": "Asia/Hong_Kong",
           "geo": {"latitude": 22.32, "longitude": 114.17}},
    "JP": {"locales": ["ja-JP"], "langs": [["ja-JP", "ja", "en-US", "en"]],
           "tz_default": "Asia/Tokyo",
           "geo": {"latitude": 35.68, "longitude": 139.69}},
    "SG": {"locales": ["en-SG"], "langs": [["en-SG", "en", "zh"]],
           "tz_default": "Asia/Singapore",
           "geo": {"latitude": 1.35, "longitude": 103.82}},
    "KR": {"locales": ["ko-KR"], "langs": [["ko-KR", "ko", "en"]],
           "tz_default": "Asia/Seoul",
           "geo": {"latitude": 37.57, "longitude": 126.98}},
    "TW": {"locales": ["zh-TW"], "langs": [["zh-TW", "zh", "en"]],
           "tz_default": "Asia/Taipei",
           "geo": {"latitude": 25.03, "longitude": 121.57}},
    "GB": {"locales": ["en-GB"], "langs": [["en-GB", "en"]],
           "tz_default": "Europe/London",
           "geo": {"latitude": 51.51, "longitude": -0.13}},
    "DE": {"locales": ["de-DE"], "langs": [["de-DE", "de", "en"]],
           "tz_default": "Europe/Berlin",
           "geo": {"latitude": 52.52, "longitude": 13.40}},
    "CA": {"locales": ["en-CA"], "langs": [["en-CA", "en"]],
           "tz_default": "America/Toronto",
           "geo": {"latitude": 43.65, "longitude": -79.38}},
    "AU": {"locales": ["en-AU"], "langs": [["en-AU", "en"]],
           "tz_default": "Australia/Sydney",
           "geo": {"latitude": -33.87, "longitude": 151.21}},
    # 中国（挂梯子场景原生人设）
    "CN": {"locales": ["zh-CN"], "langs": [["zh-CN", "zh"]],
           "tz_default": "Asia/Shanghai",
           "geo": {"latitude": 31.23, "longitude": 121.47}},
}

DEFAULT_ENV = {"locales": ["en-US"], "langs": [["en-US", "en"]],
               "tz_default": "Etc/UTC", "geo": {"latitude": 0.0, "longitude": 0.0}}

# 节点名常见国家关键词 -> 国家码（档案创建时节点还没扫描国家，按名称先猜）
_NAME_HINTS = [
    ("美国", "US"), ("US", "US"), ("LA", "US"), ("美", "US"),
    ("日本", "JP"), ("JP", "JP"), ("东京", "JP"),
    ("香港", "HK"), ("HK", "HK"),
    ("新加坡", "SG"), ("SG", "SG"), ("狮城", "SG"),
    ("韩国", "KR"), ("KR", "KR"), ("首尔", "KR"),
    ("台湾", "TW"), ("TW", "TW"), ("台北", "TW"),
    ("英国", "GB"), ("UK", "GB"), ("伦敦", "GB"),
    ("德国", "DE"), ("法兰克福", "DE"),
    ("加拿大", "CA"), ("澳大利亚", "AU"), ("悉尼", "AU"),
]


def country_from_node_name(name: str) -> str | None:
    """从节点名猜测国家（含国旗 emoji 或中文名）；未识别返回 None"""
    import unicodedata
    flags = {"🇺🇸": "US", "🇯🇵": "JP", "🇭🇰": "HK", "🇸🇬": "SG", "🇰🇷": "KR",
             "🇹🇼": "TW", "🇬🇧": "GB", "🇩🇪": "DE", "🇨🇦": "CA", "🇦🇺": "AU", "🇨🇳": "CN"}
    text = unicodedata.normalize("NFC", str(name or ""))
    for flag, cc in flags.items():
        if flag in text:
            return cc
    for kw, cc in _NAME_HINTS:
        if kw in text:
            return cc
    return None


def env_for_country(cc: str | None, city: str | None = None) -> dict:
    """生成环境配置（locale/languages/timezone/geolocation），随机选语言档。

    city: 节点所在城市（美国时区细分用）；识别不出用国家默认。
    返回的 dict 直接并入指纹使用。
    """
    import random
    cfg = ENV_MAP.get((cc or "").upper(), DEFAULT_ENV)
    tz = cfg.get("tz_default")
    geo = dict(cfg.get("geo") or {})
    city_l = (city or "").lower()
    if city_l:
        tz = cfg.get("tz_by_city", {}).get(city_l, tz)
        geo = dict(cfg.get("geo_by_city", {}).get(city_l) or geo)
    return {
        "locale": random.choice(cfg["locales"]),
        "languages": random.choice(cfg["langs"]),
        "timezone": tz,
        "geolocation": geo,
        "env_country": (cc or "").upper() or None,
    }


def apply_env_to_fp(fp: dict, env: dict) -> dict:
    """把环境配置覆盖进指纹（内存级，不回写档案指纹文件）"""
    for k in ("locale", "languages", "timezone", "geolocation", "env_country"):
        if env.get(k) is not None:
            fp[k] = env[k]
    return fp
