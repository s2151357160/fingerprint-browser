"""随机指纹生成器

每次生成一套全新的自洽指纹（不是从固定模板抽取）：
  - 屏幕、显卡、CPU/内存、Canvas 种子、视口等全部随机
  - UA 的内核版本与本地 Chromium 一致（launch 时自动校正，避免漂移）
  - 分辨率/视口/DPR、平台与字体、WebGL 厂商互相联动自洽
  - 默认只生成 Windows 指纹（与宿主机一致）：系统字体、CPU 指纹天然自洽，
    避免"Mac 指纹 + Windows 宿主"在字体层被识破；mac 指纹可通过 allow_mac 开启
    （但会带字体层限制）

用法:
    from fingerprint_browser.fp_gen import random_fingerprint
    fp = random_fingerprint()          # 每次调用都是一套新指纹
    p, b, ctx, page = launch(fp, proxy="http://127.0.0.1:7899")
"""
from __future__ import annotations

import random
import secrets

# 设备分布模式（借鉴 Camoufox fpgen：按真实世界分布抽样设备特征）
# 置 False 即回退旧的"手写组合随机"逻辑
FP_USE_DISTRIBUTION = True

# 兜底内核版本（launch 时以实际 Chromium 版本自动校正）
CHROME_VER = "151"

UA_WIN = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          f"(KHTML, like Gecko) Chrome/{CHROME_VER}.0.0.0 Safari/537.36")
UA_MAC = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
          f"(KHTML, like Gecko) Chrome/{CHROME_VER}.0.0.0 Safari/537.36")

# 屏幕（宽, 高, DPR）——CSS 逻辑像素，常见真实组合
SCREENS_WIN = [
    (1920, 1080, 1.0), (1366, 768, 1.0), (1600, 900, 1.0),
    (2560, 1440, 1.0), (1536, 864, 1.25), (1440, 900, 1.0),
]
SCREENS_MAC = [
    (1280, 800, 2.0), (1440, 900, 2.0), (1512, 982, 2.0), (1728, 1117, 2.0),
]

# Windows 常见 GPU 组合（vendor, renderer, MAX_TEXTURE_SIZE）
GPUS_WIN = [
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
    ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
    ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)", 16384),
]

CORES = [4, 6, 8, 12, 16]      # hardwareConcurrency 常见值
MEMS = [4, 8]                   # deviceMemory 上限 8，取真实常见值

FONTS_WIN = ["Segoe UI", "Microsoft YaHei", "Arial"]
FONTS_MAC = ["PingFang SC", "Helvetica Neue", "Arial"]

# Windows CH platformVersion：Win10 22H2 -> 13.0.0 / Win11 23H2 -> 15.0.0
PLATFORM_VER_WIN = ["13.0.0", "15.0.0"]

# 常见 DPR 档位（Windows 缩放比例），实际值就近取整
_DPR_SNAPS = (1.0, 1.25, 1.5, 1.75, 2.0, 2.5, 3.0)


def detect_host_screen() -> tuple[int, int, float] | None:
    """检测宿主显示器实际分辨率（CSS 逻辑像素）与 DPR。

    物理像素 / DPI 缩放 = 浏览器可见的 CSS 尺寸（与真实 Chrome 的 screen.width 语义一致）。
    失败（非 Windows/异常）返回 None，由调用方回退常见分辨率。
    """
    try:
        import ctypes  # noqa: PLC0415
        user32 = ctypes.windll.user32
        phys_w = user32.GetSystemMetrics(0)   # SM_CXSCREEN
        phys_h = user32.GetSystemMetrics(1)   # SM_CYSCREEN
        if phys_w <= 0 or phys_h <= 0:
            return None
        try:
            dpi = user32.GetDpiForSystem()
        except Exception:
            dpi = 96
        dpr = round(dpi / 96, 2)
        dpr = min(_DPR_SNAPS, key=lambda x: abs(x - dpr))   # 就近取常见档位
        return max(800, round(phys_w / dpr)), max(600, round(phys_h / dpr)), dpr
    except Exception:
        return None


def random_fingerprint(allow_mac: bool = False, use_distribution: bool | None = None) -> dict:
    """生成一套全新的随机自洽指纹。

    allow_mac: 是否允许生成 macOS 指纹。默认 False（宿主一致性优先）。
    use_distribution: 设备分布模式（True=按真实世界设备分布抽样，更接近真实流量；
        缺省跟随模块开关 FP_USE_DISTRIBUTION）。
    """
    if use_distribution is None:
        use_distribution = FP_USE_DISTRIBUTION

    if use_distribution:
        return _fingerprint_from_distribution(allow_mac)

    # ==================== 旧逻辑（手写组合随机，可回退） ====================
    is_mac = allow_mac and random.random() < 0.25

    host = detect_host_screen()

    if is_mac:
        w, h, dpr = random.choice(SCREENS_MAC)
        platform, ua = "MacIntel", UA_MAC
        ch_platform, platform_version = "macOS", "14.7.1"
        vendor, renderer, maxtex = "Apple Inc.", "Apple GPU", 16384
        fonts = FONTS_MAC
        cores = random.choice([4, 8])
        vw = w
        vh = h - random.randint(50, 80)          # 减去菜单栏/Dock
    else:
        if host:
            w, h, dpr = host                       # 宿主分辨率：窗口与屏幕天然一致
        else:
            w, h, dpr = random.choice(SCREENS_WIN)
        platform, ua = "Win32", UA_WIN
        ch_platform = "Windows"
        platform_version = random.choice(PLATFORM_VER_WIN)
        vendor, renderer, maxtex = random.choice(GPUS_WIN)
        fonts = FONTS_WIN
        cores = random.choice(CORES)
        vw = w                                    # 全屏窗口
        vh = h - random.randint(100, 160)         # 减去任务栏 + 浏览器 UI（地址栏/标签栏）

    seed = secrets.token_hex(4)
    return {
        "name": f"rnd-{seed}",
        "ua": ua,
        "platform": platform,
        "ch_platform": ch_platform,
        "platform_version": platform_version,
        "locale": "zh-CN",
        "languages": ["zh-CN", "zh"],
        "timezone": "Asia/Shanghai",
        "screen": {"width": w, "height": h, "dpr": dpr},
        "viewport": {"width": vw, "height": max(600, vh)},
        "cores": cores,
        "memory": random.choice(MEMS),
        "touch_points": 0,
        "canvas_noise_seed": f"rnd-{seed}",
        "webgl_vendor": vendor,
        "webgl_renderer": renderer,
        "webgl_max_texture": maxtex,
        "fonts": fonts,
    }


def _fingerprint_from_distribution(allow_mac: bool = False) -> dict:
    """分布模式：按真实设备分布抽一台设备，构建完整指纹。

    allow_mac=False 时强制 Windows 设备（宿主一致性：Windows 宿主尽量生成
    Windows 指纹，字体层天然自洽）。
    """
    from .fp_devices import random_device, coherence_check

    dev = None
    for _ in range(12):
        d = random_device()
        if not allow_mac and d["os"] in ("macos", "linux"):
            continue          # 不允许时重新抽（多数是 Windows，很快命中）
        dev = d
        break
    if dev is None:
        dev = random_device()   # 兜底：接受任何设备

    os_name = dev["os"]
    brand = dev["brand"]
    w, h, dpr = dev["screen"]["width"], dev["screen"]["height"], dev["screen"]["dpr"]
    cores = dev["cores"]
    memory = dev["memory"]

    if os_name == "macos":
        ua = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              f"(KHTML, like Gecko) Chrome/{CHROME_VER}.0.0.0 Safari/537.36")
        vw = w
        vh = h - random.randint(50, 80)
    elif os_name == "linux":
        ua = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              f"(KHTML, like Gecko) Chrome/{CHROME_VER}.0.0.0 Safari/537.36")
        vw = w
        vh = h - random.randint(80, 130)
    else:  # windows
        ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              f"(KHTML, like Gecko) Chrome/{CHROME_VER}.0.0.0 Safari/537.36")
        vw = w
        vh = h - random.randint(100, 160)
    if brand == "edge":
        ua += f" Edg/{CHROME_VER}.0.0.0"

    seed = secrets.token_hex(4)
    fp = {
        "name": f"rnd-{seed}",
        "ua": ua,
        "platform": dev["platform"],
        "ch_platform": dev["ch_platform"],
        "platform_version": dev["platform_version"],
        "locale": "zh-CN",
        "languages": ["zh-CN", "zh"],
        "timezone": "Asia/Shanghai",
        "screen": {"width": w, "height": h, "dpr": dpr},
        "viewport": {"width": vw, "height": max(600, vh)},
        "cores": cores,
        "memory": memory,
        "touch_points": 0,
        "canvas_noise_seed": f"rnd-{seed}",
        "webgl_vendor": dev["gpu_vendor"],
        "webgl_renderer": dev["gpu_renderer"],
        "webgl_max_texture": dev["webgl_max_texture"],
        "fonts": dev["fonts"],
        "brand": brand,
    }
    bad = coherence_check(fp)
    if bad:
        fp["coherence_warnings"] = bad   # 记录（不阻断），便于自检审计
    return fp


if __name__ == "__main__":
    import json
    fp = random_fingerprint()
    print(json.dumps(fp, ensure_ascii=False, indent=2))