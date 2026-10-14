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


def random_fingerprint(allow_mac: bool = False) -> dict:
    """生成一套全新的随机自洽指纹。

    allow_mac: 是否允许生成 macOS 指纹。默认 False（宿主一致性优先：
    Windows 宿主生成 Windows 指纹，字体/CPU 指纹天然自洽）。
    屏幕尺寸默认适配宿主显示器实际分辨率（窗口与屏幕一致，避免视口超屏）；
    宿主检测失败时回退常见分辨率池。
    """
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


if __name__ == "__main__":
    import json
    fp = random_fingerprint()
    print(json.dumps(fp, ensure_ascii=False, indent=2))