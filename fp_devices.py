"""设备分布模型 + 指纹一致性校验（借鉴 Camoufox fpgen 思路）

从"真实世界设备分布"中按权重抽样生成设备特征，避免手写模板造成的
指纹扎堆；生成后再做一致性校验，剔除现实中不存在的组合。

用法:
    from fingerprint_browser.fp_devices import random_device, coherence_check
    dev = random_device()              # 按分布抽一台"真实存在的设备"
    bad = coherence_check(dev)         # 校验组合是否合理（返回违规列表）
"""
from __future__ import annotations

import random

# ==================== 真实世界分布（权重越大越常见） ====================
# OS 桌面占比（近似全球桌面流量）
OS_DIST = [
    ("win11", 45),     # Windows 11
    ("win10", 40),     # Windows 10（仍大量存在）
    ("macos", 11),     # macOS
    ("linux", 4),      # Linux 桌面
]

# GPU 分布（Windows 主机常见，vendor -> 型号列表（含权重））
GPU_WIN = [
    ("NVIDIA", [("NVIDIA GeForce GTX 1650", 18), ("NVIDIA GeForce GTX 1660", 14),
                ("NVIDIA GeForce RTX 3060", 22), ("NVIDIA GeForce RTX 3060 Ti", 10),
                ("NVIDIA GeForce RTX 4060", 12), ("NVIDIA GeForce RTX 4060 Ti", 8),
                ("NVIDIA GeForce RTX 3080", 6), ("NVIDIA GeForce RTX 4090", 2)]),
    ("Intel", [("Intel(R) UHD Graphics 630", 20), ("Intel(R) Iris(R) Xe Graphics", 18),
               ("Intel(R) UHD Graphics 620", 10), ("Intel(R) UHD Graphics 770", 12)]),
    ("AMD", [("AMD Radeon(TM) Graphics", 14), ("AMD Radeon RX 6600", 8),
             ("AMD Radeon RX 6800 XT", 4)]),
]
GPU_WEIGHTS_WIN = [0.62, 0.26, 0.12]          # NVIDIA 主流，Intel 核显次之，AMD 较少

GPU_MAC = [("Apple", "Apple M1", 0.45), ("Apple", "Apple M2", 0.30),
           ("Apple", "Apple M3", 0.15), ("Apple", "Apple M4", 0.10)]

GPU_LINUX = [("NVIDIA", "NVIDIA GeForce RTX 3060", 0.5),
             ("NVIDIA", "NVIDIA GeForce RTX 3070", 0.2),
             ("Intel", "Intel(R) UHD Graphics 630", 0.3)]

# 屏幕池（宽, 高, DPR）——权重 = 常见度
SCREEN_WIN = [
    (1920, 1080, 1.0, 34), (1366, 768, 1.0, 20), (1536, 864, 1.25, 12),
    (2560, 1440, 1.0, 8), (1600, 900, 1.0, 8), (1440, 900, 1.0, 6),
    (1280, 720, 1.0, 5), (1920, 1200, 1.0, 4), (2560, 1600, 1.25, 3),
]
SCREEN_MAC = [
    (1512, 982, 2.0, 30), (1280, 800, 2.0, 25), (1440, 900, 2.0, 20),
    (1728, 1117, 2.0, 15), (2560, 1664, 2.0, 10),
]
SCREEN_LINUX = [(1920, 1080, 1.0, 50), (1366, 768, 1.0, 20), (2560, 1440, 1.0, 20),
                (3840, 2160, 1.0, 10)]

# CPU 核数 / 内存分布
CORES_WIN = [(4, 18), (6, 22), (8, 30), (12, 14), (16, 10), (10, 6)]
CORES_MAC = [(4, 20), (8, 50), (10, 20), (12, 10)]
CORES_LINUX = [(4, 20), (8, 40), (12, 20), (16, 20)]
MEMORY_WIN = [4, 8, 8, 8, 16, 16]        # deviceMemory 上限 8，这里取 4/8/16
MEMORY_MAC = [4, 8, 8, 8, 16, 16]
MEMORY_LINUX = [4, 8, 8, 16, 16]

# 浏览器品牌分布（Chrome 主导，Edge 少量）
BRAND_DIST = [("chrome", 0.82), ("edge", 0.18)]

FONTS_WIN = ["Segoe UI", "Microsoft YaHei", "Arial"]
FONTS_MAC = ["PingFang SC", "Helvetica Neue", "Arial", "SF Pro Display"]
FONTS_LINUX = ["Noto Sans CJK SC", "DejaVu Sans", "Liberation Sans"]

# Windows platformVersion：Win10 -> 13.0.0 / Win11 -> 15.0.0
PLATFORM_VER_WIN = {"win10": "13.0.0", "win11": "15.0.0"}


def _pick(entries: list):
    """按权重抽样。条目形式：二元 (payload, weight) 或 多元 (payload..., weight)。

    返回 payload（多元条目返回除权重外的全部字段）。
    """
    total = sum(e[-1] for e in entries)
    r = random.uniform(0, total)
    acc = 0
    for e in entries:
        acc += e[-1]
        if r <= acc:
            return e[:-1] if len(e) > 2 else e[0]
    last = entries[-1]
    return last[:-1] if len(last) > 2 else last[0]


def random_device() -> dict:
    """按真实世界分布抽一台设备，返回设备特征描述。

    返回键：os, brand, platform, ch_platform, platform_version,
            gpu_vendor, gpu_renderer, screen{width,height,dpr}, cores, memory, fonts
    """
    os_name = _pick(OS_DIST)
    brand = _pick(BRAND_DIST)
    if os_name == "macos":
        gpu_vendor, gpu_model = _pick(GPU_MAC)
        gpu_renderer = f"ANGLE ({gpu_vendor}, {gpu_model}, OpenGL 4.1)"
        gpu_vendor_webgl = "Apple Inc."
        screen = _pick(SCREEN_MAC)
        platform, ch_platform = "MacIntel", "macOS"
        platform_version = random.choice(["14.7.1", "15.0.1", "15.2.0"])
        cores = _pick(CORES_MAC)
        fonts = FONTS_MAC
        memory = random.choice(MEMORY_MAC)
    elif os_name == "linux":
        gpu_vendor, gpu_model = _pick(GPU_LINUX)
        gpu_vendor_webgl = f"Google Inc. ({gpu_vendor})"
        gpu_renderer = f"ANGLE ({gpu_vendor}, {gpu_model}, Vulkan 1.3.0)"
        screen = _pick(SCREEN_LINUX)
        platform, ch_platform = "Linux x86_64", "Linux"
        platform_version = random.choice(["6.8.0", "6.5.0", "5.15.0"])
        cores = _pick(CORES_LINUX)
        fonts = FONTS_LINUX
        memory = random.choice(MEMORY_LINUX)
    else:  # Windows
        gpu_pool, gpu_weights = [], []
        for idx, (vendor, models) in enumerate(GPU_WIN):
            for model, w in models:
                gpu_pool.append((vendor, model))
                gpu_weights.append(w * GPU_WEIGHTS_WIN[idx])
        gpu_vendor, gpu_model = random.choices(gpu_pool, weights=gpu_weights, k=1)[0]
        gpu_vendor_webgl = f"Google Inc. ({gpu_vendor})"
        gpu_renderer = (f"ANGLE ({gpu_vendor}, {gpu_model} Direct3D11 "
                        "vs_5_0 ps_5_0, D3D11)")
        screen = _pick(SCREEN_WIN)
        platform, ch_platform = "Win32", "Windows"
        platform_version = PLATFORM_VER_WIN[os_name]
        cores = _pick(CORES_WIN)
        fonts = FONTS_WIN
        memory = random.choice(MEMORY_WIN)
        # 核显机型核数收敛（Intel 核显多为办公机 4-8 核）
        if gpu_vendor == "Intel":
            cores = min(cores, 8)

    return {
        "os": os_name,
        "brand": brand,
        "gpu_vendor": gpu_vendor_webgl,
        "gpu_renderer": gpu_renderer,
        "webgl_max_texture": 16384,
        "screen": {"width": screen[0], "height": screen[1], "dpr": screen[2]},
        "cores": cores,
        "memory": memory,
        "fonts": fonts,
        "platform": platform,
        "ch_platform": ch_platform,
        "platform_version": platform_version,
    }


def coherence_check(fp: dict) -> list[str]:
    """校验指纹组合是否"现实中可能存在"，返回违规项列表（空=自洽）。

    检查维度：平台-GPU、GPU-核数、平台-屏幕、GPU-分辨率 的联动关系。
    """
    bad = []
    platform = fp.get("platform")
    vendor = (fp.get("webgl_vendor") or fp.get("gpu_vendor") or "")
    renderer = (fp.get("webgl_renderer") or fp.get("gpu_renderer") or "")
    screen = fp.get("screen") or {}
    w = screen.get("width", 0)
    cores = fp.get("cores", 0)

    if platform == "MacIntel":
        if "Apple" not in vendor:
            bad.append("macOS 平台 GPU 厂商应为 Apple")
        if renderer and "ANGLE" not in renderer and "Apple" not in renderer:
            bad.append("macOS 平台渲染器形态异常")
    elif platform == "Win32":
        if not any(k in vendor for k in ("NVIDIA", "Intel", "AMD")):
            bad.append("Windows 平台 GPU 厂商应属 NVIDIA/Intel/AMD")
        if "Intel" in vendor and cores > 8:
            bad.append("核显机型核数不应超过 8")
        if "NVIDIA" in vendor and w < 1280:
            bad.append("独显机型屏幕不应小于 1280 宽")
    elif platform in ("Linux x86_64",):
        if not any(k in vendor for k in ("NVIDIA", "Intel", "AMD")):
            bad.append("Linux 平台 GPU 厂商异常")

    dpr = screen.get("dpr", 1.0)
    h = screen.get("height", 0)
    if platform == "Win32" and dpr >= 1.5 and w < 1400:
        bad.append("Windows 高 DPI（≥1.5）小屏组合少见")
    if h < 600 or w < 800:
        bad.append("屏幕分辨率异常（过小）")
    return bad


if __name__ == "__main__":
    import json

    bad_total = 0
    for _ in range(5):
        dev = random_device()
        bad = coherence_check(dev)
        bad_total += len(bad)
        print(json.dumps({k: dev[k] for k in
                          ("os", "brand", "platform", "gpu_vendor",
                           "screen", "cores", "memory")}, ensure_ascii=False))
        print("   违规:", bad or "无")
    print(f"\n5 台设备违规总数: {bad_total}")