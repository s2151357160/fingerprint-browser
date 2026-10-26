"""可换指纹浏览器 - 核心模块（v2：反检测增强版）

覆盖范围：
  环境层   navigator / screen 原型级覆盖（enumerable + native getter 伪装）
           webdriver / plugins(5 PDF) / pdfViewerEnabled / userAgentData
  渲染层   Canvas 双通道噪声（getImageData + toDataURL/toBlob 一致）
           WebGL 厂商/渲染器 + MAX_TEXTURE_SIZE 配套 + readPixels 噪声
  音频层   AudioBuffer.getChannelData 微扰
  网络层   UA / Accept-Language / 时区 / 视口联动 + Sec-CH-UA 三件套注入
  版本同步 UA 大版本随 Chromium 内核自动校正（消除硬编码）

代理支持：
  proxy 参数接受 "auto"（自动探测本机梯子代理）或显式 "socks5://host:port" 等。

用法（代码集成）:
    from fingerprint_browser import load, launch
    fp = load("win10-chrome-151")
    p, browser, context, page = launch(fp, proxy="auto")   # 自动接梯子
    page.goto("https://example.com")
    ...
    p.stop()

命令行:
    python -m fingerprint_browser.fp_browser --list
    python -m fingerprint_browser.fp_browser --check [--profile xxx]
    python -m fingerprint_browser.fp_browser --url https://example.com [--proxy auto]
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from playwright.sync_api import sync_playwright

FINGERPRINTS_DIR = Path(__file__).resolve().parent / "fingerprints"

LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-first-run",
    "--no-default-browser-check",
    # 借鉴 patchright Command Flags 修补：命令行层禁止非代理 UDP（WebRTC 真实 IP 防泄漏），
    # 与注入层 STUN/TURN 剥离双重保险（ICMP/UDP 不经 HTTP 代理会直连真实出口）
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
]

# 显式剔除 Playwright 默认参数中会留下"自动化痕迹"的项（patchright 修补清单）：
#   --enable-automation        -> navigator.webdriver / window.chrome 自动化形态
#   --disable-popup-blocking   -> 真实浏览器弹窗拦截开启
#   --disable-component-update -> 避免被识别为 stealth driver
#   --disable-default-apps     -> 恢复默认应用
#   --disable-extensions       -> 恢复扩展能力
REMOVED_DEFAULT_ARGS = [
    "--enable-automation",
    "--disable-popup-blocking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-extensions",
]

# UA 版本兜底（launch 时会以实际内核版本自动校正）
_FALLBACK_VER = "151"


# ==================== 模板加载 ====================

def load(name: str) -> dict:
    """加载指纹模板（fingerprints/<name>.json）"""
    path = FINGERPRINTS_DIR / f"{name}.json"
    if not path.exists():
        names = ", ".join(list_templates())
        raise FileNotFoundError(f"指纹模板不存在: {name}（现有: {names}）")
    return json.loads(path.read_text("utf-8"))


def list_templates() -> list[str]:
    """列出所有可用指纹模板名"""
    return sorted(p.stem for p in FINGERPRINTS_DIR.glob("*.json"))


# ==================== 指纹版本同步 ====================

def sync_ua(fp: dict, full_version: str) -> dict:
    """把指纹 UA 的 Chrome/Edg 大版本校正为实际内核版本（返回副本，不污染原值）。

    保证 UA 与内核行为（渲染特性、CH 头来源版本）一致，消除硬编码漂移。
    同时缓存内核大版本与完整版本号，供 brands / 高熵值 / report 比对使用。
    """
    global _kernel_major
    major = full_version.split(".")[0]
    _kernel_major = major
    fp = dict(fp)
    ua = re.sub(r"(Chrome/)(\d+)", lambda m: m.group(1) + major, fp["ua"])
    ua = re.sub(r"(Edg/)(\d+)", lambda m: m.group(1) + major, ua)
    fp["ua"] = ua
    fp["chrome_major"] = major
    fp["chrome_full_ver"] = full_version
    return fp


# Chromium 官方 GREASE 品牌算法（components/embedder_support/user_agent_utils.cc）
_GREASE_CHARS = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"]
_GREASE_VERSIONS = ["8", "99", "24"]
_BRAND_ORDERS_3 = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]]


def _greased_brand(major: int) -> tuple[str, str]:
    """按 Chromium 官方算法由大版本派生 GREASE 品牌与版本（如 151 → Not=A?Brand / 99）"""
    brand = f"Not{_GREASE_CHARS[major % 11]}A{_GREASE_CHARS[(major + 1) % 11]}Brand"
    return brand, _GREASE_VERSIONS[major % 3]


def _uad_brands(fp: dict) -> tuple[list[dict], list[dict]]:
    """生成 userAgentData.brands / fullVersionList（含官方 GREASE 值与洗牌顺序）。

    Chromium 实测验证：151 → [Not=A?Brand v99, Google Chrome v151, Chromium v151]。
    Sec-CH-UA 请求头与 JS 端共用本函数，保证同源同序。
    """
    major = int(fp.get("chrome_major", _FALLBACK_VER))
    full = fp.get("chrome_full_ver", f"{major}.0.0.0")
    gbrand, gver = _greased_brand(major)
    main = "Microsoft Edge" if "Edg/" in fp["ua"] else "Google Chrome"
    m = str(major)
    raw_major = [{"brand": gbrand, "version": gver},
                 {"brand": "Chromium", "version": m},
                 {"brand": main, "version": m}]
    raw_full = [{"brand": gbrand, "version": gver + ".0.0.0"},
                {"brand": "Chromium", "version": full},
                {"brand": main, "version": full}]
    order = _BRAND_ORDERS_3[major % 6]
    brands: list = [None, None, None]
    full_list: list = [None, None, None]
    for i, pos in enumerate(order):
        brands[pos] = raw_major[i]
        full_list[pos] = raw_full[i]
    return brands, full_list


def _client_hints(fp: dict) -> dict:
    """构造 Sec-CH-UA 客户端提示头（与 JS 端 brands 同源同序，含官方 GREASE 值）"""
    brands, _ = _uad_brands(fp)
    ch = ", ".join(f'"{b["brand"]}";v="{b["version"]}"' for b in brands)
    return {
        "sec-ch-ua": ch,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": f'"{fp.get("ch_platform", "Windows")}"',
    }


# ==================== 注入脚本 ====================

# JS 部分用占位符注入（避免 f-string 花括号转义错误）
_INIT_JS = r"""
(function () {
  'use strict';

  /* ==================== 种子派生确定性噪声 ==================== */
  var __NOISE = __NOISE_FLAG__;   /* canvas_noise 模板字段开关 */
  var _h = 2166136261;
  var _seed = '__SEED__';
  for (var i = 0; i < _seed.length; i++) {
    _h = ((_h ^ _seed.charCodeAt(i)) * 16777619) >>> 0;
  }
  var SEED = _h >>> 0;
  var jitter = function (i) { return __NOISE ? (SEED + i * 2654435761) >>> 0 : 0; };

  /* ==================== native toString 伪装 ==================== */
  var _fakeNative = new Set();
  var _origToString = Function.prototype.toString;
  Function.prototype.toString = function () {
    try {
      if (_fakeNative.has(this)) {
        return 'function ' + (this.__fname || this.name || '') + '() { [native code] }';
      }
    } catch (e) {}
    return _origToString.call(this);
  };
  _fakeNative.add(Function.prototype.toString);
  var nativeFn = function (name, fn) {
    try {
      Object.defineProperty(fn, 'name', { value: name, configurable: true }); /* 真实 getter.name 与属性名一致 */
      Object.defineProperty(fn, '__fname', { value: name });
      _fakeNative.add(fn);
    } catch (e) {}
    return fn;
  };

  /* ==================== 原型级属性覆盖（enumerable + native getter） ==================== */
  var setProp = function (proto, key, val) {
    try {
      var getter = nativeFn(key, function () { return val; });
      Object.defineProperty(proto, key, {
        get: getter,
        set: undefined,
        enumerable: true,
        configurable: true,
      });
    } catch (e) {}
  };

  setProp(Navigator.prototype, 'userAgent', '__UA__');
  setProp(Navigator.prototype, 'platform', '__PLATFORM__');
  setProp(Navigator.prototype, 'webdriver', false);
  setProp(Navigator.prototype, 'language', '__LOCALE__');
  setProp(Navigator.prototype, 'languages', Object.freeze(__LANGS__));
  setProp(Navigator.prototype, 'hardwareConcurrency', __CORES__);
  setProp(Navigator.prototype, 'deviceMemory', __MEMORY__);
  setProp(Navigator.prototype, 'maxTouchPoints', __TOUCH__);
  setProp(Screen.prototype, 'width', __SW__);
  setProp(Screen.prototype, 'height', __SH__);
  setProp(Screen.prototype, 'availWidth', __SW__);
  setProp(Screen.prototype, 'availHeight', __SH__);

  /* ==================== 窗口几何：outer = inner + 窗口边框（有头窗口物理尺寸与伪装 viewport 矛盾修复） ==================== */
  /* 有头模式下 Playwright 默认窗口约 1280x720，而伪装 viewport 为 1920x969，
     outerWidth(1298) < innerWidth(1920) 在真实浏览器中物理不可能（视口必在窗口内）。
     伪装 outer 与视口联动：宽度上限对齐 screen.width（最大化/全屏形态），高度加标题栏。 */
  (function () {
    try {
      var fw = function () { return Math.min(window.innerWidth + 16, screen.width); };
      var fh = function () { return window.innerHeight + 39; };
      Object.defineProperty(window, 'outerWidth', {
        get: nativeFn('outerWidth', fw), set: nativeFn('outerWidth', function () {}),
        enumerable: true, configurable: true });
      Object.defineProperty(window, 'outerHeight', {
        get: nativeFn('outerHeight', fh), set: nativeFn('outerHeight', function () {}),
        enumerable: true, configurable: true });
    } catch (e) {}
  })();

  /* ==================== plugins / mimeTypes / pdfViewer 伪装（真实 Chrome 151 形态） ====================
     IDL 属性（name/length/item 等）一律放在"独立中间原型"上，实例自有键仅保留索引与命名项，
     与真实浏览器的 Object.keys(navigator.plugins) 完全一致 */
  (function () {
    try {
      var pdata = [
        ['PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
        ['Chrome PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
        ['Chromium PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
        ['Microsoft Edge PDF Viewer', 'internal-pdf-viewer', 'Portable Document Format'],
        ['WebKit built-in PDF', 'internal-pdf-viewer', 'Portable Document Format'],
      ];
      var mdata = [
        ['application/pdf', 'pdf', 'Portable Document Format'],
        ['text/pdf', 'pdf', 'Portable Document Format'],
      ];

      var pluginArr = (function () {
        var mid = Object.create(PluginArray.prototype);
        Object.defineProperty(mid, 'length', {
          get: nativeFn('length', function () { return pdata.length; }),
          enumerable: true, configurable: true });
        mid.item = nativeFn('item', function (i) {
          return (i >>> 0 === i && i < pdata.length) ? pluginArr[i] || null : null; });
        mid.namedItem = nativeFn('namedItem', function (n) { return pluginArr[n] || null; });
        Object.defineProperty(mid, Symbol.iterator, {
          value: nativeFn('values', function* () {
            for (var i = 0; i < pdata.length; i++) { yield pluginArr[i]; }
          }), writable: true, configurable: true });
        return Object.create(mid);
      })();
      var mimeArr = (function () {
        var mid = Object.create(MimeTypeArray.prototype);
        Object.defineProperty(mid, 'length', {
          get: nativeFn('length', function () { return mdata.length; }),
          enumerable: true, configurable: true });
        mid.item = nativeFn('item', function (i) {
          return (i >>> 0 === i && i < mdata.length) ? mimeArr[i] || null : null; });
        mid.namedItem = nativeFn('namedItem', function (n) { return mimeArr[n] || null; });
        return Object.create(mid);
      })();

      var makeMime = function (md, pluginGetter) {
        var mid = Object.create(MimeType.prototype);
        Object.defineProperty(mid, 'type', {
          get: nativeFn('type', function () { return md[0]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'suffixes', {
          get: nativeFn('suffixes', function () { return md[1]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'description', {
          get: nativeFn('description', function () { return md[2]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'enabledPlugin', {
          get: nativeFn('enabledPlugin', pluginGetter), enumerable: true, configurable: true });
        return Object.create(mid);
      };

      pdata.forEach(function (pd, idx) {
        var mimes;
        var mid = Object.create(Plugin.prototype);
        Object.defineProperty(mid, 'name', {
          get: nativeFn('name', function () { return pd[0]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'filename', {
          get: nativeFn('filename', function () { return pd[1]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'description', {
          get: nativeFn('description', function () { return pd[2]; }), enumerable: true, configurable: true });
        Object.defineProperty(mid, 'length', {
          get: nativeFn('length', function () { return mimes ? mimes.length : 0; }),
          enumerable: true, configurable: true });
        mid.item = nativeFn('item', function (i) { return mimes ? mimes[i] || null : null; });
        mid.namedItem = nativeFn('namedItem', function (n) {
          if (!mimes) return null;
          for (var k = 0; k < mimes.length; k++) { if (mimes[k].type === n) return mimes[k]; }
          return null;
        });
        var p = Object.create(mid);
        mimes = mdata.map(function (md) { return makeMime(md, function () { return p; }); });
        mimes.forEach(function (mt, j) {
          Object.defineProperty(p, String(j), { value: mt, enumerable: true });
          Object.defineProperty(p, mt.type, { value: mt, enumerable: true });
        });
        Object.defineProperty(pluginArr, String(idx), { value: p, enumerable: true });
        Object.defineProperty(pluginArr, pd[0], { value: p, enumerable: true });
      });

      mdata.forEach(function (md, idx) {
        var mt = makeMime(md, function () { return pluginArr[0]; });
        Object.defineProperty(mimeArr, String(idx), { value: mt, enumerable: true });
        Object.defineProperty(mimeArr, md[0], { value: mt, enumerable: true });
      });

      setProp(Navigator.prototype, 'plugins', pluginArr);
      setProp(Navigator.prototype, 'mimeTypes', mimeArr);
      setProp(Navigator.prototype, 'pdfViewerEnabled', true);
    } catch (e) {}
  })();

  /* ==================== userAgentData 伪装（对齐 Chromium 151 原生结构） ==================== */
  /* 原生实测基准：实例自有属性为空；brands/mobile/platform/getHighEntropyValues/toJSON
     全部在 NavigatorUAData.prototype 上；brands getter 每次返回新冻结数组；
     getHighEntropyValues 恒含低熵三项、忽略 fullVersion hint、缺参/非序列抛原生文案 TypeError。 */
  (function () {
    try {
      var fullVer = '__CH_FULL_VER__';
      var platform = '__CH_PLATFORM__';
      var platformVersion = '__CH_PLATFORM_VER__';
      var brandsRaw = __UAD_BRANDS__;
      var fullRaw = __UAD_FULL_LIST__;
      var proto = NavigatorUAData.prototype;
      var mkFrozen = function (list) {
        return Object.freeze(list.map(function (b) { return { brand: b.brand, version: b.version }; }));
      };
      var defAttr = function (key, fn) {
        Object.defineProperty(proto, key, {
          get: nativeFn(key, fn), set: undefined, enumerable: true, configurable: true,
        });
      };
      defAttr('brands', function () { return mkFrozen(brandsRaw); });
      defAttr('mobile', function () { return false; });
      defAttr('platform', function () { return platform; });
      var ghv = nativeFn('getHighEntropyValues', function (hints) {
        if (arguments.length === 0) {
          throw new TypeError("Failed to execute 'getHighEntropyValues' on 'NavigatorUAData': 1 argument required, but only 0 present.");
        }
        if (typeof hints !== 'object' || hints === null || typeof hints[Symbol.iterator] !== 'function') {
          throw new TypeError("Failed to execute 'getHighEntropyValues' on 'NavigatorUAData': The provided value cannot be converted to a sequence.");
        }
        var highMap = {
          architecture: 'x86',
          bitness: '64',
          fullVersionList: fullRaw.map(function (b) { return { brand: b.brand, version: b.version }; }),
          model: '',
          platformVersion: platformVersion,
          uaFullVersion: fullVer,
          wow64: false,
        };
        var out = {
          brands: brandsRaw.map(function (b) { return { brand: b.brand, version: b.version }; }),
          mobile: false,
          platform: platform,
        };
        var seen = {};
        for (var it of hints) {
          var h = String(it);
          if (h in highMap && !(h in seen)) { out[h] = highMap[h]; seen[h] = true; }
        }
        var keys = Object.keys(out).sort();
        var sorted = {};
        keys.forEach(function (k) { sorted[k] = out[k]; });
        return Promise.resolve(sorted);
      });
      Object.defineProperty(proto, 'getHighEntropyValues', {
        value: ghv, writable: true, enumerable: true, configurable: true,
      });
      var toJSONFn = nativeFn('toJSON', function () {
        return { brands: mkFrozen(brandsRaw), mobile: false, platform: platform };
      });
      Object.defineProperty(proto, 'toJSON', {
        value: toJSONFn, writable: true, enumerable: true, configurable: true,
      });
      var uad = Object.create(proto);
      setProp(Navigator.prototype, 'userAgentData', uad);
    } catch (e) {}
  })();

  /* ==================== Canvas 双通道确定性噪声 ==================== */
  /* getImageData 与 toDataURL/toBlob 走同一噪声函数；序列化用克隆画布，不污染原画布（幂等）。
     仅对已持有 2d context 的画布加噪：避免给无 context 画布强建 2d 而锁死 context 类型
     （否则页面先 toDataURL 再 getContext('webgl') 会失败）。 */
  var _ctx2d = new WeakSet();
  var origGetContext = HTMLCanvasElement.prototype.getContext;
  HTMLCanvasElement.prototype.getContext = nativeFn('getContext', function (type) {
    var c = origGetContext.apply(this, arguments);
    if (c && String(type) === '2d') { _ctx2d.add(this); }
    return c;
  });
  var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  var applyNoise = function (img) {
    if (!__NOISE) return img;   /* canvas_noise=false：保持原生像素（Camoufox 反噪声哲学） */
    var d = img.data;
    for (var i = 0; i < d.length; i++) {
      d[i] = (d[i] + ((jitter(i) % 3) - 1) + 256) % 256;
    }
    return img;
  };
  CanvasRenderingContext2D.prototype.getImageData = nativeFn('getImageData', function () {
    return applyNoise(origGetImageData.apply(this, arguments));
  });
  var noiseClone = function (canvas) {
    if (canvas.width * canvas.height > 16777216) return null;   /* >16M 像素性能守卫 */
    var ctx = canvas.getContext('2d');
    if (!ctx || canvas.width <= 0 || canvas.height <= 0) return null;
    var src = origGetImageData.call(ctx, 0, 0, canvas.width, canvas.height);
    var clone = document.createElement('canvas');
    clone.width = canvas.width;
    clone.height = canvas.height;
    clone.getContext('2d').putImageData(applyNoise(src), 0, 0);
    return clone;
  };
  var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = nativeFn('toDataURL', function () {
    try {
      if (_ctx2d.has(this)) {
        var clone = noiseClone(this);
        if (clone) return origToDataURL.apply(clone, arguments);
      }
    } catch (e) {}
    return origToDataURL.apply(this, arguments);
  });
  var origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = nativeFn('toBlob', function () {
    try {
      if (_ctx2d.has(this)) {
        var clone2 = noiseClone(this);
        if (clone2) return origToBlob.call(clone2, arguments[0], arguments[1], arguments[2]);
      }
    } catch (e) {}
    return origToBlob.apply(this, arguments);
  });

  /* ==================== OffscreenCanvas 双通道一致 ==================== */
  /* 真实浏览器中同一绘制内容在 Canvas 与 OffscreenCanvas 输出像素完全一致；
     主 canvas 已加噪，OffscreenCanvas 必须走同一噪声函数，否则检测者对比两通道即识破。 */
  (function () {
    try {
      var _off2d = new WeakSet();
      var origOGetContext = OffscreenCanvas.prototype.getContext;
      OffscreenCanvas.prototype.getContext = nativeFn('getContext', function (type) {
        var c = origOGetContext.apply(this, arguments);
        if (c && String(type) === '2d') { _off2d.add(this); }
        return c;
      });
      var origOGetImageData = OffscreenCanvasRenderingContext2D.prototype.getImageData;
      OffscreenCanvasRenderingContext2D.prototype.getImageData = nativeFn('getImageData', function () {
        return applyNoise(origOGetImageData.apply(this, arguments));
      });
      var offClone = function (canvas) {
        if (canvas.width * canvas.height > 16777216) return null;
        var ctx = canvas.getContext('2d');
        if (!ctx || canvas.width <= 0 || canvas.height <= 0) return null;
        var src = origOGetImageData.call(ctx, 0, 0, canvas.width, canvas.height);
        var clone = new OffscreenCanvas(canvas.width, canvas.height);
        clone.getContext('2d').putImageData(applyNoise(src), 0, 0);
        return clone;
      };
      var origOToDataURL = OffscreenCanvas.prototype.toDataURL;
      OffscreenCanvas.prototype.toDataURL = nativeFn('toDataURL', function () {
        try {
          if (_off2d.has(this)) {
            var clone = offClone(this);
            if (clone) return origOToDataURL.apply(clone, arguments);
          }
        } catch (e) {}
        return origOToDataURL.apply(this, arguments);
      });
      var origOConvert = OffscreenCanvas.prototype.convertToBlob;
      OffscreenCanvas.prototype.convertToBlob = nativeFn('convertToBlob', function () {
        try {
          if (_off2d.has(this)) {
            var clone2 = offClone(this);
            if (clone2) return origOConvert.call(clone2, arguments[0]);
          }
        } catch (e) {}
        return origOConvert.call(this, arguments[0]);
      });
    } catch (e) {}
  })();

  /* ==================== WebGL 厂商/渲染器 + 硬件参数配套 ==================== */
  var patchWebGL = function (proto) {
    var origParam = proto.getParameter;
    proto.getParameter = nativeFn('getParameter', function (p) {
      if (p === 0x1F00 || p === 0x9245) return '__WGL_VENDOR__';
      if (p === 0x1F01 || p === 0x9246) return '__WGL_RENDERER__';
      if (p === 0x0D33 || p === 0x84E8) return __WGL_MAXTEX__;   /* MAX_TEXTURE_SIZE / MAX_RENDERBUFFER_SIZE */
      return origParam.call(this, p);
    });
    var origRead = proto.readPixels;
    proto.readPixels = nativeFn('readPixels', function (x, y, w, h, format, type, pixels) {
      var r = origRead.apply(this, arguments);
      if (pixels && pixels.length) {
        for (var i = 0; i < pixels.length; i++) {
          pixels[i] = (pixels[i] + ((jitter(i) % 3) - 1)) & 0xFF;
        }
      }
      return r;
    });
  };
  patchWebGL(WebGLRenderingContext.prototype);
  patchWebGL(WebGL2RenderingContext.prototype);

  /* ==================== AudioContext 微扰 ==================== */
  var origGCD = AudioBuffer.prototype.getChannelData;
  AudioBuffer.prototype.getChannelData = nativeFn('getChannelData', function (ch) {
    var buf = origGCD.call(this, ch);
    for (var i = 0; i < buf.length; i++) {
      buf[i] += ((jitter(i) % 5) - 2) * 1e-8;
    }
    return buf;
  });

  /* ==================== WebRTC 防泄漏 ==================== */
  /* STUN 走 UDP 不经 HTTP 代理：真实公网 IP 会绕过代理直接暴露，且与
     HTTP 出口 IP 不一致（强代理/机器人信号）。剥离 STUN/TURN 后仅剩
     mDNS host 候选（真实 Chrome 在对称 NAT/企业网的常见表现）。 */
  try {
    var NativePC = window.RTCPeerConnection;
    if (NativePC) {
      window.RTCPeerConnection = new Proxy(NativePC, {
        construct: function (target, args) {
          var cfg = args[0] ? Object.assign({}, args[0]) : {};
          cfg.iceServers = [];   // 剥离 STUN/TURN：不产生公网 srflx 候选
          return args.length > 1 ? new target(cfg, args[1]) : new target(cfg);
        }
      });
    }
  } catch (e) {}
})();
"""

# ==================== 深度伪装层（可选字段驱动，默认不启用） ====================
# 模板 JSON 增加以下字段即注入对应伪装（缺省行为与原生 Chromium 一致）：
#   "vendor": "Google Inc." | "" 等        -> 覆盖 navigator.vendor
#   "chrome_ui": false                     -> 删除 window.chrome 对象（Firefox 风格）
#   "uad": false                           -> 删除 navigator.userAgentData（Firefox 风格）
#   "color_depth": 24                      -> 覆盖 colorDepth/pixelDepth
#   "network_connection": {downlink, rtt, effectiveType} -> 模拟 navigator.connection

_DEEP_JS = r"""
(function () {
  'use strict';
  /* ==================== 深度伪装（按模板字段可选注入） ==================== */
  var nativeFn = function (name, fn) {
    try {
      Object.defineProperty(fn, 'name', { value: name, configurable: true });
    } catch (e) {}
    return fn;
  };
  var setProp = function (proto, key, val) {
    try {
      Object.defineProperty(proto, key, {
        get: nativeFn(key, function () { return val; }),
        set: undefined, enumerable: true, configurable: true,
      });
    } catch (e) {}
  };
  /*__DEEP_VENDOR__*/
  /*__DEEP_NO_CHROME__*/
  /*__DEEP_NO_UAD__*/
  /*__DEEP_SCREEN__*/
  /*__DEEP_NET__*/
  /*__DEEP_QUOTA__*/
  /*__DEEP_SHADOW__*/
  /*__DEEP_CDP__*/
})();
"""


def _deep_js(fp: dict) -> str:
    """根据指纹字段编译深度伪装片段（无字段 → 空字符串，行为与原生一致）"""
    slots = {"__DEEP_VENDOR__": "", "__DEEP_NO_CHROME__": "",
             "__DEEP_NO_UAD__": "", "__DEEP_SCREEN__": "",
             "__DEEP_NET__": "", "__DEEP_QUOTA__": "",
             "__DEEP_SHADOW__": "", "__DEEP_CDP__": ""}

    vendor = fp.get("vendor")
    if vendor is not None:
        v = str(vendor).replace("\\", "\\\\").replace("'", "\\'")
        slots["__DEEP_VENDOR__"] = f"setProp(Navigator.prototype, 'vendor', '{v}');"

    if fp.get("chrome_ui") is False:
        slots["__DEEP_NO_CHROME__"] = (
            "try { if (window.chrome) { Object.defineProperty(window, 'chrome', "
            "{ get: function () { return undefined; }, set: function () {}, "
            "enumerable: true, configurable: true }); } } catch (e) {}")

    if fp.get("uad") is False:
        slots["__DEEP_NO_UAD__"] = (
            "try { if (navigator.userAgentData) { "
            "Object.defineProperty(Navigator.prototype, 'userAgentData', "
            "{ get: function () { return undefined; }, set: undefined, "
            "enumerable: true, configurable: true }); } } catch (e) {}")

    cd = fp.get("color_depth")
    if cd is not None:
        n = int(cd)
        slots["__DEEP_SCREEN__"] = (
            f"try {{ Object.defineProperty(Screen.prototype, 'colorDepth', "
            f"{{ get: function () {{ return {n}; }}, enumerable: true, configurable: true }}); "
            f"Object.defineProperty(Screen.prototype, 'pixelDepth', "
            f"{{ get: function () {{ return {n}; }}, enumerable: true, configurable: true }}); "
            f"}} catch (e) {{}}")

    net = fp.get("network_connection")
    if isinstance(net, dict):
        dl = float(net.get("downlink", 10))
        rtt = int(net.get("rtt", 50))
        et = str(net.get("effectiveType", "4g"))
        slots["__DEEP_NET__"] = (
            f"try {{ var conn = {{ effectiveType: '{et}', rtt: {rtt}, "
            f"downlink: {dl}, saveData: false, onchange: null, "
            f"addEventListener: function () {{}}, removeEventListener: function () {{}} }}; "
            f"Object.defineProperty(Navigator.prototype, 'connection', "
            f"{{ get: function () {{ return conn; }}, enumerable: true, configurable: true }}); "
            f"}} catch (e) {{}}")

    quota = fp.get("storage_quota")
    if quota:
        n = int(quota)
        # 伪 storage.estimate：普通模式配额远大于隐身模式，规避 BrowserScan 等
        # 的 incognito 判定（隐身模式配额通常 < 1GB，普通模式为 GB 级）。
        # usage 取配额 5% 的确定性伪值（同指纹页面间一致）。
        slots["__DEEP_QUOTA__"] = (
            f"try {{ var _q = {n}, _u = Math.floor({n} * 0.05); "
            f"var _est = function () {{ return Promise.resolve({{ quota: _q, usage: _u }}); }}; "
            f"if (window.StorageManager && StorageManager.prototype) {{ "
            f"Object.defineProperty(StorageManager.prototype, 'estimate', "
            f"{{ value: _est, writable: true, configurable: true }}); }} "
            f"else if (navigator.storage) {{ navigator.storage.estimate = _est; }} "
            f"}} catch (e) {{}}")

    # 借鉴 fingerprint-chromium：fakeShadowRoot 穿透 closed shadow root
    if fp.get("fake_shadow") is True:
        slots["__DEEP_SHADOW__"] = (
            "try { "
            "var _origAttach = Element.prototype.attachShadow; "
            "var _closedRoots = new WeakMap(); "
            "Element.prototype.attachShadow = function (init) { "
            "var root = _origAttach.call(this, init); "
            "if (init && init.mode === 'closed') { _closedRoots.set(this, root); } "
            "return root; }; "
            "Object.defineProperty(Element.prototype, 'fakeShadowRoot', { "
            "configurable: true, get: function () { "
            "if (!(this instanceof Element)) return null; "
            "if (this.shadowRoot) return this.shadowRoot; "
            "var r = _closedRoots.get(this); return r || null; } }); "
            "} catch (e) {}")

    # CDP 残留清理：老 chromedriver 泄漏的 cdc_ 变量 + 兜底 window.cdc_ 清理
    if fp.get("cdp_cleanup") is True:
        slots["__DEEP_CDP__"] = (
            "try { "
            "for (var k in window) { if (k.indexOf('cdc_') === 0) { "
            "try { delete window[k]; } catch (e) {} } } "
            "var _cdc = Object.getOwnPropertyNames(window).filter(function (n) { "
            "return n.indexOf('cdc_') === 0; }); "
            "_cdc.forEach(function (n) { try { delete window[n]; } catch (e) {} }); "
            "} catch (e) {}")

    if not any(slots.values()):
        return ""
    js = _DEEP_JS
    for k, v in slots.items():
        js = js.replace(f"/*{k}*/", v)
    return js


# ==================== 非 Chromium 轻量注入（Firefox / WebKit） ====================
# Chromium 版深注入依赖 NavigatorUAData / WebGL / Audio / Canvas 等原型细节，
# 与 firefox/webkit 引擎结构不通用。非 chromium 引擎改用轻量注入：
#   - navigator.webdriver=false（Playwright/firefox 会暴露任真值）
#   - plugins / mimeTypes 归零无痕（真实 Firefox 也常为 0 个表项）
#   - 其余 UA/locale/viewport/geolocation 由 Playwright context 级参数天然覆盖
_LIGHT_JS = r"""
(function () {
  'use strict';
  var nativeFn = function (name, fn) {
    try { Object.defineProperty(fn, 'name', { value: name, configurable: true }); } catch (e) {}
    return fn;
  };
  var setProp = function (proto, key, val) {
    try {
      Object.defineProperty(proto, key, {
        get: nativeFn(key, function () { return val; }),
        set: undefined, enumerable: true, configurable: true,
      });
    } catch (e) {}
  };
  setProp(Navigator.prototype, 'webdriver', false);
  try {
    var pd = [], md = [];
    var pArr = Object.create(PluginArray.prototype);
    Object.defineProperty(pArr, 'length', {
      get: nativeFn('length', function () { return 0; }), enumerable: true, configurable: true });
    pArr.item = nativeFn('item', function () { return null; });
    pArr.namedItem = nativeFn('namedItem', function () { return null; });
    var mArr = Object.create(MimeTypeArray.prototype);
    Object.defineProperty(mArr, 'length', {
      get: nativeFn('length', function () { return 0; }), enumerable: true, configurable: true });
    mArr.item = nativeFn('item', function () { return null; });
    mArr.namedItem = nativeFn('namedItem', function () { return null; });
    setProp(Navigator.prototype, 'plugins', pArr);
    setProp(Navigator.prototype, 'mimeTypes', mArr);
  } catch (e) {}
})();
"""


def browser_type(fp: dict) -> str:
    """取指纹模板声明的浏览器引擎（缺省 chromium）。"""
    return (fp.get("browser_type") or "chromium").lower()


def build_init_script_light(fp: dict) -> str:
    """非 chromium 引擎的轻量注入脚本。"""
    return _LIGHT_JS


def _client_extra_headers(fp: dict) -> dict:
    """chromium 引擎的完整请求头链路（Sec-CH-UA 三件套 + 常规 Accept）。

    说明：Chromium 不允许多 CDP 覆盖 sec-fetch-*（由网络栈控制），
    这部分保持浏览器原生；此处补齐 JS/fetch 层可覆盖的头，让
    XHR/fetch 请求在头域上更贴近真实浏览器。
    """
    base = _client_hints(fp)
    # 常规头：Chromium 允许 setExtraHTTPHeaders 覆盖，且不影响指纹注入
    base["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "image/avif,image/webp,*/*;q=0.8")
    base["Accept-Language"] = fp.get("locale", "en-US")
    base["Upgrade-Insecure-Requests"] = "1"
    return base


def build_init_script(fp: dict) -> str:
    """把指纹编译为页面注入脚本（页面任何脚本执行之前运行）。

    chromium 引擎走完整深注入；firefox/webkit 走轻量注入。
    噪声全部由 canvas_noise_seed 派生：同一指纹每次启动噪声恒定，
    不同指纹噪声不同 —— 满足"稳定但不重复"的指纹伪装原则。
    """
    if browser_type(fp) != "chromium":
        return build_init_script_light(fp)

    major = fp.get("chrome_major", _FALLBACK_VER)
    full_ver = fp.get("chrome_full_ver", f"{major}.0.0.0")
    brands, full_list = _uad_brands(fp)
    js = (_INIT_JS
          .replace("__NOISE_FLAG__", "true" if fp.get("canvas_noise") is not False else "false")
          .replace("__SEED__", fp.get("canvas_noise_seed", fp.get("name", "default")).replace("\\", "\\\\").replace("'", "\\'"))
          .replace("__UA__", fp["ua"].replace("\\", "\\\\").replace("'", "\\'"))
          .replace("__PLATFORM__", fp["platform"])
          .replace("__LOCALE__", fp["locale"])
          .replace("__LANGS__", json.dumps(fp["languages"], ensure_ascii=False))
          .replace("__CORES__", str(fp["cores"]))
          .replace("__MEMORY__", str(fp["memory"]))
          .replace("__TOUCH__", str(fp.get("touch_points", 0)))
          .replace("__SW__", str(fp["screen"]["width"]))
          .replace("__SH__", str(fp["screen"]["height"]))
          .replace("__UAD_BRANDS__", json.dumps(brands, ensure_ascii=False))
          .replace("__UAD_FULL_LIST__", json.dumps(full_list, ensure_ascii=False))
          .replace("__CH_FULL_VER__", full_ver)
          .replace("__CH_PLATFORM__", fp.get("ch_platform", "Windows"))
          .replace("__CH_PLATFORM_VER__", fp.get("platform_version", "15.0.0"))
          .replace("__WGL_VENDOR__", fp.get("webgl_vendor", "Google Inc. (NVIDIA)").replace("'", "\\'"))
          .replace("__WGL_RENDERER__", fp.get("webgl_renderer", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device))").replace("'", "\\'"))
          .replace("__WGL_MAXTEX__", str(fp.get("webgl_max_texture", 16384))))
    deep = _deep_js(fp)   # 深度伪装层（模板字段驱动，缺省为空 → 零行为变化）
    return js + deep


# ==================== 浏览器启动 ====================

def _resolve_proxy(proxy: str | None) -> str | None:
    if not proxy:
        return None
    if proxy != "auto":
        return proxy
    from .fp_proxy import detect_local_proxy

    found = detect_local_proxy()
    if found:
        print(f"[proxy] 自动检测到本机代理: {found}")
        return found
    print("[proxy] 未检测到本机代理，本次无代理启动")
    return None


def _new_context(browser, fp: dict, proxy: str | None = None, storage_state: dict | None = None):
    bt = browser_type(fp)
    kwargs = {
        "user_agent": fp["ua"],                      # UA（与注入脚本一致，双保险）
        "locale": fp["locale"],                      # 联动 Accept-Language
        "timezone_id": fp["timezone"],               # 联动时区
        "viewport": {"width": fp["viewport"]["width"],
                      "height": fp["viewport"]["height"]},
        "device_scale_factor": fp["screen"]["dpr"],
        "proxy": {"server": proxy, "bypass": "localhost,127.0.0.1,<local>"} if proxy else None,
    }
    # Chromium 引擎：Sec-CH-UA 三件套 + 常规 Accept（firefox/webkit 不适用 CH 头）
    if bt == "chromium":
        kwargs["extra_http_headers"] = _client_extra_headers(fp)
    else:
        # 非 chromium 引擎：仅补 Accept 与语言（CH 头是 chromium 专有）
        kwargs["extra_http_headers"] = {
            "Accept-Language": fp.get("locale", "en-US"),
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            "Upgrade-Insecure-Requests": "1",
        }
    # 环境人设地理坐标（与 IP 国家一致；不预授权定位权限——真实用户多数手动允许）
    geo = fp.get("geolocation")
    if isinstance(geo, dict) and geo.get("latitude") is not None:
        kwargs["geolocation"] = {"latitude": geo["latitude"],
                                 "longitude": geo["longitude"],
                                 "accuracy": 100}
    if storage_state is not None:
        kwargs["storage_state"] = storage_state       # 账号档案：还原 cookie + localStorage
    context = browser.new_context(**kwargs)
    context.add_init_script(build_init_script(fp))
    return context


def _launch_one(p, fp: dict, headless: bool):
    """按指纹模板的 browser_type 启动对应引擎。

    chromium：剔除自动化痕迹参数（patchright 修补清单）；
    firefox / webkit：不注入 chromium 专属参数（会报错或无效）。
    """
    bt = browser_type(fp)
    if bt == "firefox":
        return p.firefox.launch(headless=headless)
    if bt == "webkit":
        return p.webkit.launch(headless=headless)
    return p.chromium.launch(headless=headless, args=LAUNCH_ARGS,
                             ignore_default_args=REMOVED_DEFAULT_ARGS)


def launch(fp: dict, proxy: str | None = None, headless: bool = False,
           storage_state: dict | None = None):
    """启动带指定指纹的浏览器实例。

    返回 (playwright, browser, context, page)；用完调用 playwright.stop()。
    proxy: None 不用代理 / "auto" 自动探测本机梯子 / 或具体 "socks5://host:port"。
    storage_state: 账号档案登录态（cookie+localStorage），再次登录时完全还原。
    引擎由指纹模板 browser_type 决定（缺省 chromium；可 firefox / webkit）。
    """
    p = sync_playwright().start()
    try:
        # 显式剔除 Playwright 默认参数中的自动化痕迹清单（patchright Command Flags 修补）：
        #   --enable-automation 会让 window.chrome 等产生自动化形态，是 Cloudflare Turnstile 等
        #   验证引擎的重要判定信号（webdriver 已由注入脚本伪为 false）；其余各项避免被识别为 stealth driver
        browser = _launch_one(p, fp, headless)
        # UA 版本随实际内核校正（零成本：browser.version 现成）
        fp = sync_ua(fp, browser.version)
        context = _new_context(browser, fp, _resolve_proxy(proxy), storage_state)
        page = context.new_page()
    except Exception:
        try:
            p.stop()   # 异常时释放 playwright 实例，避免进程泄漏
        except Exception:
            pass
        raise
    return p, browser, context, page


# ==================== 校验 ====================

_PROBE_JS = """() => {
  const canvasHash = () => {
    const c = document.createElement('canvas');
    c.width = 64; c.height = 64;
    const ctx = c.getContext('2d');
    ctx.font = '16px Arial';
    ctx.fillText('fp-check', 4, 30);
    const d = ctx.getImageData(0, 0, 64, 64).data;
    let h = 2166136261;
    for (let i = 0; i < d.length; i += 13) h = ((h ^ d[i]) * 16777619) >>> 0;
    return h >>> 0;
  };
  // Canvas 读取稳定性：连续两次 toDataURL 应一致；连续两次 getImageData 应一致（真实浏览器特性）
  const chanConsistent = (() => {
    const c = document.createElement('canvas'); c.width = 60; c.height = 30;
    const ctx = c.getContext('2d');
    ctx.fillStyle = '#f60'; ctx.fillRect(0, 0, 60, 20);
    ctx.font = '14px Arial'; ctx.fillStyle = '#069'; ctx.fillText('probe', 2, 15);
    const u1 = c.toDataURL();
    const u2 = c.toDataURL();
    const g1 = ctx.getImageData(0, 0, 60, 30).data[77];
    const g2 = ctx.getImageData(0, 0, 60, 30).data[77];
    return u1 === u2 && g1 === g2;
  })();
  let v = null, r = null, maxtex = null;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    if (gl) { v = gl.getParameter(0x1F00); r = gl.getParameter(0x1F01); maxtex = gl.getParameter(0x0D33); }
  } catch (e) {}
  const d = Object.getOwnPropertyDescriptor(Navigator.prototype, 'userAgent');
  return {
    ua: navigator.userAgent,
    platform: navigator.platform,
    webdriver: navigator.webdriver,
    language: navigator.language,
    languages: navigator.languages,
    cores: navigator.hardwareConcurrency,
    memory: navigator.deviceMemory,
    screenW: screen.width,
    screenH: screen.height,
    canvasHash: canvasHash(),
    webglVendor: v,
    webglRenderer: r,
    webglMaxTex: maxtex,
    pluginsLen: navigator.plugins.length,
    pdfViewer: navigator.pdfViewerEnabled,
    uadPlatform: navigator.userAgentData ? navigator.userAgentData.platform : '(missing)',
    propEnumerable: d ? d.enumerable : false,
    getterNative: d && d.get ? String(d.get).includes('native code') : false,
    chanConsistent,
  };
}
"""


_LIGHT_PROBE_JS = """() => {
  return {
    ua: navigator.userAgent,
    platform: navigator.platform,
    webdriver: navigator.webdriver,
    language: navigator.language,
    languages: navigator.languages,
    cores: navigator.hardwareConcurrency,
    screenW: screen.width,
    screenH: screen.height,
    pluginsLen: (navigator.plugins || []).length,
  };
}
"""


def verify(fp: dict) -> dict:
    """headless 快速校验：读取浏览器实际暴露的指纹，返回供比对。

    chromium 引擎采集完整信号；firefox/webkit 采集轻量信号（深注入
    仅 chromium 适用）。
    """
    probe = _PROBE_JS if browser_type(fp) == "chromium" else _LIGHT_PROBE_JS
    with sync_playwright() as p:
        browser = _launch_one(p, fp, True)
        fp = sync_ua(fp, browser.version)
        context = _new_context(browser, fp)
        page = context.new_page()
        page.goto("about:blank")
        actual = page.evaluate(probe)
        browser.close()
    return actual


def report(fp: dict) -> dict:
    """比对配置与实际值，返回 {"pass": bool, "diffs": [...], "actual": {...}}"""
    a1 = verify(fp)   # verify 内部会缓存 _kernel_major 并用校正后 UA
    a2 = verify(fp)  # 第二次独立启动，验证噪声确定性
    if _kernel_major:
        fp = sync_ua(fp, _kernel_major + ".0.0.0")   # 期望值同步用校正后的 UA
    expected_map = {
        "ua": fp["ua"],
        "platform": fp["platform"],
        "language": fp["locale"],
        "cores": fp["cores"],
        "memory": fp["memory"],
        "screenW": fp["screen"]["width"],
        "screenH": fp["screen"]["height"],
    }
    labels = {
        "ua": "UA", "platform": "platform", "language": "language",
        "cores": "hardwareConcurrency", "memory": "deviceMemory",
        "screenW": "screen.width", "screenH": "screen.height",
    }
    diffs = []
    for key, expected in expected_map.items():
        if str(a1[key]) != str(expected):
            diffs.append(f"{labels[key]}: 期望 {expected}，实际 {a1[key]}")
    if a1["webdriver"] is not False:
        diffs.append(f"webdriver: 期望 False，实际 {a1['webdriver']}")
    if fp.get("webgl_vendor") and a1["webglVendor"] != fp["webgl_vendor"]:
        diffs.append(f"webglVendor: 期望 {fp['webgl_vendor']}，实际 {a1['webglVendor']}")
    if a1["canvasHash"] != a2["canvasHash"]:
        diffs.append("canvas 噪声不稳定（同一指纹两次启动结果不同，违反确定性原则）")
    # 反检测关键项
    if a1["pluginsLen"] != 5:
        diffs.append(f"plugins: 期望 5 个，实际 {a1['pluginsLen']}")
    if a1["pdfViewer"] is not True:
        diffs.append(f"pdfViewerEnabled: 期望 True，实际 {a1['pdfViewer']}")
    # uad 关闭（Firefox 风格模板）时，缺失 userAgentData 属预期行为
    if fp.get("uad") is False:
        if a1["uadPlatform"] != "(missing)":
            diffs.append(f"userAgentData: 期望缺失（模板 uad=false），实际 {a1['uadPlatform']}")
    elif a1["uadPlatform"] != fp.get("ch_platform", "Windows"):
        diffs.append(f"userAgentData.platform: 期望 {fp.get('ch_platform', 'Windows')}，实际 {a1['uadPlatform']}")
    if a1["propEnumerable"] is not True:
        diffs.append("userAgent 属性 enumerable: 期望 true（真实浏览器原型属性可枚举）")
    if a1["getterNative"] is not True:
        diffs.append("userAgent getter: toString 未伪装为 [native code]")
    if a1["chanConsistent"] is not True:
        diffs.append("Canvas 读取不稳定（连续两次 toDataURL/getImageData 结果应一致）")
    if fp.get("webgl_max_texture") and a1["webglMaxTex"] != fp["webgl_max_texture"]:
        diffs.append(f"MAX_TEXTURE_SIZE: 期望 {fp['webgl_max_texture']}，实际 {a1['webglMaxTex']}")
    return {"pass": not diffs, "diffs": diffs, "actual": a1}


# ==================== CLI ====================

def main():
    parser = argparse.ArgumentParser(description="可换指纹浏览器（fingerprint_browser）")
    parser.add_argument("--profile", default=None, help="指纹模板名（默认取第一个）")
    parser.add_argument("--list", action="store_true", help="列出所有指纹模板")
    parser.add_argument("--check", action="store_true", help="headless 校验指纹注入是否生效")
    parser.add_argument("--proxy", default=None, help="None/auto/socks5://127.0.0.1:7890")
    parser.add_argument("--url", default="about:blank", help="启动后打开的地址")
    parser.add_argument("--headless", action="store_true", help="无头模式")
    args = parser.parse_args()

    if args.list:
        for name in list_templates():
            print(f"  {name}")
        return

    profile = args.profile or (list_templates()[0] if list_templates() else None)
    if not profile:
        print("指纹目录为空，请先添加 fingerprints/*.json")
        return

    fp = load(profile)

    if args.check:
        result = report(fp)
        print(json.dumps(result["actual"], ensure_ascii=False, indent=2))
        if result["pass"]:
            print(f"\n[PASS] 指纹 {profile} 注入全部生效（含反检测关键项），噪声稳定")
        else:
            print(f"\n[FAIL] {len(result['diffs'])} 处问题:")
            for d in result["diffs"]:
                print(f"  - {d}")
        return

    print(f"正在启动浏览器（指纹: {profile}）...")
    p, browser, _, page = launch(fp, proxy=args.proxy, headless=args.headless)
    page.goto(args.url)
    print(f"已打开: {args.url}\n按 Enter 关闭浏览器（或直接关闭浏览器窗口）")
    try:
        input()
    finally:
        p.stop()


if __name__ == "__main__":
    main()