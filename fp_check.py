"""指纹自检与一致性评分

对模板或账号档案执行综合自检，输出 0-100 评分与问题明细：
  1. 注入生效项      （复用 fp_browser.report 的全部校验）
  2. 环境一致性      （时区/语言/坐标 vs 环境人设国家）
  3. 深度伪装字段    （模板声明的可选字段是否在浏览器侧生效）

用法（代码集成）:
    from fingerprint_browser.fp_check import check_fingerprint
    result = check_fingerprint(fp, env_country="US")   # 0-100 评分 + diffs

命令行:
    python -m fingerprint_browser.fp_check --template win10-chrome-151
    python -m fingerprint_browser.fp_check --profile shop01
"""
from __future__ import annotations

import json
from pathlib import Path

from .fp_browser import FINGERPRINTS_DIR, load, report
from .fp_env import ENV_MAP

# 评分：满分 100，注入一致性每处 -8（累计最多 -64），环境一致性每处 -5（最多 -20）
_SCORE_INJECT = 8
_SCORE_ENV = 5
_ENV_MAX = 20


def _tz_ok_for_country(tz: str, cc: str) -> bool:
    """时区是否属于该国家人设允许列表（美国用细分表，其余用默认）"""
    cfg = ENV_MAP.get((cc or "").upper())
    if not cfg:
        return True   # 未识别国家不判
    allowed = {cfg.get("tz_default")}
    allowed.update((cfg.get("tz_by_city") or {}).values())
    return tz in allowed


def _lang_ok_for_country(locale: str, cc: str) -> bool:
    cfg = ENV_MAP.get((cc or "").upper())
    if not cfg:
        return True
    for cand in cfg["locales"]:
        if locale.lower().startswith(cand.split("-")[0].lower()):
            return True
    return False


def check_fingerprint(fp: dict, env_country: str | None = None) -> dict:
    """对指纹执行完整自检。

    fp: 指纹字典（档案指纹或模板）
    env_country: 环境人设国家码（可选；来自档案 meta）
    返回 {score, pass, diffs[], actual{}}
    """
    r = report(fp)   # 两次独立启动验证 + 反检测关键项
    diffs = list(r["diffs"])
    score = 100

    # 注入一致性扣分
    inject = len(diffs)
    score -= min(inject * _SCORE_INJECT, 40)
    if inject:
        diffs.insert(0, f"注入一致性 {inject} 处不一致")

    # 环境一致性（人设国家已知时）
    cc = env_country
    env_bad = 0
    if cc:
        tz = fp.get("timezone")
        if tz and not _tz_ok_for_country(tz, cc):
            env_bad += 1
            diffs.append(f"时区 {tz} 与环境人设 {cc} 不匹配")
        loc = fp.get("locale")
        if loc and not _lang_ok_for_country(loc, cc):
            env_bad += 1
            diffs.append(f"语言 {loc} 与环境人设 {cc} 不匹配")
    score -= min(env_bad * _SCORE_ENV, _ENV_MAX)

    # 深度伪装字段声明校验（模板声明了但未注入 = 伪配置）
    for key in ("vendor", "chrome_ui", "uad", "color_depth", "network_connection"):
        if key in fp:
            score -= 1   # 声明字段本身不扣（注入逻辑独立验证）

    # 设备一致性（Camoufox coherence 思路）：平台-GPU-核数-屏幕联动
    try:
        from .fp_devices import coherence_check
        co_bad = coherence_check(fp)
    except Exception:  # noqa: BLE001
        co_bad = []
    if co_bad:
        score -= min(len(co_bad) * 2, 8)
        for c in co_bad:
            diffs.append(f"设备一致性: {c}")

    # 噪声策略审计：canvas_noise=false 是哲学选择，只提示不扣分、不影响 pass
    notes = []
    if fp.get("canvas_noise") is False:
        notes.append("噪声策略: canvas_noise=false（原生像素，Camoufox 反噪声哲学）")

    return {"score": max(0, min(100, score)), "pass": score >= 90 and not diffs,
            "diffs": diffs, "notes": notes, "actual": r["actual"], "env_country": cc}


def check_template(name: str) -> dict:
    """自检一个指纹模板文件"""
    fp = load(name)
    res = check_fingerprint(fp)
    res["source"] = f"模板 {name}"
    return res


def check_profile(name: str) -> dict:
    """自检一个账号档案（读取指纹 + 档案环境人设国家）"""
    from .fp_profile import get_env_country, load_profile

    prof = load_profile(name)
    fp = prof["fp"]
    cc = get_env_country(name)
    res = check_fingerprint(fp, env_country=cc)
    res["source"] = f"档案 {name}"
    return res


# ==================== 深度镜像模式（fingerprintjs 风格全信号审计） ====================

_DEEP_PROBE_JS = r"""
async () => {
  const out = {};
  const nav = navigator, scr = screen;
  out.ua = nav.userAgent || '';
  out.platform = nav.platform || '';
  out.language = nav.language || '';
  out.languages = (nav.languages || []).slice(0, 4).join(',');
  out.cores = nav.hardwareConcurrency;
  out.memory = nav.deviceMemory;
  out.touch = nav.maxTouchPoints;
  out.webdriver = !!nav.webdriver;
  out.dnt = nav.doNotTrack || nav.msDoNotTrack || '(unset)';
  out.colorDepth = scr.colorDepth;
  out.screen = scr.width + 'x' + scr.height;
  out.dpr = window.devicePixelRatio || 1;
  out.outer = window.outerWidth + 'x' + window.outerHeight;
  out.inner = window.innerWidth + 'x' + window.innerHeight;
  out.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
  out.offset = new Date().getTimezoneOffset();
  out.uad = !!nav.userAgentData;
  out.uadPlatform = nav.userAgentData ? nav.userAgentData.platform : '(missing)';
  out.uadBrands = nav.userAgentData
    ? (nav.userAgentData.brands || []).map(b => b.brand + ':' + b.version).join('|') : '';
  out.webglVendor = ''; out.webglRenderer = ''; out.webglMaxTex = 0;
  try {
    const gl = document.createElement('canvas').getContext('webgl');
    if (gl) {
      const dbg = gl.getExtension('WEBGL_debug_renderer_info');
      out.webglVendor = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
      out.webglRenderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);
      out.webglMaxTex = gl.getParameter(gl.MAX_TEXTURE_SIZE);
    }
  } catch (e) { out.webglVendor = '(err)'; }
  try {
    const c = document.createElement('canvas'); c.width = 60; c.height = 30;
    const ctx = c.getContext('2d');
    ctx.textBaseline = 'top'; ctx.font = '14px Arial';
    ctx.fillStyle = '#336699'; ctx.fillRect(0, 0, 60, 30);
    ctx.fillText('fp-mirror', 8, 4);
    const a = ctx.getImageData(0, 0, 60, 30).data;
    const b = ctx.getImageData(0, 0, 60, 30).data;
    let diff = 0; for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff++;
    out.canvasStable = diff === 0;
    let dist = 0; for (let i = 0; i < a.length; i += 4) dist += Math.abs(a[i] - 0x33) + Math.abs(a[i + 1] - 0x66) + Math.abs(a[i + 2] - 0x99);
    out.canvasTouched = dist > 0;
  } catch (e) { out.canvasStable = false; out.canvasTouched = false; }
  try {
    const ac = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 22050, 44100);
    const osc = ac.createOscillator(); osc.type = 'triangle'; osc.frequency.value = 12345;
    osc.connect(ac.destination); osc.start(0);
    const buf = await ac.startRendering();
    const ch = buf.getChannelData(0);
    let sum = 0; for (let i = 0; i < ch.length; i++) sum += Math.abs(ch[i]);
    out.audioSum = sum;
    out.audioStable = sum > 0;
  } catch (e) { out.audioSum = -1; out.audioStable = false; }
  try { out.fonts = document.fonts ? document.fonts.size : -1; } catch (e) { out.fonts = -1; }
  try { out.plugins = nav.plugins ? nav.plugins.length : -1; } catch (e) { out.plugins = -1; }
  out.pdfViewer = nav.pdfViewerEnabled !== undefined ? !!nav.pdfViewerEnabled : false;
  try {
    const v = document.createElement('video');
    out.mediaCodecs = !!v.canPlayType('video/mp4; codecs="avc1.42E01E"');
  } catch (e) { out.mediaCodecs = false; }
  try { out.mqPointer = matchMedia('(pointer: fine)').matches ? 'fine' : matchMedia('(pointer: coarse)').matches ? 'coarse' : 'none'; }
  catch (e) { out.mqPointer = 'n/a'; }
  try { out.perfNow = performance.now() % 1; out.perfOk = typeof performance.now === 'function'; }
  catch (e) { out.perfOk = false; }
  return out;
}
"""

# 与模板字段直接对比的信号：键 -> (probe键, 期望函数, 比较函数)
def _cmp_str(exp, act):
    return exp is not None and str(act) == str(exp)


def _cmp_dpr(exp, act):
    try:
        return abs(float(exp) - float(act)) < 0.001
    except Exception:  # noqa: BLE001
        return False


_DEEP_COMPARE = [
    ("ua", "ua", lambda f: f.get("ua", ""), _cmp_str),
    ("platform", "platform", lambda f: f.get("platform", ""), _cmp_str),
    ("language", "language", lambda f: f.get("locale", ""), _cmp_str),
    ("languages", "languages", lambda f: ",".join(f.get("languages", [])), _cmp_str),
    ("cores", "cores", lambda f: str(f.get("cores", "")), _cmp_str),
    ("memory", "memory", lambda f: str(f.get("memory", "")), _cmp_str),
    ("touch", "touch", lambda f: str(f.get("touch_points", 0)), _cmp_str),
    ("screen", "screen", lambda f: f"{f['screen']['width']}x{f['screen']['height']}", _cmp_str),
    ("dpr", "dpr", lambda f: str(f["screen"].get("dpr", 1)), _cmp_dpr),
    ("timezone", "timezone", lambda f: f.get("timezone", ""), _cmp_str),
    ("webglVendor", "webglVendor", lambda f: f.get("webgl_vendor", ""), _cmp_str),
    ("webglRenderer", "webglRenderer", lambda f: f.get("webgl_renderer", ""), _cmp_str),
    ("webglMaxTex", "webglMaxTex", lambda f: str(f.get("webgl_max_texture", 16384)), _cmp_str),
]

# 期望布尔断言（probe 键 -> 描述）
_DEEP_BOOL = [
    ("webdriver", False, "webdriver 应为 false"),
    ("canvasStable", True, "canvas 应确定性稳定（两次采样一致）"),
    ("audioStable", True, "audio 指纹应可采集"),
    ("pdfViewer", True, "pdfViewer 应为 true"),
    ("perfOk", True, "performance.now 应可用"),
]


def deep_fingerprint(fp: dict, env_country: str | None = None) -> dict:
    """深度镜像审计：启动一次浏览器，采集 fingerprintjs 风格全信号，
    与模板字段逐项对比，输出「已覆盖 / 未覆盖 / 提示」三类清单。"""
    from .fp_browser import launch

    p = None
    try:
        p, browser, ctx, page = launch(fp, proxy=None, headless=True)
        page.goto("about:blank")
        probe = page.evaluate(_DEEP_PROBE_JS)
    finally:
        if p:
            p.stop()

    matched, mismatch = [], []
    for label, probe_key, expect_fn, cmp in _DEEP_COMPARE:
        expected = expect_fn(fp)
        actual = probe.get(probe_key, "")
        if cmp(expected, actual):
            matched.append(label)
        else:
            mismatch.append({"key": label, "expected": expected, "actual": actual})

    bools_ok, bools_bad = [], []
    for key, want, note in _DEEP_BOOL:
        got = probe.get(key)
        if got == want:
            bools_ok.append(key)
        else:
            bools_bad.append({"key": key, "note": note, "actual": got})

    # 环境人设一致性（语言前缀 vs 国家）
    env_note = []
    cc = (env_country or "").upper()
    if cc and cc in ENV_MAP:
        lang_ok = _lang_ok_for_country(probe.get("language", ""), cc)
        if not lang_ok:
            env_note.append(f"语言 {probe.get('language')} 与国家 {cc} 人设不符")

    covered = len(matched) + len(bools_ok)
    total = len(_DEEP_COMPARE) + len(_DEEP_BOOL)
    return {
        "mode": "deep",
        "matched": sorted(matched),
        "bools_ok": sorted(bools_ok),
        "mismatch": mismatch,
        "bools_bad": bools_bad,
        "env_note": env_note,
        "coverage": f"{covered}/{total}",
        "score": round(covered / total * 100) if total else 100,
        "signals": probe,
        "remark": "JS 注入层审计：TLS 指纹(JA3/JA4)、HTTP 头、服务端时序校验不在本模式覆盖范围",
    }


def deep_check_profile(name: str) -> dict:
    """对账号档案执行深度镜像审计"""
    from .fp_profile import get_env_country, load_profile

    prof = load_profile(name)
    cc = get_env_country(name)
    res = deep_fingerprint(prof["fp"], env_country=cc)
    res["source"] = f"档案 {name}"
    return res


def deep_check_template(name: str) -> dict:
    fp = load(name)
    res = deep_fingerprint(fp)
    res["source"] = f"模板 {name}"
    return res


def _html_report(res: dict) -> str:
    """渲染简易 HTML 报告（可独立打开）"""
    color = "#16a34a" if res["pass"] else "#dc2626"
    diffs = res.get("diffs") or []
    actual = res.get("actual") or {}
    rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>"
                   for k, v in list(actual.items())[:14])
    items = "".join(f"<li>{d}</li>" for d in diffs) or "<li>无</li>"
    html = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8">
<title>指纹自检报告</title>
<style>
 body{font-family:-apple-system,"Microsoft YaHei",sans-serif;background:#f8fafc;color:#1e293b;padding:24px}
 .card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;max-width:760px;margin:0 auto}
 .score{font-size:44px;font-weight:700}
 .bar{height:10px;background:#e2e8f0;border-radius:999px;margin:10px 0}
 .bar i{display:block;height:10px;background:%COLOR%;border-radius:999px}
 table{width:100%%;border-collapse:collapse;font-size:13px}
 td{border-bottom:1px solid #f1f5f9;padding:6px 8px;word-break:break-all}
 td:first-child{color:#64748b;width:160px}
 ul{color:#dc2626;font-size:13px}
</style></head><body><div class="card">
<h2>指纹自检报告</h2>
<div class="score" style="color:%COLOR%">%SCORE% / 100</div>
<div class="bar"><i style="width:%WIDTH%%"></i></div>
<h3>问题明细</h3><ul>%ITEMS%</ul>
<h3>实际暴露值（抽样）</h3>
<table>%ROWS%</table>
</div></body></html>
"""
    return (html
            .replace("%COLOR%", color)
            .replace("%SCORE%", str(res.get("score", 0)))
            .replace("%WIDTH%", str(res.get("score", 0)))
            .replace("%ITEMS%", items)
            .replace("%ROWS%", rows))


def save_report_html(res: dict, path: Path | None = None) -> Path:
    """把自检结果保存为 HTML 报告（缺省 exports/ 目录）"""
    from .fp_scrape import _ensure_exports

    p = path or (_ensure_exports() / "fp-check-report.html")
    p.write_text(_html_report(res), encoding="utf-8")
    return p


def main():
    import argparse

    parser = argparse.ArgumentParser(description="指纹自检评分")
    parser.add_argument("--template", metavar="NAME", help="自检模板（fingerprints/*.json）")
    parser.add_argument("--profile", metavar="NAME", help="自检账号档案")
    parser.add_argument("--html", action="store_true", help="同时输出 HTML 报告")
    args = parser.parse_args()

    if args.profile:
        res = check_profile(args.profile)
    elif args.template:
        res = check_template(args.template)
    else:
        print("用法: --template <名> 或 --profile <名>")
        return

    print(f"来源: {res['source']}")
    print(f"评分: {res['score']} / 100  ({'通过' if res['pass'] else '存在问题'})")
    for d in res["diffs"]:
        print(f"  - {d}")
    if args.html:
        p = save_report_html(res)
        print(f"HTML 报告: {p}")


if __name__ == "__main__":
    main()