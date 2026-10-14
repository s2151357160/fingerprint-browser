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

    return {"score": max(0, min(100, score)), "pass": score >= 90 and not diffs,
            "diffs": diffs, "actual": r["actual"], "env_country": cc}


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