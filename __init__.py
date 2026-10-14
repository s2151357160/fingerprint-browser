"""可换指纹浏览器（fingerprint_browser）

作为模块集成到现有采集/自动化体系，提供：
  load(name)            加载指纹模板（fingerprints/*.json）
  list_templates()      列出所有可用指纹模板
  launch(fp, proxy)     启动带指定指纹的浏览器（返回 p, browser, context, page）
  verify(fp)            读取浏览器实际暴露的指纹
  report(fp)            比对配置与实际值，返回差异列表
  detect_local_proxy()  自动探测本机梯子代理（socks5://... 或 http://...）

用法：
    from fingerprint_browser import load, launch
    fp = load("win10-chrome-151")
    p, browser, context, page = launch(fp, proxy="auto")   # auto = 自动接本机梯子
    page.goto("https://example.com")
    p.stop()
"""
__version__ = "1.0.0"

_BROWSER_FUNCS = ("load", "list_templates", "launch", "verify", "report", "build_init_script",
                  "random_fingerprint")
_PROXY_FUNCS = ("detect_local_proxy",)
_EXTRA_FUNCS = ("list_scripts", "run_script", "extract_rules", "export_items",
                "check_fingerprint")


def __getattr__(name):
    if name in _BROWSER_FUNCS:
        from .fp_browser import (build_init_script, launch, list_templates,
                                 load, report, verify)
        if name == "random_fingerprint":
            from .fp_gen import random_fingerprint
            return random_fingerprint
        return {"load": load, "list_templates": list_templates, "launch": launch,
                "verify": verify, "report": report,
                "build_init_script": build_init_script}[name]
    if name in _PROXY_FUNCS:
        from .fp_proxy import detect_local_proxy
        return {"detect_local_proxy": detect_local_proxy}[name]
    if name in _EXTRA_FUNCS:
        if name == "check_fingerprint":
            from .fp_check import check_fingerprint
            return check_fingerprint
        if name in ("list_scripts", "run_script"):
            from .fp_automation import list_scripts, run_script
            return {"list_scripts": list_scripts, "run_script": run_script}[name]
        if name == "extract_rules":
            from .fp_scrape import extract_rules
            return extract_rules
        if name == "export_items":
            from .fp_scrape import export_items
            return export_items
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")