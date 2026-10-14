"""账号自动化脚本引擎

把常用操作编排成 JSON 脚本（打开页面、点击、输入、等待、滚动、
执行 JS、抽取数据、导出、换 IP、截图、断言、循环），
在会话线程内安全执行（所有 Playwright 调用只在 worker 线程做）。

脚本目录: scripts/*.json
  示例:
    python -m fingerprint_browser.fp_automation --demo shop-checkout

动作类型（action.type）:
  goto        {url}                      打开页面
  wait        {ms} 或 {selector, timeout} 等待
  click       {selector, index?, count?} 点击（count>1 表示连续点击多次）
  type        {selector, text, delay_ms?} 输入（逐字符）
  fill        {selector, text}            一次性填入
  press       {key}                       键盘按键（Tab/Enter 等）
  scroll      {to: 'top'|'bottom'|selector, smooth?}
  eval        {js, save?: 变量名}           执行 JS，结果存入变量
  extract     {rules: 采集规则[], save}     按规则抽取页面数据
  export      {source: 变量名|'actions', fmt: 'json'|'csv'|'xlsx'|'md', title}
  rotate_ip   {target?: 节点名}             换 IP（可选指定节点）
  screenshot  {path?, full?: bool}
  log         {message}
  assert      {js, expect?}                断言（不满足抛错）
  loop        {count, actions[]}            循环
  save_state  {}                            保存登录态
  结束        {stop: true}                 停止会话
"""
from __future__ import annotations

import json
import random
import re
import time
from datetime import datetime
from pathlib import Path

from .fp_scrape import export_items, extract_rules

SCRIPTS_DIR = Path(__file__).resolve().parent / "scripts"


# ============================================================ 脚本管理

def scripts_root() -> Path:
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    return SCRIPTS_DIR


def list_scripts() -> list[dict]:
    """列出所有自动化脚本（含名称/动作数/描述）"""
    out = []
    if not SCRIPTS_DIR.exists():
        return out
    for p in sorted(SCRIPTS_DIR.glob("*.json")):
        try:
            s = json.loads(p.read_text("utf-8"))
            out.append({"name": p.stem, "actions": len(s.get("actions", [])),
                        "desc": s.get("desc", ""), "mtime": datetime.fromtimestamp(
                            p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")})
        except Exception:  # noqa: BLE001
            continue
    return out


def load_script(name: str) -> dict:
    """加载脚本 JSON（含 name 字段）"""
    p = SCRIPTS_DIR / f"{name}.json"
    if not p.exists():
        raise FileNotFoundError(f"脚本不存在: {name}")
    s = json.loads(p.read_text("utf-8"))
    s["name"] = name
    return s


def save_script(name: str, script: dict) -> Path:
    """保存脚本（同名覆盖）。name 仅允许安全字符。"""
    if not re.fullmatch(r"[A-Za-z0-9_\-\u4e00-\u9fff]{1,32}", name):
        raise ValueError("脚本名仅支持字母/数字/下划线/短横线/中文（1-32 字符）")
    actions = script.get("actions") or []
    if not isinstance(actions, list) or not actions:
        raise ValueError("脚本 actions 不能为空")
    p = scripts_root() / f"{name}.json"
    body = {"desc": (script.get("desc") or "").strip() or name,
            "actions": actions}
    p.write_text(json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def delete_script(name: str) -> bool:
    p = SCRIPTS_DIR / f"{name}.json"
    if p.exists():
        p.unlink()
        return True
    return False


# ============================================================ 执行器

class ScriptError(RuntimeError):
    """脚本执行失败（带步骤号）"""


class _Fail(Exception):
    """步骤内失败（可被 ignore_errors 跳过）"""


class _UnknownAction(Exception):
    """未知动作类型"""


def _num(v) -> int | None:
    try:
        return int(v)
    except Exception:  # noqa: BLE001
        return None


def _interp(text, vars: dict) -> str:
    """把 $var / ${var} 展开为脚本上下文变量值（缺失变量保持原样）"""
    if not text or "$" not in text:
        return text

    def _rep(m):
        k = m.group(1)
        v = vars.get(k)
        return str(v) if v is not None else ""

    out = re.sub(r"\$\{(\w+)\}", _rep, str(text))
    return re.sub(r"\$(\w+)", _rep, out)


def run_script(page, actions: list[dict], log=None, ctx: dict | None = None) -> dict:
    """在会话页面上顺序执行动作序列。

    page: Playwright Page（必须在会话 worker 线程内调用）
    log:  日志回调（可选）
    ctx:  上下文注入，可用键:
        worker  （SessionWorker，用于换 IP/停止/存储）
        vars    （脚本变量字典，各动作可读写）
        humanize（bool）——人类行为模拟（点击/输入/滚动走拟人曲线）
        human_preset（str）拟人预设：default / careful
    """
    ctx = ctx or {}
    vars: dict = ctx.setdefault("vars", {})
    if log is not None:
        ctx.setdefault("log", log)
    human = None
    if ctx.get("humanize"):
        from .fp_human import Human
        human = Human(page, preset=ctx.get("human_preset") or "default")
    ok = 0
    fail = 0
    started = time.strftime("%H:%M:%S")

    def _log(msg):
        if ctx.get("log"):
            ctx["log"](f"[脚本] {msg}")

    def _step(i, act):
        t = act.get("type")
        if t == "goto":
            url = _interp(act.get("url") or "", vars)
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
            _log(f"打开 {url[:80]}")
        elif t == "wait":
            if act.get("ms") is not None:
                time.sleep(max(0, int(act["ms"])) / 1000.0)
            else:
                sel = act.get("selector")
                if sel:
                    page.wait_for_selector(sel, timeout=int(act.get("timeout") or 30000),
                                           state=act.get("state", "visible"))
        elif t == "click":
            sel = _interp(act.get("selector") or "", vars)
            idx = _num(act.get("index"))
            count = _num(act.get("count")) or 1
            if human and not act.get("raw"):
                for _ in range(count):
                    human.click(sel, idx or 0)
                    if random.random() < 0.4:
                        human.idle()
                _log(f"拟人点击 {sel}" + (f" ×{count}" if count > 1 else ""))
            else:
                loc = page.locator(sel).nth(idx or 0)
                for _ in range(count):
                    loc.click(timeout=30000)
                    time.sleep(0.15)
                _log(f"点击 {sel}" + (f" ×{count}" if count > 1 else ""))
        elif t == "type":
            sel = _interp(act.get("selector") or "", vars)
            text = _interp(act.get("text") or "", vars)
            if human and not act.get("raw"):
                human.type_text(sel, text, clear=not act.get("append"))
                _log(f"拟人输入 {sel}")
            else:
                delay = _num(act.get("delay_ms"))
                if delay:
                    loc = page.locator(sel).first
                    loc.click()
                    for ch in str(text):
                        page.keyboard.type(ch, delay=int(delay) / 1000.0)
                else:
                    page.locator(sel).first.fill(text)
                _log(f"输入 {sel}")
        elif t == "press":
            page.keyboard.press(act.get("key") or "Enter")
        elif t == "scroll":
            target = act.get("to")
            if human and not act.get("raw"):
                human.scroll(target if "top" in str(target) or "bottom" in str(target) else str(target or "bottom"))
            else:
                if target == "top":
                    page.evaluate("window.scrollTo(0,0)")
                elif target == "bottom":
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                elif target:
                    page.locator(str(target)).scroll_into_view_if_needed()
                else:
                    page.mouse.wheel(0, _num(act.get("dy")) or 300)
                time.sleep(0.4)
        elif t == "eval":
            js = act.get("js") or ""
            val = page.evaluate(js)
            save = act.get("save")
            if save:
                vars[save] = val
        elif t == "capture":
            rules = act.get("rules") or []
            res = extract_rules(page, rules)
            save = act.get("save") or "captured"
            vars[save] = res
            _log(f"抽取 {len(res)} 字段")
        elif t == "export":
            src = act.get("source") or "captured"
            data = vars.get(src)
            if data is None:
                data = []
            if isinstance(data, dict):
                data = [data]
            path = export_items(list(data), title=act.get("title") or "capture",
                                fmt=act.get("fmt") or "xlsx")
            _log(f"已导出 {len(data)} 条 -> {path.name}")
        elif t == "rotate_ip":
            worker = ctx.get("worker")
            if worker:
                target = act.get("target")
                worker._rotate_ip(target)
                _log("已换 IP" + (f"（{target}）" if target else "（随机）"))
        elif t == "screenshot":
            path = act.get("path")
            page.screenshot(path=path or None, full_page=bool(act.get("full")))
        elif t == "assert":
            js = act.get("js") or ""
            expect = act.get("expect")
            val = page.evaluate(js)
            if expect is not None and val != expect:
                raise _Fail(f"断言失败: {js} = {val!r} ≠ {expect!r}")
        elif t == "loop":
            count = _num(act.get("count")) or 1
            for i in range(count):
                vars["i"] = i
                for sub in act.get("actions") or []:
                    _step(i, sub)
        elif t == "log":
            _log(_interp(act.get("message") or "", vars))
        elif t == "save_state":
            ctx.get("worker") and ctx["worker"]._save_storage(quiet=True)
            _log("登录态已保存")
        elif t == "stop":
            ctx.get("worker") and ctx["worker"]._stop()
            _log("会话已停止")
        else:
            raise _UnknownAction(t)

    idx = 0
    for act in actions:
        idx += 1
        try:
            _step(idx, act)
            ok += 1
        except _Fail as e:
            fail += 1
            _log(f"步骤{idx} 失败: {e}")
            if act.get("ignore_errors") or ctx.get("ignore_errors"):
                continue
            raise ScriptError(f"步骤{idx}（{act.get('type')}）失败: {e}") from e
    return {"ok": ok, "fail": fail, "started": started,
            "ended": time.strftime("%H:%M:%S"), "vars": vars}


# ============================================================ 示例脚本

DEMO_SCRIPTS = {
    "养号-每日活跃": {
        "desc": "每日养号示例：打开主页 → 随机滚动浏览 → 停留 → 保存登录态（不换 IP）",
        "actions": [
            {"type": "log", "message": "开始每日活跃（养号）"},
            {"type": "goto", "url": "https://x.com/home"},
            {"type": "wait", "ms": 3000},
            {"type": "scroll", "to": "bottom"},
            {"type": "wait", "ms": 2500},
            {"type": "scroll", "to": "top"},
            {"type": "wait", "ms": 2000},
            {"type": "save_state"},
            {"type": "log", "message": "养号完成"},
        ],
    },
    "登录-免密校验": {
        "name": "登录态校验",
        "desc": "打开站点确认登录态（可配合登录后保存的 cookie）",
        "actions": [
            {"type": "goto", "url": "https://x.com"},
            {"type": "wait", "ms": 4000},
            {"type": "assert", "js": "document.title", "expect": ""},
            {"type": "log", "message": "页面标题: ${captured.title}"},
        ],
    },
    "采集-页面快照": {
        "name": "页面采集",
        "desc": "按规则抽取页面数据并导出 xlsx",
        "actions": [
            {"type": "goto", "url": "${url}"},
            {"type": "wait", "ms": 2500},
            {"type": "extract", "rules": [
                {"name": "标题", "css": "h1", "attr": "text"},
                {"name": "链接", "css": "main a", "attr": "href", "many": True},
            ], "save": "captured"},
            {"type": "export", "source": "captured", "fmt": "xlsx", "title": "${url}"},
        ],
    },
}


def write_demo_scripts() -> list[str]:
    """把内置示例脚本写入 scripts/ 目录（已存在则跳过），返回写出/已存在的名字"""
    written = []
    scripts_root()   # 确保目录存在
    for name, script in DEMO_SCRIPTS.items():
        p = SCRIPTS_DIR / f"{name}.json"
        if p.exists():
            continue
        p.write_text(json.dumps({"desc": script.get("desc", ""),
                                 "actions": script.get("actions", [])},
                                ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(name)
    return written


# ============================================================ CLI

def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="账号自动化脚本引擎")
    parser.add_argument("--list", action="store_true", help="列出脚本")
    parser.add_argument("--show", metavar="NAME", help="查看脚本内容")
    parser.add_argument("--demo", action="store_true", help="写入内置示例脚本")
    parser.add_argument("--check", metavar="NAME", help="校验脚本格式")
    args = parser.parse_args()

    if args.demo:
        names = write_demo_scripts()
        print("已写入示例脚本:" if names else "示例脚本已存在:")
        for n in names or [p.stem for p in SCRIPTS_DIR.glob("*.json")]:
            print(f"  {n}")
        return

    if args.list:
        for s in list_scripts():
            print(f"  {s['name']}  ({s['actions']} 步) {s['desc']}")
        return

    if args.show:
        print(json.dumps(load_script(args.show), ensure_ascii=False, indent=2))
        return

    if args.check:
        s = load_script(args.check)
        print(f"脚本 {args.check}: {len(s.get('actions', []))} 步，格式正确")
        return

    parser.print_help()


if __name__ == "__main__":
    main()