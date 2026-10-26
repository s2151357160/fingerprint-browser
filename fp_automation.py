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
  进阶动作:
  solve_captcha {kind: turnstile|recaptcha|hcaptcha, sitekey, url, save?, inject?}
               第三方打码解码并注入 token
  check_logged_in {selector, save?, warn?, selector?}
              登录态探测（selector 命中仍在登录）
  db_save     {source, data: 变量名, dedup_keys?}  采集入库（SQLite 去重）
  export      新增 webhook=true/false 联动推送
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


def _inject_captcha(page, kind: str, token: str):
    """把解码得到的 token 尽量注入页面（Turnstile/hCaptcha/reCAPTCHA）。

    各服务商的注入细节高度依赖其回调约定，这里做通用尽力而为：
      - 找隐藏响应文本框并写入 token + 触发 input/change
      - 触发常见回调（cf turnstile 回调 / hcaptcha 校验）
    失败不报错（token 已在 vars 中，用户可自行处理），仅提示。
    """
    import json as _json

    js = r"""
    (function () {
      var token = __TOKEN__;
      var kind = __KIND__;
      var sels = {
        turnstile: ['textarea[name="cf-turnstile-response"]', '[name="cf-turnstile-response"]'],
        recaptcha: ['textarea[name="g-recaptcha-response"]', '[name="g-recaptcha-response"]'],
        hcaptcha:  ['textarea[name="h-captcha-response"]', '[name^="h-captcha-response"]']
      };
      var list = sels[kind] || Object.values(sels).flat();
      var wrote = 0;
      list.forEach(function (sel) {
        document.querySelectorAll(sel).forEach(function (el) {
          try {
            var proto = Object.getPrototypeOf(el);
            var setter = Object.getOwnPropertyDescriptor(proto, 'value') && Object.getOwnPropertyDescriptor(proto, 'value').set;
            if (setter) setter.call(el, token); else el.value = token;
            el.dispatchEvent(new Event('input', { bubbles: true }));
            el.dispatchEvent(new Event('change', { bubbles: true }));
            wrote++;
          } catch (e) {}
        });
      });
      // 触发常见回调（尽力而为，找到谁在监听就调谁）
      try {
        var cb = window.__cf_chl_opt && window.__cf_chl_opt.cb;
        if (typeof cb === 'function') cb();
      } catch (e) {}
      try {
        callChallengeCompleted && (kind.indexOf('hcaptcha') >= 0 || true) && callChallengeCompleted();
      } catch (e) {}
      return { wrote: wrote };
    })()
    """
    try:
        page.evaluate(js.replace("__TOKEN__", _json.dumps(token)).replace("__KIND__", _json.dumps(kind)))
    except Exception:  # noqa: BLE001
        pass


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
        elif t == "longpress":
            # 真实鼠标长按（mousedown → hold → mouseup）：
            # 微软 WBA / 部分人机验证要求物理按压，JS dispatchEvent 被判定为合成事件而失败。
            sel = _interp(act.get("selector") or "", vars)
            hold = _num(act.get("hold")) or 3
            if sel:
                loc = page.locator(sel).first
                loc.scroll_into_view_if_needed()
                box = loc.bounding_box()
                if not box:
                    raise _Fail(f"长按目标不可见: {sel}")
                cx = box["x"] + box["width"] / 2
                cy = box["y"] + box["height"] / 2
            else:
                cx = float(act.get("px") or 0)
                cy = float(act.get("py") or 0)
            # 人类式落地：从旁斜落再定住，保持期间轻微抖动（真实按压力感）
            page.mouse.move(cx - 40, cy - 20, steps=6)
            time.sleep(0.25)
            page.mouse.move(cx, cy, steps=6)
            time.sleep(0.15)
            page.mouse.down()
            if act.get("stable"):
                # WBA 长按进度环需稳定按压：全程钉死不移动，直到松开
                time.sleep(max(0.3, hold))
            else:
                # 默认微抖（更拟人）
                t0 = time.time()
                while time.time() - t0 < max(0.3, hold):
                    page.mouse.move(cx + random.randint(-1, 1), cy + random.randint(-1, 1))
                    time.sleep(0.15)
            page.mouse.up()
            _log(f"长按 ({int(cx)},{int(cy)}) {hold}s" + ("（稳定）" if act.get("stable") else ""))
        elif t == "press_probe":
            # 调试：按下长按目标，持续监测进度环/滑块/activeElement，松开后返回观察结果
            px = float(act.get("px") or 0)
            py = float(act.get("py") or 0)
            max_ms = int(act.get("max_ms") or 6000)
            page.mouse.move(px - 30, py - 15, steps=5)
            time.sleep(0.2)
            page.mouse.move(px, py, steps=5)
            time.sleep(0.15)
            page.mouse.down()
            observed = []
            t0 = time.time()
            while (time.time() - t0) * 1000 < max_ms:
                try:
                    st = page.evaluate("""(() => {
                        const active = document.activeElement ? (document.activeElement.tagName + '|' + (document.activeElement.className||'').toString().slice(0,20)) : '';
                        const prog = document.querySelectorAll('[role=progressbar],[role=slider],[class*=progress],svg[class*=inner],svg[class*=ring],button[aria-label*=hold],button[aria-label*=Hold]').length;
                        const bodyTxt = (document.body.innerText||'').slice(0,80);
                        return {active, prog, bodyTxt};
                    })()""")
                    observed.append((round((time.time()-t0)*1000), st))
                except Exception:
                    break
                time.sleep(0.4)
            page.mouse.up()
            _log(f"press_probe {max_ms}ms 观察 {len(observed)} 次")
            vars[act.get("save") or "obs"] = observed
        elif t == "frame_probe":
            # 跨域验证 iframe（如 hsprotect WBA）内部交互探测：
            # 遍历 frames，枚举 iframe 内可交互元素并换算成主视口坐标。
            _log("frame_probe: 探测验证 iframe")
            try:
                results = []
                for fr in page.frames:
                    if fr is page.main_frame:
                        continue
                    try:
                        # 枚举 iframe 内所有元素（button/img/带pointer区域），安全 selector
                        els = fr.query_selector_all("button, img, svg, a, [role=button], [aria-label], [role=slider], [class*=hold], [class*=captcha], [class*=slider], [class*=button], [class*=control], [data-testid]")
                        for el in els:
                            try:
                                box = el.bounding_box()
                                if not box or (box["width"] < 6 or box["height"] < 6):
                                    continue
                                info = el.evaluate("""e => {
                                    const aria = e.getAttribute('aria-label')||'';
                                    const role = e.getAttribute('role')||'';
                                    const dt = e.getAttribute('data-testid')||'';
                                    const txt = (e.textContent||'').trim().slice(0,24);
                                    const cls = (e.className||'').toString().slice(0,46);
                                    return {aria, role, dt, txt, cls};
                                }""")
                                results.append({"frame": fr.url[:40], "tag": el.evaluate("e => e.tagName").lower(),
                                                 "x": round(box["x"],1), "y": round(box["y"],1),
                                                 "w": round(box["width"],1), "h": round(box["height"],1),
                                                 **info})
                            except Exception:
                                continue
                    except Exception:
                        continue
                vars[act.get("save") or "fp"] = results
                _log(f"frame_probe: 找到 {len(results)} 个候选元素")
            except Exception as e:
                _log(f"frame_probe 失败: {e}")
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
            js = _interp(act.get("js") or "", vars)   # 支持 ${var} 插值
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
            if act.get("webhook") is not False:
                from .fp_store import push_webhook
                if push_webhook(list(data)):
                    _log("已推送 webhook")
        elif t == "db_save":
            # 采集入库：source + 记录 + 去重键
            from .fp_store import save_items
            src = _interp(act.get("source") or "default", vars)
            data = vars.get(act.get("data") or "captured") or []
            if isinstance(data, dict):
                data = [data]
            dedup_keys = act.get("dedup_keys")
            r = save_items(src, list(data), dedup_keys=dedup_keys)
            _log(f"入库 {src}: 新增 {r['inserted']} / 重复 {r['skipped']}")
        elif t == "mail_code":
            # 开第二个 page 读临时邮箱验证码（主流程页不动）。
            # 流程：boomlify 首页每个地址一行 → 点行内「查看收件箱」进 email-dashboard
            #       → 再点击含发件人/主题的邮件卡片展开正文 → 读正文 6 位验证码。
            address = _interp(act.get("address") or "", vars)
            save = act.get("save") or "code"
            np = page.context.new_page()
            try:
                np.goto("https://boomlify.com/zh/", wait_until="domcontentloaded", timeout=45000)
                time.sleep(6)
                # 1) 定位地址行并点「查看收件箱」
                if address:
                    try:
                        addr_el = np.locator(f"text={address}").first
                        addr_el.wait_for(state="visible", timeout=8000)
                        for _ in range(6):
                            addr_el = addr_el.locator("xpath=..")
                            if addr_el.locator("text=\u67e5\u770b\u6536\u4ef6\u7bb1").count() > 0:
                                break
                        # 优先用地址行按钮，其次页面任意「查看收件箱」
                        try:
                            addr_el.locator("text=\u67e5\u770b\u6536\u4ef6\u7bb1").first.click(timeout=6000)
                        except Exception:
                            np.locator("text=\u67e5\u770b\u6536\u4ef6\u7bb1").first.click(timeout=6000)
                        time.sleep(5)
                    except Exception:
                        pass
                # 2) 进入收件箱列表后点击微软邮件卡片（发件人 account-security 或主题 Verify your email 或微软验证码正文）
                clicked_mail = False
                for sel in [
                    "text=account-security-noreply@accountprotection.microsoft.com",
                    "text=Verify your email address",
                ]:
                    try:
                        mail = np.locator(sel).first
                        if mail.count() > 0 and not clicked_mail:
                            mail.click(timeout=4000)
                            clicked_mail = True
                            time.sleep(3)
                            break
                    except Exception:
                        continue
                # 3) 读正文验证码
                txt = np.evaluate("document.body ? document.body.innerText : ''")
                m = re.findall(r"\b\d{6}\b", txt)
                code = m[0] if m else ""
                # 兜底：邮件正文常在 iframe/srcdoc 里，跨帧提取 6 位码
                if not code:
                    try:
                        ifr = np.evaluate("""(() => {
                          let acc='';
                          document.querySelectorAll('iframe').forEach(f=>{try{const d=f.contentDocument;if(d)acc+=' '+d.body.innerText;}catch(e){}});
                          return acc;
                        })()""")
                        mi = re.findall(r"\b\d{6}\b", ifr or "")
                        code = mi[0] if mi else ""
                    except Exception:
                        pass
                vars[save] = code
                _log(f"邮箱验证码({address}): {code}")
            finally:
                np.close()
        elif t == "rotate_ip":
            worker = ctx.get("worker")
            if worker:
                target = act.get("target")
                worker._rotate_ip(target)
                _log("已换 IP" + (f"（{target}）" if target else "（随机）"))
        elif t == "solve_captcha":
            # 第三方打码：解 reCAPTCHA/hCaptcha/Turnstile 并注入 token
            from . import fp_captcha
            kind = act.get("kind") or "turnstile"
            sitekey = _interp(act.get("sitekey") or "", vars)
            url = _interp(act.get("url") or page.url, vars)
            token = fp_captcha.solve(kind, sitekey, url,
                                     provider=act.get("provider"),
                                     api_key=act.get("api_key"))
            if act.get("save"):
                vars[act["save"]] = token
            _log(f"验证码已解码（{kind}），token 长度 {len(token)}")
            if act.get("inject") is not False:
                _inject_captcha(page, kind, token)
        elif t == "check_logged_in":
            # 登录态探测：selector 命中即判定"仍登录"，否则记 vars/告警
            sel = _interp(act.get("selector") or "", vars)
            logged = bool(page.query_selector(sel)) if sel else None
            if act.get("save"):
                vars[act["save"]] = logged
            if logged is False:
                _log("未检测到登录态（可能需要重新登录）")
            else:
                _log("已登录" if logged else "已登录（未配置 selector）")
            if logged is False and act.get("warn"):
                worker = ctx.get("worker")
                if worker:
                    worker.login_warning = True
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