"""可换指纹浏览器 - 本地控制台（多账号并行版）

核心业务：账号档案
  - 每个账号一个独立档案：全新随机指纹 + 绑定出口节点 + 登录态（cookie/localStorage）
  - 注册时创建档案（全新指纹 + 换 IP），再次登录完全还原（同指纹 + 同节点 + 同登录态）
  - 多账号可同时在线：每会话独立窗口 + 独立内置内核（独立出口节点），互不干扰

启动:
    python -m fingerprint_browser.fp_app            # 默认 http://127.0.0.1:8230
    python -m fingerprint_browser.fp_app --port 8230 --no-open
"""
from __future__ import annotations

import argparse
import json
import random
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import queue as _queue

from .fp_browser import launch
from .fp_core import Core, SPECIAL_NODES, find_local_nodes
from .fp_env import apply_env_to_fp, country_from_node_name, env_for_country
from .fp_gen import random_fingerprint
from .fp_profile import (create_profile, delete_profile, list_profiles,
                          load_profile, load_storage, reset_fingerprint,
                          save_storage, set_bound_node, set_env_country,
                          get_env_country, get_last_url, set_last_url)
from .fp_reputation import scan as scan_reputation
from .fp_reputation import store as reputation_store
from .fp_sched import Scheduler, delete_task as sched_delete, upsert as sched_upsert


# ============================================================ 会话管理（每账号一线程）

class SessionWorker:
    """单个账号会话：独立线程内跑 Playwright sync 实例 + 独立内置内核。

    ops: start / stop / ip / status
    """

    def __init__(self, name: str, pool: list[dict], log: callable, port: int = 8230):
        self.name = name
        self._pool = pool
        self.log = log
        self.port = port
        self._q: _queue.Queue = _queue.Queue()
        self._stop_flag = False
        self.core = Core()
        self.pw = self.browser = self.ctx = self.page = None
        self.fp = None
        self.node: str | None = None
        self.ip: str | None = None
        self.started_at: str | None = None
        self.running = False
        self.last_err: str | None = None
        self._save_timer_stop: threading.Event | None = None
        self._manual_stop = False
        self._disconnect_handled = False
        self._chall_last = 0.0
        self._recording = False
        self._recorded: list = []
        threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, op: str, timeout: float = 150, **kw):
        ev = threading.Event()
        box: dict = {}
        self._q.put((op, kw, ev, box))
        ev.wait(timeout)
        if "error" in box:
            raise RuntimeError(box["error"])
        return box.get("result")

    def shutdown(self):
        self._stop_flag = True
        try:
            self.submit("stop", timeout=20)
        except Exception:
            pass

    def _loop(self):
        while not self._stop_flag:
            try:
                op, kw, ev, box = self._q.get(timeout=1)
            except _queue.Empty:
                self._pump_events()
                continue
            try:
                if op == "start":
                    res = self._start()
                elif op == "stop":
                    self._stop()
                    res = None
                elif op == "ip":
                    res = self._rotate_ip(kw.get("target"))
                elif op == "fingerprint":
                    res = self._rotate_fingerprint()
                elif op == "save":
                    res = self._save_storage(quiet=True)
                elif op == "script":
                    res = self._do_script(kw.get("js", ""), kw.get("url"))
                elif op == "automation":
                    res = self._run_automation(kw.get("script_name"),
                                               kw.get("variables") or {},
                                               kw.get("humanize"))
                elif op == "rec_start":
                    res = self._start_record()
                elif op == "rec_stop":
                    res = self._stop_record()
                elif op == "status":
                    res = self.status()
                else:
                    res = None
                box["result"] = res
            except Exception as e:  # noqa: BLE001
                box["error"] = str(e)
                self.last_err = f"{time.strftime('%H:%M:%S')} {e}"[:200]   # 供状态展示失败原因
                self.log(f"[{self.name}] 错误: {e}")
            finally:
                ev.set()

    def _pump_events(self):
        """空闲心跳（每秒）：探活浏览器 + 检测人机验证。

        实测 is_connected() 在进程被强杀后仍返回 True（本地标志不更新），
        不可靠；用轻量 RPC 探活——浏览器已死时抛 TargetClosedError，即触发
        回收。顺带检测页面是否出现 Cloudflare 验证，出现则自动勾选。
        """
        if not self.browser or not self.page:
            return
        try:
            found = self.page.evaluate(
                "!!((document.querySelector('iframe[src*=\"challenges.cloudflare.com\"]')"
                " || document.querySelector('.cf-turnstile'))"
                " && !((document.querySelector('[name=\"cf-turnstile-response\"]') || {value: ''}).value))")
        except Exception as e:
            # 导航中报“context destroyed”属正常瞬时错误，不算断连
            if "has been closed" in str(e):
                self._on_disconnected()
            return
        if found:
            self._auto_solve_challenge()

    def _auto_solve_challenge(self):
        """自动处理 Cloudflare Turnstile 勾选式人机验证。

        仅处理可点击的 checkbox（人类式鼠标轨迹 + 随机延迟后点击）；
        无交互的托管挑战由 Cloudflare 自动评估，图片类验证码无法自动处理。
        同页面 12s 冷却，避免重复点击。
        """
        now = time.time()
        if now - self._chall_last < 12:
            return
        self._chall_last = now
        self.log(f"[{self.name}] 检测到 Cloudflare 验证，尝试自动勾选")
        clicked = False
        try:
            for fr in self.page.frames:
                if "challenges.cloudflare.com" not in (fr.url or ""):
                    continue
                for sel in ("input[type=checkbox]", ".ctp-checkbox-label", "label"):
                    try:
                        loc = fr.locator(sel).first
                        box = loc.bounding_box(timeout=1500)
                        if box and box["width"] > 5 and box["height"] > 5:
                            cx = box["x"] + box["width"] / 2
                            cy = box["y"] + box["height"] / 2
                            # 人类式鼠标：先移动到旁边再分步移近，随机停顿后点击
                            self.page.mouse.move(cx - 60, cy - 25)
                            self.page.mouse.move(cx - 20, cy - 8, steps=4)
                            time.sleep(random.uniform(0.25, 0.6))
                            self.page.mouse.click(cx, cy)
                            clicked = True
                            break
                    except Exception:
                        continue
                if clicked:
                    break
        except Exception:
            pass
        if clicked:
            self.log(f"[{self.name}] 已点击验证框，等待验证结果")
        else:
            self.log(f"[{self.name}] 验证无需点击（托管模式自动评估中）")

    # ---------- 操作 ----------
    def _resolve_env(self, node_name: str | None) -> str | None:
        """解析会话环境人设国家：档案已有则沿用（人设稳定）；
        否则按节点 IP 国家/节点名自动设定并回写档案。"""
        env_cc = get_env_country(self.name)
        if env_cc:
            return env_cc
        cc, city = reputation_store.node_country(node_name) if node_name else (None, None)
        if not cc and node_name:
            cc = country_from_node_name(node_name)
        if cc:
            set_env_country(self.name, cc)
            self.log(f"[{self.name}] 环境人设设定: {cc}（时区/语言/坐标随 IP 国家）")
            return cc
        return None

    def _start(self):
        """还原账号档案启动：绑定节点 → 同指纹 + 同登录态 + 环境人设 → 查询出口 IP"""
        if self.running:
            return self.status()
        self._manual_stop = False
        self._disconnect_handled = False
        # 上次窗口被强杀时遗留的 playwright 实例（无法在断连回调里安全停止）
        # 在 worker 线程内安全回收，避免线程/transport 泄漏累积
        if self.pw:
            try:
                self.pw.stop()
            except Exception:
                pass
            self.pw = self.browser = self.ctx = self.page = None
        prof = load_profile(self.name)
        self.fp = prof["fp"]
        meta = prof["meta"]
        has_storage = load_storage(self.name) is not None
        self.log(f"[{self.name}] 启动：指纹 {self.fp.get('name', '?')}，还原登录态={'是' if has_storage else '无'}")

        # 1) 专属内核（独立端口 + 独立出口节点）
        if not self.core.running:
            pool = self._pool or find_local_nodes()
            if not pool:
                raise RuntimeError("节点池为空，请先「重新探测」")
            self.core.start(nodes=pool)
        # 2) 绑定档案节点（完全还原）；节点失效/为直连策略则随机换并回写
        bound = meta.get("node")
        if bound and bound.upper() not in SPECIAL_NODES and self.core.select_node(bound):
            self.node = bound
            self.log(f"[{self.name}] 节点还原: {bound}")
        else:
            if bound:
                self.log(f"[{self.name}] 绑定节点 {bound} 不可用或为直连策略，自动换新并更新档案")
            node = self.core.rotate_node()
            self.node = node
            if node:
                set_bound_node(self.name, node)
        # 3) 环境人设：按档案国家（或绑定节点国家）覆盖时区/语言/坐标，
        #    呈现为该国本地用户（美国 IP → en-US + 美国时区 + 美国坐标）
        env_cc = self._resolve_env(self.node)
        _, node_city = reputation_store.node_country(self.node) if self.node else (None, None)
        if env_cc:
            env = env_for_country(env_cc, node_city)
            apply_env_to_fp(self.fp, env)
            self.log(f"[{self.name}] 环境已应用: {env_cc} | 时区 {env['timezone']} | 语言 {env['locale']}")
        # 4) 浏览器：同指纹 + 同登录态
        from .fp_browser import launch
        p, b, ctx, page = launch(self.fp, proxy=self.core.proxy_url,
                                 headless=False, storage_state=load_storage(self.name))
        self.pw, self.browser, self.ctx, self.page = p, b, ctx, page
        # 悬浮窗桥：页面内数据/按钮走 Playwright 桥回 Python（绕过页面 CSP/CORS 对 fetch 的限制）
        ctx.expose_function("__fpBridge", self._bridge)
        # 悬浮窗（可收缩：显示指纹/IP，支持换 IP / 换指纹）
        ctx.add_init_script(build_overlay(self.name, self.port))
        # 窗口被用户手动关闭/浏览器崩溃 → 自动回收内核与线程资源（否则内核泄漏：占端口占节点）
        self.browser.on("disconnected", self._on_disconnected)
        # 登录态定期保存：浏览器被强杀时最多丢 60s 增量（只在 stop 时保存的旧方案会全丢）
        self._save_timer_stop = threading.Event()
        threading.Thread(target=self._save_loop, daemon=True).start()
        self.running = True
        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.last_err = None
        # 启动页面：优先回到上次访问的页面（像浏览器“继续上次会话”），
        # 否则空白页；空白页体验割裂（每次都要重新输网址）
        resume = get_last_url(self.name)
        try:
            page.goto(resume, wait_until="domcontentloaded", timeout=30000)
        except Exception:
            try:
                page.goto("about:blank")
            except Exception:
                pass
        self.ip = self._query_ip()
        if self.ip:
            self.log(f"[{self.name}] 出口 IP: {self.ip}")
        else:
            self.log(f"[{self.name}] IP 查询失败（不影响使用）")
        return self.status()

    def _on_disconnected(self, _browser=None):
        """浏览器窗口被手动关闭/崩溃时的自动回收。

        回调在 Playwright 事件线程触发：这里只做不碰 Playwright 的安全清理
        （内核停止 + 引用置空）。注意不能调 pw.stop()/ctx.storage_state()——
        会与事件线程互锁死锁；遗留的 playwright 实例由下次 _start 在
        worker 线程内安全回收，登录态由 60s 定期保存兑底。
        """
        def _clean():
            if self._manual_stop or self._disconnect_handled:
                return   # 正常停止路径 / 已处理过，避免重复回收
            self._disconnect_handled = True
            try:
                self.core.stop()
            except Exception:
                pass
            self.ctx = self.page = None
            self.browser = None
            self.running = False
            self.ip = None
            self.started_at = None
            if self._save_timer_stop:
                self._save_timer_stop.set()
            self.log(f"[{self.name}] 浏览器窗口已关闭，内核已回收（登录态有定期保存兑底）")
        threading.Thread(target=_clean, daemon=True).start()

    def _save_loop(self):
        """登录态定期保存（60s）：经 worker 队列执行，保证 Playwright 线程安全"""
        while not self._save_timer_stop.wait(60):
            if not self.running:
                break
            try:
                self.submit("save", timeout=30)
            except Exception:
                pass

    def _save_storage(self, quiet: bool = False) -> bool:
        """保存登录态 + 当前页面（在 worker 线程内调用才安全）"""
        if not self.ctx:
            return False
        try:
            # 顺带记录当前页面（启动恢复用）；页面失效不影响登录态保存
            try:
                u = self.page.url
                if u and u.startswith(("http://", "https://")):
                    set_last_url(self.name, u)
            except Exception:
                pass
            st = self.ctx.storage_state()
            if st:
                save_storage(self.name, st)
                if not quiet:
                    self.log(f"[{self.name}] 登录态已保存")
                return True
        except Exception:
            pass
        return False

    def _stop(self):
        """停止会话：保存登录态 → 关闭窗口/内核"""
        self._manual_stop = True   # 关闭 browser 会触发 disconnected 回调，标记避免重复回收
        if self._save_timer_stop:
            self._save_timer_stop.set()
        if self.ctx is not None:
            try:
                # 记录最后页面（下次启动回到这里）
                try:
                    u = self.page.url
                    if u and u.startswith(("http://", "https://")):
                        set_last_url(self.name, u)
                except Exception:
                    pass
                st = self.ctx.storage_state()
                if st:
                    save_storage(self.name, st)
                    self.log(f"[{self.name}] 登录态已保存")
            except Exception:
                pass
        try:
            if self.browser and self.browser.is_connected():
                self.browser.close()
        except Exception:
            pass
        try:
            if self.pw:
                self.pw.stop()
        except Exception:
            pass
        try:
            self.core.stop()
        except Exception:
            pass
        self.pw = self.browser = self.ctx = self.page = None
        self.running = False
        self.ip = None
        self.started_at = None
        self.log(f"[{self.name}] 会话已停止")

    def _do_script(self, js: str, url: str | None = None):
        """在会话线程内执行页面脚本（同会话页面上操作，跨线程安全）"""
        if not self.running or not self.page:
            raise RuntimeError("会话未运行")
        if url:
            self.page.goto(url, wait_until="domcontentloaded")
        return self.page.evaluate(js)

    def _run_automation(self, script_name: str, variables: dict | None = None,
                        humanize: bool = False):
        """在会话线程内执行自动化脚本（Playwright 操作必须在本线程）。

        script_name: scripts/*.json 的名称
        variables:   脚本上下文变量（$var 引用）
        humanize:    拟人行为模拟（点击/输入/滚动走人类曲线）
        """
        if not self.running or not self.page:
            raise RuntimeError("会话未运行，请先启动账号")
        from .fp_automation import load_script, run_script

        script = load_script(script_name)
        ctx = {"worker": self, "vars": dict(variables or {}),
               "log": self.log, "humanize": bool(humanize)}
        result = run_script(self.page, script.get("actions", []), ctx=ctx)
        return {"script": script_name, "ok": result["ok"], "fail": result["fail"],
                "started": result["started"], "ended": result["ended"],
                "vars": result["vars"], "humanize": bool(humanize)}

    # ---------- 操作录制 ----------
    def _start_record(self):
        """开始录制：注入监听脚本到当前页面 + 后续页面"""
        if not self.running or not self.page:
            raise RuntimeError("会话未运行")
        from .fp_recorder import recorder_js

        self._recorded = []
        self._recording = True
        js = recorder_js()
        if self.ctx:
            self.ctx.add_init_script(js)
        try:
            self.page.evaluate(js)
        except Exception:
            pass
        self.log(f"[{self.name}] 开始录制操作（点击/输入/导航/滚动）")
        return {"recording": True}

    def _stop_record(self) -> dict:
        """停止录制并转换为自动化动作"""
        from .fp_recorder import actions_to_script

        self._recording = False
        acts = actions_to_script(self._recorded)
        self.log(f"[{self.name}] 录制结束：{len(acts)} 步动作")
        return {"recording": False, "actions": acts, "count": len(acts)}

    def _do_rotate(self, target: str | None = None) -> dict:
        """换 IP 核心逻辑（仅内核/urllib，不碰 Playwright 对象）

        target: None=随机（信誉优先）；指定节点名=切到该节点（不存在/失败则报错保持原状）。
        bridge 回调与控制台 API 共用；可在会话线程外安全执行。
        """
        if not self.running or not self.core.running:
            return self.status()
        if target is not None:
            if target not in self.core.node_names():
                return {"error": f"节点不存在: {target}"}
            if not self.core.select_node(target):
                self.log(f"[{self.name}] 切换到 {target} 失败，保持原节点")
                return self.status()
            node = target
            # 跨国家切换提示（环境人设固定，时区/语言不随节点变）
            env_cc = get_env_country(self.name)
            if env_cc:
                tgt_cc, _ = reputation_store.node_country(target)
                if tgt_cc and tgt_cc.upper() != env_cc.upper():
                    self.log(f"[{self.name}] 注意: 目标节点在 {tgt_cc}，账号人设为 {env_cc}（时区/语言不变，可能与 IP 不匹配）")
        else:
            preferred = reputation_store.preferred_names(self.core.node_names())
            # 环境人设国家优先：随机换 IP 默认限制在同国节点（时区/语言与 IP 自洽）
            env_cc = get_env_country(self.name)
            if env_cc:
                same_cc = [n for n in reputation_store.same_country_names(
                    self.core.node_names(), env_cc) if n != self.node]
                if same_cc:
                    node = random.choice(same_cc)
                    if not self.core.select_node(node):
                        node = None
            if not env_cc or not node:
                node = self.core.rotate_node(preferred=preferred or None)
            if not node:
                self.log(f"[{self.name}] 换 IP 失败（节点池异常）")
                return self.status()
        self.node = node
        set_bound_node(self.name, node)   # 主动更换即更新档案绑定
        self.log(f"[{self.name}] 已换节点: {node}（刷新页面自动走新 IP）")
        self.ip = self._query_ip()
        if self.ip:
            self.log(f"[{self.name}] 新出口 IP: {self.ip}")
        return self.status()

    def _rotate_ip(self, target: str | None = None):
        """仅换出口 IP：不重启窗口、不动指纹、不动登录态（内核切节点 + 断旧连接）"""
        return self._do_rotate(target)

    def _rotate_fingerprint(self):
        """悬浮窗「换指纹」：记录当前页面 → 停会话（保存登录态）→ 全新指纹 → 重启并回原页面

        回原页面让用户感知连续（旧方案新窗口落在 about:blank，
        叠加 IP 探测慢时窗口迟迟不出，被感知为“点击没反应”）。
        """
        prev_url = None
        try:
            if self.page:
                prev_url = self.page.url
        except Exception:
            prev_url = None
        if not prev_url or prev_url.startswith("about:"):
            prev_url = None
        self._stop()
        fp = reset_fingerprint(self.name)
        self.log(f"[{self.name}] 指纹已更换: {fp.get('name')}（登录态保留）")
        res = self._start()
        if prev_url and self.page:
            try:
                self.page.goto(prev_url, wait_until="domcontentloaded", timeout=30000)
                self.log(f"[{self.name}] 已恢复页面: {prev_url[:60]}")
            except Exception:
                pass
        return res

    def _bridge(self, op: str | None = None, arg: str | None = None):
        """页面悬浮窗桥接（Playwright expose_function）。

        不受页面 CSP / CORS 限制。
        注意：该回调在页面调用线程内直接执行，**不能** submit 回队列
        （若回调在 worker 线程触发，submit 会等自己处理队列 → 自锁死锁）。
        这里只执行纯 Python 逻辑（内核切换 / IP 查询 / 状态读取），
        不触碰 Playwright 浏览器对象，因此跨线程安全。
        ops: status / nodes(节点列表) / ip(随机或指定 arg) / fingerprint(队列投递)
        """
        if op == "status":
            return self.status()
        if op == "record":
            # 录制器回调：纯 Python append，跨线程安全（在页面 IO 线程执行）
            if self._recording and isinstance(arg, dict):
                self._recorded.append(arg)
                if len(self._recorded) > 2000:
                    del self._recorded[:500]
            return {"ok": True}
        if op == "nodes":
            out = []
            for n in self.core.node_names():
                r = reputation_store.get(n) or {}
                out.append({"name": n, "score": r.get("score", -1),
                            "lat": r.get("latency_ms")})
            out.sort(key=lambda x: (-(x["score"] if x["score"] is not None else -1),
                                    x["lat"] if x["lat"] is not None else 99999))
            return {"nodes": out, "current": self.node}
        if op == "ip":
            return self._do_rotate(arg)
        if op == "fingerprint":
            # 换指纹需重启浏览器（Playwright 操作，只能在 worker 线程做）。
            # 回调运行在 playwright IO 线程：只投递队列、立即返回（不等待，
            # 等待会与阻塞中的 worker 互锁）；worker 空闲后取出执行。
            self._q.put(("fingerprint", {}, threading.Event(), {}))
            return {"started": True}
        return {"error": f"未知操作: {op}"}

    def _query_ip(self, timeout_each: int = 4) -> str | None:
        """查询当前出口 IP。

        直接走内置内核代理发 HTTP 请求（浏览器同一条出口链路），不依赖浏览器：
        Playwright 实例已在会话线程运行，同一进程内再启第二个 sync 实例会冲突。
        IP 仅为展示信息：首个源 4s 拿不到即返回 None（不串行拖满三个源——
        换指纹/启动会话等链路曾因此拖 20s+，窗口迟迟不出）。
        """
        import re
        import urllib.request
        proxy = self.core.proxy_url
        if not proxy:
            return None
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        for url in ("http://api.ipify.org", "http://myip.ipip.net", "http://ip.3322.net")[:2]:
            try:
                with opener.open(url, timeout=timeout_each) as r:
                    txt = r.read().decode("utf-8", "ignore")
                m = re.search(r"(\d{1,3}\.){3}\d{1,3}", txt)
                if m:
                    return m.group(0)
            except Exception:
                continue   # 不记日志（高频心跳场景刷屏）
        return None

    @property
    def _nodes(self) -> list[dict]:
        return self._pool

    def status(self) -> dict:
        running = False
        if self.browser:
            try:
                running = self.browser.is_connected()
            except Exception:
                running = False
        if not running and self.running:
            self.running = False
        return {
            "name": self.name,
            "running": running,
            "fp": (self.fp or {}).get("name"),
            "node": self.node,
            "node_score": reputation_store.get_score(self.node) if self.node else None,
            "ip": self.ip,
            "started_at": self.started_at,
            "last_err": self.last_err,
        }


# ============================================================ 控制台管理

LOG_DIR = Path(__file__).resolve().parent / "logs"


class SessionManager:
    """多账号会话调度：档案增删、会话启停、全局节点池、自动轮换"""

    def __init__(self):
        self._lock = threading.Lock()
        self.workers: dict[str, SessionWorker] = {}
        self.nodes: list[dict] = []
        self.port = 8230
        self._log: list[str] = []
        self._log_lock = threading.Lock()
        self.auto = {"enabled": False, "interval_min": 30}
        self._scan_flag = threading.Event()
        self._scan_flag.set()   # set=空闲（未在扫描）；Event 初始未置位，必须显式置位
        self._scan_progress = ""
        threading.Thread(target=self._auto_loop, daemon=True).start()
        # 定时养号/保活调度（任务执行动作绑定到本管理器）
        self.sched = Scheduler(log=self.log)
        self.sched.bind(self._sched_runner)
        self.detect()
        if reputation_store.summary()["count"] == 0:
            self.start_reputation_scan()   # 首次使用自动扫描一次

    # ---------- 定时任务执行 ----------
    def _sched_runner(self, task: dict):
        """定时任务动作：启动目标账号 → 可选换 IP → 可选跑脚本 → 可选停止。

        由 Scheduler 线程调用（后台执行，不阻塞调度循环）。
        """
        names = task.get("accounts") or list(self.workers.keys())
        if not names:
            self.log("[定时] 无目标账号（未指定且无在线会话），跳过")
            return
        for name in names:
            try:
                w = self.workers.get(name)
                if not w or not w.running:
                    self.log(f"[定时] 启动账号 {name}")
                    self.start_session(name)
                    w = self.workers.get(name)
                if not w:
                    continue
                if task.get("rotate_ip"):
                    w.submit("ip")
                    self.log(f"[定时] {name} 已换 IP")
                if task.get("script"):
                    self.log(f"[定时] {name} 执行脚本 {task['script']}")
                    w.submit("automation", script_name=task["script"])
                if task.get("stop_after"):
                    self.stop_session(name)
                    self.log(f"[定时] {name} 已停止")
            except Exception as e:  # noqa: BLE001
                self.log(f"[定时] {name} 执行失败: {e}")

    # ---------- 日志 ----------
    def log(self, msg: str):
        line = time.strftime("%H:%M:%S") + "  " + msg
        with self._log_lock:
            self._log.append(line)
            del self._log[:-200]
            try:   # 落盘（排障用；失败不影响运行）
                LOG_DIR.mkdir(parents=True, exist_ok=True)
                with open(LOG_DIR / ("console-" + datetime.now().strftime("%Y%m%d") + ".log"),
                          "a", encoding="utf-8") as f:
                    f.write(datetime.now().strftime("%Y-%m-%d ") + line + "\n")
            except Exception:
                pass
        print(line)

    # ---------- 全局 ----------
    def detect(self):
        """刷新节点池（内置内核节点来源）"""
        nodes = find_local_nodes()
        with self._lock:
            self.nodes = nodes
        self.log(f"[内核] 节点池刷新: {len(nodes)} 个")
        return {"nodes": len(nodes)}

    def create_account(self, name: str, count: int = 1) -> list[dict]:
        """创建账号档案（支持批量）：全新指纹 + 信誉优先分配节点，逐个启动。

        返回创建结果列表；单个失败不影响其余（同名拦截等业务错误直接抛出）。
        """
        count = max(1, min(10, int(count or 1)))
        with self._lock:
            pool = list(self.nodes)
        created = []
        for i in range(count):
            n = name if count == 1 else f"{name}-{i + 1}"
            node = None
            if pool:
                hi = reputation_store.preferred_names([p["name"] for p in pool])
                node = random.choice(hi or [p["name"] for p in pool])
            prof = create_profile(n, node=node)
            self.log(f"[账号] 创建档案 {n}（指纹 {prof['fp'].get('name')}，绑定节点 {node}）")
            created.append({"name": n, "node": node})
        return created

    # ---------- 节点信誉扫描 ----------
    def start_reputation_scan(self) -> dict:
        """后台扫描全池节点信誉（逐节点切→探 IP→批量分类）。重复调用返回进度。"""
        if not self._scan_flag.is_set():
            return {"scanning": True, "progress": self._scan_progress}
        self._scan_flag.clear()

        def _run():
            try:
                self.log("[信誉] 开始扫描节点池（不影响在线会话）…")
                pool = list(self.nodes) or find_local_nodes()

                def progress(s):
                    self._scan_progress = s

                results = scan_reputation(pool, self.log, progress)
                reputation_store.update(results)
                s = reputation_store.summary()
                d = s["distribution"]
                self.log(f"[信誉] 扫描完成：移动 {d['3']} | 住宅 {d['2']} | "
                         f"数据中心 {d['1']} | 代理标记 {d['0']} | 未知 {d['unknown']}")
            except Exception as e:
                self.log(f"[信誉] 扫描失败: {e}")
            finally:
                self._scan_progress = ""
                self._scan_flag.set()
        threading.Thread(target=_run, daemon=True).start()
        return {"scanning": True, "progress": "0"}

    def node_list(self) -> list[dict]:
        """节点明细（信誉+延迟，按信誉降序/延迟升序）——控制台/悬浮窗选择用"""
        with self._lock:
            pool = [n["name"] for n in self.nodes]
        out = []
        for n in pool:
            r = reputation_store.get(n) or {}
            out.append({"name": n, "score": r.get("score", -1),
                        "lat": r.get("latency_ms")})
        out.sort(key=lambda x: (-(x["score"] if x["score"] is not None else -1),
                                x["lat"] if x["lat"] is not None else 99999))
        return out

    def start_session(self, name: str):
        with self._lock:
            w = self.workers.get(name)
        if not w:
            w = SessionWorker(name, self.nodes, self.log, self.port)
            with self._lock:
                self.workers[name] = w
        w.submit("start")
        return w.status()

    def stop_session(self, name: str):
        with self._lock:
            w = self.workers.get(name)
        if w:
            w.submit("stop", timeout=60)
        return {"ok": True}

    def rotate_ip(self, name: str, target: str | None = None):
        with self._lock:
            w = self.workers.get(name)
        if not w:
            raise RuntimeError(f"会话不存在: {name}")
        return w.submit("ip", target=target)

    def rotate_fingerprint(self, name: str):
        """悬浮窗「换指纹」：停止会话 → 生成全新指纹写入档案 → 重启会话（登录态保留）"""
        with self._lock:
            w = self.workers.get(name)
        if w:
            w.submit("stop", timeout=120)
        fp = reset_fingerprint(name)
        self.log(f"[{name}] 指纹已更换: {fp.get('name')}（登录态保留）")
        return self.start_session(name)

    def delete_account(self, name: str):
        """删除账号（含档案指纹/登录态/会话）。前端已二次确认。"""
        with self._lock:
            w = self.workers.pop(name, None)
        if w:
            w.shutdown()
        delete_profile(name)
        self.log(f"[账号] 已删除: {name}")
        return {"ok": True}

    def status(self) -> dict:
        with self._lock:
            workers = dict(self.workers)   # 锁内拷贝：避免遍历中修改
        sessions = []
        for n, w in workers.items():
            try:
                sessions.append(w.status())
            except Exception:
                sessions.append({"name": n, "running": False})
        return {
            "profiles": list_profiles(),
            "sessions": sessions,
            "nodes": len(self.nodes),
            "auto": dict(self.auto),
            "reputation": {
                "scanning": not self._scan_flag.is_set(),
                "progress": self._scan_progress,
                **reputation_store.summary(),
            },
            "logs": self.logs()[-40:],
        }

    def logs(self) -> list[str]:
        with self._log_lock:
            return list(self._log)

    # ---------- 自动轮换（每会话定时仅换 IP） ----------
    def set_auto(self, enabled: bool, interval_min: int):
        with self._lock:
            self.auto = {"enabled": bool(enabled), "interval_min": max(1, int(interval_min))}
        self.log(f"[自动] 定时换 IP {'开启，间隔 ' + str(self.auto['interval_min']) + ' 分钟' if enabled else '关闭'}")
        return {"ok": True}

    # ---------- 自动化脚本 ----------
    def automation_list(self) -> list[dict]:
        from .fp_automation import list_scripts
        return list_scripts()

    def automation_save(self, name: str, actions: list, desc: str = "") -> dict:
        from .fp_automation import save_script
        save_script(name, {"actions": actions, "desc": desc})
        self.log(f"[自动化] 已保存脚本 {name}（{len(actions)} 步）")
        return {"ok": True}

    def automation_delete(self, name: str) -> dict:
        from .fp_automation import delete_script
        return {"ok": delete_script(name)}

    def run_automation(self, name: str, script_name: str, variables: dict | None = None,
                       humanize: bool = False) -> dict:
        with self._lock:
            w = self.workers.get(name)
        if not w:
            raise RuntimeError(f"会话不存在: {name}（请先启动账号）")
        return w.submit("automation", script_name=script_name, variables=variables,
                        humanize=bool(humanize), timeout=600)

    def start_record(self, name: str) -> dict:
        with self._lock:
            w = self.workers.get(name)
        if not w:
            raise RuntimeError(f"会话不存在: {name}")
        return w.submit("rec_start", timeout=30)

    def stop_record(self, name: str) -> dict:
        with self._lock:
            w = self.workers.get(name)
        if not w:
            raise RuntimeError(f"会话不存在: {name}")
        return w.submit("rec_stop", timeout=60)

    def batch_op(self, op: str, names: list | None = None) -> dict:
        """批量操作：start/stop/ip/fingerprint，names 空=全部在线账号"""
        with self._lock:
            targets = names or list(self.workers.keys())
        done, failed = 0, []
        for n in targets:
            try:
                if op == "start":
                    self.start_session(n)
                elif op == "stop":
                    self.stop_session(n)
                elif op == "ip":
                    self.rotate_ip(n)
                elif op == "fingerprint":
                    self.rotate_fingerprint(n)
                done += 1
            except Exception as e:  # noqa: BLE001
                failed.append(f"{n}: {e}")
        label = {"start": "启动", "stop": "停止", "ip": "换 IP",
                 "fingerprint": "换指纹"}.get(op, op)
        self.log(f"[批量] {label}：{done}/{len(targets)} 成功"
                 + (f"（失败 {failed[:3]}）" if failed else ""))
        return {"ok": True, "op": op, "done": done, "total": len(targets),
                "failed": failed[:5]}

    # ---------- 定时养号 ----------
    def sched_list(self) -> list[dict]:
        from .fp_sched import list_tasks
        return list_tasks()

    def sched_save(self, task: dict) -> dict:
        return {"ok": True, "task": sched_upsert(task)}

    def sched_delete(self, name: str) -> dict:
        return {"ok": sched_delete(name)}

    # ---------- 指纹自检 ----------
    def check_fingerprint(self, profile: str | None = None) -> dict:
        """自检：缺省全部档案/模板；profile 指定时只检该档案"""
        from .fp_check import check_profile, check_template
        from .fp_browser import list_templates
        if profile:
            if profile in [p["name"] for p in list_profiles()]:
                return check_profile(profile)
            if profile in list_templates():
                return check_template(profile)
            raise RuntimeError(f"既不是档案也不是模板: {profile}")
        # 全量：每个档案 + 模板（模板多、耗时，仅取前 3 个模板）
        out = []
        for p in list_profiles()[:5]:
            try:
                out.append(check_profile(p["name"]))
            except Exception as e:  # noqa: BLE001
                out.append({"source": f"档案 {p['name']}", "score": 0, "diffs": [str(e)]})
        for t in list_templates()[:3]:
            try:
                out.append(check_template(t))
            except Exception as e:  # noqa: BLE001
                out.append({"source": f"模板 {t}", "score": 0, "diffs": [str(e)]})
        return {"items": out}

    def _auto_loop(self):
        last = None
        while True:
            time.sleep(3)
            with self._lock:
                a = dict(self.auto)
            if not a["enabled"]:
                last = None          # 关闭后重置：下次开启重新计周期
                continue
            if last is None:
                last = time.time()   # 开启时刻起算，首个周期到点才轮换（不立即换）
                continue
            if time.time() - last < a["interval_min"] * 60:
                continue
            last = time.time()
            with self._lock:
                names = list(self.workers)   # 锁内拷贝，遍历期间不受增删影响
            for name in names:
                try:
                    self.rotate_ip(name)
                except Exception:
                    pass
            self.log("[自动] 已为全部在线会话换 IP")


# ============================================================ HTTP 服务

def make_handler(manager: SessionManager):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, content_type: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            # 浏览器悬浮窗从任意站点页面调用本地 API 需要 CORS
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code: int = 200):
            self._send(code, "application/json; charset=utf-8",
                       json.dumps(obj, ensure_ascii=False).encode("utf-8"))

        def do_OPTIONS(self):
            self._send(204, "text/plain; charset=utf-8", b"")

        def do_GET(self):
            if self.path == "/" or self.path == "/index.html":
                self._send(200, "text/html; charset=utf-8", FRONTEND.encode("utf-8"))
            elif self.path == "/api/status":
                self._json(manager.status())
            elif self.path == "/api/nodes":
                self._json(manager.node_list())
            elif self.path == "/api/automation/list":
                self._json(manager.automation_list())
            elif self.path == "/api/sched/list":
                self._json(manager.sched_list())
            else:
                self._send(404, "text/plain; charset=utf-8", b"not found")

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
            except Exception:
                body = {}
            try:
                if self.path == "/api/profile/create":
                    name = (body.get("name") or "").strip()
                    count = int(body.get("count") or 1)
                    if not name:
                        raise RuntimeError("请输入账号名")
                    created = manager.create_account(name, count)
                    for it in created:            # 逐个启动（串行更稳）
                        manager.start_session(it["name"])
                    self._json({"created": created})
                elif self.path == "/api/session/start":
                    self._json(manager.start_session(body.get("name")))
                elif self.path == "/api/session/stop":
                    self._json(manager.stop_session(body.get("name")))
                elif self.path == "/api/session/ip":
                    self._json(manager.rotate_ip(body.get("name"), body.get("node")))
                elif self.path == "/api/session/fingerprint":
                    self._json(manager.rotate_fingerprint(body.get("name")))
                elif self.path == "/api/session/nav":
                    with manager._lock:
                        w = manager.workers.get(body.get("name"))
                    if not w:
                        raise RuntimeError(f"会话不存在: {body.get('name')}")
                    self._json(w.submit("script", js="location.href", url=body.get("url")))
                elif self.path == "/api/session/eval":
                    with manager._lock:
                        w = manager.workers.get(body.get("name"))
                    if not w:
                        raise RuntimeError(f"会话不存在: {body.get('name')}")
                    self._json({"result": w.submit("script", js=body.get("js"), url=body.get("url"))})
                elif self.path == "/api/session/delete":
                    self._json(manager.delete_account(body.get("name")))
                elif self.path == "/api/reputation/scan":
                    self._json(manager.start_reputation_scan())
                elif self.path == "/api/detect":
                    self._json(manager.detect())
                elif self.path == "/api/auto":
                    self._json(manager.set_auto(bool(body.get("enabled")),
                                                int(body.get("interval_min") or 30)))
                elif self.path == "/api/session/record":
                    name = body.get("name")
                    action = body.get("action") or "stop"
                    if action == "start":
                        self._json(manager.start_record(name))
                    else:
                        self._json(manager.stop_record(name))
                elif self.path == "/api/batch":
                    op = body.get("op") or body.get("action")
                    if op not in ("start", "stop", "ip", "fingerprint"):
                        raise RuntimeError("batch op 仅支持 start/stop/ip/fingerprint")
                    self._json(manager.batch_op(op, body.get("names")))
                elif self.path == "/api/cookie/export":
                    from .fp_cookie import export_cookies
                    self._json({"ok": True,
                                "file": str(export_cookies(body.get("name")))})
                elif self.path == "/api/cookie/import":
                    from .fp_cookie import import_cookies
                    self._json({"ok": import_cookies(body.get("name"),
                                                     body.get("path"))})
                elif self.path == "/api/automation/list":
                    self._json(manager.automation_list())
                elif self.path == "/api/automation/save":
                    name = (body.get("name") or "").strip()
                    actions = body.get("actions") or []
                    if not name or not actions:
                        raise RuntimeError("脚本名与 actions 不能为空")
                    self._json(manager.automation_save(name, actions, body.get("desc") or ""))
                elif self.path == "/api/automation/delete":
                    self._json(manager.automation_delete(body.get("name")))
                elif self.path == "/api/automation/run":
                    name = body.get("name")
                    script = body.get("script")
                    if not name or not script:
                        raise RuntimeError("缺少 name 或 script")
                    self._json(manager.run_automation(name, script,
                                                      body.get("variables") or {},
                                                      bool(body.get("humanize"))))
                elif self.path == "/api/sched/list":
                    self._json(manager.sched_list())
                elif self.path == "/api/sched/save":
                    self._json(manager.sched_save(body))
                elif self.path == "/api/sched/delete":
                    self._json(manager.sched_delete(body.get("name")))
                elif self.path == "/api/check":
                    self._json(manager.check_fingerprint(body.get("profile")))
                else:
                    self._send(404, "text/plain; charset=utf-8", b"not found")
            except Exception as e:  # noqa: BLE001
                self._json({"error": str(e)}, 500)

        def log_message(self, *args):
            pass

    return Handler


# ============================================================ 悬浮窗注入（浏览器窗口内）

def build_overlay(name: str, port: int) -> str:
    """构建注入到浏览器页面的悬浮窗脚本。

    悬浮窗显示当前指纹/节点/IP，支持「换 IP」与「换指纹」（调用本地控制台 API）。
    仅顶层 frame 注入（iframe 内不重复）；固定右下角、可收缩。
    """
    js = r"""
(function () {
  if (window.top !== window) return;
  if (window.__fp_overlay_done) return;
  window.__fp_overlay_done = true;
  try {
    var API = "__API__";
    var NAME = "__NAME__";
    var $ = function (id) { return document.getElementById(id); };
    /* 页面 CSP 常阻止 fetch 到 127.0.0.1（如 x.ai 等严格站点 → “控制台未连接”）。
       优先走 Playwright 桥（window.__fpBridge，不受页面 CSP/CORS 限制），
       旧页面无桥时回退 fetch。 */
    var callApi = function (op, arg) {
      if (typeof window.__fpBridge === 'function') {
        return window.__fpBridge(op, arg).then(function (r) { return r || {}; });
      }
      var url = API + (op === 'status' ? '/api/status' : op === 'nodes' ? '/api/nodes'
        : op === 'ip' ? '/api/session/ip' : '/api/session/fingerprint');
      var body = { name: NAME };
      if (op === 'ip' && arg) body.node = arg;
      var opt = (op === 'status' || op === 'nodes') ? undefined
        : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
      return fetch(url, opt).then(function (r) { return r.json(); });
    };
    var root = document.createElement('div');
    root.id = 'fp-ov-root';
    root.style.cssText = 'position:fixed;right:14px;bottom:14px;z-index:2147483647;' +
      'font-family:system-ui,-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;' +
      'font-size:12px;line-height:1.5;user-select:none;';
    /* 全部用 DOM API 构建：不用 innerHTML（Trusted Types 站点会拦截赋值） */
    var mk = function (tag, style, text, id) {
      var el = document.createElement(tag);
      if (style) el.style.cssText = style;
      if (text != null) el.textContent = text;
      if (id) el.id = id;
      return el;
    };
    var bar = mk('div', 'background:rgba(15,23,42,.92);color:#e5e7eb;border-radius:8px;' +
      'padding:6px 12px;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,.28);' +
      'display:flex;align-items:center;gap:8px;backdrop-filter:blur(4px);');
    bar.appendChild(mk('span', 'color:#60a5fa', '指纹'));
    bar.appendChild(mk('b', 'color:#fff', '-', 'ovFp'));
    bar.appendChild(mk('span', 'color:#475569', '|'));
    bar.appendChild(mk('span', 'color:#60a5fa', 'IP'));
    bar.appendChild(mk('b', 'color:#fff', '-', 'ovIp'));
    bar.appendChild(mk('span', 'color:#94a3b8;margin-left:4px', '▾', 'ovArrow'));
    var body = mk('div', 'display:none;margin-top:6px;background:rgba(255,255,255,.98);' +
      'border:1px solid #dbeafe;border-radius:10px;padding:10px 12px;' +
      'box-shadow:0 6px 20px rgba(0,0,0,.18);min-width:250px;color:#1e293b;');
    var row = function (label, id, gap) {
      var r = mk('div', 'display:flex;justify-content:space-between;margin-bottom:' + (gap || '6px'));
      r.appendChild(mk('span', 'color:#64748b', label));
      r.appendChild(mk('b', '', '-', id));
      return r;
    };
    body.appendChild(row('账号', 'dvName'));
    body.appendChild(row('指纹', 'dvFp2'));
    body.appendChild(row('节点', 'dvNode'));
    body.appendChild(row('出口 IP', 'dvIp2', '6px'));
    /* 选节点：下拉列表（信誉+延迟），变更即切；随机由「换 IP」按钮负责 */
    var selRow = mk('div', 'display:flex;align-items:center;gap:6px;margin-bottom:10px');
    selRow.appendChild(mk('span', 'color:#64748b;white-space:nowrap', '选节点'));
    var sel = document.createElement('select');
    sel.id = 'dvNodeSel';
    sel.style.cssText = 'flex:1;border:1px solid #bfdbfe;border-radius:6px;padding:3px 4px;' +
      'font-size:12px;background:#fff;color:#1e293b;max-width:170px';
    selRow.appendChild(sel);
    body.appendChild(selRow);
    var btns = mk('div', 'display:flex;gap:6px');
    btns.appendChild(mk('button', 'flex:1;border:1px solid #bfdbfe;background:#eff6ff;color:#1d4ed8;' +
      'border-radius:6px;padding:5px 0;cursor:pointer;font-size:12px', '换 IP', 'dvBtnIp'));
    btns.appendChild(mk('button', 'flex:1;border:1px solid #fecaca;background:#fef2f2;color:#dc2626;' +
      'border-radius:6px;padding:5px 0;cursor:pointer;font-size:12px', '换指纹', 'dvBtnFp'));
    body.appendChild(btns);
    body.appendChild(mk('div', 'margin-top:7px;color:#94a3b8;font-size:11px', '连接中...', 'dvMsg'));
    root.appendChild(bar);
    root.appendChild(body);
    /* init script 在文档解析最早期执行（body 尚未就绪）。
       按钮事件必须等 root 挂入 DOM 后再绑定（getElementById 才能取到按钮，
       否则 onclick 赋值为 null.onclick 抛异常被 catch 吞掉，点击无反应）。
       因此：refresh/bindButtons 先定义，挂载成功回调里再绑定按钮 + 首次刷新。 */
    var collapsed = false;
    var refresh = function (quiet) {
      callApi('status').then(function (s) {
        var list = s.sessions || (s && s.name ? [s] : []);
        var it = list.filter(function (x) { return x.name === NAME; })[0] || {};
        var stars = (it.node_score != null && it.node_score >= 0) ? ' ★' + it.node_score : '';
        $('ovFp').textContent = it.fp || '-';
        $('ovIp').textContent = it.ip || '-';
        $('dvName').textContent = it.name || NAME;
        $('dvFp2').textContent = it.fp || '-';
        $('dvNode').textContent = (it.node || '-') + stars;
        $('dvIp2').textContent = it.ip || '-';
        if (!quiet) $('dvMsg').textContent = '已刷新（' + new Date().toLocaleTimeString() + '）';
      }).catch(function () {
        if (!quiet) $('dvMsg').textContent = '控制台未连接';
      });
    };
    var loadNodes = function () {
      callApi('nodes').then(function (r) {
        var s = $('dvNodeSel');
        if (!s || !r || !r.nodes) return;
        while (s.firstChild) s.removeChild(s.firstChild);   /* 纯 DOM 重建，防 Trusted Types */
        var ph = document.createElement('option');
        ph.value = ''; ph.textContent = '── 选择节点 ──';
        s.appendChild(ph);
        r.nodes.forEach(function (n) {
          var o = document.createElement('option');
          o.value = n.name;
          o.textContent = n.name
            + (n.score != null && n.score >= 0 ? ' ★' + n.score : '')
            + (n.lat ? ' (' + n.lat + 'ms)' : '');
          if (n.name === r.current) o.selected = true;
          s.appendChild(o);
        });
      }).catch(function () {});
    };
    var bindButtons = function () {
      bar.onclick = function () {
        collapsed = !collapsed;
        body.style.display = collapsed ? 'none' : 'block';
        $('ovArrow') && ($('ovArrow').textContent = collapsed ? '▸' : '▾');
        if (!collapsed) { refresh(false); loadNodes(); }
      };
      $('dvNodeSel').onchange = function () {
        var v = this.value;
        if (!v) return;
        $('dvMsg').textContent = '正在切换到 ' + v + ' ...';
        callApi('ip', v).then(function (j) {
          if (j.error) { $('dvMsg').textContent = '失败: ' + j.error; return; }
          $('dvMsg').textContent = '已切换节点: ' + (j.node || v) + '（刷新页面生效）';
          refresh(true);
        }).catch(function () { $('dvMsg').textContent = '控制台未连接'; });
      };
      $('dvBtnIp').onclick = function () {
        $('dvMsg').textContent = '正在切换出口 IP（窗口不动）...';
        callApi('ip').then(function (j) {
          if (j.error) { $('dvMsg').textContent = '失败: ' + j.error; return; }
          $('dvMsg').textContent = '已切换节点: ' + (j.node || '-') + '（刷新页面生效）';
          refresh(true);
        })
        .catch(function () { $('dvMsg').textContent = '控制台未连接'; });
      };
      $('dvBtnFp').onclick = function () {
        if (!confirm('将重启当前浏览器窗口并生成全新指纹（登录态保留），确定？')) return;
        $('dvMsg').textContent = '正在更换指纹并重启窗口...';
        callApi('fingerprint').then(function (j) {
          if (j.error) { $('dvMsg').textContent = '失败: ' + j.error; return; }
          $('dvMsg').textContent = '正在更换指纹，新窗口即将打开...';
        }).catch(function () { $('dvMsg').textContent = '控制台未连接'; });
      };
    };
    var _mounted = false;
    var _mount = function () {
      if (_mounted) return;
      var t = document.body || document.documentElement;
      if (t) { t.appendChild(root); _mounted = true; bindButtons(); refresh(true); loadNodes(); }
      else { setTimeout(_mount, 60); }
    };
    _mount();
    setInterval(function () { refresh(true); }, 3000);
  } catch (e) {}
})();
"""
    return js.replace("__API__", f"http://127.0.0.1:{port}").replace("__NAME__", name.replace("\\", "\\\\").replace("'", "\\'"))


# ============================================================ 前端

FRONTEND = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>可换指纹浏览器 · 多账号控制台</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, "PingFang SC", "Microsoft YaHei", "Segoe UI", sans-serif;
    background: linear-gradient(160deg, #f8fbff 0%, #ffffff 50%, #e8f1fd 100%);
    color: #1e293b; padding: 18px;
  }
  h1 { font-size: 20px; margin-bottom: 14px; display: flex; align-items: center; gap: 10px; }
  h2 { font-size: 15px; margin-bottom: 8px; color: #334155; }
  .badge { padding: 2px 10px; border-radius: 999px; font-size: 12px; }
  .badge.on { background: #dcfce7; color: #15803d; }
  .badge.off { background: #fee2e2; color: #b91c1c; }
  .card {
    background: rgba(255,255,255,.85); border: 1px solid #dbeafe; border-radius: 10px;
    padding: 12px 14px; backdrop-filter: blur(6px);
  }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; }
  .row { display: flex; justify-content: space-between; font-size: 13px; padding: 3px 0; }
  .row .k { color: #64748b; }
  .controls { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .btn {
    border: 1px solid #bfdbfe; background: #fff; color: #1d4ed8; border-radius: 7px;
    padding: 5px 12px; font-size: 13px; cursor: pointer;
  }
  .btn:hover { background: #eff6ff; }
  .btn:disabled { opacity: .45; cursor: not-allowed; }
  .btn.primary { background: #2563eb; color: #fff; border-color: #2563eb; }
  .btn.primary:hover { background: #1d4ed8; }
  .btn.danger { color: #dc2626; border-color: #fecaca; }
  .btn.danger:hover { background: #fef2f2; }
  .btn.small { padding: 2px 8px; font-size: 12px; }
  .input { border: 1px solid #bfdbfe; border-radius: 7px; padding: 6px 10px; font-size: 13px; width: 160px; }
  .switch { display: flex; align-items: center; gap: 8px; margin: 6px 0; font-size: 13px; }
  .switch input { width: 16px; height: 16px; accent-color: #3b82f6; }
  .num { width: 64px; border: 1px solid #bfdbfe; border-radius: 6px; padding: 3px 6px; }
  .hint { color: #64748b; font-size: 12px; margin-top: 6px; }
  #logs { font-family: ui-monospace, Consolas, monospace; font-size: 12px; line-height: 1.6;
          background: #0f172a; color: #cbd5e1; border-radius: 8px; padding: 10px 12px;
          max-height: 220px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
  .toast { position: fixed; top: 18px; right: 18px; background: #1e293b; color: #fff;
    padding: 10px 16px; border-radius: 8px; font-size: 13px; display: none; z-index: 99; }
  .sess-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .sess-head .name { font-weight: 600; font-size: 14px; }
  .empty { color: #94a3b8; font-size: 13px; padding: 18px 0; text-align: center; }
  .mt { margin-top: 14px; }
</style>
</head>
<body>
<h1>可换指纹浏览器 · 多账号控制台 <span class="badge" id="bProxy">-</span> <span class="badge" id="bNode">-</span></h1>

<div class="grid">
  <div class="card">
    <h2>新建账号档案</h2>
    <div class="row"><span class="k">说明</span><span class="v">注册时生成全新指纹 + 绑定节点；再次登录完全还原</span></div>
    <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
      <input class="input" id="newName" placeholder="账号名（如 shop01）" style="flex:1">
      <input class="num" type="number" id="newCount" value="1" min="1" max="10" title="批量数量">
      <button class="btn primary" onclick="createAccount()">创建并启动</button>
    </div>
    <div class="hint">批量时自动编号（shop01-1、shop01-2…），最多 10 个</div>
  </div>

    <div class="card">
    <h2>全局状态</h2>
    <div class="row"><span class="k">节点池</span><span class="v" id="gNodes">-</span></div>
    <div class="row"><span class="k">节点信誉</span><span class="v" id="gRep">-</span></div>
    <div class="row"><span class="k">账号档案</span><span class="v" id="gProfiles">-</span></div>
    <div class="row"><span class="k">在线会话</span><span class="v" id="gRunning">-</span></div>
    <div class="controls">
      <button class="btn" onclick="doApi('detect')">重新探测节点</button>
      <button class="btn" onclick="doApi('reputation/scan')">扫描节点信誉</button>
    </div>
    <h2 style="margin-top:12px">批量操作</h2>
    <div class="controls">
      <button class="btn" onclick="batchOp('start')">全部启动</button>
      <button class="btn" onclick="batchOp('stop')">全部停止</button>
      <button class="btn" onclick="batchOp('ip')">全部换 IP</button>
    </div>
    <h2 style="margin-top:12px">定时换 IP</h2>
    <div class="switch">
      <input type="checkbox" id="autoOn" onchange="saveAuto()">
      <span>每</span>
      <input class="num" type="number" id="autoMin" value="30" min="1" onchange="saveAuto()">
      <span>分钟为全部在线账号换 IP</span>
    </div>
  </div>
</div>

<div class="grid mt">
  <div class="card">
    <h2>自动化脚本</h2>
    <div class="hint" style="margin-top:0">账号启动后，在会话卡片上选脚本一键执行（可编排浏览/点击/采集/导出）</div>
    <div id="scriptList"><div class="empty">加载中...</div></div>
    <div class="controls">
      <input class="input" id="scriptName" placeholder="脚本名（如 养号-晚间）" style="flex:1">
      <button class="btn primary" onclick="saveScript()">保存</button>
    </div>
    <div class="hint">脚本为 JSON 动作列表；不填则保存内置养号示例：打开 → 滚动 → 停留 → 保存登录态</div>
    <textarea class="input" id="scriptJson" rows="4" spellcheck="false"
      placeholder='[{"type":"goto","url":"https://x.com/home"},{"type":"wait","ms":3000},{"type":"scroll","to":"bottom"}]'
      style="width:100%;margin-top:8px;font-family:ui-monospace,Consolas,monospace;font-size:12px;resize:vertical"></textarea>
  </div>

  <div class="card">
    <h2>定时养号 / 保活</h2>
    <div id="schedList"><div class="empty">加载中...</div></div>
    <div class="controls" style="align-items:end">
      <input class="input" id="schedName" placeholder="任务名" style="width:110px">
      <select class="input" id="schedType" style="width:90px">
        <option value="daily">每天</option>
        <option value="weekly">每周</option>
        <option value="interval">间隔</option>
      </select>
      <input class="input" id="schedTime" placeholder="09:00" style="width:80px" title="每天/每周的时刻">
      <input class="num" id="schedMin" value="120" title="间隔分钟" style="width:64px">
    </div>
    <div class="controls">
      <input class="input" id="schedAccount" placeholder="账号名（空=全部在线）" style="flex:1">
      <button class="btn primary" onclick="addSched()">新建任务</button>
    </div>
    <div class="switch">
      <label style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="schedRotate"> 执行前换 IP</label>
      <label style="display:flex;align-items:center;gap:6px"><input type="checkbox" id="schedStop" checked> 执行后停止</label>
    </div>
  </div>

  <div class="card">
    <h2>指纹自检</h2>
    <div class="row"><span class="k">说明</span><span class="v">注入一致性 + 环境人设匹配评分（0-100）</span></div>
    <div class="controls">
      <button class="btn primary" onclick="runCheck()">跑全量自检</button>
    </div>
    <div id="checkOut"></div>
  </div>
</div>

<div class="grid mt" id="sessGrid"></div>

<div class="card mt">
  <h2>操作日志</h2>
  <div id="logs"><div>等待操作...</div></div>
</div>

<div class="toast" id="toast"></div>

<script>
let state = null;
let nodeList = [];   /* 节点明细缓存（选节点下拉用） */
let scripts = [];    /* 自动化脚本列表 */
let schedTasks = []; /* 定时任务列表 */
let recording = {};  /* 录制状态（会话名 -> bool） */
function toast(m) { const t = document.getElementById('toast'); t.textContent = m; t.style.display = 'block';
  clearTimeout(t._tm); t._tm = setTimeout(() => t.style.display = 'none', 2200); }
async function api(path, body) {
  const opts = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) };
  const r = await fetch(path, opts); const j = await r.json();
  if (j.error) throw new Error(j.error); return j;
}
async function refresh() {
  try {
    state = await api('/api/status');
    if (!nodeList.length) { try { nodeList = await api('/api/nodes'); } catch (e) {} }
    render();
  } catch (e) {}
}
function esc(s) { return String(s ?? '').replace(/</g, '&lt;'); }

function render() {
  document.getElementById('bProxy').className = 'badge ' + (state.nodes > 0 ? 'on' : 'off');
  document.getElementById('bProxy').textContent = state.nodes > 0 ? '节点池就绪' : '节点池为空';
  document.getElementById('bNode').className = 'badge ' + (state.nodes > 0 ? 'on' : 'off');
  document.getElementById('bNode').textContent = state.nodes + ' 节点';
  document.getElementById('gNodes').textContent = state.nodes + ' 个';
  const rep = state.reputation || {};
  const d = rep.distribution || {};
  document.getElementById('gRep').textContent = rep.scanning
    ? '扫描中 ' + (rep.progress || '0')
    : (rep.count ? `住宅 ${d['2'] || 0} · 移动 ${d['3'] || 0} · 机房 ${d['1'] || 0} · 代理 ${d['0'] || 0}`
       + (rep.avg_latency_ms != null ? ` · 均延 ${rep.avg_latency_ms}ms` : '') : '未扫描');
  document.getElementById('gProfiles').textContent = state.profiles.length + ' 个';
  const running = (state.sessions || []).filter(s => s.running).length;
  document.getElementById('gRunning').textContent = running + ' 个';
  document.getElementById('autoOn').checked = state.auto.enabled;
  document.getElementById('autoMin').value = state.auto.interval_min;

  const grid = document.getElementById('sessGrid');
  const ps = state.profiles || [];
  const ss = state.sessions || [];
  if (!ps.length) { grid.innerHTML = '<div class="card empty">暂无账号档案，先在上方创建</div>'; }
  else {
    grid.innerHTML = ps.map(p => {
      const s = ss.find(x => x.name === p.name) || {};
      const run = !!s.running;
      return '<div class="card"><div class="sess-head"><span class="name">' + esc(p.name) + '</span>'
        + '<span class="badge ' + (run ? 'on' : 'off') + '">' + (run ? '在线' : '已停止') + '</span></div>'
        + '<div class="row"><span class="k">指纹</span><span class="v">' + esc(s.fp || '-') + '</span></div>'
        +         '<div class="row"><span class="k">绑定节点</span><span class="v">' + esc((s.node || p.node || '-') + (s.node_score != null && s.node_score >= 0 ? ' ★' + s.node_score : '')) + '</span></div>'
        + '<div class="row"><span class="k">出口 IP</span><span class="v">' + esc(s.ip || '-') + '</span></div>'
        + '<div class="row"><span class="k">登录态</span><span class="v">' + (p.has_storage ? '已保存' : '无') + '</span></div>'
        + '<div class="row"><span class="k">创建时间</span><span class="v">' + esc(p.created_at || '-') + '</span></div>'
        + '<div class="controls">'
        + (run ? ''
            : '<button class="btn small primary" onclick="act(\'start\',\'' + esc(p.name) + '\')">启动</button>')
        + (run ? '<button class="btn small" onclick="act(\'stop\',\'' + esc(p.name) + '\')">停止</button>'
            + '<button class="btn small" onclick="act(\'ip\',\'' + esc(p.name) + '\')">随机换 IP</button>'
            + '<select class="btn small" style="padding:2px 4px;color:#1d4ed8" onchange="if(this.value){act(\'ip\',\'' + esc(p.name) + '\', this.value); this.value=\'\';}"><option value="">选节点…</option>'
              + nodeList.map(n => '<option value="' + esc(n.name) + '">' + esc(n.name + (n.score >= 0 ? ' ★' + n.score : '') + (n.lat ? ' (' + n.lat + 'ms)' : '')) + '</option>').join('')
              + '</select>'
            + '<select class="btn small" style="padding:2px 4px;color:#1d4ed8;max-width:130px" id="sc_' + esc(p.name) + '"><option value="">运行脚本…</option>'
              + (scripts || []).map(s => '<option value="' + esc(s.name) + '">' + esc(s.name) + '</option>').join('')
              + '</select>'
            + '<button class="btn small primary" onclick="runScriptOn(\'' + esc(p.name) + '\')">执行</button>'
            + '<label style="display:flex;align-items:center;gap:3px;font-size:12px;color:#64748b" title="拟人行为：贝塞尔鼠标曲线/逐字输入/滚动节奏"><input type="checkbox" id="hz_' + esc(p.name) + '" checked style="width:13px;height:13px">拟人</label>'
            + '<button class="btn small" id="rec_' + esc(p.name) + '" style="' + (recording[p.name] ? 'background:#fef2f2;color:#dc2626;border-color:#fecaca' : '') + '" onclick="toggleRecord(\'' + esc(p.name) + '\')">' + (recording[p.name] ? '停止录制' : '录制') + '</button>'
            + '<button class="btn small" onclick="exportCookie(\'' + esc(p.name) + '\')">Cookie</button>'
            : '')
        + '<button class="btn small danger" onclick="del(\'' + esc(p.name) + '\')">删除</button>'
        + '</div></div>';
    }).join('');
  }
  document.getElementById('logs').innerHTML =
    (state.logs || []).map(l => '<div>' + esc(l) + '</div>').join('') || '<div>-</div>';
}

async function createAccount() {
  const name = document.getElementById('newName').value.trim();
  const count = parseInt(document.getElementById('newCount').value) || 1;
  if (!name) { toast('请输入账号名称'); return; }
  try { toast(count > 1 ? `批量创建 ${count} 个并启动中...` : '创建档案并启动中...');
    await api('/api/profile/create', { name, count }); toast('已启动: ' + name + (count > 1 ? ' 等 ' + count + ' 个' : '')); }
  catch (e) { toast('失败: ' + e.message); }
  await refresh();
}
async function act(op, name, node) {
  try {
    if (op === 'start') { toast('启动中（还原指纹+IP+登录态）...'); await api('/api/session/start', { name }); }
    else if (op === 'stop') { toast('停止中（保存登录态）...'); await api('/api/session/stop', { name }); }
    else if (op === 'ip') { toast(node ? '切换到 ' + node + '...' : '随机换 IP（窗口不动）...'); await api('/api/session/ip', { name, node }); }
  } catch (e) { toast('失败: ' + e.message); }
  await refresh();
}
async function del(name) {
  if (!confirm('确定删除账号 ' + name + '？指纹/登录态将一并删除，不可恢复')) return;
  try { await api('/api/session/delete', { name }); toast('已删除: ' + name); } catch (e) { toast('失败: ' + e.message); }
  await refresh();
}
async function doApi(op) { try { await api('/api/' + op, {}); } catch (e) { toast(e.message); } await refresh(); }
async function saveAuto() {
  const enabled = document.getElementById('autoOn').checked;
  const interval_min = parseInt(document.getElementById('autoMin').value) || 30;
  try { await api('/api/auto', { enabled, interval_min }); toast(enabled ? '已开启定时换 IP' : '已关闭'); }
  catch (e) { toast(e.message); }
  await refresh();
}

/* ==================== 自动化脚本 ==================== */
const DEMO_ACTIONS = [
  { type: 'log', message: '开始养号活跃' },
  { type: 'goto', url: 'https://x.com/home' },
  { type: 'wait', ms: 3000 },
  { type: 'scroll', to: 'bottom' },
  { type: 'wait', ms: 2000 },
  { type: 'scroll', to: 'top' },
  { type: 'wait', ms: 1500 },
  { type: 'save_state' },
  { type: 'log', message: '养号完成' }
];
async function refreshScripts() {
  try { scripts = await api('/api/automation/list'); renderScripts(); } catch (e) {}
}
function renderScripts() {
  const el = document.getElementById('scriptList');
  if (!el) return;
  if (!scripts.length) { el.innerHTML = '<div class="empty">暂无脚本，保存一个或后续添加</div>'; return; }
  el.innerHTML = scripts.map(s =>
    '<div class="row"><span class="k" title="' + esc(s.desc) + '">' + esc(s.name)
    + '</span><span><em style="color:#94a3b8;font-style:normal">' + s.actions + ' 步</em> '
    + '<button class="btn small danger" onclick="delScript(\'' + esc(s.name) + '\')">删除</button></span></div>'
  ).join('');
}
async function saveScript() {
  const name = document.getElementById('scriptName').value.trim();
  if (!name) { toast('请输入脚本名'); return; }
  const raw = document.getElementById('scriptJson').value.trim();
  let actions = DEMO_ACTIONS;
  if (raw) {
    try {
      actions = JSON.parse(raw);
      if (!Array.isArray(actions) || !actions.length) throw new Error('empty');
    } catch (e) { toast('JSON 格式错误'); return; }
  }
  try {
    await api('/api/automation/save', {
      name, desc: raw ? '自定义 JSON 脚本' : '养号节奏（示例模板）', actions
    });
    toast('已保存: ' + name);
  } catch (e) { toast('失败: ' + e.message); }
  document.getElementById('scriptName').value = '';
  document.getElementById('scriptJson').value = '';
  await refreshScripts();
}
async function delScript(name) {
  if (!confirm('删除脚本 ' + name + '？')) return;
  try { await api('/api/automation/delete', { name }); toast('已删除'); }
  catch (e) { toast('失败: ' + e.message); }
  await refreshScripts();
}
async function runScriptOn(name) {
  const sel = document.getElementById('sc_' + name);
  if (!sel || !sel.value) { toast('请先选择脚本'); return; }
  const script = sel.value;
  const hzEl = document.getElementById('hz_' + name);
  const hz = hzEl ? hzEl.checked : false;
  toast(name + ' 执行脚本 ' + script + (hz ? '（拟人）' : '') + ' ...');
  try {
    const r = await api('/api/automation/run', { name, script, humanize: hz });
    toast('执行完成: 成功 ' + r.ok + ' 步 / 失败 ' + r.fail + '（' + (r.ended || '') + '）');
  } catch (e) { toast('失败: ' + e.message); }
  await refresh();
}

/* ==================== 操作录制 ==================== */
async function toggleRecord(name) {
  if (recording[name]) {
    try {
      const r = await api('/api/session/record', { name, action: 'stop' });
      recording[name] = false;
      const cnt = r.count || 0;
      if (cnt) {
        const sname = prompt('录制结束，共 ' + cnt + ' 步。保存为脚本名：', name + '-录');
        if (sname && r.actions && r.actions.length) {
          await api('/api/automation/save', { name: sname, desc: '录制生成', actions: r.actions });
          toast('已保存脚本: ' + sname);
          await refreshScripts();
        }
      } else { toast('录制结束（0 步）'); }
    } catch (e) { toast('失败: ' + e.message); }
  } else {
    try {
      await api('/api/session/record', { name, action: 'start' });
      recording[name] = true;
      toast('开始录制：请在浏览器窗口内操作');
    } catch (e) { toast('失败: ' + e.message); }
  }
  await refresh();
}

/* ==================== 批量操作 & Cookie ==================== */
async function batchOp(op) {
  const label = { start: '全部启动', stop: '全部停止', ip: '全部换 IP' }[op] || op;
  if (!confirm('确认执行「' + label + '」？')) return;
  try {
    const r = await api('/api/batch', { op });
    toast(label + '完成: ' + r.done + '/' + r.total + (r.failed && r.failed.length ? '，失败: ' + r.failed.join('; ') : ''));
  } catch (e) { toast('失败: ' + e.message); }
  await refresh();
}
async function exportCookie(name) {
  try {
    const r = await api('/api/cookie/export', { name });
    toast('Cookie 已导出: ' + (r.file || '').split(/[\\/]/).pop());
  } catch (e) { toast('失败: ' + e.message); }
}

/* ==================== 定时养号 ==================== */
async function refreshSched() {
  try { schedTasks = await api('/api/sched/list'); renderSched(); } catch (e) {}
}
function renderSched() {
  const el = document.getElementById('schedList');
  if (!el) return;
  if (!schedTasks.length) { el.innerHTML = '<div class="empty">暂无定时任务，新建一个养号节奏</div>'; return; }
  const wd = ['一', '二', '三', '四', '五', '六', '日'];
  el.innerHTML = schedTasks.map(t => {
    const when = t.type === 'interval' ? '每 ' + (t.interval_min || 60) + ' 分钟'
      : t.type === 'weekly' ? '每周' + wd[(t.weekday || 0)] + ' ' + (t.time || '')
      : t.type === 'once' ? '一次性 ' + (t.time || '')
      : '每天 ' + (t.time || '');
    const extra = (t.rotate_ip ? '换IP ' : '') + (t.script ? '脚本:' + t.script + ' ' : '') + (t.stop_after ? '执行后停止' : '');
    return '<div class="row"><span class="k">' + esc(t.name)
      + ' <span class="badge ' + (t.enabled ? 'on' : 'off') + '">' + (t.enabled ? '启用' : '停用') + '</span></span>'
      + '<span>' + esc(when) + ' <em style="color:#94a3b8;font-style:normal">' + esc(extra) + '</em> '
      + '<button class="btn small" onclick="schedToggle(\'' + esc(t.name) + '\',' + (t.enabled ? 'false' : 'true') + ')">' + (t.enabled ? '停' : '启') + '</button> '
      + '<button class="btn small danger" onclick="schedDel(\'' + esc(t.name) + '\')">删</button></span></div>';
  }).join('');
}
async function schedToggle(name, enabled) {
  try { await api('/api/sched/save', { name, enabled }); toast(enabled ? '已启用' : '已停用'); }
  catch (e) { toast('失败: ' + e.message); }
  await refreshSched();
}
async function schedDel(name) {
  if (!confirm('删除定时任务 ' + name + '？')) return;
  try { await api('/api/sched/delete', { name }); toast('已删除'); }
  catch (e) { toast('失败: ' + e.message); }
  await refreshSched();
}
async function addSched() {
  const name = document.getElementById('schedName').value.trim();
  const type = document.getElementById('schedType').value;
  const time = document.getElementById('schedTime').value.trim();
  const interval_min = parseInt(document.getElementById('schedMin').value) || 120;
  const account = document.getElementById('schedAccount').value.trim();
  const rotate_ip = document.getElementById('schedRotate').checked;
  const stop_after = document.getElementById('schedStop').checked;
  if (!name) { toast('请输入任务名'); return; }
  try {
    await api('/api/sched/save', {
      name, type, time: time || undefined, interval_min,
      accounts: account ? [account] : [],
      rotate_ip, stop_after, enabled: true
    });
    toast('已创建定时任务');
  } catch (e) { toast('失败: ' + e.message); }
  document.getElementById('schedName').value = '';
  await refreshSched();
}

/* ==================== 指纹自检 ==================== */
async function runCheck() {
  const el = document.getElementById('checkOut');
  if (!el) return;
  el.innerHTML = '<div class="hint">检查中（每个指纹需启动两次浏览器，请稍候）...</div>';
  try {
    const r = await api('/api/check', {});
    const items = r.items || [];
    el.innerHTML = items.map(it =>
      '<div class="row"><span class="k">' + esc(it.source) + '</span>'
      + '<span style="color:' + (it.score >= 90 ? '#16a34a' : it.score >= 60 ? '#d97706' : '#dc2626')
      + '"><b>' + it.score + '</b> 分</span></div>'
      + (it.diffs || []).slice(0, 3).map(d => '<div class="hint" style="margin:1px 0 1px 12px">· ' + esc(d) + '</div>').join('')
    ).join('') || '<div class="empty">无结果</div>';
  } catch (e) {
    el.innerHTML = '<div class="hint">自检失败: ' + esc(e.message) + '</div>';
  }
}

refresh();
refreshScripts();
refreshSched();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser(description="可换指纹浏览器多账号控制台")
    parser.add_argument("--port", type=int, default=8230)
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args()

    manager = SessionManager()
    manager.port = args.port
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(manager))
    except OSError as e:
        print(f"[错误] 端口 {args.port} 被占用（{e}）。请换端口启动：")
        print(f"       python -m fingerprint_browser.fp_app --port {args.port + 1}")
        return
    url = f"http://127.0.0.1:{args.port}"
    print(f"控制台已启动: {url}  （Ctrl+C 退出）")
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("正在退出...")
    finally:
        for w in list(manager.workers.values()):
            try:
                w.shutdown()
            except Exception:
                pass


if __name__ == "__main__":
    main()