"""定时养号 / 保活调度

按计划自动执行"养号节奏"：到点启动账号会话 → 可选换 IP →
运行自动化脚本（浏览/停留/操作）→ 可选停止，让账号像真人一样定期活跃。

任务类型:
  daily     每天固定时刻（time: "10:30"）
  weekly    每周某天固定时刻（weekday: 0=周一 .. 6=周日）
  interval  每隔 N 分钟（interval_min: 120）
  once      一次性（time: "YYYY-MM-DD HH:MM"）

任务字段:
  name        任务名（唯一）
  enabled     启用开关
  accounts    目标账号列表（[] = 全部在线账号）
  script      执行自动化脚本名（scripts/*.json，可空）
  rotate_ip   执行前是否换 IP
  stop_after  执行后是否停止会话
  last_run    上次执行时间（内部维护）

持久化: schedules.json（模块同级）
"""
from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

SCHEDULES_FILE = Path(__file__).resolve().parent / "schedules.json"

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff]{1,32}$")


def _load() -> list[dict]:
    if not SCHEDULES_FILE.exists():
        return []
    try:
        return json.loads(SCHEDULES_FILE.read_text("utf-8"))
    except Exception:  # noqa: BLE001
        return []


def _save(tasks: list):
    SCHEDULES_FILE.write_text(
        json.dumps(tasks, ensure_ascii=False, indent=2), encoding="utf-8")


def list_tasks() -> list[dict]:
    return _load()


def _next_due(task: dict, now: datetime) -> datetime | None:
    """计算任务下一次应执行的时间（None=不启用/不排期）"""
    if not task.get("enabled"):
        return None
    t = task.get("type")
    try:
        if t == "once":
            due = datetime.strptime(task.get("time") or "", "%Y-%m-%d %H:%M")
            last = task.get("last_run")
            if last and datetime.fromisoformat(last) >= due:
                return None  # 一次性已跑过
            return due
        if t in ("daily", "weekly"):
            hh, mm = (task.get("time") or "10:00").split(":")
            hh, mm = int(hh), int(mm)
            if t == "daily":
                due = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if due <= now:
                    due += timedelta(days=1)
            else:
                wd = int(task.get("weekday") or 0)
                days_ahead = (wd - now.weekday()) % 7
                due = (now + timedelta(days=days_ahead)).replace(
                    hour=hh, minute=mm, second=0, microsecond=0)
                if due <= now:
                    due += timedelta(days=7)
            last = task.get("last_run")
            if last and datetime.fromisoformat(last) >= due:
                return None
            return due
        if t == "interval":
            mins = max(1, int(task.get("interval_min") or 60))
            last = task.get("last_run")
            if not last:
                return now + timedelta(minutes=1)  # 首次启用后 1 分钟首跑
            return datetime.fromisoformat(last) + timedelta(minutes=mins)
    except Exception:  # noqa: BLE001
        return None
    return None


def upsert(task: dict) -> dict:
    """新增/更新任务（同名校验）。返回保存后的任务。"""
    name = (task.get("name") or "").strip()
    if not _NAME_RE.match(name):
        raise ValueError("任务名仅支持字母/数字/下划线/短横线/中文（1-32 字符）")
    t = task.get("type")
    if t not in ("daily", "weekly", "interval", "once"):
        raise ValueError("type 仅支持 daily/weekly/interval/once")
    tasks = _load()
    tasks = [x for x in tasks if x.get("name") != name]
    body = {
        "name": name,
        "enabled": bool(task.get("enabled", True)),
        "type": t,
        "time": task.get("time"),
        "weekday": int(task.get("weekday") or 0),
        "interval_min": int(task.get("interval_min") or 60),
        "accounts": list(task.get("accounts") or []),
        "script": task.get("script"),
        "rotate_ip": bool(task.get("rotate_ip")),
        "stop_after": bool(task.get("stop_after")),
        "last_run": task.get("last_run"),
    }
    tasks.append(body)
    _save(tasks)
    return body


def delete_task(name: str) -> bool:
    tasks = _load()
    new = [x for x in tasks if x.get("name") != name]
    if len(new) == len(tasks):
        return False
    _save(new)
    return True


class Scheduler:
    """调度线程：周期检查到期任务并在后台执行。

    与 SessionManager 解耦：执行回调由外部注入（控制台装配）。
    """

    def __init__(self, log=lambda m: None):
        self.log = log
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._running: dict[str, threading.Thread] = {}
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    # ---------- 装配（由控制台注入执行能力） ----------
    def bind(self, runner: callable):
        """runner(task) 由外部提供：真正执行任务的函数（线程内调用）。"""
        self._runner = runner

    def shutdown(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(15):
            try:
                tasks = _load()
            except Exception:  # noqa: BLE001
                continue
            now = datetime.now()
            for task in tasks:
                if task.get("name") in self._running:
                    continue   # 上一次还没跑完
                due = _next_due(task, now)
                if due is None or due > now:
                    continue
                self._trigger(task)

    def _trigger(self, task: dict):
        name = task["name"]
        with self._lock:
            if name in self._running:
                return
            t = threading.Thread(target=self._run, args=(task,), daemon=True)
            self._running[name] = t
            t.start()

    def _run(self, task: dict):
        name = task["name"]
        self.log(f"[定时] 任务「{name}」开始执行")
        try:
            # 回写 last_run（先用当前时间，避免执行期间重复触发）
            self._mark(name)
            runner = getattr(self, "_runner", None)
            if runner:
                runner(task)
            self.log(f"[定时] 任务「{name}」执行完成")
        except Exception as e:  # noqa: BLE001
            self.log(f"[定时] 任务「{name}」执行失败: {e}")
        finally:
            with self._lock:
                self._running.pop(name, None)

    def _mark(self, name: str):
        tasks = _load_tasks()
        for t in tasks:
            if t.get("name") == name:
                t["last_run"] = datetime.now().isoformat(timespec="seconds")
        _save(tasks)


_load_tasks = _load   # Scheduler 内部别名


def demo_task() -> dict:
    return {
        "name": "每日养号",
        "enabled": False,
        "type": "daily",
        "time": "09:00",
        "accounts": [],
        "script": "养号-每日活跃",
        "rotate_ip": False,
        "stop_after": True,
    }


if __name__ == "__main__":
    print(json.dumps(list_tasks(), ensure_ascii=False, indent=2))