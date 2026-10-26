"""采集数据入库：SQLite 存储 + 去重 + 在线导出/Webhook 推送

自动化脚本动作 db_save 将抽取的数据写库；export 可推送到 webhook。
去重按 (source, keys_hash) 唯一 —— keys_hash 由 dedup_keys 字段拼接 MD5，
相同来源+相同关键字段的重复记录只入库一次（增量采集/轮询限流友好）。

DB: <project>/exports/collection.db（WAL 模式，支持并发读写）。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from .fp_http import post

DB_PATH = Path(__file__).resolve().parent.parent / "exports" / "collection.db"
_WEBHOOK_CONFIG = Path(__file__).resolve().parent.parent / "config" / "webhook.json"
_LOCK = threading.Lock()


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(DB_PATH))
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("""CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        record TEXT NOT NULL,
        keys_hash TEXT NOT NULL,
        created_at TEXT
    )""")
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_items ON items(source, keys_hash)")
    return c


def _hash(record: dict, keys: list[str] | None) -> str:
    part = [str(record.get(k)) for k in (keys or list(record.keys()))]
    return hashlib.md5("|".join(part).encode("utf-8")).hexdigest()


def save_items(source: str, records: list[dict], *,
               dedup_keys: list[str] | None = None) -> dict:
    """批量入库，按 (source, keys_hash) 去重。返回 {inserted, skipped}。"""
    if not source or not records:
        return {"inserted": 0, "skipped": 0}
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    inserted = skipped = 0
    with _LOCK:
        c = _conn()
        try:
            for rec in records:
                h = _hash(rec, dedup_keys)
                try:
                    before = c.total_changes
                    c.execute(
                        "INSERT OR IGNORE INTO items(source, record, keys_hash, created_at) VALUES(?,?,?,?)",
                        (source, json.dumps(rec, ensure_ascii=False), h, now))
                    if c.total_changes > before:
                        inserted += 1
                    else:
                        skipped += 1
                except Exception:  # noqa: BLE001
                    skipped += 1
            c.commit()
        finally:
            c.close()
    return {"inserted": inserted, "skipped": skipped}


def query(source: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
    with _LOCK:
        c = _conn()
        try:
            if source:
                rows = c.execute(
                    "SELECT id, source, record, created_at FROM items WHERE source=? ORDER BY id DESC LIMIT ? OFFSET ?",
                    (source, limit, offset)).fetchall()
            else:
                rows = c.execute(
                    "SELECT id, source, record, created_at FROM items ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset)).fetchall()
            return [{"id": r[0], "source": r[1],
                     "record": json.loads(r[2]), "created_at": r[3]} for r in rows]
        finally:
            c.close()


def stats() -> dict:
    with _LOCK:
        c = _conn()
        try:
            total = c.execute("SELECT COUNT(*) FROM items").fetchone()[0]
            by_source = dict(c.execute(
                "SELECT source, COUNT(*) FROM items GROUP BY source").fetchall())
            return {"total": total, "by_source": by_source}
        finally:
            c.close()


def webhook_config() -> dict:
    cfg = {}
    if _WEBHOOK_CONFIG.exists():
        try:
            cfg = json.loads(_WEBHOOK_CONFIG.read_text("utf-8"))
        except Exception:  # noqa: BLE001
            cfg = {}
    return cfg


def set_webhook(url: str | None) -> dict:
    cfg = webhook_config()
    if url:
        cfg["url"] = url
    else:
        cfg.pop("url", None)
    _WEBHOOK_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    _WEBHOOK_CONFIG.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")
    return cfg


def push_webhook(records: list[dict]) -> bool:
    """把记录推送配置的 webhook。webhook 目标不可达/失败不向上抛（静默），
    避免采集主流程（db_save/export）被一个离线的 webhook 中断。"""
    cfg = webhook_config()
    url = cfg.get("url")
    if not url or not records:
        return False
    try:
        payload = {"items": records,
                   "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        headers = {"Authorization": f"Bearer {cfg['token']}"} if cfg.get("token") else None
        r = post(url, json=payload, headers=headers,
                 timeout=int(cfg.get("timeout") or 10))
        return bool(getattr(r, "status_code", 200) and 200 <= r.status_code < 300)
    except Exception:  # noqa: BLE001
        return False


def clear(source: str | None = None):
    with _LOCK:
        c = _conn()
        try:
            if source:
                c.execute("DELETE FROM items WHERE source=?", (source,))
            else:
                c.execute("DELETE FROM items")
            c.commit()
        finally:
            c.close()


if __name__ == "__main__":
    print("stats:", stats())
    r = save_items("demo", [{"a": 1}, {"a": 1}, {"a": 2}], dedup_keys=["a"])
    print("save:", r)
    print("query:", query("demo", limit=10))
    print("stats:", stats())
    clear("demo")
    print("after clear:", stats())
