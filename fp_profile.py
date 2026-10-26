"""账号档案管理：指纹 / 绑定节点 / 登录态（storage）按账号持久化

核心需求：注册或登录必须是"全新指纹 + 换 IP"，且同一账号再次登录时
完全还原（同指纹 + 同节点 + 同登录态），每个账号彼此隔离。

档案目录结构（profiles/<name>/）：
  fingerprint.json   完整指纹（首次注册时全新生成，此后固定复用）
  meta.json          绑定节点、创建时间、更新历史
  storage.json       Playwright storage_state（cookie + localStorage）

用法：
    from fingerprint_browser.fp_profile import create_profile, load_profile, save_storage, ...
    p = create_profile("shop01")                    # 全新指纹 + 绑定随机节点
    p, meta = load_profile("shop01")                # 再次登录：还原同一指纹
    save_storage("shop01", ctx.storage_state())     # 登录后保存登录态
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .fp_browser import load
from .fp_gen import random_fingerprint
from . import fp_secret

PROFILES_DIR = Path(__file__).resolve().parent.parent / "profiles"

# 档案名安全校验：字母数字下划线短横线，避免路径穿越
_NAME_RE = re.compile(r"^[A-Za-z0-9_\-\u4e00-\u9fff]{1,32}$")


def profiles_root() -> Path:
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    return PROFILES_DIR


def _dir(name: str) -> Path:
    if not _NAME_RE.match(name):
        raise ValueError("档案名仅支持字母/数字/下划线/短横线/中文（1-32 字符）")
    d = PROFILES_DIR / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_profiles() -> list[dict]:
    """列出所有档案及元信息（不含指纹明文细节）"""
    out = []
    if not PROFILES_DIR.exists():
        return out
    for d in sorted(PROFILES_DIR.iterdir()):
        if not d.is_dir():
            continue
        meta_path = d / "meta.json"
        fp_path = d / "fingerprint.json"
        meta = {}
        try:
            meta = json.loads(meta_path.read_text("utf-8"))
        except Exception:
            pass
        out.append({
            "name": d.name,
            "node": meta.get("node"),
            "email": meta.get("email", ""),
            "username": meta.get("username", ""),
            "tags": meta.get("tags", []),
            "notes": meta.get("notes", ""),
            "created_at": meta.get("created_at"),
            "updated_at": meta.get("updated_at"),
            "has_storage": (d / "storage.json").exists(),
            "has_fingerprint": fp_path.exists(),
            "profile_dir": str(d),
        })
    return out


_SAFE_FIELDS = ("email", "username", "tags", "notes", "login_selector",
                "logged_in_selector", "env_country")


def update_profile(name: str, *, email: str | None = None, username: str | None = None,
                   password: str | None = None, tags: list | None = None,
                   notes: str | None = None, login_selector: str | None = None,
                   logged_in_selector: str | None = None,
                   set_bound_node: str | None = None) -> dict:
    """更新档案业务字段（邮箱/用户名/密码/标签/备注/登录检测选择器）。

    password 经 fp_secret 加密落盘；其余字段明文存 meta.json。
    传 None 表示不修改该字段；登录检测：login_selector 命中=已退出/需登录，
    logged_in_selector 命中=仍在登录态。
    """
    d = _dir(name)
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    for field, val in (("email", email), ("username", username),
                       ("notes", notes), ("login_selector", login_selector),
                       ("logged_in_selector", logged_in_selector),
                       ("set_bound_node", set_bound_node)):
        if val is not None:
            if field == "set_bound_node":
                meta["node"] = val
            else:
                meta[field] = val
    if tags is not None:
        meta["tags"] = [str(t) for t in tags if str(t).strip()][:20]
    if password is not None:
        if password:
            meta["password_enc"] = fp_secret.encrypt(password)
            meta["has_password"] = True
        else:
            # 显式传空 = 清除已存密码
            meta.pop("password_enc", None)
            meta.pop("has_password", None)
    meta["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def profile_full(name: str) -> dict:
    """返回档案完整元信息，含解密后的密码（仅控制台/用户侧展示用）。"""
    d = _dir(name)
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    meta["password"] = fp_secret.decrypt(meta.get("password_enc")) if meta.get("password_enc") else None
    meta.pop("password_enc", None)
    return {"name": name, "meta": meta}


def create_profile(name: str, node: str | None = None) -> dict:
    """创建账号档案：全新随机指纹 + 绑定节点（缺省随机池中指定）。

    node 由调用方传入（控制台从节点池挑选），首次创建后固定绑定。
    同名档案已存在时抛错（防误操作覆盖既有指纹/登录态）。
    """
    if not _NAME_RE.match(name):
        raise ValueError("档案名仅支持字母/数字/下划线/短横线/中文（1-32 字符）")
    d = PROFILES_DIR / name
    if (d / "fingerprint.json").exists():
        raise FileExistsError(f"档案已存在: {name}（如需重置请用「换指纹」或先删除）")
    d = _dir(name)
    fp = random_fingerprint()
    (d / "fingerprint.json").write_text(
        json.dumps(fp, ensure_ascii=False, indent=2), encoding="utf-8")
    meta = {
        "name": name,
        "node": node,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"name": name, "fp": fp, "node": node}


def load_profile(name: str) -> dict:
    """读取档案指纹与元信息（用于还原启动）"""
    d = _dir(name)
    fp_path = d / "fingerprint.json"
    if not fp_path.exists():
        raise FileNotFoundError(f"档案不存在或指纹缺失: {name}")
    fp = json.loads(fp_path.read_text("utf-8"))
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    return {"name": name, "fp": fp, "meta": meta}


def reset_fingerprint(name: str) -> dict:
    """为既有档案生成全新指纹（悬浮窗「换指纹」入口）。登录态档案不变。"""
    d = _dir(name)
    fp = random_fingerprint()
    (d / "fingerprint.json").write_text(
        json.dumps(fp, ensure_ascii=False, indent=2), encoding="utf-8")
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    meta["fingerprint_reset_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return fp


def set_bound_node(name: str, node: str | None):
    """更新档案绑定节点（订阅变更、绑定节点失效时回写）"""
    d = _dir(name)
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    meta["node"] = node
    meta["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def get_env_country(name: str) -> str | None:
    """读档案环境人设国家码（meta.env_country）"""
    try:
        meta = json.loads((PROFILES_DIR / name / "meta.json").read_text("utf-8"))
        return meta.get("env_country")
    except Exception:
        return None


def get_last_url(name: str) -> str | None:
    """读档案上次访问页面（启动时自动回去，像浏览器“继续上次会话”）"""
    try:
        meta = json.loads((PROFILES_DIR / name / "meta.json").read_text("utf-8"))
        u = meta.get("last_url")
        if u and str(u).startswith(("http://", "https://")):
            return str(u)
    except Exception:
        pass
    return None


def set_last_url(name: str, url: str | None):
    """写档案上次访问页面（None/非 http 不写入）"""
    if not (url and str(url).startswith(("http://", "https://"))):
        return
    d = _dir(name)
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    if meta.get("last_url") == url:
        return   # 未变不写盘
    meta["last_url"] = str(url)[:500]
    meta["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def set_env_country(name: str, country: str | None):
    """写档案环境人设国家码（None=删除，回退中国默认人设）"""
    d = _dir(name)
    meta = {}
    try:
        meta = json.loads((d / "meta.json").read_text("utf-8"))
    except Exception:
        pass
    if country:
        meta["env_country"] = country
    else:
        meta.pop("env_country", None)
    meta["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    (d / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def save_storage(name: str, storage: dict | None):
    """保存登录态（cookie + localStorage）。storage 为空/异常时不落盘。"""
    if not storage:
        return
    d = _dir(name)
    (d / "storage.json").write_text(
        json.dumps(storage, ensure_ascii=False), encoding="utf-8")


def load_storage(name: str) -> dict | None:
    d = _dir(name)
    p = d / "storage.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text("utf-8"))
    except Exception:
        return None


def delete_profile(name: str):
    """删除档案（含指纹/登录态）。确认后由控制层调用。"""
    d = PROFILES_DIR / name
    if d.exists() and d.is_dir():
        for f in d.iterdir():
            if f.is_file():
                f.unlink()
        d.rmdir()