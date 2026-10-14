"""Cookie / 登录态导入导出工具

把账号档案的登录态导出为标准 Netscape 格式（可导入 curl/浏览器扩展/其他工具），
或从外部导入 Cookie（Netscape / JSON）写回档案（登录时自动还原）。

用法（代码集成）:
    from fingerprint_browser.fp_cookie import export_cookies, import_cookies
    path = export_cookies("shop01")            # 导出 Netscape 格式到 exports/
    ok = import_cookies("shop01", "cookies.txt")

命令行:
    python -m fingerprint_browser.fp_cookie --export shop01
    python -m fingerprint_browser.fp_cookie --import shop01 --file cookies.txt
"""
from __future__ import annotations

import json
from pathlib import Path

from .fp_profile import load_storage, save_storage
from .fp_scrape import _ensure_exports


def export_cookies(name: str, path: Path | None = None) -> Path:
    """把账号档案登录态导出为 Netscape cookies.txt（也可附带 localStorage）。

    返回导出文件路径（缺省 exports/<name>-cookies.txt）。
    """
    st = load_storage(name)
    if not st:
        raise FileNotFoundError(f"档案 {name} 无登录态（未登录或从未保存）")
    cookies = st.get("cookies") or []
    if not cookies:
        raise FileNotFoundError(f"档案 {name} 的 storage 里没有 cookie")

    p = path or (_ensure_exports() / f"{name}-cookies.txt")
    lines = ["# Netscape HTTP Cookie File",
             "# 由 fingerprint_browser 导出，可用于其他工具导入"]
    for c in cookies:
        dom = (c.get("domain") or "").lstrip(".")
        flag = "TRUE" if (c.get("secure") and "https" in str(c.get("url", ""))) else "FALSE"
        # secure 按 cookie 自身标志
        secure = "TRUE" if c.get("secure") else "FALSE"
        path_str = c.get("path") or "/"
        expires = int(c.get("expires", 0))
        key = c.get("name") or ""
        val = c.get("value") or ""
        lines.append("\t".join([dom, flag, path_str, secure, str(expires), key, val]))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _parse_netscape(text: str) -> list[dict]:
    cookies = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, _, path, secure, expires, key, val = parts[:7]
        cookies.append({
            "name": key, "value": val, "domain": domain, "path": path,
            "secure": secure.lower() == "true",
            "expires": float(expires) if expires.isdigit() else -1,
        })
    return cookies


def _parse_json_file(path: Path) -> list[dict]:
    data = json.loads(path.read_text("utf-8"))
    cookies = data.get("cookies") or data.get("cookie") or data
    if isinstance(cookies, dict):
        cookies = [{"name": k, "value": v} for k, v in cookies.items()]
    out = []
    for c in cookies:
        out.append({
            "name": c.get("name") or c.get("key") or "",
            "value": c.get("value") or "",
            "domain": c.get("domain") or "",
            "path": c.get("path") or "/",
            "secure": bool(c.get("secure")),
            "expires": float(c.get("expires") or 0) or -1,
        })
    return out


def import_cookies(name: str, path: str | None) -> bool:
    """从文件导入 Cookie 并合并到档案登录态。

    path: cookies.txt（Netscape）或 cookies.json（Playwright storage_state / 键值对）。
    返回是否写入成功。
    """
    if not path:
        raise ValueError("缺少文件路径")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    text = p.read_text("utf-8", errors="ignore")
    cookies = _parse_netscape(text) if p.suffix.lower() in (".txt",) else _parse_json_file(p)
    # JSON 文件如果含 cookies 数组则用 JSON 解析（storage_state 形态）
    if not cookies and p.suffix.lower() == ".json":
        cookies = _parse_netscape("") or _parse_json_file(p)
    if not cookies:
        raise ValueError("文件中未解析出 cookie")

    st = load_storage(name) or {}
    existing = st.get("cookies") or []
    merged: list = []
    for c in existing:
        if not any(c.get("name") == n and c.get("domain") == d
                   for n, d in [(x["name"], x["domain"]) for x in cookies]):
            merged.append(c)
    merged.extend(cookies)
    st["cookies"] = merged
    save_storage(name, st)
    return True


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Cookie 导入导出")
    parser.add_argument("--export", metavar="NAME", help="导出账号 cookie")
    parser.add_argument("--import", dest="imp", metavar="NAME", help="导入账号 cookie")
    parser.add_argument("--file", metavar="PATH", help="导入文件路径")
    args = parser.parse_args()

    if args.export:
        p = export_cookies(args.export)
        print(f"已导出: {p}")
    elif args.imp:
        if not args.file:
            print("请指定 --file 文件路径")
            return
        ok = import_cookies(args.imp, args.file)
        print(f"导入 {'成功' if ok else '失败'}: {args.imp}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()