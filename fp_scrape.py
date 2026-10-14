"""数据采集与导出模块

从页面按规则抽取结构化数据（CSS 选择器 / JS 表达式 / 预置类型），
导出 JSON / CSV / XLSX（openpyxl 可用时）到 exports/ 目录。

用法（代码集成）:
    from fingerprint_browser.fp_scrape import extract_rules, export_items
    items = extract_rules(page, [
        {"name": "title", "css": "h1", "attr": "text"},
        {"name": "links", "css": "a.card", "attr": "href", "many": True},
    ])
    path = export_items(items, fmt="xlsx", title="采集结果")

命令行:
    python -m fingerprint_browser.fp_scrape --demo          # 生成示例规则
"""
from __future__ import annotations

import csv
import json
import re
import time
from datetime import datetime
from pathlib import Path

EXPORTS_DIR = Path(__file__).resolve().parent.parent / "exports"

# 动作类型对应的脚本键（fp_automation 里 rules 的复用入口）
_EXTRACT_RULES = (
    # 一条 CSS 匹配多个元素时（many=true）逐项取值；many=false 只取第一个
    "() => {"
    "  const pick = (el, attr) => {"
    "    if (attr === 'text') return (el.innerText || '').trim();"
    "    if (attr === 'href') return el.getAttribute('href');"
    "    if (attr === 'src') return el.getAttribute('src');"
    "    if (attr === 'html') return el.outerHTML;"
    "    return el.getAttribute(attr) || '';"
    "  };"
    "  const rows = [];"
    "  const sel = '__SEL__';"
    "  const many = __MANY__;"
    "  const attr = '__ATTR__';"
    "  const els = document.querySelectorAll(sel);"
    "  if (!els.length) return [];"
    "  const list = many ? Array.from(els) : [els[0]];"
    "  for (const el of list) rows.push(pick(el, attr));"
    "  return rows;"
    "}"
)


def _ensure_exports() -> Path:
    EXPORTS_DIR.mkdir(parents=True, exist_ok=True)
    return EXPORTS_DIR


def extract_rules(page, rules: list[dict]) -> dict:
    """按规则列表抽取单页数据。

    rules 每项:
      {"name": "标题", "css": "h1", "attr": "text", "many": false}
      {"name": "链接", "css": "a", "attr": "href", "many": true}
      {"name": "价格", "js": "() => document.querySelector('.price')?.innerText"}
      {"name": "整页文本", "css": "body", "attr": "text"}
    返回 {规则名: 值或值列表}。
    """
    out: dict = {}
    for rule in rules or []:
        name = rule.get("name") or "field"
        try:
            if rule.get("js"):
                val = page.evaluate(rule["js"])
            else:
                css = rule.get("css")
                if not css:
                    continue
                attr = rule.get("attr", "text")
                many = bool(rule.get("many"))
                js = (_EXTRACT_RULES
                      .replace("__SEL__", css.replace("\\", "\\\\").replace("'", "\\'"))
                      .replace("__MANY__", "true" if many else "false")
                      .replace("__ATTR__", attr))
                val = page.evaluate(js)
                if not many and isinstance(val, list):
                    val = val[0] if val else None
            out[name] = val
        except Exception as e:  # noqa: BLE001
            out[name] = {"__error__": str(e)[:120]}
    return out


def extract_table(page, selector: str, header_map: dict | None = None) -> list[dict]:
    """抽取 HTML 表格为行字典列表。

    selector: table 的 CSS 选择器
    header_map: {列名: 数据列名}；缺省时按表头文本自动命名。
    """
    js = r"""() => {
      const rows = [];
      const table = document.querySelector('__SEL__');
      if (!table) return rows;
      const trs = table.querySelectorAll('tr');
      for (const tr of trs) {
        const cells = Array.from(tr.querySelectorAll('th,td')).map(c => (c.innerText || '').trim());
        if (cells.length) rows.push(cells);
      }
      return rows;
    }
    """
    js = js.replace("__SEL__", selector.replace("\\", "\\\\").replace("'", "\\'"))
    raw = page.evaluate(js)
    if not raw:
        return []
    header = raw[0]
    cols = header if header else [f"col{i}" for i in range(len(raw[1]))]
    items = []
    for row in raw[1:]:
        item = {}
        for i, col in enumerate(cols):
            key = (header_map or {}).get(col, col)
            item[key] = row[i] if i < len(row) else ""
        items.append(item)
    return items


def export_items(items: list[dict], title: str = "export", fmt: str = "xlsx") -> Path:
    """把抽取结果导出到 exports/ 目录（自动时间戳文件名）。

    fmt: json / csv / xlsx / md（markdown 表格）。
    返回导出的文件路径。xlsx 需 openpyxl（缺失自动回退 csv）。
    """
    d = _ensure_exports()
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^\w\u4e00-\u9fff-]", "_", title)[:40] or "export"
    base = d / f"{safe}-{ts}"

    if fmt == "json":
        path = base.with_suffix(".json")
        path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
        return path

    if fmt == "md":
        path = base.with_suffix(".md")
        cols = list(dict.fromkeys(k for it in items for k in it.keys()))
        lines = [f"# {title}", "", f"共 {len(items)} 条", "",
                 "| " + " | ".join(cols) + " |",
                 "|" + "|".join(["---"] * len(cols)) + "|"]
        for it in items:
            lines.append("| " + " | ".join(str(it.get(c, "")).replace("|", "\\|") for c in cols) + " |")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    if fmt == "xlsx":
        try:
            import openpyxl  # noqa: PLC0415
            path = base.with_suffix(".xlsx")
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = safe[:30]
            cols = list(dict.fromkeys(k for it in items for k in it.keys()))
            ws.append(cols)
            for it in items:
                ws.append([it.get(c, "") for c in cols])
            wb.save(path)
            return path
        except Exception:  # noqa: BLE001
            fmt = "csv"

    # csv 兜底
    path = base.with_suffix(".csv")
    cols = list(dict.fromkeys(k for it in items for k in it.keys()))
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for it in items:
            w.writerow({k: it.get(k, "") for k in cols})
    return path


def demo_rules() -> list[dict]:
    """示例采集规则（供前端/文档展示）"""
    return [
        {"name": "标题", "css": "h1", "attr": "text"},
        {"name": "链接", "css": "main a", "attr": "href", "many": True},
        {"name": "导航", "css": "nav a", "attr": "text", "many": True},
    ]


if __name__ == "__main__":
    import sys

    if "--demo" in sys.argv:
        print(json.dumps(demo_rules(), ensure_ascii=False, indent=2))
        print("\nexports 目录: ", _ensure_exports())