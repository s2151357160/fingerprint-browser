"""浏览器操作录制器

在会话页面内注入监听脚本，把用户的实际操作（点击/输入/导航/滚动）
捕获并上报到会话线程，停止后转换为 fp_automation 可执行的 JSON 动作。

用法（由控制台集成，不直接面向用户）:
    from fingerprint_browser.fp_recorder import recorder_js, actions_to_script
    ctx.add_init_script(recorder_js())          # 后续页面自动监听
    page.evaluate(recorder_js())                # 当前页面立即生效
    actions = actions_to_script(worker._recorded)
"""
from __future__ import annotations

# ==================== 录制脚本（干净实现） ====================

_RECORD_JS = r"""
(function () {
  if (window.__fp_recorder_done) return;
  window.__fp_recorder_done = true;
  var bridge = window.__fpBridge;
  if (typeof bridge !== 'function') return;
  var lastUrl = location.href;

  function cssPath(el) {
    if (!el || el.nodeType !== 1) return '';
    if (el.id) return '#' + CSS.escape(el.id);
    var parts = [];
    var node = el;
    while (node && node.nodeType === 1 &&
           node !== document.body && node !== document.documentElement) {
      var sel = node.tagName.toLowerCase();
      if (node.id) { parts.unshift('#' + CSS.escape(node.id)); break; }
      if (node.classList && node.classList.length) {
        var names = [];
        for (var i = 0; i < Math.min(node.classList.length, 3); i++) {
          names.push('.' + CSS.escape(node.classList[i]));
        }
        sel += names.join('');
      }
      var parent = node.parentElement;
      if (parent) {
        var sibs = Array.prototype.filter.call(parent.children,
          function (c) { return c.tagName === node.tagName; });
        if (sibs.length > 1) {
          var idx = Array.prototype.indexOf.call(parent.children, node) + 1;
          sel += ':nth-child(' + idx + ')';
        }
      }
      parts.unshift(sel);
      node = parent;
    }
    return parts.join(' > ');
  }

  function isEditable(el) {
    if (!el) return false;
    var tag = el.tagName ? el.tagName.toLowerCase() : '';
    return el.isContentEditable || tag === 'input' || tag === 'textarea' ||
           tag === 'select';
  }

  document.addEventListener('click', function (e) {
    var el = e.target;
    if (!el || !el.nodeType) return;
    var sel = cssPath(el);
    var txt = '';
    try { txt = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim(); }
    catch (err) {}
    bridge('record', { op: 'click', sel: sel, text: (txt || '').slice(0, 60) });
  }, true);

  document.addEventListener('input', function (e) {
    var el = e.target;
    if (!el || !el.tagName) return;
    var tag = el.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea') {
      if (el.type === 'password') return;
      var v = el.value;
      if (v && v.length <= 2000) {
        bridge('record', { op: 'type', sel: cssPath(el), text: v });
      }
    }
  }, true);

  function checkNav() {
    if (location.href !== lastUrl) {
      if (location.href && !location.href.startsWith('about:')) {
        bridge('record', { op: 'goto', url: location.href.slice(0, 500) });
      }
      lastUrl = location.href;
    }
  }
  window.addEventListener('popstate', checkNav);
  window.addEventListener('hashchange', checkNav);
  setInterval(checkNav, 600);

  var lastScrollY = window.scrollY || 0;
  var scrollTimer = null;
  window.addEventListener('scroll', function () {
    if (scrollTimer) return;
    scrollTimer = setTimeout(function () {
      scrollTimer = null;
      var y = window.scrollY || 0;
      var delta = y - lastScrollY;
      lastScrollY = y;
      if (Math.abs(delta) < 200) return;
      bridge('record', { op: 'scroll',
        to: delta > 0 ? 'down' : 'up', dy: Math.round(delta) });
    }, 300);
  }, { passive: true });
})();
"""


def recorder_js() -> str:
    """返回可注入页面的录制脚本（对当前页面 evaluate + add_init_script 均可）"""
    return _RECORD_JS


def actions_to_script(events: list[dict]) -> list[dict]:
    """把录制的原始事件转换为 fp_automation 动作列表（相邻同类压缩）。"""
    actions: list[dict] = []
    for ev in events or []:
        op = ev.get("op")
        if op == "click":
            sel = ev.get("sel") or ""
            if not sel:
                continue
            actions.append({"type": "click", "selector": sel})
        elif op == "type":
            sel = ev.get("sel") or ""
            text = ev.get("text") or ""
            if not sel or not text:
                continue
            actions.append({"type": "type", "selector": sel, "text": text})
        elif op == "goto":
            url = ev.get("url") or ""
            if not url or url.startswith("about:"):
                continue
            actions.append({"type": "goto", "url": url})
        elif op == "scroll":
            d = ev.get("dy") or 0
            actions.append({"type": "scroll", "to": "top" if d < 0 else "bottom"})
    return actions


if __name__ == "__main__":
    demo = [{"op": "goto", "url": "https://x.com/home"},
            {"op": "click", "sel": "a[href='/explore']", "text": "Explore"},
            {"op": "type", "sel": "input[role=combobox]", "text": "hello"},
            {"op": "scroll", "dy": 900}]
    import json
    print(json.dumps(actions_to_script(demo), ensure_ascii=False, indent=2))