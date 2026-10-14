"""人类行为模拟器（humanize）

借鉴 CloakBrowser 的反向设计：让自动化交互在"微观层面"与真人一致——
贝塞尔曲线鼠标移动、自然瞄准点、按下停顿、逐字输入+偶发抖字自纠、
滚动加速-巡航-减速节奏、动作间随机空闲与微动。

用法（由 fp_automation 在 humanize 开关下自动调用）:
    from fingerprint_browser.fp_human import Human
    h = Human(page)                      # preset="careful" 更慢更谨慎
    h.click("#submit")
    h.type_text("#email", "user@x.com")
    h.scroll("bottom")
    h.idle()

注意：所有操作基于 Playwright Page，必须在会话 worker 线程内调用。
"""
from __future__ import annotations

import random
import time

_LETTERS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"


def _curve(x0, y0, x1, y1, steps: int, rng: random.Random) -> list[tuple[float, float]]:
    """生成从 (x0,y0) 到 (x1,y1) 的贝塞尔路径（控制点随机偏置 + 末段抖动）"""
    cx1 = x0 + (x1 - x0) * 0.4 + (rng.random() - 0.5) * 60
    cy1 = y0 + (y1 - y0) * 0.4 + (rng.random() - 0.5) * 60
    cx2 = x0 + (x1 - x0) * 0.6 + (rng.random() - 0.5) * 60
    cy2 = y0 + (y1 - y0) * 0.6 + (rng.random() - 0.5) * 60
    pts = []
    for i in range(steps):
        t = (i + 1) / steps
        it = 1 - t
        x = it ** 3 * x0 + 3 * it ** 2 * t * cx1 + 3 * it * t ** 2 * cx2 + t ** 3 * x1
        y = it ** 3 * y0 + 3 * it ** 2 * t * cy1 + 3 * it * t ** 2 * cy2 + t ** 3 * y1
        if t > 0.85:   # 末段微抖动：模拟"瞄准修正"
            x += (rng.random() - 0.5) * 2.5
            y += (rng.random() - 0.5) * 2.5
        pts.append((x, y))
    return pts


class Human:
    """人类行为模拟器（每次实例独立随机源）"""

    def __init__(self, page, seed: int | None = None, preset: str = "default"):
        self.page = page
        self.rng = random.Random(seed)
        if preset == "careful":
            self.move_delay = (0.014, 0.038)
            self.pause_before_click = (0.2, 0.7)
            self.typing_delay = (0.06, 0.16)
            self.mistype_chance = 0.06
            self.idle_range = (0.4, 1.2)
            self.hold_duration = (0.08, 0.18)
        else:
            self.move_delay = (0.007, 0.02)
            self.pause_before_click = (0.08, 0.35)
            self.typing_delay = (0.035, 0.12)
            self.mistype_chance = 0.04
            self.idle_range = (0.2, 0.8)
            self.hold_duration = (0.05, 0.15)

    def _sleep(self, a, b):
        time.sleep(self.rng.uniform(a, b))

    # ---------- 鼠标 ----------
    def mouse_move(self, x: float, y: float):
        """贝塞尔曲线移动到 (x, y)（从当前 cursor 位置出发）"""
        try:
            pos = self.page.mouse.get_position() if hasattr(self.page.mouse, "get_position") else None
        except Exception:  # noqa: BLE001
            pos = None
        if not pos:
            try:
                pos = self.page.evaluate("() => ({x: window.__fp_cx || 0, y: window.__fp_cy || 0})")
                sx, sy = pos["x"], pos["y"]
            except Exception:  # noqa: BLE001
                sx, sy = 0, 0
        else:
            sx, sy = pos
        for px, py in _curve(sx, sy, x, y, steps=26, rng=self.rng):
            self.page.mouse.move(px, py)
            self._sleep(*self.move_delay)
        try:
            self.page.evaluate("(v) => { __fp_cx = v[0]; __fp_cy = v[1]; }", [x, y])
        except Exception:  # noqa: BLE001
            pass

    # ---------- 点击 ----------
    def click(self, selector: str, index: int = 0):
        """自然点击：元素内随机瞄准点 + 接近-停顿-按下-松开节奏"""
        loc = self.page.locator(selector).nth(index)
        box = loc.bounding_box(timeout=30000)
        if not box:
            raise RuntimeError(f"元素不可见: {selector}")
        # 瞄准点：元素内随机（偏向中心的正态分布）
        tx = box["x"] + box["width"] * (0.3 + 0.4 * self.rng.random())
        ty = box["y"] + box["height"] * (0.3 + 0.4 * self.rng.random())
        # 先移动到旁边再分步靠近（人类视角）
        self.mouse_move(tx - self.rng.randint(15, 45), ty - self.rng.randint(10, 35))
        self._sleep(0.1, 0.3)
        self.mouse_move(tx, ty)
        self._sleep(*self.pause_before_click)
        self.page.mouse.down()
        self._sleep(*self.hold_duration)
        self.page.mouse.up()
        self._sleep(0.05, 0.2)

    # ---------- 输入 ----------
    def type_text(self, selector: str, text: str, clear: bool = True):
        """逐字输入：聚焦（人类式点击）→ 清空 → 逐字符敲击（偶发错字自纠）"""
        text = str(text or "")
        loc = self.page.locator(selector).nth(0)
        box = loc.bounding_box(timeout=30000)
        if box:
            self.mouse_move(box["x"] + box["width"] * 0.5, box["y"] + box["height"] * 0.5)
            self._sleep(0.08, 0.25)
            self.page.mouse.click(box["x"] + box["width"] * 0.5, box["y"] + box["height"] * 0.5)
        else:
            loc.click()
        if clear:
            self.page.keyboard.press("Control+A")
            self._sleep(0.05, 0.15)
            self.page.keyboard.press("Backspace")
            self._sleep(0.05, 0.15)
        for ch in text:
            if ch == "\n":
                self.page.keyboard.press("Enter")
                self._sleep(0.1, 0.3)
                continue
            # 偶发打错字符 → 退格自纠
            if self.rng.random() < self.mistype_chance:
                self.page.keyboard.type(self.rng.choice(_LETTERS), delay=0)
                self._sleep(0.12, 0.35)
                self.page.keyboard.press("Backspace")
                self._sleep(0.08, 0.2)
            self.page.keyboard.type(ch, delay=0)
            self._sleep(*self.typing_delay)
        self._sleep(0.1, 0.4)   # 打完停顿（思考/核对）

    # ---------- 滚动 ----------
    def scroll(self, target: str, by_px: int | None = None):
        """滚动：target=top/bottom（分段带节奏）；否则视为选择器滚动到可见"""
        if target == "top":
            for _ in range(self.rng.randint(5, 8)):
                self.page.mouse.wheel(0, -self.rng.randint(300, 550))
                self._sleep(0.05, 0.14)
            return
        if target == "bottom":
            try:
                total = self.page.evaluate("document.body ? document.body.scrollHeight : 0") or 0
            except Exception:  # noqa: BLE001
                total = 0
            if not total:
                total = by_px or 2000
            steps = self.rng.randint(8, 14)
            step = max(60, int(total / steps))
            for i in range(steps):
                ratio = i / max(1, steps - 1)
                # 加速-减速：先小后大再小
                factor = 0.4 + 0.6 * (1 - abs(ratio - 0.5) * 2)
                self.page.mouse.wheel(0, max(30, int(step * factor)))
                self._sleep(0.03, 0.1)
            return
        self.page.locator(str(target)).scroll_into_view_if_needed()
        self._sleep(0.1, 0.3)

    # ---------- 空闲微动 ----------
    def idle(self):
        """自然停顿 + 轻微鼠标漂移（人不会完全静止）"""
        self._sleep(*self.idle_range)
        if self.rng.random() < 0.5:
            try:
                x, y = self.page.mouse.get_position() if hasattr(self.page.mouse, "get_position") else (0, 0)
            except Exception:  # noqa: BLE001
                x, y = 0, 0
            self.page.mouse.move(x + self.rng.randint(-8, 8),
                                 y + self.rng.randint(-6, 6), steps=2)
            self._sleep(0.1, 0.4)


if __name__ == "__main__":
    print("Human 模块加载 OK")
    print("曲线示例: 6 个点 ->", [(round(p[0]), round(p[1]))
                                 for p in _curve(0, 0, 500, 300, 6, random.Random(7))])