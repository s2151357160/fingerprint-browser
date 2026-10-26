"""第三方打码服务接入（reCAPTCHA v2/v3、hCaptcha、Cloudflare Turnstile）

供自动化脚本动作 solve_captcha 与手动切换容器使用。当前支持
2captcha 与 capsolver（HTTP API），配置从环境变量或本地
config/captcha.json 读取：

    FP_CAPTCHA_PROVIDER = 2captcha|capsolver
    FP_CAPTCHA_API_KEY  = 服务商 API key
    FP_CAPTCHA_TIMEOUT  = 轮询超时（秒，默认 120）

或在仓库根目录建 config/captcha.json：
    {"provider": "2captcha", "api_key": "xxxx", "timeout": 120}

用法（直接解码拿 token）:
    token = fp_captcha.solve("turnstile", "0x4AAA...", "https://example.com/login",
                             provider="2captcha")
    token = fp_captcha.solve("hcaptcha", "sitekey", url)

生成服务商配置:
    fp_captcha.configure(provider="2captcha", api_key="xxx")  # 落盘 config/captcha.json
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .fp_http import post, get, request

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "captcha.json"

_KIND_MAP_2CAPTCHA = {
    "recaptcha": "userrecaptcha",
    "recaptcha3": "userrecaptcha3",
    "hcaptcha": "hcaptcha",
    "turnstile": "turnstile",
}
_KIND_MAP_CAPSOLVER = {
    "recaptcha": "ReCaptchaV2TaskProxyless",
    "recaptcha3": "ReCaptchaV3TaskProxyless",
    "hcaptcha": "HCaptchaTaskProxyless",
    "turnstile": "AntiTurnstileTaskProxyLess",
}


def _load_config() -> dict:
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text("utf-8"))
        except Exception:  # noqa: BLE001
            cfg = {}
    cfg.setdefault("provider", os.getenv("FP_CAPTCHA_PROVIDER", cfg.get("provider", "2captcha")))
    cfg.setdefault("api_key", os.getenv("FP_CAPTCHA_API_KEY", cfg.get("api_key", "")))
    cfg.setdefault("timeout", int(os.getenv("FP_CAPTCHA_TIMEOUT", cfg.get("timeout", 120))))
    return cfg


def configure(provider: str | None = None, api_key: str | None = None,
              timeout: int | None = None) -> dict:
    """写入本地打码配置并返回当前生效配置。"""
    cfg = _load_config()
    if provider:
        cfg["provider"] = provider
    if api_key:
        cfg["api_key"] = api_key
    if timeout:
        cfg["timeout"] = timeout
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), "utf-8")
    return cfg


def status() -> dict:
    cfg = _load_config()
    return {"provider": cfg.get("provider"), "configured": bool(cfg.get("api_key")),
            "timeout": cfg.get("timeout")}


# ---------------- 2captcha ----------------

def _solve_2captcha(kind: str, sitekey: str, pageurl: str, cfg: dict) -> str:
    key = cfg["api_key"]
    method = _KIND_MAP_2CAPTCHA.get(kind) or "userrecaptcha"
    base = "http://2captcha.com"
    resp = post(f"{base}/in.php", params={"key": key, "method": method,
                                          "googlekey": sitekey, "pageurl": pageurl,
                                          "json": 1})
    j = resp.json()
    if int(j.get("status", 0)) != 1 or "request" not in j:
        raise RuntimeError(f"2captcha 提交失败: {j}")
    cid = str(j["request"])
    deadline = time.time() + int(cfg.get("timeout", 120))
    while time.time() < deadline:
        time.sleep(3)
        r = get(f"{base}/res.php", params={"key": key, "action": "get", "id": cid, "json": 1})
        j = r.json()
        if int(j.get("status", 0)) == 1:
            return j["request"]
        if j.get("request") and "CAPCHA_NOT_READY" not in j["request"]:
            raise RuntimeError(f"2captcha 失败: {j}")
    raise TimeoutError("2captcha 解码超时")


# ---------------- capsolver ----------------

def _solve_capsolver(kind: str, sitekey: str, pageurl: str, cfg: dict) -> str:
    key = cfg["api_key"]
    task_type = _KIND_MAP_CAPSOLVER.get(kind) or "ReCaptchaV2TaskProxyless"
    task = {"websiteURL": pageurl, "websiteKey": sitekey}
    if kind == "recaptcha3":
        pass  # V3 需 action/pageAction，默认页面内找
    payload = {"clientKey": key, "task": {"type": task_type, **task}}
    resp = post("https://api.capsolver.com/createTask", json=payload)
    j = resp.json()
    tid = j.get("taskId")
    if not tid:
        raise RuntimeError(f"capsolver 提交失败: {j}")
    deadline = time.time() + int(cfg.get("timeout", 120))
    while time.time() < deadline:
        time.sleep(3)
        resp = post("https://api.capsolver.com/getTaskResult", json={"clientKey": key, "taskId": tid})
        j = resp.json()
        st = j.get("status", "")
        if st == "ready":
            return j.get("solution", {}).get("gRecaptchaResponse") or j.get("solution", {}).get("token")
        if st == "failed":
            raise RuntimeError(f"capsolver 失败: {j}")
    raise TimeoutError("capsolver 解码超时")


def solve(kind: str, sitekey: str, pageurl: str, *,
          provider: str | None = None, api_key: str | None = None,
          timeout: int | None = None) -> str:
    """解码指定类型的验证码，返回可注入的 token。"""
    cfg = _load_config()
    if provider:
        cfg["provider"] = provider
    if api_key:
        cfg["api_key"] = api_key
    if timeout:
        cfg["timeout"] = timeout
    if not cfg.get("api_key"):
        raise RuntimeError("未配置打码 API key（用 fp_captcha.configure() 或环境变量）")
    prov = (cfg.get("provider") or "2captcha").lower()
    if prov == "capsolver":
        return _solve_capsolver(kind, sitekey, pageurl, cfg)
    return _solve_2captcha(kind, sitekey, pageurl, cfg)


if __name__ == "__main__":
    print("打码状态:", status())
