"""本地机密加解密（密码/API key 等档案敏感字段落盘安全）

默认用 cryptography Fernet(对称 AES-128-GCM)，密钥存本机
config/fp_secret.key（首次自动生成）。同机跨会话可解密，密钥文件
不进 git、权限收紧；换机即失效（防拷走 profile 目录反推敏感字段）。

use = fp_secret.encrypt / fp_secret.decrypt
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path

try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except Exception:  # noqa: BLE001
    HAS_FERNET = False

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_KEY_FILE = _CONFIG_DIR / "fp_secret.key"


def _load_fernet():
    if not HAS_FERNET:
        return None
    if _KEY_FILE.exists():
        try:
            key = _KEY_FILE.read_text("utf-8").strip()
            return Fernet(key.encode())
        except Exception:  # noqa: BLE001
            pass
    key = Fernet.generate_key()
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _KEY_FILE.write_bytes(key)
    # 收紧权限（文件属主可读写，其余只读）；失败忽略
    for cmd in (f'icacls "{_KEY_FILE}" /inheritance:r /grant:r "%USERNAME%:R"',):
        try:
            os.system(cmd)
        except Exception:  # noqa: BLE001
            pass
    return Fernet(key)


def encrypt(plain: any) -> str | None:
    """加密任意可序列化对象，返回 base64 密文。失败返回 None。"""
    if plain in (None, ""):
        return None
    f = _load_fernet()
    if f is None:
        # 无 cryptography 时降级 base64 标记（不加密，但标识待加密）
        return "plain:" + base64.b64encode(
            json.dumps(plain, ensure_ascii=False).encode("utf-8")).decode("ascii")
    data = json.dumps(plain, ensure_ascii=False).encode("utf-8")
    return f.encrypt(data).decode("ascii")


def decrypt(token: str | None):
    """解密 encrypt() 输出；解密失败/明文标记时原样返回。"""
    if not token:
        return None
    if token.startswith("plain:"):
        try:
            return json.loads(base64.b64decode(token[6:]))
        except Exception:  # noqa: BLE001
            return token[6:]
    f = _load_fernet()
    if f is None:
        return token
    try:
        raw = f.decrypt(token.encode("ascii"))
        return json.loads(raw.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return token


if __name__ == "__main__":
    s = encrypt({"password": "hunter2", "extra": 123})
    print("cipher:", (s or "")[:30])
    print("plain:", decrypt(s))
