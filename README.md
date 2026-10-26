---
AIGC:
  ContentProducer: '001191110102MAD55U9H0F10002'
  ContentPropagator: '001191110102MAD55U9H0F10002'
  Label: '1'
  ProduceID: '7a0fbf78-f423-4f21-bf2e-850cca434b12'
  PropagateID: '7a0fbf78-f423-4f21-bf2e-850cca434b12'
  ReservedCode1: '531e7d7c-3125-41f4-9cc6-c75bbac4570d'
  ReservedCode2: '531e7d7c-3125-41f4-9cc6-c75bbac4570d'
---

# fingerprint_browser — 可换指纹浏览器

Python + Playwright 的浏览器指纹一致性与多会话自动化框架：为每个浏览器会话注入一套可信、自洽的设备指纹，配合内置代理内核与账号档案，让多个会话以彼此独立且稳定的身份运行。内置单页 Web 控制台，全功能同时提供 HTTP API。

## 特性

- **指纹伪装体系**：Canvas 噪声、WebGL、UA/ClientHints、屏幕/字体/时区/语言、plugins、设备内存/核数等全链路一致化；`navigator.webdriver` 等自动化痕迹清理
- **设备分布模型**：OS/GPU/屏幕/核数按真实世界权重抽样，`coherence_check` 保证配置自洽（不会出现 Windows 配 Apple GPU）
- **深度伪装字段**（模板驱动，缺省关闭）：storage_quota、network_connection、chrome_ui 等 18 项信号
- **自检审计**：基础比对 + 深度镜像自检（FingerprintJS 风格全信号采集，逐项标注 原生/覆盖/伪装）
- **内置代理内核**：自带 mihomo 单文件内核，自动合并本机 Clash 配置与订阅源（`subscriptions.txt`），节点池去重；多会话并行各自独立端口与凭据
- **节点信誉**：探测出口 IP 类型（移动/住宅/数据中心/代理标记），会话分配信誉优先
- **WebRTC 防泄漏**：命令行层禁非代理 UDP + 注入层 STUN/TURN 剥离，双层保险
- **账号档案**：指纹 + 登录态（cookie/localStorage）+ 绑定节点 + 上次页面，一键启停还原；密码等敏感字段本地加密落盘
- **拟人行为**：真人轨迹库（可选 `cursory`，LGPL，未安装自动回退贝塞尔）驱动鼠标/输入/滚动
- **自动化引擎**：JSON 脚本（goto/click/type/longpress/wait/extract/export/loop 等 20+ 动作，变量插值）、录制器、采集导出（xlsx/csv/json/md）
- **定时调度**：daily/weekly/interval/once 四类任务，到点自动 启动会话→换 IP→跑脚本→停止
- **控制台**：单页 Web UI（账号/会话/节点/脚本/定时/自检/批量），同步暴露 `/api/*` HTTP 接口

## 安装

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

可选依赖（缺失时对应功能自动降级）：

```bash
pip install curl_cffi      # HTTP 层 Chrome TLS 指纹（订阅拉取/打码请求更稳）
pip install openpyxl       # 采集导出 xlsx（缺失回退 csv）
pip install cryptography   # 档案敏感字段本地加密（缺失回退 base64 标记）
```

### 代理内核（自动换 IP 需要）

本仓库不含 mihomo 内核（约 58MB）。从其官方发布页下载对应平台的单文件可执行，放入 `core/` 目录：

```
core/mihomo-windows-amd64.exe
```

无内核时仍可用：手动指定外部代理（Clash/V2Ray 等），仅失去自动节点池/换 IP 能力。

## 快速开始

### 方式一：控制台

```bash
python -m fingerprint_browser.fp_app          # 默认 http://127.0.0.1:8230
python -m fingerprint_browser.fp_app --port 8230 --no-open
```

### 方式二：作为库

```python
from fingerprint_browser import load, launch

fp = load("win10-chrome-151")
p, browser, context, page = launch(fp, proxy="auto")   # auto = 自动探测本机代理
page.goto("https://example.com")
p.stop()
```

### 节点订阅（可选）

在项目根（仓库外层）建 `subscriptions.txt`，每行一个 Clash 订阅 URL，节点自动合并进池：

```
https://example.com/api/v1/client/subscribe?token=xxx
```

## 指纹模板

`fingerprints/` 内置 9 个模板：win10/win11 的 Chrome/Edge、win11 Firefox、linux/mac Chrome，以及 `win11-chrome-151-deep`（18 项深度信号参考模板）。

用 `random_fingerprint()` 生成随机指纹，或基于设备分布模型抽样。

## 运行测试

```bash
python test_all.py
```

## 目录结构

```
fingerprint_browser/
├── fp_app.py          # 控制台入口（Web UI + HTTP API）
├── fp_browser.py      # 核心：指纹加载/启动/注入/校验
├── fp_gen.py          # 随机指纹生成（分布模式）
├── fp_devices.py      # 设备分布模型 + 一致性校验
├── fp_core.py         # 内置 mihomo 内核管理/订阅合并
├── fp_proxy.py        # 外部代理探测/Clash 联动
├── fp_reputation.py   # 节点信誉库
├── fp_profile.py      # 账号档案（指纹/登录态/节点）
├── fp_secret.py       # 敏感字段本地加密
├── fp_automation.py   # JSON 脚本引擎
├── fp_human.py        # 拟人行为模拟
├── fp_recorder.py     # 操作录制器
├── fp_scrape.py       # 数据采集导出
├── fp_sched.py        # 定时调度
├── fp_captcha.py      # 打码服务接入（2captcha/capsolver）
├── fp_cookie.py       # Cookie 导入导出
├── fp_check.py        # 指纹自检（基础+深度镜像）
├── fp_http.py         # TLS 指纹化 HTTP 客户端
├── fingerprints/      # 指纹模板（9 个）
├── scripts/           # 自动化脚本示例
└── test_all.py        # 测试套件（38 项）
```

## 许可证

MIT，见 [LICENSE](LICENSE)。

> AI生成