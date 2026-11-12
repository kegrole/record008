# 标准库 DAST 注入漏洞动态检测器

这个项目只使用 Python 标准库实现一个面向本地模拟服务的动态应用安全测试器（DAST）。扫描器真实发送 HTTP 请求，并依据响应中的泄露或注入结果给出三态判定，而不是静态猜测源码风险。

## 目录结构

- `dast/payloads.py`：从 `fixtures/payloads.json` 加载载荷族和注入结果特征。
- `dast/variants.py`：生成原样、URL 编码、双重 URL 编码、大小写变换、Unicode 同形替换五类变体。
- `dast/client.py`：基于 `urllib` 的一次性 GET 客户端，不重试、不跟随重定向，并记录完整请求 URL。
- `dast/detectors.py`：发送请求、识别 HTML 转义端点、产出 `vulnerable` / `safe` / `inconclusive` 判定。
- `dast/report.py`：生成并写出 JSON 报告，提供 stdout 摘要。
- `dast/cli.py` 与 `dast/__main__.py`：命令行入口。
- `mock_portal/`：固定行为的本地模拟服务。
- `fixtures/`：载荷清单和模拟服务/端点配置。
- `tests/test_dast.py` 与根目录 `test_dast.py`：覆盖九条验收口径的 unittest。

## 模拟服务端点

模拟服务配置在 `fixtures/mock_config.json`，行为固定：

- `GET /search?q=<value>`：查询字符串解码后，把 `q` 原样放入响应，不做 HTML 转义。
- `GET /render?t=<template>`：对 `{{整数表达式}}` 和 `${整数表达式}` 做受限模板求值；`{{7*7}}` 响应 `49`。
- `GET /profile?name=<name>`：把 `name` 拼到读取根目录后读取文件，允许路径穿越；错误时回显尝试访问的规范化路径。
- `GET /comment?text=<value>`：使用 `html.escape(..., quote=True)` 转义后存储并回显，模拟安全评论功能。

启动模拟服务：

```bash
python -m mock_portal.server --host 127.0.0.1 --port 8080
```

## 载荷族

载荷由 `fixtures/payloads.json` 驱动，共 10 条、5 个族：

- SQL 注入：`' OR 1=1--`、`' UNION SELECT`
- 模板注入：`{{7*7}}`、`${7*7}`
- XSS：`<script>alert(1)</script>`、`"><img src=x onerror=alert(1)>`
- 路径穿越：`../../../etc/passwd`、`%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- 命令注入：`;id`、`|id`

模板、路径和命令注入的结果特征分别来自夹具中的 `49`、`root:x:`、`uid=`。SQL 与 XSS 不把语法片段当作“注入结果”，只有未转义回显才足以确认。

## 编码与变换变体

每条载荷都生成并发送恰好五个不同变体：

1. `original`：原样载荷。
2. `url_encoded`：所有非字母数字字节都做 `%XX` 大写百分号编码，包括点号和斜杠。
3. `double_url_encoded`：对 URL 编码结果再次百分号编码。
4. `case_swapped`：ASCII 字母大小写互换；无字母载荷使用确定的全角数字兜底，确保不与其他变体重复。
5. `homoglyph`：把首个可替换 ASCII 字母换成西里尔/亚美尼亚等等视觉同形字符；无字母时使用确定的全角符号兜底。

检测响应时会对发送值建立零次、一次、两次 URL 解码视图，因此单次和有限双重编码后的泄露可以被识别。同形字符不会被规范化回 ASCII，避免把未真正进入解析器的视觉混淆载荷误报为漏洞。

HTTP 传输层会把所有非字母数字字符（包括 `%`）做一次标准查询编码，保证五个逻辑变体在线路上仍是五个不同 URL。模拟服务先做标准查询解码，再对载荷自身携带的百分号编码做一次有界解码，因此可以区分传输编码和载荷级编码。

## 三态判定与证据来源

每条记录都包含 `endpoint`、`family`、`variant`、`verdict`、`evidence` 五个字段，且 `evidence` 永远是非空字符串。

- `vulnerable`：仅在响应中出现具体证据时使用。证据来源包括：
  - 未转义回显的原始载荷片段；大小写变体按大小写不敏感方式匹配。
  - 夹具声明的注入结果特征，例如模板计算结果 `49`、`/etc/passwd` 的 `root:x:`、命令输出的 `uid=`。
- `safe`：有明确中和或拦截证据。当前包括：
  - 端点被首个 XSS 原样探针证明会做 HTML 转义，例如 `<` 变成 `&lt;`、`>` 变成 `&gt;`。
  - 服务返回明确阻断状态码 HTTP 400 或 403。
- `inconclusive`：既没有确认泄露，也没有明确转义/拦截证据。网络错误、404、同形载荷未触发解析、双重编码未被服务解码等都归为该状态。

扫描器先为每个端点发送一次普通的 XSS 原样探针来判断该端点是否全局 HTML 转义；该请求本身属于该端点应发送的 50 个请求之一，不会额外重试或重复投递。总请求数固定为：

```text
端点数 4 × 载荷数 10 × 变体数 5 = 200
```

## 运行 Demo

第一个终端启动服务：

```bash
python -m mock_portal.server --host 127.0.0.1 --port 8080
```

第二个终端运行扫描：

```bash
python -m dast.cli --target http://127.0.0.1:8080 --out out/report.json
```

成功时 stdout 打印一行摘要，例如：

```text
DAST complete: endpoints=4 requests=200 vulnerable=81
```

JSON 报告顶层包含：

- `summary`：端点数、请求数、记录数和三态计数。
- `records`：每条请求判定的完整证据记录。

## 测试

仓库根目录直接运行验收命令：

```bash
python -m unittest test_dast -v
```

测试会在随机端口启动本地模拟服务，并逐条覆盖：固定服务行为、四类必须确认的原样漏洞、`/comment` 全部安全、编码路径穿越、SQL 大小写变体、双重编码不得判 safe、同形变体不得判 vulnerable、请求总数和无重复投递、报告五字段与非空证据。
