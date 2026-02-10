---
name: cc-proxy-detector
description: 检测 Claude Code 中转站的真实后端来源（Anthropic 官方 / AWS Bedrock Kiro / Google Vertex AI Antigravity / 疑似伪装）。当用户想要检测中转站渠道来源、验证 API 是否为官方直连、识别中转站伪装、扫描多模型混合渠道时使用。触发词包括"检测渠道"、"检测中转"、"proxy detect"、"渠道来源"、"是不是官方"。
---

# CC Proxy Detector

检测 Claude Code 中转站后端来源，支持混合渠道检测和防伪装识别。

## 检测流程

1. 确定目标中转站地址和 API Key
2. 选择检测模式（单模型 / 多模型扫描）
3. 运行 `scripts/detect.py`
4. 分析报告，结合指纹矩阵人工复核

## 使用方式

```bash
# 单模型自动检测
python3 scripts/detect.py

# 多模型扫描（推荐，检测混合渠道）
python3 scripts/detect.py --scan-all --rounds 2

# 指定模型列表
python3 scripts/detect.py --scan-models "claude-opus-4-6,claude-sonnet-4-5-20250929"

# 指定地址和密钥
python3 scripts/detect.py --base-url https://your-proxy.com --api-key sk-xxx

# JSON 输出 + 保存
python3 scripts/detect.py --scan-all --json --output report.json
```

环境变量：`ANTHROPIC_BASE_URL`（中转站地址）、`ANTHROPIC_AUTH_TOKEN` 或 `FACTORY_API_KEY`（密钥）。

依赖：`pip install requests`

## 后端来源全景

所有 Claude 访问最终落到三个后端之一，各种工具逆向这些后端：

| 来源 | 后端 | 说明 |
|------|------|------|
| Anthropic API | Anthropic | 官方 API Key 或 Max 订阅 |
| Claude Code Max | Anthropic | OAuth 认证，可通过 CLIProxyAPI 转 API Key |
| Kiro | AWS Bedrock | AWS AI IDE，model 前缀 `kiro-` |
| Factory Droid | Anthropic/Bedrock | 支持 BYOK，后端取决于配置 |
| Antigravity | Google Vertex AI | Google Cloud Code，走 `googleapis.com` |
| Windsurf | Bedrock/未知 | Codeium AI IDE，内部渠道不明 |
| Warp | 未知 | AI 终端，内部渠道不明 |

## 检测维度

脚本对每个模型发送 tool_use 探测 + thinking 探测 + ratelimit 动态验证，采集以下指纹：

| 指纹 | Anthropic 官方 | Bedrock/Kiro | Vertex/Antigravity |
|------|---------------|--------------|-------------------|
| tool_use id | `toolu_` | `tooluse_` | `tooluse_` / `tool_N` |
| message id | `msg_<base62>` | UUID / `msg_<UUID>` | `msg_<UUID>` / `req_vrtx_` |
| thinking sig | len 200+ | len 200+ / 截断 | `claude#` 前缀 |
| model 格式 | `claude-*` | `kiro-*` / `anthropic.*` | `claude-*` |
| service_tier | 有 | 无 | 无 |
| inference_geo | 有 | 无 | 无 |
| ratelimit hdr | 有（动态递减） | 无 | 无 |
| cache_creation | 嵌套对象 | 无 | 无 |

## 判读报告

脚本自动评分并给出判定，但**自动评分可被中转站伪装骗过**。人工复核要点：

**确认真 Anthropic 的铁证组合**：
- `inference_geo` 存在 + ratelimit remaining 动态递减 + `toolu_` 前缀

**识别伪装的关键**：
- ratelimit remaining 固定不变（如始终 299000）→ 伪造 headers
- `inference_geo` 缺失 → 中转站未伪造此字段
- 所有正面指纹通过但必有字段缺失 → 高度可疑

**已知可被伪造的字段**：`toolu_` 前缀、`service_tier`、ratelimit headers（静态值）、`cache_creation` 嵌套对象

**最难伪造**：ratelimit remaining 动态递减（需中转站维护配额计数系统）

## 行为异常（逆向渠道线索）

除指纹字段外，逆向渠道常出现运行时异常，可作为辅助判据：

- **tool_use 配对错误**：`Each tool_use block must have a corresponding tool_result block` — 中转站重写 tool ID 但破坏了配对链
- **间歇性 HTTP 500**：中转站格式转换管道在特定模型/功能组合上失败
- **模型可用性缺口**：部分模型可用、部分不可用 — 中转站只映射了部分模型 ID
- **延迟偏高且波动大**：多一跳中转增加 1-3s，P99 尾延迟明显
- **thinking/streaming 异常**：中转站未正确转发 SSE 事件或 thinking 块
- **多模态/读图失败**：图片数据在中转时丢失或后端不支持，Read 图片返回空内容
- **Write 大段内容报错**：中转站对请求/响应体大小有限制，写入超过一定行数时失败
- **WebFetch 被拦截**：中转站网络策略限制外部域名访问
- **工具参数校验异常**：部分工具（如 TaskList）出现参数校验错误，中转站格式转换不完整

## 参考资料

- 三源指纹矩阵与已知渠道检测案例：见 [references/fingerprint-matrix.md](references/fingerprint-matrix.md)
- 历史检测报告 JSON：`references/*.json`
