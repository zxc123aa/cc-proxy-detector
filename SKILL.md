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

## 参考资料

- 三源指纹矩阵与已知渠道检测案例：见 [references/fingerprint-matrix.md](references/fingerprint-matrix.md)
- 历史检测报告 JSON：`references/*.json`
