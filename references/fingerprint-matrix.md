# CC Proxy Detector v5.1 - Claude Code 中转来源检测工具

检测 Claude Code 中转站后端来源: **Anthropic 官方** / **AWS Bedrock (Kiro)** / **Google Antigravity (Vertex AI)** / **疑似伪装**

支持**混合渠道检测**: 同一中转站不同模型可能路由到不同后端。

v5.1 新增: **缺失字段负面证据**机制，识别重写 tool_id + 注入 service_tier 的防检测伪装。

## 三源指纹矩阵

| 指纹 | Anthropic 原生 | Bedrock (Kiro) | Antigravity (Vertex) |
|------|---------------|----------------|---------------------|
| tool_use id | `toolu_` | `tooluse_` | `tooluse_` / `tool_N` |
| message id | `msg_<base62>` | UUID / `msg_<UUID>` | `msg_<UUID>` / `req_vrtx_` |
| thinking sig | len 200+ | len 200+ / 截断 | `claude#` 前缀 / 截断 |
| model 格式 | `claude-*` | `kiro-*` / `anthropic.*` | `claude-*` |
| service_tier | 有 (standard) | 无 | 无 |
| inference_geo | 有 | 无 | 无 |
| rate-limit hdr | `anthropic-ratelimit-*` | 无 | 无 |
| cache_creation | 嵌套对象 | 无 | 无 |
| AWS headers | 无 | 可能有 `x-amzn-*` | 无 |
| usage 字段 | snake_case | camelCase / 改写 | snake_case |

## 指纹可靠性分级

### 铁证级 (中转站几乎无法伪造)

| 指纹 | 指向 | 说明 |
|------|------|------|
| `kiro-*` model 前缀 | Kiro/Bedrock | 如 `kiro-claude-sonnet-4-5-agentic`，model 字段泄露 |
| `req_vrtx_` message id | Vertex AI | Google Vertex AI 原生请求 ID |
| `tool_N` tool_use id | Vertex AI | Vertex 简化 ID 格式，如 `tool_1` |
| `claude#` thinking 签名 | Vertex AI | Vertex 原生签名前缀 |
| `inference_geo` 字段 | Anthropic | **Anthropic 必有**，Bedrock/Vertex 无此字段，中转站无法伪造 |
| `cache_creation` 嵌套对象 | Anthropic | Anthropic 新格式，中转站难以凭空构造 |
| thinking signature (len 200+) | Anthropic/Bedrock | thinking 探测轮应有签名，被清洗为 0 说明中转站干预 |

### 参考级 (中转站已知可伪造/注入)

| 指纹 | 风险 |
|------|------|
| `toolu_` vs `tooluse_` | ⚠️ **已被突破**: 中转站可重写 `tooluse_` → `toolu_` |
| `service_tier` 字段 | ⚠️ **已被突破**: 中转站可注入 `service_tier=standard` |
| `cache_creation` 嵌套对象 | 中转站可注入，不可单独作为 Anthropic 判据 |
| `msg_` 前缀 | 中转站可能拼出 `msg_msg_` 双前缀导致误判 |
| model 格式 | 中转站通常会改写为标准格式 |
| usage 字段风格 | 中转站通常会做 camelCase → snake_case 转换 |

## 检测工作流

```
1. 自动选择可用模型 (或 --scan-all 扫描全部)
2. 对每个模型发送:
   ├── N 轮 tool_use 探测 → 提取 tool_id 前缀、msg_id 格式
   └── 1 轮 thinking 探测 → 提取 thinking signature、service_tier
3. 采集响应 headers → AWS/Anthropic/中转平台指纹
4. 采集响应 body → model 格式、usage 风格、cache_creation
5. 多维指纹正面评分 → 三源初步判定
6. [v5.1] 缺失字段负面证据 → 检查 inference_geo / cache_creation / thinking_sig
   ├── 正面指纹全指向 Anthropic 但必有字段缺失 → 扣分
   └── 缺失 ≥ 2 个必有字段 → 判定"疑似伪装"
7. 人工复核原始数据 → 最终结论
```

**重要**: 脚本是采集工具，不是裁判。自动评分只能处理已知模式，遇到中转站的新花样（双前缀、字段注入、ID 重写等）会误判。最终结论需要人看原始指纹数据。

## 已知渠道检测结果

### 1. charitydoing.com (AccountHub 平台)

#### 1.1 首次检测 (已过时)

| 模型 | 判定 | 关键证据 |
|------|------|---------|
| sonnet | **Bedrock/Kiro** | `tooluse_` 前缀 |

- 中转平台: Aidistri (`X-Aidistri-Request-Id`)
- 中转站清洗了 model/usage/headers，但 `tooluse_` 前缀泄露了 Bedrock 来源

#### 1.2 二次检测 - 防检测升级后

| 模型 | 表面判定 | 实际疑点 |
|------|---------|---------|
| sonnet | Anthropic (100%) | `inference_geo` 缺失, thinking_sig=0, 无 anthropic headers |
| haiku | Anthropic (100%) | 同上 |

- 中转平台从 Aidistri 切换为 **AccountHub**
- **疑似 ID 重写**: `tooluse_` → `toolu_`，注入 `service_tier=standard`
- 但无法伪造的字段全部缺失：

| 指纹 | 真 Anthropic (superaichao) | charitydoing 现在 | 说明 |
|------|--------------------------|-------------------|------|
| `toolu_` 前缀 | ✅ | ✅ | 可重写 |
| `service_tier` | ✅ | ✅ | 可注入 |
| `inference_geo` | ✅ | ❌ | **无法伪造** |
| rate-limit headers | ✅ | ❌ | **无法伪造** |
| `thinking_signature` | 正常(200+字节) | len=0 | **被清洗** |
| `cache_creation_obj` | ✅ | ❌ | 未注入 |

- **结论**: 自动评分被骗到 100% Anthropic，但缺失的字段组合高度可疑。真正的 Anthropic 官方不会同时缺少 `inference_geo`、rate-limit headers 和 thinking signature
- **教训**: 中转站已学会重写 tool_id 前缀和注入 service_tier，检测器需要引入"缺失字段"负面证据

### 2. superaichao.xin

| 模型 | 判定 | 关键证据 |
|------|------|---------|
| sonnet | **Anthropic 官方** | `toolu_` 前缀, `service_tier=standard`, `inference_geo` |

- 三个 Anthropic 独有字段全部命中，确认官方 API

### 3. bookapi.cc

| 模型 | 判定 | 关键证据 |
|------|------|---------|
| sonnet | **Anthropic Max** | `toolu_` 前缀, `service_tier=standard`, `anthropic-ratelimit-unified-5h-*` headers |

- 泄露 Max 订阅专属 rate-limit headers，显示 74% 额度利用率
- 确认为 Anthropic Max 订阅而非普通 API Key

### 4. stonefancyx.com (混合渠道)

| 模型 | 判定 | 关键证据 |
|------|------|---------|
| opus-thinking | **Antigravity/Vertex** | `tool_1`, `req_vrtx_`, `claude#` 签名前缀 |
| sonnet | **Kiro/Bedrock** | `tooluse_`, model=`kiro-claude-sonnet-4-5-agentic` |

- 典型混合渠道: opus 走 Google Vertex AI，sonnet 走 AWS Bedrock (Kiro)
- opus 通道泄露大量 Vertex 原生指纹 (`req_vrtx_`, `tool_1`, `claude#`)
- sonnet 通道 model 字段直接暴露 `kiro-` 前缀

### 5. gptgod (混合渠道 - 多域名多后端)

#### 5.1 第一渠道 (gptgod.cloud)

| 模型 | 判定 | 关键证据 | 备注 |
|------|------|---------|------|
| opus-thinking | Bedrock/Kiro (56%) | `tooluse_` 前缀 | `msg_msg_` 双前缀 + `cache_creation` 注入干扰评分 |
| sonnet | Bedrock/Kiro (56%) | `tooluse_` 前缀 | 同上 |
| haiku | 未知 (0%) | tool_id 丢失 | 中转站对 haiku 处理管道不同 |

- 中转站拼接 ID 时产生 `msg_msg_` 双前缀，导致分类器误判为 Anthropic
- 中转站注入了 `cache_creation` 嵌套对象，本以为 Anthropic 独有
- **教训**: 自动评分被两个参考级指纹干扰，实际 `tooluse_` 铁证已指向 Bedrock

#### 5.2 第二渠道 (new.gptgod.cloud)

| 模型 | 判定 | 关键证据 |
|------|------|---------|
| sonnet | **Anthropic 官方** | `toolu_` 前缀, `service_tier=standard`, `inference_geo` |
| haiku | **Anthropic 官方** | `toolu_` 前缀, `service_tier=standard`, `inference_geo` |

- 三个 Anthropic 独有字段全部命中 (`toolu_`, `service_tier`, `inference_geo`)
- `msg_<base62>` 格式（无连字符，Anthropic 原生）
- thinking signature 正常长度（292-296 字节）
- **结论**: 典型多渠道架构 - 不同域名路由到不同后端（Bedrock + Anthropic 官方混用）

## 使用

```bash
# 单模型自动检测 (自动选 sonnet/haiku)
python3 detect.py

# 指定模型检测
python3 detect.py --model claude-opus-4-6-thinking

# 多模型扫描 (混合渠道检测)
python3 detect.py --scan-all

# 自定义扫描模型列表
python3 detect.py --scan-models "claude-opus-4-6-thinking,claude-sonnet-4-5-20250929"

# 多轮采样
python3 detect.py --scan-all --rounds 3

# JSON 输出 + 保存
python3 detect.py --scan-all --json --output report.json

# 手动指定地址和密钥
python3 detect.py --base-url https://your-proxy.com --api-key sk-xxx
```

## 环境变量

| 变量 | 说明 |
|------|------|
| `ANTHROPIC_BASE_URL` | 中转站地址 (默认读取) |
| `ANTHROPIC_AUTH_TOKEN` | API Key (优先) |
| `FACTORY_API_KEY` | API Key (备选) |

## 依赖

```bash
pip install requests
```
