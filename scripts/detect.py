#!/usr/bin/env python3
"""
CC Proxy Detector v5.2 - Claude Code 中转来源检测工具
检测中转站后端来源: Anthropic 官方 | AWS Bedrock (Kiro) | Google Antigravity
支持混合渠道检测: 不同模型可能路由到不同后端

三源指纹矩阵:
  指纹维度          Anthropic 官方        Bedrock (Kiro)       Antigravity (Google)
  ─────────────     ──────────────        ──────────────       ────────────────────
  tool_use id       toolu_                tooluse_             tooluse_ / tool_N
  message id        msg_<base62>          UUID / msg_<UUID>    msg_<UUID> / req_vrtx_
  thinking sig      len 200+              len 200+ / 截断      claude# 前缀 / 截断
  model 格式        claude-*              kiro-* / anthropic.* claude-*
  service_tier      有 (standard)         无                   无
  inference_geo     有                    无                   无
  cache_creation    嵌套对象              无                   无
  rate-limit hdr    anthropic-ratelimit   无                   无
  AWS headers       无                    可能有               无
  usage 字段        snake_case            camelCase / 改写     snake_case
"""
import argparse
import json
import os
import re
import sys
import time
import concurrent.futures
from dataclasses import dataclass, field, asdict

try:
    import requests
except ImportError:
    print("需要 requests: pip install requests")
    sys.exit(1)


# ── 指纹常量 ──────────────────────────────────────────────

ANTHROPIC_TOOL_PREFIX = "toolu_"
BEDROCK_TOOL_PREFIX = "tooluse_"
ANTHROPIC_MSG_PREFIX = "msg_"
BEDROCK_MODEL_PREFIX = "anthropic."
KIRO_MODEL_PREFIX = "kiro-"

# Anthropic 原生 msg id: msg_ + base62 (无连字符, 如 msg_01PzoexiYoH5j9X4TZWfkx5q)
# Antigravity 伪造:      msg_ + UUID (有连字符, 可能截断, 如 msg_5a4e4f0a-d67d-4424-a1dc-)
# 关键区别: base62 不含连字符, UUID 含连字符
MSG_ID_UUID_PATTERN = re.compile(
    r"^msg_[0-9a-f]{8}-[0-9a-f]{4}-",
    re.IGNORECASE,
)

# thinking signature 长度阈值
THINKING_SIG_SHORT_THRESHOLD = 100  # Antigravity 签名通常 < 100

AWS_HEADER_KEYWORDS = ("x-amzn", "x-amz-", "bedrock")
ANTHROPIC_HEADER_KEYWORDS = ("anthropic-ratelimit", "x-ratelimit", "retry-after")

# 扫描模型列表 (按优先级)
SCAN_MODELS = [
    "claude-opus-4-6-thinking",
    "claude-opus-4-6-20250918",
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",
    "claude-3-5-sonnet-20241022",
    "claude-3-haiku-20240307",
]

# 自动选模型用 (排除 opus 以节省额度)
PROBE_MODELS = [
    "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001",
    "claude-3-5-sonnet-20241022",
    "claude-3-haiku-20240307",
]


# ── 数据结构 ─────────────────────────────────────────────

@dataclass
class Fingerprint:
    """单次探测的指纹"""
    # 核心指纹
    tool_id: str = ""
    tool_id_source: str = "unknown"       # anthropic / bedrock / rewritten
    msg_id: str = ""
    msg_id_source: str = "unknown"        # anthropic / antigravity / rewritten
    msg_id_format: str = ""               # base62 / msg_uuid / uuid / other
    model: str = ""
    model_requested: str = ""
    model_source: str = "unknown"
    usage_style: str = "unknown"
    # thinking 指纹
    thinking_supported: bool = False
    thinking_signature: str = ""
    thinking_sig_prefix: str = ""
    thinking_sig_len: int = 0
    thinking_sig_class: str = ""          # normal / short / none
    # usage 扩展字段
    has_service_tier: bool = False
    service_tier: str = ""
    has_inference_geo: bool = False
    inference_geo: str = ""
    has_cache_creation_obj: bool = False
    # header 指纹
    has_aws_headers: bool = False
    has_anthropic_headers: bool = False
    aws_headers_found: list = field(default_factory=list)
    anthropic_headers_found: list = field(default_factory=list)
    # 中转站指纹
    proxy_platform: str = ""
    proxy_headers: list = field(default_factory=list)
    # ratelimit 动态验证
    ratelimit_input_limit: int = 0
    ratelimit_input_remaining: int = 0
    ratelimit_input_reset: str = ""
    # 元数据
    latency_ms: int = 0
    stop_reason: str = ""
    error: str = ""
    probe_type: str = ""
    raw_headers: dict = field(default_factory=dict)
    raw_body: dict = field(default_factory=dict)


@dataclass
class DetectResult:
    """单模型检测结果"""
    verdict: str = "unknown"      # anthropic / bedrock / antigravity / unknown
    confidence: float = 0.0
    scores: dict = field(default_factory=dict)
    evidence: list = field(default_factory=list)
    fingerprints: list = field(default_factory=list)
    base_url: str = ""
    model: str = ""
    rounds: int = 0
    avg_latency_ms: int = 0
    proxy_platform: str = ""
    ratelimit_dynamic: str = ""  # dynamic / static / unavailable


@dataclass
class ScanResult:
    """多模型扫描结果"""
    base_url: str = ""
    proxy_platform: str = ""
    model_results: list = field(default_factory=list)  # list of DetectResult
    summary: dict = field(default_factory=dict)         # model -> verdict
    is_mixed: bool = False


# ── 探测 Payload ─────────────────────────────────────────

def build_tool_payload(model: str) -> dict:
    return {
        "model": model,
        "max_tokens": 50,
        "tools": [{
            "name": "probe",
            "description": "Probe function",
            "input_schema": {
                "type": "object",
                "properties": {"q": {"type": "string"}},
                "required": ["q"]
            }
        }],
        "tool_choice": {"type": "tool", "name": "probe"},
        "messages": [{"role": "user", "content": "call probe with q=test"}],
    }


def build_thinking_payload(model: str) -> dict:
    return {
        "model": model,
        "max_tokens": 2048,
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [{"role": "user", "content": "What is 2+3?"}],
    }


def build_simple_payload(model: str) -> dict:
    return {
        "model": model,
        "max_tokens": 5,
        "messages": [{"role": "user", "content": "Say OK"}],
    }


# ── 辅助分析 ─────────────────────────────────────────────

def classify_msg_id(msg_id: str) -> tuple[str, str]:
    """分类 message id 格式, 返回 (source, format)
    - anthropic:    msg_ + base62 (无连字符, 如 msg_01PzoexiYoH5j9X4TZWfkx5q)
    - antigravity:  msg_ + UUID  (有连字符, 如 msg_8a5da866-783c-4dad-...)
    - vertex:       req_vrtx_ 前缀 (Google Vertex AI)
    - rewritten:    纯 UUID 或其他
    """
    if not msg_id:
        return "unknown", ""

    # Google Vertex AI 请求 ID
    if msg_id.startswith("req_vrtx_"):
        return "vertex", "req_vrtx"

    if msg_id.startswith(ANTHROPIC_MSG_PREFIX):
        if MSG_ID_UUID_PATTERN.match(msg_id):
            return "antigravity", "msg_uuid"
        else:
            return "anthropic", "base62"
    else:
        # 检查是否是纯 UUID
        uuid_pat = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            re.IGNORECASE,
        )
        if uuid_pat.match(msg_id):
            return "rewritten", "uuid"
        return "rewritten", "other"


def classify_thinking_sig(sig: str) -> str:
    """分类 thinking signature"""
    if not sig:
        return "none"
    if len(sig) < THINKING_SIG_SHORT_THRESHOLD:
        return "short"  # Antigravity 特征 (伪装转发)
    if sig.startswith("claude#"):
        return "vertex"  # Google Vertex AI 原生签名
    return "normal"


def detect_proxy_platform(headers: dict) -> tuple[str, list]:
    """从响应 header 中识别中转平台"""
    h = {k.lower(): v for k, v in headers.items()}
    platform = ""
    clues = []

    if any("aidistri" in k for k in h):
        platform = "Aidistri"
        clues.append("X-Aidistri-Request-Id")

    cors = h.get("access-control-allow-headers", "")
    if "accounthub" in cors.lower():
        if not platform:
            platform = "AccountHub"
        pool_headers = [x.strip() for x in cors.split(",")
                        if "accounthub" in x.lower() or "pool" in x.lower()]
        clues.extend(pool_headers[:5])

    if any("openrouter" in k or "openrouter" in str(h.get(k, "")) for k in h):
        platform = "OpenRouter"
        clues.append("OpenRouter header detected")

    if any("one-api" in k or "new-api" in k for k in h):
        platform = "OneAPI/NewAPI"
        clues.append("OneAPI header detected")

    if h.get("server") == "cloudflare" and "cf-ray" in h:
        clues.append(f"CF-Ray: {h['cf-ray']}")

    return platform, clues


# ── 探测主函数 ────────────────────────────────────────────

def probe_once(base_url: str, api_key: str, model: str,
               probe_type: str = "tool", verbose: bool = False) -> Fingerprint:
    """发送一次探测请求，提取指纹"""
    fp = Fingerprint()
    fp.probe_type = probe_type
    fp.model_requested = model
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": api_key,
        "Authorization": f"Bearer {api_key}",
    }

    if probe_type == "tool":
        payload = build_tool_payload(model)
    elif probe_type == "thinking":
        payload = build_thinking_payload(model)
    else:
        payload = build_simple_payload(model)

    url = f"{base_url}/v1/messages"

    t0 = time.time()
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.exceptions.RequestException as e:
        fp.error = str(e)
        return fp
    fp.latency_ms = int((time.time() - t0) * 1000)

    if resp.status_code != 200:
        fp.error = f"HTTP {resp.status_code}: {resp.text[:200]}"
        return fp

    # ── Headers ──
    fp.raw_headers = dict(resp.headers)
    for k, v in resp.headers.items():
        kl = k.lower()
        if any(kw in kl for kw in AWS_HEADER_KEYWORDS):
            fp.has_aws_headers = True
            fp.aws_headers_found.append(f"{k}: {v}")
        if any(kw in kl for kw in ANTHROPIC_HEADER_KEYWORDS):
            fp.has_anthropic_headers = True
            fp.anthropic_headers_found.append(f"{k}: {v}")
        # 提取 ratelimit 数值
        if kl == "anthropic-ratelimit-input-tokens-limit":
            try: fp.ratelimit_input_limit = int(v)
            except: pass
        elif kl == "anthropic-ratelimit-input-tokens-remaining":
            try: fp.ratelimit_input_remaining = int(v)
            except: pass
        elif kl == "anthropic-ratelimit-input-tokens-reset":
            fp.ratelimit_input_reset = v

    fp.proxy_platform, fp.proxy_headers = detect_proxy_platform(resp.headers)

    # ── Body ──
    try:
        body = resp.json()
    except ValueError:
        fp.error = "响应体非 JSON"
        return fp

    if verbose:
        fp.raw_body = body

    # 1) tool_use id
    for block in body.get("content", []):
        if block.get("type") == "tool_use":
            fp.tool_id = block.get("id", "")
            if fp.tool_id.startswith(BEDROCK_TOOL_PREFIX):
                fp.tool_id_source = "bedrock"
            elif fp.tool_id.startswith(ANTHROPIC_TOOL_PREFIX):
                fp.tool_id_source = "anthropic"
            elif re.match(r"^tool_\d+$", fp.tool_id):
                fp.tool_id_source = "vertex"  # Google Vertex AI 简化 ID
            else:
                fp.tool_id_source = "rewritten"
            break

    # 2) thinking signature
    for block in body.get("content", []):
        if block.get("type") == "thinking":
            fp.thinking_supported = True
            sig = block.get("signature", "")
            fp.thinking_signature = sig
            fp.thinking_sig_len = len(sig)
            fp.thinking_sig_prefix = sig[:24] if sig else ""
            fp.thinking_sig_class = classify_thinking_sig(sig)
            break

    # 3) message id (区分 Anthropic 原生 / Antigravity 伪造 / 纯改写)
    fp.msg_id = body.get("id", "")
    fp.msg_id_source, fp.msg_id_format = classify_msg_id(fp.msg_id)

    # 4) model
    fp.model = body.get("model", "")
    if fp.model.startswith(KIRO_MODEL_PREFIX):
        fp.model_source = "kiro"
    elif fp.model.startswith(BEDROCK_MODEL_PREFIX):
        fp.model_source = "bedrock"
    elif fp.model:
        fp.model_source = "anthropic"

    # 5) usage
    usage = body.get("usage", {})
    if "inputTokens" in usage:
        fp.usage_style = "camelCase"
    elif "input_tokens" in usage:
        fp.usage_style = "snake_case"

    if "service_tier" in usage:
        fp.has_service_tier = True
        fp.service_tier = str(usage["service_tier"])
    if "inference_geo" in usage:
        fp.has_inference_geo = True
        fp.inference_geo = str(usage["inference_geo"])
    if isinstance(usage.get("cache_creation"), dict):
        fp.has_cache_creation_obj = True

    # 6) stop_reason
    fp.stop_reason = body.get("stop_reason", "")

    return fp


# ── 三源综合分析 ─────────────────────────────────────────

def analyze(fingerprints: list[Fingerprint], base_url: str,
            model: str = "") -> DetectResult:
    """多轮指纹三源判定: anthropic / bedrock / antigravity"""
    result = DetectResult(base_url=base_url, rounds=len(fingerprints), model=model)
    evidence = []
    scores = {"anthropic": 0, "bedrock": 0, "antigravity": 0}

    valid_fps = [fp for fp in fingerprints if not fp.error]
    if not valid_fps:
        result.verdict = "unknown"
        result.evidence = ["所有探测均失败"]
        result.scores = scores
        return result

    result.avg_latency_ms = sum(fp.latency_ms for fp in valid_fps) // len(valid_fps)

    # 中转平台
    platforms = [fp.proxy_platform for fp in valid_fps if fp.proxy_platform]
    if platforms:
        result.proxy_platform = platforms[0]
        evidence.append(f"中转平台: {result.proxy_platform}")

    for i, fp in enumerate(valid_fps):
        tag = f"[R{i+1}]"

        # ── 1. tool_use id (权重 5) ──
        if fp.tool_id_source == "bedrock":
            # tooluse_ 可能是 Bedrock/Kiro 或 Antigravity，先暂记 bedrock
            scores["bedrock"] += 5
            evidence.append(f"{tag} tool_use id: {fp.tool_id[:28]}  -> tooluse_ (Bedrock/AG)")
        elif fp.tool_id_source == "anthropic":
            scores["anthropic"] += 5
            evidence.append(f"{tag} tool_use id: {fp.tool_id[:28]}  -> toolu_ (Anthropic)")
        elif fp.tool_id_source == "vertex":
            scores["antigravity"] += 5
            evidence.append(f"{tag} tool_use id: {fp.tool_id[:28]}  -> tool_N (Vertex AI)")
        elif fp.tool_id and fp.tool_id_source == "rewritten":
            evidence.append(f"{tag} tool_use id: {fp.tool_id[:28]}  -> 被改写")

        # ── 2. thinking signature ──
        if fp.thinking_supported:
            if fp.thinking_sig_class == "short":
                # 签名截断: 单独不足以判定，需结合其他指纹
                evidence.append(
                    f"{tag} thinking sig: {fp.thinking_sig_prefix}... "
                    f"(len={fp.thinking_sig_len}) -> 签名截断")
            elif fp.thinking_sig_class == "vertex":
                scores["antigravity"] += 5
                evidence.append(
                    f"{tag} thinking sig: {fp.thinking_sig_prefix}... "
                    f"(len={fp.thinking_sig_len}) -> claude# 前缀 (Vertex AI)")
            elif fp.thinking_sig_class == "normal":
                evidence.append(
                    f"{tag} thinking sig: {fp.thinking_sig_prefix}... "
                    f"(len={fp.thinking_sig_len}) -> 正常签名")
            elif fp.thinking_sig_class == "none":
                evidence.append(f"{tag} thinking sig: 无签名")

        # ── 3. message id ──
        if fp.msg_id_source == "anthropic":
            scores["anthropic"] += 2
            evidence.append(f"{tag} message id:  {fp.msg_id[:28]}  -> msg_<base62> (Anthropic)")
        elif fp.msg_id_source == "antigravity":
            # msg_<UUID> 可能是 Antigravity 伪造 或 Kiro 中转改写，先暂记
            evidence.append(f"{tag} message id:  {fp.msg_id[:28]}  -> msg_<UUID> (非原生)")
        elif fp.msg_id_source == "vertex":
            scores["antigravity"] += 6
            evidence.append(f"{tag} message id:  {fp.msg_id[:28]}  -> req_vrtx_ (Vertex AI)")
        elif fp.msg_id_source == "rewritten":
            evidence.append(f"{tag} message id:  {fp.msg_id[:28]}  -> 被改写")

        # ── 4. model 格式 (关键区分 Kiro vs Antigravity) ──
        if fp.model_source == "kiro":
            scores["bedrock"] += 8
            evidence.append(f"{tag} model:       {fp.model}  -> kiro-* (Kiro 逆向铁证)")
        elif fp.model_source == "bedrock":
            scores["bedrock"] += 3
            evidence.append(f"{tag} model:       {fp.model}  -> anthropic.* (Bedrock)")

        # ── 5. service_tier / inference_geo (Anthropic 独有) ──
        if fp.has_service_tier:
            scores["anthropic"] += 3
            evidence.append(f"{tag} service_tier: {fp.service_tier}  -> Anthropic 独有")
        if fp.has_inference_geo:
            scores["anthropic"] += 2
            evidence.append(f"{tag} inference_geo: {fp.inference_geo}  -> Anthropic 独有")
        if fp.has_cache_creation_obj:
            scores["anthropic"] += 1
            evidence.append(f"{tag} cache_creation: 嵌套对象  -> Anthropic 新格式")

        # ── 6. usage 风格 ──
        if fp.usage_style == "camelCase":
            scores["bedrock"] += 2
            evidence.append(f"{tag} usage:       camelCase (Bedrock)")

        # ── 7. AWS headers ──
        if fp.has_aws_headers:
            scores["bedrock"] += 3
            evidence.append(f"{tag} AWS headers: {', '.join(fp.aws_headers_found[:3])}")

        # ── 8. Anthropic rate-limit headers ──
        if fp.has_anthropic_headers:
            scores["anthropic"] += 2
            evidence.append(f"{tag} Anthropic headers: {', '.join(fp.anthropic_headers_found[:3])}")

    # ── 二次修正: tooluse_ 归属 ──
    # 如果有 Vertex/Antigravity 强信号 且没有 kiro- model，tooluse_ 应归 Antigravity
    has_kiro_model = any(fp.model_source == "kiro" for fp in valid_fps)
    has_vertex_signal = any(
        fp.tool_id_source == "vertex" or fp.msg_id_source == "vertex"
        or fp.thinking_sig_class == "vertex"
        for fp in valid_fps
    )

    if not has_kiro_model and scores["antigravity"] > 0 and scores["bedrock"] > 0:
        tooluse_points = sum(
            5 for fp in valid_fps
            if fp.tool_id_source == "bedrock"
        )
        if scores["antigravity"] >= 4:
            scores["antigravity"] += tooluse_points
            scores["bedrock"] -= tooluse_points
            evidence.append(f"[修正] tooluse_ 分数 {tooluse_points} 从 Bedrock 转移到 Antigravity")

    # 如果有 kiro- model，msg_<UUID> 也应归 Bedrock 而非 Antigravity
    if has_kiro_model:
        msg_uuid_count = sum(
            1 for fp in valid_fps
            if fp.msg_id_source == "antigravity"
        )
        if msg_uuid_count > 0:
            evidence.append(f"[修正] msg_<UUID> x{msg_uuid_count} 归属 Kiro 中转改写 (非 Antigravity)")

    # ── 三次修正: 缺失字段负面证据 ──
    # 当正面指纹全指向 anthropic 时，检查"应有字段"是否缺失
    # 可靠区分字段 (真 Anthropic 必有，中转站无法伪造):
    #   - inference_geo: Anthropic 官方始终返回此字段
    #   - cache_creation 嵌套对象: Anthropic 新格式
    #   - thinking_signature: thinking 探测轮应有正常签名 (len 200+)
    # 不可靠字段 (真 Anthropic 也可能缺失，不用于扣分):
    #   - anthropic rate-limit headers: 可能被中转站剥离
    missing_flags = []
    has_thinking_probe = any(fp.probe_type == "thinking" for fp in valid_fps)

    if scores["anthropic"] > 0 and scores["bedrock"] == 0 and scores["antigravity"] == 0:
        # 检查 inference_geo (权重高 - 真 Anthropic 必有)
        any_inference_geo = any(fp.has_inference_geo for fp in valid_fps)
        if not any_inference_geo:
            missing_flags.append("inference_geo")
            scores["anthropic"] -= 3
            evidence.append("[缺失] inference_geo 未出现 (Anthropic 官方必有字段)")

        # 检查 cache_creation 嵌套对象 (权重中)
        any_cache_obj = any(fp.has_cache_creation_obj for fp in valid_fps)
        if not any_cache_obj:
            missing_flags.append("cache_creation_obj")
            scores["anthropic"] -= 2
            evidence.append("[缺失] cache_creation 嵌套对象未出现")

        # 检查 thinking signature (仅检查 thinking 探测轮，真 Anthropic 应有 len 200+)
        if has_thinking_probe:
            thinking_fps = [fp for fp in valid_fps if fp.probe_type == "thinking"]
            any_thinking_sig = any(fp.thinking_sig_len > 0 for fp in thinking_fps)
            if not any_thinking_sig:
                missing_flags.append("thinking_signature")
                scores["anthropic"] -= 3
                evidence.append("[缺失] thinking signature 为空 (真 Anthropic thinking 轮应有 len 200+ 签名)")

        # 以下仅作为辅助参考记录，不扣分
        any_anthropic_hdrs = any(fp.has_anthropic_headers for fp in valid_fps)
        if not any_anthropic_hdrs:
            evidence.append("[参考] anthropic rate-limit headers 未出现 (可能被中转剥离)")

    # 确保分数不为负
    for k in scores:
        if scores[k] < 0:
            scores[k] = 0

    # ── 判定 ──
    total = sum(scores.values())
    result.scores = scores
    suspicious = False

    if total == 0:
        if missing_flags:
            # 所有正面分被扣光 → 高度可疑
            result.verdict = "anthropic"
            result.confidence = 0.0
            suspicious = True
            evidence.append(f"[!] 正面分数被缺失扣分抵消，高度可疑伪装 Anthropic")
        else:
            result.verdict = "unknown"
            result.confidence = 0.0
            evidence.append("未获取到有效指纹信号")
    else:
        winner = max(scores, key=scores.get)
        result.verdict = winner
        result.confidence = round(scores[winner] / total, 2)
        # 两个可靠字段都缺失 → 标记可疑
        if winner == "anthropic" and len(missing_flags) >= 2:
            suspicious = True

    if suspicious:
        result.verdict = "suspicious"
        evidence.append(
            f"[!!] 疑似伪装 Anthropic: {len(missing_flags)} 个必有字段缺失 "
            f"({', '.join(missing_flags)})")
        evidence.append(
            "[!!] 中转站可能重写了 tool_id 前缀并注入 service_tier，"
            "但无法伪造 inference_geo 和 cache_creation 嵌套对象")

    result.evidence = evidence
    result.fingerprints = [asdict(fp) for fp in fingerprints]
    return result


# ── 输出 ─────────────────────────────────────────────────

VERDICT_MAP = {
    "anthropic":    "Anthropic 官方 API (Max / API Key)",
    "bedrock":      "AWS Bedrock (Kiro 逆向)",
    "antigravity":  "Google Antigravity (Vertex AI 逆向)",
    "suspicious":   "疑似伪装 Anthropic (缺失字段过多)",
    "unknown":      "无法确定",
}

VERDICT_ICON = {
    "anthropic":   "[+]",
    "bedrock":     "[K]",
    "antigravity": "[G]",
    "suspicious":  "[!]",
    "unknown":     "[?]",
}

VERDICT_SHORT = {
    "anthropic":   "Anthropic",
    "bedrock":     "Kiro/Bedrock",
    "antigravity": "Antigravity",
    "suspicious":  "疑似伪装",
    "unknown":     "???",
}


def print_report(result: DetectResult):
    """打印单模型检测报告"""
    v = result.verdict
    print()
    print("+" + "=" * 60 + "+")
    print("|          CC Proxy Detector v5.2 - 检测报告                |")
    print("+" + "=" * 60 + "+")
    print()
    print(f"  目标:       {result.base_url}")
    if result.model:
        print(f"  模型:       {result.model}")
    print(f"  采样轮次:   {result.rounds}")
    print(f"  平均延迟:   {result.avg_latency_ms}ms")
    if result.proxy_platform:
        print(f"  中转平台:   {result.proxy_platform}")
    print()
    print(f"  {VERDICT_ICON.get(v, '?')} 判定: {VERDICT_MAP.get(v, v)}")
    print(f"  置信度:     {result.confidence:.0%}")
    s = result.scores
    print(f"  评分:       Anthropic={s.get('anthropic',0)}  "
          f"Bedrock={s.get('bedrock',0)}  "
          f"Antigravity={s.get('antigravity',0)}")
    print()

    # 证据链
    print("-- 证据链 " + "-" * 50)
    for e in result.evidence:
        print(f"  {e}")
    print()

    # 指纹摘要表
    print("-- 指纹摘要 " + "-" * 48)
    print(f"  {'#':<3}  {'探测':<8}  {'tool_id':<10}  {'msg_id':<12}  "
          f"{'svc_tier':<10}  {'think':<8}  {'ms':<6}")
    print(f"  {'─'*3}  {'─'*8}  {'─'*10}  {'─'*12}  {'─'*10}  {'─'*8}  {'─'*6}")
    for i, fp_dict in enumerate(result.fingerprints):
        if fp_dict.get("error"):
            print(f"  {i+1:<3}  FAIL: {fp_dict['error'][:48]}")
            continue
        svc = fp_dict.get("service_tier", "") or "-"
        sig_cls = fp_dict.get("thinking_sig_class", "") or "-"
        msg_src = fp_dict.get("msg_id_source", "?")
        if fp_dict.get("msg_id_format") == "msg_uuid":
            msg_src = "ag_fake"
        elif fp_dict.get("msg_id_format") == "req_vrtx":
            msg_src = "vertex"
        print(f"  {i+1:<3}  "
              f"{fp_dict.get('probe_type', '?'):<8}  "
              f"{fp_dict['tool_id_source']:<10}  "
              f"{msg_src:<12}  "
              f"{svc:<10}  "
              f"{sig_cls:<8}  "
              f"{fp_dict['latency_ms']:<6}")
    print()

    # 指纹说明
    print("-- 三源指纹说明 " + "-" * 44)
    print("                   Anthropic       Bedrock(Kiro)    Antigravity(Google)")
    print("  tool_use id:     toolu_          tooluse_         tooluse_ / tool_N")
    print("  message id:      msg_<base62>    UUID/msg_<UUID>  msg_<UUID> / req_vrtx_")
    print("  thinking sig:    len 200+        len 200+/截断    claude#前缀 / 截断")
    print("  model:           claude-*        kiro-*/anthropic.*  claude-*")
    print("  service_tier:    有              无               无")
    print("  inference_geo:   有              无               无")
    print("  rate-limit hdr:  有              无               无")
    print()


def print_scan_report(scan: ScanResult):
    """打印多模型扫描报告"""
    print()
    print("+" + "=" * 68 + "+")
    print("|          CC Proxy Detector v5.2 - 多模型扫描报告                  |")
    print("+" + "=" * 68 + "+")
    print()
    print(f"  目标:       {scan.base_url}")
    if scan.proxy_platform:
        print(f"  中转平台:   {scan.proxy_platform}")
    print(f"  扫描模型:   {len(scan.model_results)} 个")
    if scan.is_mixed:
        print(f"  混合渠道:   是 (不同模型路由到不同后端)")
    else:
        verdicts = set(scan.summary.values())
        verdicts.discard("unavailable")
        if verdicts:
            v = list(verdicts)[0]
            print(f"  统一渠道:   {VERDICT_MAP.get(v, v)}")
    print()

    # 总览表
    print("=" * 68)
    print(f"  {'模型':<36}  {'来源':<18}  {'置信度':<8}  {'延迟':<6}")
    print(f"  {'─'*36}  {'─'*18}  {'─'*8}  {'─'*6}")

    for r in scan.model_results:
        model_name = r.model
        if r.verdict == "unavailable":
            print(f"  {model_name:<36}  {'不可用':<18}  {'-':<8}  {'-':<6}")
        else:
            icon = VERDICT_ICON.get(r.verdict, "?")
            short = VERDICT_SHORT.get(r.verdict, r.verdict)
            conf = f"{r.confidence:.0%}"
            lat = f"{r.avg_latency_ms}ms"
            print(f"  {model_name:<36}  {icon} {short:<14}  {conf:<8}  {lat:<6}")

    print()

    # 详细证据 (每个模型)
    for r in scan.model_results:
        if r.verdict == "unavailable":
            continue

        v = r.verdict
        print(f"-- [{r.model}] " + "-" * (54 - len(r.model)))
        print(f"   判定: {VERDICT_ICON.get(v, '?')} {VERDICT_MAP.get(v, v)} "
              f"(置信度 {r.confidence:.0%})")
        s = r.scores
        print(f"   评分: Anthropic={s.get('anthropic',0)} "
              f"Bedrock={s.get('bedrock',0)} "
              f"Antigravity={s.get('antigravity',0)}")
        print(f"   证据:")
        for e in r.evidence:
            print(f"     {e}")
        print()

    # 指纹参考
    print("-- 三源指纹说明 " + "-" * 52)
    print("                   Anthropic       Bedrock(Kiro)    Antigravity(Google)")
    print("  tool_use id:     toolu_          tooluse_         tooluse_ / tool_N")
    print("  message id:      msg_<base62>    UUID/msg_<UUID>  msg_<UUID> / req_vrtx_")
    print("  thinking sig:    len 200+        len 200+/截断    claude#前缀 / 截断")
    print("  model:           claude-*        kiro-*/anthropic.*  claude-*")
    print("  service_tier:    有              无               无")
    print("  inference_geo:   有              无               无")
    print("  rate-limit hdr:  有              无               无")
    print()


# ── 自动选模型 ────────────────────────────────────────────

def find_working_model(base_url: str, api_key: str) -> str:
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": api_key,
        "Authorization": f"Bearer {api_key}",
    }
    for model in PROBE_MODELS:
        payload = {
            "model": model,
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "hi"}],
        }
        try:
            resp = requests.post(
                f"{base_url}/v1/messages", headers=headers,
                json=payload, timeout=15,
            )
            if resp.status_code == 200:
                return model
        except requests.exceptions.RequestException:
            continue
    return PROBE_MODELS[0]


def check_model_available(base_url: str, api_key: str, model: str) -> bool:
    """快速检查模型是否可用"""
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": api_key,
        "Authorization": f"Bearer {api_key}",
    }
    payload = {
        "model": model,
        "max_tokens": 5,
        "messages": [{"role": "user", "content": "hi"}],
    }
    try:
        resp = requests.post(
            f"{base_url}/v1/messages", headers=headers,
            json=payload, timeout=20,
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def verify_ratelimit_dynamic(base_url: str, api_key: str, model: str,
                             shots: int = 4, quiet: bool = False) -> dict:
    """连发多次简单请求，检查 ratelimit-remaining 是否真的在递减。
    返回 {"verdict": "dynamic"|"static"|"unavailable",
           "samples": [(remaining, reset_ts), ...],
           "detail": str}
    """
    samples = []
    for i in range(shots):
        fp = probe_once(base_url, api_key, model, "simple")
        if fp.error:
            if not quiet:
                print(f"      shot {i+1}: 失败 ({fp.error[:40]})")
            continue
        r = fp.ratelimit_input_remaining
        t = fp.ratelimit_input_reset
        samples.append((r, t))
        if not quiet:
            print(f"      shot {i+1}: remaining={r}  reset={t}  ({fp.latency_ms}ms)")
        time.sleep(0.3)

    if len(samples) < 2:
        return {"verdict": "unavailable", "samples": samples,
                "detail": "有效样本不足"}

    remainings = [s[0] for s in samples]
    resets = [s[1] for s in samples]

    # 检查 remaining 是否全部相同
    all_same = len(set(remainings)) == 1
    # 检查是否单调递减（允许相等，因为可能同一秒内）
    monotone_dec = all(remainings[i] >= remainings[i+1]
                       for i in range(len(remainings)-1))
    # 检查递减量是否合理（每次请求消耗几十到几百 tokens）
    total_drop = remainings[0] - remainings[-1]

    if all_same:
        return {"verdict": "static", "samples": samples,
                "detail": f"remaining 固定为 {remainings[0]}，未随请求变化 → 伪造"}
    elif monotone_dec and total_drop > 0:
        return {"verdict": "dynamic", "samples": samples,
                "detail": f"remaining 递减 {remainings[0]}→{remainings[-1]} "
                          f"(消耗 {total_drop}) → 真实"}
    else:
        # 非单调但有变化 — 可能是多 key 轮询或窗口重置
        return {"verdict": "dynamic", "samples": samples,
                "detail": f"remaining 有变化但非单调递减: {remainings} → 可能真实"}


# ── 单模型检测流程 ────────────────────────────────────────

def detect_single_model(base_url: str, api_key: str, model: str,
                        rounds: int = 2, verbose: bool = False,
                        quiet: bool = False) -> DetectResult:
    """对单个模型执行检测"""
    fingerprints: list[Fingerprint] = []

    # tool 探测
    for i in range(rounds):
        if not quiet:
            print(f"    [{i+1}/{rounds+1}] [tool]     ", end="", flush=True)

        fp = probe_once(base_url, api_key, model, "tool", verbose)
        fingerprints.append(fp)

        if not quiet:
            if fp.error:
                print(f"x  {fp.error[:50]}")
            else:
                print(f"ok {fp.latency_ms}ms "
                      f"| tool={fp.tool_id_source} "
                      f"| msg={fp.msg_id_source}({fp.msg_id_format})")

        if i < rounds - 1:
            time.sleep(0.3)

    # thinking 探测
    if not quiet:
        print(f"    [{rounds+1}/{rounds+1}] [thinking] ", end="", flush=True)

    fp = probe_once(base_url, api_key, model, "thinking", verbose)
    fingerprints.append(fp)

    if not quiet:
        if fp.error:
            print(f"x  {fp.error[:50]}")
        else:
            extra = ""
            if fp.thinking_sig_class:
                extra = f" | sig={fp.thinking_sig_class}({fp.thinking_sig_len})"
            if fp.has_service_tier:
                extra += f" | svc={fp.service_tier}"
            print(f"ok {fp.latency_ms}ms "
                  f"| msg={fp.msg_id_source}({fp.msg_id_format}){extra}")

    # ratelimit 动态验证 (仅当检测到 ratelimit headers 时)
    has_rl = any(fp.ratelimit_input_remaining > 0 for fp in fingerprints if not fp.error)
    rl_result = None
    if has_rl:
        if not quiet:
            print(f"    [RL] ratelimit 动态验证 (4 shots)...")
        rl_result = verify_ratelimit_dynamic(base_url, api_key, model, shots=4, quiet=quiet)
        if not quiet:
            print(f"    [RL] 结论: {rl_result['detail']}")
            print()

    result = analyze(fingerprints, base_url, model)

    # 将 ratelimit 验证结果注入
    if rl_result:
        result.ratelimit_dynamic = rl_result["verdict"]
        result.evidence.append(f"[RL] ratelimit 动态验证: {rl_result['detail']}")
        if rl_result["verdict"] == "static":
            # ratelimit 是假的 → 加重伪装嫌疑
            if result.verdict == "anthropic":
                result.verdict = "suspicious"
                result.evidence.append(
                    "[!!] ratelimit-remaining 固定不变，确认为伪造 headers")
            elif result.verdict == "suspicious":
                result.evidence.append(
                    "[!!] ratelimit-remaining 固定不变，进一步确认伪装")

    return result


# ── 多模型扫描 ───────────────────────────────────────────

def scan_all_models(base_url: str, api_key: str,
                    models: list[str] = None,
                    rounds: int = 1, verbose: bool = False,
                    quiet: bool = False) -> ScanResult:
    """扫描多个模型，检测每个模型的后端来源"""
    if models is None:
        models = SCAN_MODELS

    scan = ScanResult(base_url=base_url)

    if not quiet:
        print()
        print(f"  [*] 开始多模型扫描 ({len(models)} 个模型)...")
        print()

    # 先检测可用性
    available_models = []
    for model in models:
        if not quiet:
            print(f"  [?] 检测 {model}...", end=" ", flush=True)
        if check_model_available(base_url, api_key, model):
            available_models.append(model)
            if not quiet:
                print("可用")
        else:
            if not quiet:
                print("不可用")
            # 添加不可用记录
            r = DetectResult(model=model, verdict="unavailable", base_url=base_url)
            scan.model_results.append(r)
            scan.summary[model] = "unavailable"

    if not quiet:
        print()
        print(f"  [*] 可用模型: {len(available_models)}/{len(models)}")
        print()

    # 对每个可用模型进行检测
    for model in available_models:
        if not quiet:
            print(f"  == 检测 {model} ==")

        result = detect_single_model(
            base_url, api_key, model,
            rounds=rounds, verbose=verbose, quiet=quiet,
        )
        scan.model_results.append(result)
        scan.summary[model] = result.verdict

        if not quiet:
            v = result.verdict
            print(f"    -> {VERDICT_ICON.get(v, '?')} {VERDICT_SHORT.get(v, v)} "
                  f"(置信度 {result.confidence:.0%})")
            print()

        # 模型间隔
        time.sleep(0.5)

    # 判断是否混合渠道
    verdicts = set(v for v in scan.summary.values() if v != "unavailable")
    scan.is_mixed = len(verdicts) > 1

    # 中转平台
    platforms = [r.proxy_platform for r in scan.model_results if r.proxy_platform]
    if platforms:
        scan.proxy_platform = platforms[0]

    return scan


# ── 主入口 ────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CC Proxy Detector v5.2 - 三源检测 + 混合渠道扫描",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 detect.py                          # 自动检测 (单模型)
  python3 detect.py --scan-all               # 扫描所有模型 (混合渠道检测)
  python3 detect.py --model claude-opus-4-6-20250918  # 指定模型
  python3 detect.py --scan-all --rounds 2    # 多轮多模型
  python3 detect.py --json --output r.json   # JSON 输出
        """,
    )
    parser.add_argument("--base-url", default=None,
                        help="中转站地址 (默认: $ANTHROPIC_BASE_URL)")
    parser.add_argument("--api-key", default=None,
                        help="API Key (默认: $ANTHROPIC_AUTH_TOKEN / $FACTORY_API_KEY)")
    parser.add_argument("--model", default=None,
                        help="探测用模型 (默认: 自动选择)")
    parser.add_argument("--scan-all", action="store_true",
                        help="扫描所有模型，检测混合渠道")
    parser.add_argument("--scan-models", default=None,
                        help="自定义扫描模型列表 (逗号分隔)")
    parser.add_argument("--rounds", type=int, default=2,
                        help="每个模型的 tool 探测轮次 (默认: 2)")
    parser.add_argument("--parallel", action="store_true",
                        help="并行发送探测请求")
    parser.add_argument("--json", action="store_true",
                        help="JSON 格式输出")
    parser.add_argument("--verbose", action="store_true",
                        help="输出完整响应体")
    parser.add_argument("--output", default=None,
                        help="保存报告到文件")
    args = parser.parse_args()

    base_url = (args.base_url
                or os.environ.get("ANTHROPIC_BASE_URL", "")).rstrip("/")
    api_key = (args.api_key
               or os.environ.get("ANTHROPIC_AUTH_TOKEN", "")
               or os.environ.get("FACTORY_API_KEY", ""))

    if not base_url:
        print("错误: 需要 --base-url 或 $ANTHROPIC_BASE_URL")
        sys.exit(1)
    if not api_key:
        print("错误: 需要 --api-key 或 $ANTHROPIC_AUTH_TOKEN")
        sys.exit(1)

    quiet = args.json

    if not quiet:
        print()
        print("  CC Proxy Detector v5.2 (三源检测 + 混合渠道)")
        print(f"  目标: {base_url}")
        print()

    # ── 多模型扫描模式 ──
    if args.scan_all or args.scan_models:
        models = None
        if args.scan_models:
            models = [m.strip() for m in args.scan_models.split(",") if m.strip()]

        scan = scan_all_models(
            base_url, api_key,
            models=models,
            rounds=args.rounds,
            verbose=args.verbose,
            quiet=quiet,
        )

        if args.json:
            report = {
                "base_url": scan.base_url,
                "proxy_platform": scan.proxy_platform,
                "is_mixed": scan.is_mixed,
                "summary": scan.summary,
                "model_results": [asdict(r) for r in scan.model_results],
            }
            if not args.verbose:
                for mr in report["model_results"]:
                    for fp in mr.get("fingerprints", []):
                        fp.pop("raw_headers", None)
                        fp.pop("raw_body", None)
            out = json.dumps(report, indent=2, ensure_ascii=False)
            if args.output:
                with open(args.output, "w") as f:
                    f.write(out)
                print(f"已保存: {args.output}", file=sys.stderr)
            else:
                print(out)
        else:
            print_scan_report(scan)
            if args.output:
                report = {
                    "base_url": scan.base_url,
                    "proxy_platform": scan.proxy_platform,
                    "is_mixed": scan.is_mixed,
                    "summary": scan.summary,
                    "model_results": [asdict(r) for r in scan.model_results],
                }
                if not args.verbose:
                    for mr in report["model_results"]:
                        for fp in mr.get("fingerprints", []):
                            fp.pop("raw_headers", None)
                            fp.pop("raw_body", None)
                with open(args.output, "w") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                print(f"  JSON 报告已保存: {args.output}")
        return

    # ── 单模型模式 ──
    model = args.model
    if not model:
        if not quiet:
            print("  [*] 自动选择可用模型...", end=" ", flush=True)
        model = find_working_model(base_url, api_key)
        if not quiet:
            print(f"{model}")
            print()

    if not quiet:
        print(f"  [*] 开始探测 ({args.rounds} 轮 tool + 1 轮 thinking)...")
        print()

    result = detect_single_model(
        base_url, api_key, model,
        rounds=args.rounds, verbose=args.verbose, quiet=quiet,
    )

    if args.json:
        report = asdict(result)
        report["verdict_text"] = VERDICT_MAP.get(result.verdict, result.verdict)
        if not args.verbose:
            for fp in report["fingerprints"]:
                fp.pop("raw_headers", None)
                fp.pop("raw_body", None)
        out = json.dumps(report, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w") as f:
                f.write(out)
            print(f"已保存: {args.output}", file=sys.stderr)
        else:
            print(out)
    else:
        print_report(result)
        if args.output:
            report = asdict(result)
            if not args.verbose:
                for fp in report["fingerprints"]:
                    fp.pop("raw_headers", None)
                    fp.pop("raw_body", None)
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  JSON 报告已保存: {args.output}")


if __name__ == "__main__":
    main()
