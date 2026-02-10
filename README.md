# CC Proxy Detector v5.2

Detect the real backend origin of Claude Code proxy/relay services.

检测 Claude Code 中转站的真实后端来源。

## Features

- **Three-backend detection**: Anthropic API / AWS Bedrock / Google Vertex AI
- **Reverse-engineering source identification**: Kiro, Antigravity, Droid, Windsurf, Warp, Claude Code Max, etc.
- **Multi-model scanning**: Detect mixed-channel routing (different models → different backends)
- **Ratelimit dynamic verification**: Distinguish real vs forged ratelimit headers
- **Anti-disguise**: Missing-field negative evidence to catch deep spoofing

## Backend & Reverse-Engineering Sources

All Claude access ultimately routes through one of three backends. Various tools reverse-engineer these backends:

| Source | Backend | Description |
|--------|---------|-------------|
| **Anthropic API** | Anthropic | Official API Key or Max subscription |
| **Claude Code Max** | Anthropic | OAuth-based, can be proxied via CLIProxyAPI |
| **Kiro** | AWS Bedrock | AWS AI IDE, model prefix `kiro-` |
| **Factory Droid** | Anthropic/Bedrock | Supports BYOK, backend depends on config |
| **Antigravity** | Google Vertex AI | Google Cloud Code, via `googleapis.com` |
| **Windsurf** | Bedrock/Unknown | Codeium AI IDE, internal channel unclear |
| **Warp** | Unknown | AI terminal, internal channel unclear |

## Behavioral Anomalies (Reverse-Engineering Clues)

Beyond fingerprint fields, reverse-engineered channels often exhibit runtime anomalies:

- **tool_use pairing errors**: `Each tool_use block must have a corresponding tool_result block` — proxy rewrites tool IDs but breaks the pairing chain
- **Intermittent HTTP 500**: Proxy's format conversion pipeline fails on certain model/feature combos
- **Model availability gaps**: Some models work, others don't — proxy only mapped certain model IDs
- **Elevated latency + variance**: Extra hop through proxy adds 1-3s and higher P99 tail latency
- **Thinking/streaming glitches**: Proxy fails to properly relay SSE events or thinking blocks

## Quick Start

```bash
pip install requests

# Auto-detect (single model)
python3 scripts/detect.py

# Scan all models (recommended)
python3 scripts/detect.py --scan-all --rounds 2

# Specify models
python3 scripts/detect.py --scan-models "claude-opus-4-6,claude-sonnet-4-5-20250929"

# Custom endpoint
python3 scripts/detect.py --base-url https://your-proxy.com --api-key sk-xxx

# JSON output
python3 scripts/detect.py --scan-all --json --output report.json
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_BASE_URL` | Proxy endpoint URL |
| `ANTHROPIC_AUTH_TOKEN` | API Key (primary) |
| `FACTORY_API_KEY` | API Key (fallback) |

## Fingerprint Matrix

| Fingerprint | Anthropic | Bedrock/Kiro | Vertex/Antigravity |
|-------------|-----------|--------------|-------------------|
| tool_use id | `toolu_` | `tooluse_` | `tooluse_` / `tool_N` |
| message id | `msg_<base62>` | UUID / `msg_<UUID>` | `msg_<UUID>` / `req_vrtx_` |
| thinking sig | len 200+ | len 200+ / truncated | `claude#` prefix |
| model format | `claude-*` | `kiro-*` / `anthropic.*` | `claude-*` |
| service_tier | present | absent | absent |
| inference_geo | present | absent | absent |
| ratelimit hdr | dynamic | absent | absent |
| cache_creation | nested object | absent | absent |

## How It Works

```
1. Send tool_use probes → extract tool_id prefix, msg_id format
2. Send thinking probe → extract thinking signature, service_tier
3. Collect response headers → AWS / Anthropic / proxy platform fingerprints
4. Collect response body → model format, usage style, cache_creation
5. Multi-dimensional scoring → three-source verdict
6. Missing-field negative evidence → detect spoofing
7. Ratelimit dynamic verification → confirm or deny forged headers
```

## Known Spoofing Techniques

Proxies have been observed to:
- Rewrite `tooluse_` → `toolu_` prefix
- Inject `service_tier=standard`
- Inject static ratelimit headers (fixed 300000/299000)
- Inject `cache_creation` nested objects

**Hardest to fake**: ratelimit remaining dynamic decrement (requires maintaining a real quota tracking system)

## Detailed Fingerprint Reference

See [references/fingerprint-matrix.md](references/fingerprint-matrix.md) for the full fingerprint matrix, reliability grading, and known channel detection results.

## License

MIT
