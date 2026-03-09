# IntelWatch — AI Configuration Guide
updated 
> Complete step-by-step guide for administrators to configure, tune, and manage AI-powered features across the platform.

---

## Table of Contents

1. [Overview](#1-overview)
2. [Accessing AI Settings](#2-accessing-ai-settings)
3. [Provider Setup](#3-provider-setup)
   - [Groq (Recommended Primary)](#groq-recommended-primary)
   - [Cerebras (Recommended Fallback)](#cerebras-recommended-fallback)
   - [Google Gemini](#google-gemini)
   - [OpenAI](#openai)
   - [Anthropic](#anthropic)
   - [Ollama (Self-Hosted)](#ollama-self-hosted)
   - [HuggingFace](#huggingface)
   - [Custom OpenAI-Compatible](#custom-openai-compatible)
4. [Fallback Chain](#4-fallback-chain)
5. [Feature Toggles](#5-feature-toggles)
6. [Per-Feature Model Overrides](#6-per-feature-model-overrides)
7. [Daily Limits](#7-daily-limits)
8. [Custom Prompts](#8-custom-prompts)
9. [Advanced Parameters](#9-advanced-parameters)
10. [Health Monitoring](#10-health-monitoring)
11. [Recommended Configurations](#11-recommended-configurations)
12. [Troubleshooting](#12-troubleshooting)
13. [API Reference](#13-api-reference)
14. [Architecture](#14-architecture)

---

## 1. Overview

IntelWatch uses AI to power six core features:

| Feature | Description | Token Usage | Recommended Model |
|---------|-------------|-------------|-------------------|
| **Intel Summary** | Auto-generates 2-3 sentence summaries for intel items | ~150 tokens | Fast (8B) |
| **Intel Enrichment** | Deep analysis: threat actors, TTPs, MITRE mappings | ~3,000 tokens | Large (70B) |
| **News AI Extraction** | Extracts IOCs, CVEs, threat actors from news articles | ~3,500 tokens | Large (70B) |
| **Live Lookup** | Real-time IOC analysis with risk assessment | ~800 tokens | Fast (8B) |
| **Report Generation** | AI-drafted executive threat reports | ~4,000 tokens | Large (70B) |
| **Threat Briefing** | Periodic threat intelligence briefings | ~5,000 tokens | Large (70B) |

All providers must be **OpenAI-compatible** (expose `/v1/chat/completions` endpoint). The platform supports automatic fallback across multiple providers when rate limits are hit.

### How It Works

```
Request → Primary Provider → [429 Rate Limit?] → Fallback #1 → Fallback #2 → ...
            ↓ (success)
        Return AI content + cache result
```

Settings are stored in PostgreSQL and cached in Redis (60-second TTL). Changes made in the admin UI take effect within 60 seconds without requiring a restart.

---

## 2. Accessing AI Settings

1. Log in with an **admin** account
2. Navigate to **Settings** (gear icon in the sidebar)
3. The **AI Configuration** section is visible only to admins
4. The panel has six sub-tabs:

| Tab | Purpose |
|-----|---------|
| **Provider** | Primary & fallback provider configuration |
| **Features** | Enable/disable individual AI features + model overrides |
| **Limits & Usage** | Daily call limits with real-time usage counters |
| **Custom Prompts** | Override built-in system prompts |
| **Advanced** | Temperature, max tokens, rate limiting, cache TTLs |
| **Health & Stats** | Live provider health checks, daily usage reset |

### Master AI Toggle

The **AI Engine** toggle in the header bar is a global kill switch. When OFF:
- All AI features are disabled platform-wide
- No API calls are made to any provider
- Features degrade gracefully (e.g., intel items show without summaries)

---

## 3. Provider Setup

### Prerequisites

Before configuring a provider, you need:
- An account with the provider (free tier is sufficient for most)
- An API key from the provider's dashboard
- The provider's OpenAI-compatible API endpoint URL

### Groq (Recommended Primary)

**Best for:** High-volume summarization, fastest free inference

| Field | Value |
|-------|-------|
| Provider | `Groq` |
| API URL | `https://api.groq.com/openai/v1/chat/completions` |
| Model | `llama-3.3-70b-versatile` |
| Timeout | `30` seconds |

**Free Tier Limits:** 30 req/min, 14,400 req/day, 6,000 tokens/min

**Steps:**
1. Go to [console.groq.com](https://console.groq.com)
2. Sign up / log in
3. Navigate to **API Keys** → **Create API Key**
4. Copy the key (starts with `gsk_`)
5. In IntelWatch Settings → Provider tab:
   - Select **Groq** from the Provider dropdown
   - Paste the API key
   - The URL and model auto-populate from the info panel. Use suggested values or pick from: `llama-3.3-70b-versatile`, `llama-3.1-8b-instant`, `gemma2-9b-it`, `mixtral-8x7b-32768`
6. Click **Test Connection** — should show "OK"
7. Click **Save**

**Tip:** Enter comma-separated models (e.g., `llama-3.3-70b-versatile, llama-3.1-8b-instant`) to automatically create in-provider model fallbacks. If the first model hits its rate limit, the system tries the next model with the same API key.

**Available Models:**
| Model | Size | Speed | Best For |
|-------|------|-------|----------|
| `llama-3.3-70b-versatile` | 70B | Fast | Enrichment, reports, complex analysis |
| `llama-3.1-8b-instant` | 8B | Fastest | Summaries, lookups |
| `gemma2-9b-it` | 9B | Fast | General purpose |
| `mixtral-8x7b-32768` | 8x7B | Fast | Long context tasks |

---

### Cerebras (Recommended Fallback)

**Best for:** Fast fallback when Groq is rate-limited

| Field | Value |
|-------|-------|
| Provider | `Cerebras` |
| API URL | `https://api.cerebras.ai/v1/chat/completions` |
| Model | `llama3.1-8b` or `llama3.1-70b` |
| Timeout | `60` seconds |

**Free Tier Limits:** 30 req/min, 1,000 req/day, 60,000 tokens/min

**Steps:**
1. Go to [cloud.cerebras.ai](https://cloud.cerebras.ai)
2. Sign up / log in
3. Navigate to **API Keys** → **Generate Key**
4. Copy the key
5. Add as a **Fallback Provider** in IntelWatch (see [Fallback Chain](#4-fallback-chain))
6. Test the connection

---

### Google Gemini

**Best for:** Very generous free tier, good quality

| Field | Value |
|-------|-------|
| Provider | `Google Gemini` |
| API URL | `https://generativelanguage.googleapis.com/v1beta/openai/` |
| Model | `gemini-2.0-flash` |
| Timeout | `30` seconds |

**Free Tier Limits:** 15 req/min, 1,000,000 tokens/day (Gemini 2.0 Flash)

**Steps:**
1. Go to [aistudio.google.com](https://aistudio.google.com)
2. Sign in with a Google account
3. Click **Get API Key** → **Create API Key**
4. Copy the key (starts with `AIza`)
5. In IntelWatch, set the URL to `https://generativelanguage.googleapis.com/v1beta/openai/`
6. Set model to `gemini-2.0-flash`
7. Test and Save

**Available Models:**
| Model | Speed | Best For |
|-------|-------|----------|
| `gemini-2.0-flash` | Very fast | General purpose, best free option |
| `gemini-2.0-flash-lite` | Fastest | Simple tasks, summaries |
| `gemini-1.5-flash` | Fast | Balanced quality/speed |
| `gemini-1.5-pro` | Slower | Complex analysis (lower free limits) |

> **Note:** Gemini may show as "Unreachable" in health checks because its OpenAI-compatible `/models` endpoint behaves differently. This does not mean the provider is broken — use "Test Connection" to verify actual connectivity.

---

### OpenAI

**Best for:** Highest quality output (paid)

| Field | Value |
|-------|-------|
| Provider | `OpenAI` |
| API URL | `https://api.openai.com/v1/chat/completions` |
| Model | `gpt-4o-mini` or `gpt-4o` |
| Timeout | `30` seconds |

**Pricing:** ~$0.15/1M input tokens (gpt-4o-mini), ~$2.50/1M input tokens (gpt-4o)

**Steps:**
1. Go to [platform.openai.com](https://platform.openai.com)
2. Navigate to **API Keys** → **Create new secret key**
3. Copy the key (starts with `sk-`)
4. Configure in IntelWatch with the URL and model above
5. Test and Save

---

### Anthropic

**Best for:** Strong analytical quality (paid)

| Field | Value |
|-------|-------|
| Provider | `Anthropic` |
| API URL | `https://api.anthropic.com/v1/chat/completions` |
| Model | `claude-sonnet-4-20250514` |
| Timeout | `30` seconds |

> **Note:** Anthropic's native API is not fully OpenAI-compatible. Use an OpenAI-compatible proxy or adapter if your version does not natively support the chat completions format.

---

### Ollama (Self-Hosted)

**Best for:** Air-gapped environments, unlimited usage, no API costs

| Field | Value |
|-------|-------|
| Provider | `Ollama (Local)` |
| API URL | `http://<your-ollama-host>:11434/v1/chat/completions` |
| Model | `llama3.1:8b` or `llama3.1:70b` |
| Timeout | `120` seconds (local inference is slower) |

**Steps:**
1. Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`
2. Pull a model: `ollama pull llama3.1:8b`
3. Start serving: `ollama serve` (default port 11434)
4. Configure IntelWatch with `http://<host>:11434/v1/chat/completions`
5. Test and Save

**Tip:** Use a longer timeout (60-120s) for Ollama since local inference depends on your hardware.

---

### HuggingFace

**Best for:** Wide model variety, last-resort fallback

| Field | Value |
|-------|-------|
| Provider | `HuggingFace` |
| API URL | `https://api-inference.huggingface.co/v1/chat/completions` |
| Model | `mistralai/Mistral-7B-Instruct-v0.3` |
| Timeout | `60` seconds |

**Free Tier Limits:** ~1,000 req/day (varies by model popularity)

**Steps:**
1. Go to [huggingface.co](https://huggingface.co) → Settings → Access Tokens
2. Create a new token with **Inference** permission
3. Copy the key (starts with `hf_`)
4. Configure in IntelWatch
5. Test and Save

---

### Custom OpenAI-Compatible

Any API endpoint that implements the OpenAI chat completions standard will work:

```
POST /v1/chat/completions
Authorization: Bearer <key>
Content-Type: application/json

{
  "model": "model-name",
  "messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}],
  "max_tokens": 800,
  "temperature": 0.3
}
```

Examples: LM Studio, vLLM, text-generation-webui, LocalAI, Together.ai, Fireworks.ai, Perplexity.

---

## 4. Fallback Chain

The fallback chain is a priority-ordered list of backup providers. When the primary provider fails with a **429** (rate limit), **503** (overloaded), or **403** (forbidden) error, the platform automatically tries the next provider.

### Setting Up Fallback Providers

1. Go to **Provider** tab → **Fallback Chain** section
2. Click **+ Add Provider**
3. Configure each fallback the same way as the primary (provider, URL, key, model)
4. Use the **toggle** to enable/disable individual fallbacks without removing them
5. Use the **X** button to delete a fallback
6. Click **Test** on each fallback to verify connectivity
7. **Save** to persist the chain

### Recommended Fallback Chains

**Free-tier maximum resilience (recommended):**
```
Primary: Groq (llama-3.3-70b-versatile, llama-3.1-8b-instant)
  ↓ 429
Fallback #1: Cerebras (llama3.1-8b)
  ↓ 429
Fallback #2: Gemini (gemini-2.0-flash)
```

**Quality-focused (paid):**
```
Primary: OpenAI (gpt-4o)
  ↓ rate limit
Fallback #1: Anthropic (claude-sonnet-4-20250514)
  ↓ rate limit
Fallback #2: Groq (llama-3.3-70b-versatile)
```

**Self-hosted + cloud backup:**
```
Primary: Ollama (llama3.1:70b)
  ↓ timeout/error
Fallback #1: Groq (llama-3.3-70b-versatile)
```

### Comma-Separated Models

For any provider (primary or fallback), you can enter multiple models separated by commas:
```
llama-3.3-70b-versatile, llama-3.1-8b-instant
```

The system creates separate chain entries for each model using the same API key. Groq, for example, rate-limits per-model — so if `70b-versatile` is rate-limited, the system automatically tries `8b-instant` before moving to the next provider.

### How Masked Keys Work After Save

After saving, page reload shows API keys as masked (e.g., `gsk_****xY2z`). This is a security feature — real keys are stored only in the database.

- **Test Connection** works correctly with masked keys — the backend resolves the real key from the database
- **Re-entering** a key overwrites the existing one
- **Leaving masked** (not editing) preserves the original key on save

---

## 5. Feature Toggles

Go to the **Features** tab to enable/disable individual AI capabilities.

| Feature | Default | When Disabled |
|---------|---------|---------------|
| Intel Summary | ON | Intel items display without AI summary |
| Intel Enrichment | ON | "Enrich" button hidden on intel detail page |
| News AI Extraction | ON | News items ingested without AI entity extraction |
| Live Lookup | ON | Investigate page works without AI context |
| Report Generation | ON | Reports created without AI-drafted executive summary |
| Threat Briefing | ON | Briefing generation unavailable |

**Important:** The master **AI Engine** toggle must be ON for any individual feature to work. If the master toggle is OFF, all features are disabled regardless of individual settings.

---

## 6. Per-Feature Model Overrides

Each feature can use a different model from the primary. This lets you optimize cost and quality:

| Feature | Recommended Override | Reason |
|---------|---------------------|--------|
| Intel Summary | `llama-3.1-8b-instant` | Short output, speed matters |
| Intel Enrichment | (use primary 70B) | Complex structured JSON extraction |
| News AI Extraction | (use primary 70B) | Multi-field entity extraction |
| Live Lookup | `llama-3.1-8b-instant` | Interactive, speed critical |
| Report Generation | (use primary 70B) | Long-form coherent output |
| Threat Briefing | (use primary 70B) | Multi-item synthesis |

**How to configure:**
1. Go to **Features** tab
2. Under each feature, enter the model name in the model override field
3. Leave blank to use the primary model
4. Click **Save**

> **Note:** The model override must be available on your **primary provider**. It does not cross provider boundaries — the override only affects which model is requested from the primary.

---

## 7. Daily Limits

Go to the **Limits & Usage** tab to set per-feature daily call limits.

- **0 = Unlimited** — no daily cap
- Counters reset at **midnight UTC**
- When a limit is reached, that feature stops making AI calls until the next day
- Other features continue to work normally

### Recommended Limits (Free Tier)

| Feature | Suggested Limit | Reasoning |
|---------|----------------|-----------|
| Intel Summary | 500 | High volume, low cost per call |
| Intel Enrichment | 200 | Heavy token usage, on-demand only |
| News AI Extraction | 300 | Automated pipeline, moderate volume |
| Live Lookup | 100 | Interactive, unpredictable volume |
| Report Generation | 50 | Infrequent, high token usage |
| Threat Briefing | 20 | Daily/periodic, very high token usage |

### Usage Monitoring

The limits section shows real-time progress bars:
- **Green** — Under 70% of limit
- **Yellow** — 70-90% of limit
- **Red** — Over 90% of limit

The **Health & Stats** tab shows cumulative usage per feature and a **Reset** button to clear today's counters.

---

## 8. Custom Prompts

Go to the **Custom Prompts** tab to override the built-in system prompts.

### Viewing Default Prompts

1. Expand any feature by clicking its name
2. Click **View Default Prompt** to see the built-in prompt (read-only reference)
3. The default prompt is displayed below the edit area

### Writing Custom Prompts

1. Expand the feature
2. Type your custom prompt in the text area
3. The "Custom" badge appears next to features with overrides
4. Click **Save**
5. To revert, click **Clear custom prompt** → **Save**

### Prompt Writing Tips

- **Be specific:** "You are a cybersecurity analyst specializing in APT groups" is better than "You are an AI assistant"
- **Define output format:** If you need structured output, specify the exact JSON schema or bullet point format in the prompt
- **Set boundaries:** Include "Do not fabricate data" or "If information is not available, say so" to prevent hallucination
- **Keep it focused:** Each feature's prompt should be tailored to that specific task
- **Test after saving:** Use the relevant feature to verify the new prompt produces desired output

### Example Custom Prompt (Intel Summary)

```
You are a senior threat intelligence analyst at a Fortune 500 SOC.
Analyze the provided threat intelligence and write a 3-sentence summary:

Sentence 1: What the threat is and which threat actor/campaign is behind it.
Sentence 2: What systems, software, or sectors are affected and the severity.
Sentence 3: The single most important action a defender should take right now.

Be direct, technical, and actionable. Do not use marketing language.
```

---

## 9. Advanced Parameters

Go to the **Advanced** tab to tune generation parameters, rate limiting, and caching.

### Temperature

Controls response randomness. Range: `0.0` to `1.0`

| Value | Behavior | Use Case |
|-------|----------|----------|
| 0.0 – 0.2 | Very deterministic, consistent | Structured JSON extraction (enrichment) |
| 0.2 – 0.4 | **Recommended for TI** | Summaries, reports, analysis |
| 0.4 – 0.7 | More varied output | Creative writing, brainstorming |
| 0.7 – 1.0 | Highly creative/random | Not recommended for TI |

**Default:** `0.3`

### Max Tokens

Maximum response length in tokens (~4 characters per token).

| Setting | Tokens | Approximate Output |
|---------|--------|--------------------|
| Short summary | 150-300 | 2-3 sentences |
| Standard analysis | 800 | 1-2 paragraphs |
| Detailed report | 2000-4000 | Full page |

**Default:** `800`

> **Warning:** Higher max tokens = higher API cost per call. Most free tiers count output tokens against rate limits.

### Rate Limiting

Controls how fast the platform sends requests to AI providers.

| Parameter | Default | Description |
|-----------|---------|-------------|
| Requests per Minute | 30 | Global cap on AI API calls/minute |
| Batch Delay (ms) | 1000 | Delay between consecutive batch operations |

**Tuning guide:**
- **Groq free tier:** 30 req/min → set requests_per_minute to 25 (leave headroom)
- **Gemini free tier:** 15 req/min → set to 12
- **Paid providers:** Can increase to 100-500+ depending on plan
- **Batch delay:** Increase to 2000ms if hitting rate limits during news ingestion

### Cache TTLs

How long AI responses are cached in Redis before regeneration.

| Cache | Default | Recommended Range |
|-------|---------|-------------------|
| Summary | 3600s (1 hour) | 1800-86400 (30min to 24h) |
| Enrichment | 21600s (6 hours) | 3600-86400 (1h to 24h) |
| Lookup | 300s (5 minutes) | 60-3600 (1min to 1h) |

- **Longer TTL** = fewer API calls, lower cost, but potentially stale data
- **Shorter TTL** = more API calls, fresher results, higher cost
- **0** = no caching (every request hits the API)

---

## 10. Health Monitoring

Go to the **Health & Stats** tab.

### Provider Health Check

Click **Check Now** to test connectivity to all configured providers.

| Status | Icon | Meaning |
|--------|------|---------|
| ✅ Healthy | Green | Provider API responded with 200 to `/models` |
| ❌ Unreachable | Red | Provider did not respond or returned an error |

Each provider also shows a **usage badge** (e.g., "42 today") indicating how many successful AI calls were routed through that provider today.

> **Note:** Some providers (like Gemini) may show "Unreachable" in health checks even though they work correctly for chat completions. Use **Test Connection** on the Provider tab for definitive connectivity testing.

### Usage Counters

The **Today's Usage** section shows per-feature call counts:
- Counters increment when an AI call completes successfully
- "Limit Reached" badge appears when a feature hits its daily cap
- Click **Reset** to clear all counters for today

---

## 11. Recommended Configurations

### Small Deployment (Free Tier, < 500 Intel Items/Day)

```
Primary: Groq
  Model: llama-3.3-70b-versatile
  Timeout: 30s

Fallback #1: Cerebras
  Model: llama3.1-8b
  Timeout: 60s

Temperature: 0.3
Max Tokens: 800
Requests/Min: 25
Batch Delay: 1500ms

Daily Limits:
  Intel Summary: 500
  Intel Enrichment: 200
  News Extraction: 300
  Live Lookup: 100
  Report Gen: 50
  Briefing Gen: 20

Cache TTLs:
  Summary: 3600 (1h)
  Enrichment: 21600 (6h)
  Lookup: 300 (5m)
```

### Medium Deployment (Free Tier + Gemini Fallback)

```
Primary: Groq
  Model: llama-3.3-70b-versatile, llama-3.1-8b-instant

Fallback #1: Cerebras
  Model: llama3.1-70b

Fallback #2: Gemini
  Model: gemini-2.0-flash

Temperature: 0.3
Max Tokens: 800
Requests/Min: 25
Batch Delay: 1000ms

Model Overrides:
  Intel Summary: llama-3.1-8b-instant
  Live Lookup: llama-3.1-8b-instant
  (others: use primary)

Daily Limits: 0 (unlimited — rely on provider rate limits)
```

### Enterprise Deployment (Paid Provider)

```
Primary: OpenAI
  Model: gpt-4o-mini

Fallback #1: OpenAI
  Model: gpt-4o  (for complex tasks only via model override)

Fallback #2: Groq
  Model: llama-3.3-70b-versatile

Temperature: 0.2
Max Tokens: 2000
Requests/Min: 200
Batch Delay: 200ms

Daily Limits: 0 (unlimited)

Cache TTLs:
  Summary: 7200 (2h)
  Enrichment: 43200 (12h)
  Lookup: 600 (10m)
```

---

## 12. Troubleshooting

### Test Connection Fails

| Error | Cause | Fix |
|-------|-------|-----|
| "Connection timed out" | Network issue or wrong URL | Verify URL, check firewall rules, increase timeout |
| "HTTP 401" | Invalid API key | Re-enter the correct API key and save |
| "HTTP 403" | Account suspended or key revoked | Check provider dashboard for account status |
| "HTTP 404" | Wrong API endpoint URL | Verify the URL matches provider documentation |
| "HTTP 429" | Rate limit hit | Wait a moment and retry, or switch providers |
| "url, key, and model are required" | Missing fields | Fill in all required fields and save first |

### Test Works But AI Features Don't Generate

1. Check **Master AI Toggle** is ON
2. Check the specific **feature toggle** is ON
3. Check **daily limit** hasn't been reached (Limits & Usage tab)
4. Check API container logs: `docker compose logs api --tail 100 | grep ai_`
5. Verify settings cache is fresh: changes take up to 60 seconds

### Provider Shows "Unreachable" in Health Check

The health check calls `GET /models` on the provider's API. Some providers don't support this endpoint.

- **Gemini:** May show Unreachable — use Test Connection instead
- **Ollama:** Ensure the server is running and accessible from the Docker network
- **Custom:** Not all OpenAI-compatible APIs support `/models`

If the provider works with Test Connection but shows Unreachable in health, it's safe to ignore.

### Masked Keys After Page Reload

This is expected security behavior. After saving:
- Keys display as `gsk_****xY2z` (first 4 + last 4 characters)
- **Test Connection** still works — the backend resolves real keys from the database
- **Re-save** without editing the key field preserves the original key
- To **change** a key, clear the field and enter the new key

### All Providers Show 429 Errors in Logs

You've exhausted rate limits across all providers. Options:
1. **Add more fallback providers** (Gemini has 1M free tokens/day)
2. **Increase batch delay** (2000-5000ms) to slow down batch operations
3. **Reduce requests per minute** setting
4. **Enable caching** (increase cache TTLs to reduce repeated calls)
5. **Set daily limits** to prevent runaway usage
6. **Upgrade** to a paid provider tier

### Changes Don't Take Effect

AI settings are cached for 60 seconds. After saving:
1. Wait up to 60 seconds for the cache to expire
2. Or restart the API container: `docker compose restart api`
3. Hard refresh the browser (Ctrl+Shift+R) to clear frontend cache

---

## 13. API Reference

All endpoints require admin authentication. Base path: `/api/v1/ai-settings`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/ai-settings` | Fetch current config (keys masked) |
| `PUT` | `/ai-settings` | Update config (partial update) |
| `POST` | `/ai-settings/test-provider` | Test provider connectivity |
| `GET` | `/ai-settings/usage` | Get today's usage counters |
| `POST` | `/ai-settings/reset-usage` | Reset today's usage counters |
| `GET` | `/ai-settings/defaults` | Get optimal default values |
| `GET` | `/ai-settings/default-prompts` | Get built-in system prompts |
| `POST` | `/ai-settings/reset-defaults` | Reset to defaults (preserves keys) |
| `GET` | `/ai-settings/health` | Provider health check |

### Test Provider Request

```json
POST /api/v1/ai-settings/test-provider
{
  "url": "https://api.groq.com/openai/v1/chat/completions",
  "key": "gsk_...",
  "model": "llama-3.3-70b-versatile",
  "provider_type": "primary"
}
```

`provider_type` can be `"primary"` or a fallback index (`"0"`, `"1"`, etc.). When provided, the backend resolves the real API key from the database (supports masked keys).

### Update Settings Request

```json
PUT /api/v1/ai-settings
{
  "primary_provider": "groq",
  "primary_model": "llama-3.3-70b-versatile",
  "default_temperature": 0.3,
  "feature_intel_summary": true,
  "daily_limit_intel_summary": 500
}
```

Only send the fields you want to change. Unspecified fields are preserved.

---

## 14. Architecture

### Data Flow

```
┌─────────────────────────────────────────┐
│       Admin UI  (Settings Page)         │
│   AI Configuration Component            │
└──────────────┬──────────────────────────┘
               │  REST API (JSON)
               ▼
┌─────────────────────────────────────────┐
│   FastAPI Route (/ai-settings)          │
│   - Input validation                    │
│   - Key masking on read                 │
│   - Key preservation on write           │
│   - Cache invalidation on write         │
└──────┬─────────────────────┬────────────┘
       │                     │
       ▼                     ▼
┌──────────────┐   ┌─────────────────────┐
│ PostgreSQL   │   │ Redis               │
│ ai_settings  │   │ • ai_settings_cache │
│ table        │   │ • ai_daily_usage:*  │
│ (persistent) │   │ • ai_provider_usage:*│
└──────────────┘   └─────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────┐
│   AI Service (ai.py)                    │
│   - Reads settings from Redis/DB cache  │
│   - Builds provider fallback chain      │
│   - Routes AI calls across providers    │
│   - Tracks usage per feature + provider │
└─────────────────────────────────────────┘
```

### Settings Cache Flow

```
Admin saves → DB update → Redis cache invalidated
                ↓
AI service (next request within 60s) → Redis miss → DB query → Redis cache set
                ↓
Subsequent requests → Redis hit (fast path)
```

### Security

- API keys are **never** returned in API responses — only masked versions
- Keys are stored encrypted at rest in PostgreSQL
- Admin-only access enforced via JWT middleware
- `provider_type` parameter enables secure key resolution from DB for test requests
- All AI API calls use HTTPS with TLS
- Input validation prevents injection through model names, URLs, and prompts
