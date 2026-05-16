# trino-chart

Trino Helm chart configured for OpenShift with GenAI functions and an Iceberg lakehouse on MinIO S3.

## Architecture

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Trino Query │     │    Trino     │     │   LLM (MaaS) │
│     UI       │────▶│ Coordinator  │────▶│ Llama 4 Scout│
└──────────────┘     │  + Workers   │     └──────────────┘
                     └──────┬───────┘
                            │
               ┌────────────┼────────────┐
               │            │            │
        ┌──────▼──┐  ┌──────▼──┐  ┌──────▼──┐
        │  Nessie │  │  MinIO  │  │  TPC-H  │
        │ Catalog │  │   S3    │  │ TPC-DS  │
        └─────────┘  └─────────┘  └─────────┘
```

## What's Included

- **Trino** (v480) — distributed SQL query engine, OpenShift SCC-compatible
- **AI Functions** — sentiment analysis, classification, extraction, translation, masking, grammar correction, and text generation via an OpenAI-compatible LLM endpoint
- **Iceberg Lakehouse** — S3-backed tables on MinIO with Nessie catalog
- **Trino Query UI** — web-based SQL editor with syntax highlighting
- **21 example queries** covering all 7 AI functions, including 3 that query a HuggingFace hotel reviews dataset from S3

## Quick Start

See [SETUP.md](SETUP.md) for the full step-by-step guide.

```bash
# Deploy Trino
helm install trino ./trino -n trino --create-namespace

# Deploy Nessie catalog + create MinIO bucket
oc apply -f nessie/ -n trino

# Load HuggingFace dataset
python examples/load_dataset.py

# Run all AI function examples
./examples/run_all.sh
```

## Examples

| # | Example | AI Functions Used |
|---|---------|-------------------|
| 01-03 | Sentiment analysis (insider threats, phishing, support) | `ai_analyze_sentiment` |
| 04-07 | Classification (firewall, phishing, SIEM, web requests) | `ai_classify` |
| 08-10 | Data extraction (auth logs, FIM, process logs) | `ai_extract` |
| 11-12 | Grammar correction (firewall, IDS alerts) | `ai_fix_grammar` |
| 13-14 | Text generation (threat report, anomaly explanation) | `ai_gen` |
| 15-16 | PII masking (login events, firewall logs) | `ai_mask` |
| 17-18 | Translation (Japanese, Spanish security logs) | `ai_translate` |
| 19 | Review intelligence pipeline (S3 data) | `ai_analyze_sentiment` + `ai_classify` + `ai_extract` |
| 20 | Executive summary from reviews (S3 data) | `ai_gen` |
| 21 | PII-safe multilingual export (S3 data) | `ai_mask` + `ai_fix_grammar` + `ai_translate` |

## Project Structure

```
trino-chart/
├── trino/              # Helm chart
├── nessie/             # Nessie catalog server manifests
├── examples/           # SQL examples + loader script + test runner
├── SETUP.md            # Full setup guide
└── README.md
```

## Notes and Links

The trino chart was extracted and modified to run with OpenShift's more secure defaults.

```bash
helm pull trino/trino --version 1.42.2 --untar
```

See:

- https://trino.io/docs/current/installation/kubernetes.html

The original trino examples were from this medium post:

- https://levelup.gitconnected.com/trino-471-when-sql-meets-ai-and-s3-gets-easier-0ce690334b34
