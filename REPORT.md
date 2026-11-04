# ZeusLock Level 1 report

## Evaluation

Rules-only baseline using `python eval\eval.py --no-llm`:

| Labels | Decision accuracy | Mean latency | P50 | P95 |
|---|---:|---:|---:|---:|
| Original | 94%* | See `eval/original_report.json` | See report | See report |
| Corrected | 100% | 3.86 ms | 0.57 ms | 7.09 ms |

*The original score includes the known incorrect labels for the public IP and
the email address.

## Ollama evaluation

The harness was rerun with Ollama available using `qwen2.5:3b`.

| Labels | Decision accuracy | Mean latency | P50 | P95 | LLM-hit fraction |
|---|---:|---:|---:|---:|---:|
| Original | 96% | 366.11 ms | 0.72 ms | 1696.28 ms | 12% |
| Corrected | 100% | 369.57 ms | 0.57 ms | 1649.86 ms | 12% |

The model judged 6 ambiguous candidates in each run. All 6 model decisions were
`sensitive: true`; no model request failed. The complete per-prompt findings
are stored in [eval/corrected_report_llm.json](eval/corrected_report_llm.json)
and [eval/original_report_llm.json](eval/original_report_llm.json).

The original-set misses are `dev-031` (public `1.1.1.1` incorrectly labelled
sensitive) and `dev-048` (an email incorrectly labelled clean). Corrected labels
make those decisions explicit rather than weakening the detector.

## Design trade-offs

- Validated payment identifiers and known credential prefixes bypass the model
  because deterministic validators are faster and more reliable for exact spans.
- Invalid card numbers alert only with nearby card context and can be disabled
  with `ZEUSLOCK_ALERT_INVALID_CARDS=0`.
- Loopback IPs are allowed; RFC1918 private addresses alert.
- An internal IP inside a credential URI is retained as a nested network finding
  for auditability.
- When Ollama is unavailable, ambiguous candidates retain their deterministic
  result and the API never raises.
- `phonenumbers` validates FR, US, GB, DE, ES, and PK numbers; local numbers
  still require phone context to avoid order numbers and ISBNs.

## Model measurement

The measured local model was `qwen2.5:3b`. The evaluator records prompt-level
findings, strict and lenient value matches, model calls, cache hits, failures,
decisions, and latency percentiles.

## Submission notes

This implementation used AI coding assistance for scaffolding, detector
implementation, test generation, and review; every generated file was
reviewed and validated locally. Exact wall-clock hours were not tracked.
