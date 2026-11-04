# ZeusLock

ZeusLock is a local, rules-first detector for sensitive values in prompts.

## Run

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
ollama pull qwen2.5:3b
ollama serve
python -c "from submission import detect; print(detect('card 4532015112830366'))"
```

`detect(text)` returns `{"decision": "alert"|"allow", "findings": [...]}`.
Every finding contains offsets into the original input, and the implementation
does not require network access or a model to run.

The current Level 1 implementation uses deterministic validators for payment
data, credentials, contacts, government IDs, private IPs, and proprietary
code-looking blocks. Ambiguous address, invalid-card, and code candidates are
optionally judged by a local Ollama model; if Ollama is unavailable, the
deterministic result is retained.

```powershell
python -c "from submission import detect; print(detect('password: example-secret'))"
```

Set `ZEUSLOCK_ENABLE_LLM=0` for rules-only operation.

## Development

```powershell
python -m unittest discover -s tests -v
python eval\eval.py --no-llm --labels corrected --json-out eval\corrected_report.json
```

The evaluator reports prompt accuracy, per-category precision/recall/F1,
latency percentiles, and individual failures. The detector is intentionally
rules-first: validated high-confidence secrets do not incur an LLM call, while
ambiguous addresses, invalid card numbers, and code blocks may use Ollama.
