import os


OLLAMA_URL = os.getenv("ZEUSLOCK_OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("ZEUSLOCK_OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_TIMEOUT = float(os.getenv("ZEUSLOCK_OLLAMA_TIMEOUT", "10"))
OLLAMA_ENABLED = os.getenv("ZEUSLOCK_ENABLE_LLM", "1").lower() not in {"0", "false", "no"}
# Invalid card numbers are ambiguous references, so this trade-off is explicit and configurable.
ALERT_INVALID_CARDS = os.getenv("ZEUSLOCK_ALERT_INVALID_CARDS", "1").lower() not in {"0", "false", "no"}
