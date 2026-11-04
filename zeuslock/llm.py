"""Small, local-only Ollama judge for ambiguous detector candidates."""

import hashlib # creates a hash of the prompt to avoid storing sensitive text in memory
import json
import threading
import urllib.error
import urllib.request

from .config import OLLAMA_ENABLED, OLLAMA_MODEL, OLLAMA_TIMEOUT, OLLAMA_URL

_cache: dict[str, bool] = {}
_cache_lock = threading.Lock()
_unavailable = False
_stats = {
    "judge_calls": 0,
    "cache_hits": 0,
    "model_requests": 0,
    "model_failures": 0,
    "true_decisions": 0,
    "false_decisions": 0,
}


def reset_stats() -> None:
    with _cache_lock:
        for key in _stats:
            _stats[key] = 0


def stats() -> dict[str, int]:
    with _cache_lock:
        return dict(_stats)


def _request(prompt: str, schema: dict) -> dict | None:
    global _unavailable
    if not OLLAMA_ENABLED or _unavailable:
        return None
    # Ollama is contacted only on localhost, keeping prompt content on the machine.
    payload = {
        "model": OLLAMA_MODEL,
        "stream": False,
        "keep_alive": "10m",
        "format": schema,
        "options": {"temperature": 0, "num_predict": 20},
        "prompt": prompt,
    }
    request = urllib.request.Request(
        OLLAMA_URL.rstrip("/") + "/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    for _ in range(2):
        with _cache_lock:
            _stats["model_requests"] += 1
        try:
            with urllib.request.urlopen(request, timeout=OLLAMA_TIMEOUT) as response:
                body = json.loads(response.read().decode("utf-8"))
            result = json.loads(body["response"])
            if isinstance(result, dict):
                return result
        except (OSError, ValueError, KeyError, urllib.error.URLError):
            continue
    with _cache_lock:
        _stats["model_failures"] += 1
    # Avoid paying a timeout on every prompt when the optional local service is down.
    _unavailable = True
    return None


def _cached(prompt: str, schema: dict) -> bool | None:
    key = hashlib.sha256((OLLAMA_MODEL + "\0" + prompt).encode("utf-8")).hexdigest()
    # Hashing keeps repeated prompts fast without retaining their sensitive text as a key.
    with _cache_lock:
        _stats["judge_calls"] += 1
        if key in _cache:
            _stats["cache_hits"] += 1
            return _cache[key]
    result = _request(prompt, schema)
    if result is None:
        return None
    value = result.get("sensitive")
    if not isinstance(value, bool):
        return None
    with _cache_lock:
        _cache[key] = value
        _stats["true_decisions" if value else "false_decisions"] += 1
    return value


def judge_candidate(category: str, value: str, context: str) -> bool | None:
    prompt = (
        "You are a privacy classifier. Return JSON only. "
        "Decide whether the marked text is sensitive private data, not merely a "
        "public example, placeholder, log, or question about a secret. "
        "Categories include CONTACT address and PAYMENT card. "
        "Text may be English, French, Spanish, or German.\n"
        f"Category: {category}\nMarked text: {value}\nContext:\n{context}\n"
    )
    return _cached(prompt, {"type": "object", "properties": {"sensitive": {"type": "boolean"}}, "required": ["sensitive"]})


def judge_code(block: str) -> bool | None:
    prompt = (
        "Return JSON only. Decide whether this code is proprietary or internal "
        "business logic (internal names, pricing, scoring, secret configuration), "
        "rather than a generic/public snippet or stack trace.\n"
        f"Code:\n{block}\n"
    )
    return _cached(prompt, {"type": "object", "properties": {"sensitive": {"type": "boolean"}}, "required": ["sensitive"]})
