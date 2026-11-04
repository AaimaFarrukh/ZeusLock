"""Public ZeusLock interface."""

from zeuslock.detectors import all_findings
from zeuslock.llm import judge_candidate, judge_code
from zeuslock.merge import merge
from zeuslock.normalize import normalize
from zeuslock.router import needs_llm
from zeuslock.types import Finding


def _merge(text: str, findings: list[Finding]) -> list[Finding]:
    return merge(text, findings)


def detect(text: str) -> dict:
    """Detect sensitive values without ever allowing an internal error to escape."""
    if not isinstance(text, str):
        return {"decision": "allow", "findings": []}
    normalized = normalize(text)
    try:
        rules_findings = all_findings(normalized.text)
    except Exception:
        rules_findings = []
    judged: list[Finding] = []
    for finding in rules_findings:
        try:
            if not needs_llm(finding):
                decision = True
            else:
                context = normalized.text[max(0, finding.start - 120):min(len(normalized.text), finding.end + 120)]
                decision = judge_code(finding.value) if finding.category == "SOURCE_CODE" else judge_candidate(
                    finding.category, finding.value, context
                )
            # Ollama failures return None and preserve the deterministic candidate.
            if decision is not False:
                start, end = normalized.span(finding.start, finding.end)
                value = text[start:end]
                judged.append(Finding(finding.category, start, end, value, finding.confidence, finding.needs_llm))
        except Exception:
            # A judge failure must not discard a high-confidence rules finding.
            start, end = normalized.span(finding.start, finding.end)
            judged.append(Finding(finding.category, start, end, text[start:end], finding.confidence, finding.needs_llm))
    try:
        findings = _merge(text, judged)
    except Exception:
        findings = []
    return {
        "decision": "alert" if findings else "allow",
        "findings": [finding.as_dict() for finding in findings],
    }
