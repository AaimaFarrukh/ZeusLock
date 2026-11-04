from .types import Finding


def needs_llm(finding: Finding) -> bool:
    """Only ambiguous candidates need a model; validated secrets stay deterministic."""
    return finding.needs_llm
