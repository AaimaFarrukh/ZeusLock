from .types import Finding

# smaller numbers are higher priority.
PRIORITY = {"CREDENTIAL": 0, "PAYMENT": 1, "GOV_ID": 2, "CONTACT": 3, "NETWORK": 4, "SOURCE_CODE": 5}


def merge(text: str, findings: list[Finding]) -> list[Finding]:
    # Reject bad offsets at the boundary so an LLM can never corrupt the API contract.
    valid = [
        item for item in findings
        if 0 <= item.start < item.end <= len(text) and text[item.start:item.end] == item.value
    ]
    unique = {(item.category, item.start, item.end): item for item in valid} # deduplication
    ordered = sorted(unique.values(), key=lambda item: (PRIORITY.get(item.category, 99), item.start, -(item.end - item.start)))
    selected: list[Finding] = []
    for candidate in ordered:
        conflicts = [item for item in selected if candidate.start < item.end and item.start < candidate.end]
        if not conflicts:
            selected.append(candidate)
        # if network is fully in credential then it is not skipped and both are kept. This is because the network is evidence of the credential and should be kept for context.
        elif candidate.category == "NETWORK" and any(
            item.category == "CREDENTIAL" and item.start <= candidate.start and candidate.end <= item.end
            for item in conflicts
        ):
            # The nested IP is useful evidence of the private host inside a secret URI.
            selected.append(candidate)
    return sorted(selected, key=lambda item: item.start)
