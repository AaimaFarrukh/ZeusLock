from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    category: str
    start: int
    end: int
    value: str
    confidence: float = 1.0
    needs_llm: bool = False

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "value": self.value,
        }
