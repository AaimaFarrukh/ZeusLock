from dataclasses import dataclass
import unicodedata


@dataclass(frozen=True) # frozen=True makes the dataclass immutable, meaning that once an instance is created, its fields cannot be modified. This is useful for ensuring that the data remains consistent and prevents accidental changes to the instance's state.
class NormalizedText:
    text: str
    original_indices: tuple[int, ...]

    def span(self, start: int, end: int) -> tuple[int, int]:
        """Map a normalized span back without losing exact source offsets."""
        if start >= end or start >= len(self.original_indices):
            return (0, 0)
        original_start = self.original_indices[start]
        original_end = self.original_indices[min(end - 1, len(self.original_indices) - 1)] + 1
        return original_start, original_end


def normalize(text: str) -> NormalizedText:
    # Removing zero-width characters prevents evasion while retaining source positions.
    output: list[str] = []
    indices: list[int] = []
    for index, character in enumerate(text):
        if unicodedata.category(character) == "Cf":
            continue  # Cf = Other, Format (zero-width, etc.). Skip this and move on to the next character.
        replacement = unicodedata.normalize("NFKC", character) # NFKC= Unicode Normalization Form KC (Compatibility Composition). This will replace characters with their compatibility equivalents, e.g., full-width to standard equivalents.
        for normalized_character in replacement:
            output.append(normalized_character)
            indices.append(index)
    return NormalizedText("".join(output), tuple(indices))
