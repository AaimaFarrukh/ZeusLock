import re

# The detector does not blindly trust every number that matches a pattern. It uses mathematical validation to reduce false positives.

def luhn_valid(value: str) -> bool:
    # Credit card validation, a checksum used by many payment-card numbering systems to distinguish valid numbers from mistyped or otherwise incorrect numbers.
    # Luhn catches transcription errors; it is not a claim that a card exists or is active.
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2: # True when index is 1, 3, 5, ... 
            digit *= 2 # double every second digit from the right (the check digit is not doubled).
            if digit > 9: # if the result of this doubling operation is greater than 9 (e.g., 8 * 2 = 16), then subtract 9 from the product (e.g., 16: 1 + 6 = 7, or equivalently, 16 - 9 = 7).
                digit -= 9
        total += digit
    return total % 10 == 0 


IBAN_LENGTHS = {
    "AT": 20, "BE": 16, "CH": 21, "DE": 22, "DK": 18, "ES": 24,
    "FI": 18, "FR": 27, "GB": 22, "IE": 22, "IT": 27, "LU": 20,
    "NL": 18, "NO": 15, "PL": 28, "PT": 25, "SE": 24,
}


# IBAN: Move the first 4 characters to the end, convert letters to numbers (A=10…Z=35), then compute the whole number mod 97 — valid if the remainder is 1.
def iban_valid(value: str) -> bool:
    # IBAN's rearranged mod-97 check rejects invoice/order numbers that merely look similar.
    compact = re.sub(r"\s+", "", value).upper()
    if len(compact) < 5 or compact[:2] not in IBAN_LENGTHS:
        return False
    if len(compact) != IBAN_LENGTHS[compact[:2]] or not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]+", compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    remainder = 0
    for chunk in re.findall(r".{1,7}", numeric):
        remainder = int(str(remainder) + chunk) % 97
    return remainder == 1


def ssn_valid(value: str) -> bool:
    # SSA-invalid ranges prevent generic nine-digit identifiers from becoming SSNs. SSN -> US Social Security Number
    digits = re.sub(r"\D", "", value)
    return (
        len(digits) == 9
        and digits[:3] not in {"000", "666"}
        and not digits.startswith("9")
        and digits[3:5] != "00"
        and digits[5:] != "0000"
    )


# Nir-> French National Identification Number.
def nir_valid(value: str) -> bool:
    compact = re.sub(r"\s+", "", value).upper()
    if len(compact) != 15:
        return False
    body, key = compact[:13], compact[13:]
    if not re.fullmatch(r"\d{5}(?:\d{2}|2A|2B)\d{6}", body) or not key.isdigit():
        return False
    # Corsican department codes are letters in source documents but numeric in the key formula.
    if body[5:7] == "2A":
        body = body[:5] + "19" + body[7:]
    elif body[5:7] == "2B":
        body = body[:5] + "18" + body[7:]
    # French NIR uses a numeric key; Corsica's 2A/2B variants are handled by normalization upstream.
    return (97 - int(body) % 97) == int(key)


def entropy(value: str) -> float:
    from math import log2
    counts = {char: value.count(char) for char in set(value)}
    return -sum((count / len(value)) * log2(count / len(value)) for count in counts.values()) if value else 0.0
