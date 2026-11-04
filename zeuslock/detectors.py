import ipaddress
import re
try:
    import phonenumbers
except ImportError:
    phonenumbers = None

from .types import Finding
from .config import ALERT_INVALID_CARDS
from .validators import iban_valid, luhn_valid, nir_valid, ssn_valid


def _finding(category: str, match: re.Match[str], group: int = 0, **kwargs) -> Finding:
    start, end = match.span(group)
    return Finding(category, start, end, match.group(group), **kwargs)


def payment(text: str) -> list[Finding]:
    # Validators are applied after broad matching so formatting variants remain supported.
    found: list[Finding] = []
    iban_pattern = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[\s-]?[A-Z0-9]){11,34}(?![A-Z0-9])", re.I)
    for match in iban_pattern.finditer(text):
        value = match.group()
        end = len(value)
        while end >= 5 and not iban_valid(value[:end]):
            end -= 1
        if end >= 5:
            candidate = value[:end].rstrip()
            start = match.start()
            found.append(Finding("PAYMENT", start, start + len(candidate), candidate))
    crypto = re.compile(r"\b(?:0x[0-9a-fA-F]{40}|bc1[a-z0-9]{25,87}|[13][1-9A-HJ-NP-Za-km-z]{25,39})\b")
    found.extend(_finding("PAYMENT", m) for m in crypto.finditer(text))
    card = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
    for match in card.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        if 13 <= len(digits) <= 19 and luhn_valid(digits):
            found.append(_finding("PAYMENT", match))
        elif ALERT_INVALID_CARDS and 13 <= len(digits) <= 19: 
            # if invalid-card alets are enabbled, then it extracts upto 25 characters before the preceeding text. if card etc words are there then its given lower confidence and should be passed to the llm for evaluation. 
            context = text[max(0, match.start() - 25):match.start()].lower()
            if re.search(r"\b(?:card|carte|tarjeta|american express|visa|mastercard)\b", context):
                found.append(_finding("PAYMENT", match, confidence=0.5, needs_llm=True))
    return found


def credential(text: str) -> list[Finding]:
    found: list[Finding] = []
    prefixes = re.compile(
        r"\b(?:sk_(?:live|test)_[A-Za-z0-9_-]{10,}|sk-(?:live|test|proj)-[A-Za-z0-9_-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|"
        r"github_pat_[A-Za-z0-9_]{20,}|hf_[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{15,}|"
        r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,})\b"
    )
    found.extend(_finding("CREDENTIAL", m) for m in prefixes.finditer(text))
    pem = re.compile(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", re.S)
    found.extend(_finding("CREDENTIAL", m) for m in pem.finditer(text))
    jwt = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
    found.extend(_finding("CREDENTIAL", m) for m in jwt.finditer(text))
    key = re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_ -]?key|authorization|"
        r"mot de passe|contraseña|passwort)(?:[^\n:=]{0,35})\s*[:=]\s*"
        r"(?!YOUR_[A-Z_]+)([^\s,;\"']+)"
    )
    for match in key.finditer(text):
        value = match.group(1).rstrip(".!?")
        start = match.start(1)
        found.append(Finding("CREDENTIAL", start, start + len(value), value, 0.9)) # 0.9 -> Because a matching assignment doesn't necessarily guarantee that the value is a real secret. It could be an example or placeholder.
    # Natural-language secrets are deliberately restricted to explicit assignment context.
    natural = re.compile(r"(?i)(?:password|mot de passe|contraseña)\s+(?:to|à|a)\s+.*?\b(?:so\s+)?([A-Za-z][A-Za-z0-9!@#$%^&*_+-]{5,})")
    for match in natural.finditer(text):
        found.append(_finding("CREDENTIAL", match, 1, confidence=0.8))
    uri = re.compile(r"(?<!\w)(\*{3,}[A-Za-z0-9._-]+(?::\d+)?(?:/[A-Za-z0-9._/?=-]*)?)")
    found.extend(_finding("CREDENTIAL", m) for m in uri.finditer(text))
    aws = re.compile(r"(?i)AWS_SECRET_ACCESS_KEY\s*=\s*([A-Za-z0-9/+=]{30,})")
    found.extend(_finding("CREDENTIAL", m, 1) for m in aws.finditer(text))
    connection = re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
        r"([^/\s:@]+):([^@\s]+)@[^ \s]+"
    )
    for match in connection.finditer(text):
        found.append(Finding("CREDENTIAL", match.start(), match.end(), match.group(), 0.95))
    return found


def contact(text: str) -> list[Finding]:
    found = [_finding("CONTACT", m) for m in re.finditer(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b", text)]
    # Requiring phone context for local numbers avoids order IDs and ISBNs.
    phone = re.compile(r"(?<![\w@])(?:\+\d{1,3}[\s-]?)?(?:\d[\s().-]?){7,14}\d(?![\w@])")
    for match in phone.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        context = text[max(0, match.start() - 35):match.start()].lower()
        phone_context = bool(re.search(r"phone|tel|call|reach|mobile|\+33|\+44|\+92|\+49|téléphone|numéro|erreichbar|llama|telefono|\bau\b", context))
        valid_phone = False
        if phonenumbers is not None:
            for region in ("FR", "US", "GB", "DE", "ES", "PK"):
                try:
                    parsed = phonenumbers.parse(match.group(), region)
                    if phonenumbers.is_valid_number(parsed):
                        valid_phone = True
                        break
                except phonenumbers.NumberParseException:
                    continue
        explicit_phone = match.group().lstrip().startswith("+") or phone_context
        if explicit_phone and (valid_phone or 9 <= len(digits) <= 15):
            found.append(_finding("CONTACT", match))
    address = re.compile(
        r"(?i)\b\d{1,5}\s+[^.\n]{5,110}?\b(?:\d{5}(?:-\d{4})?|[A-Z]{2}\s+\d{5})\b"
    )
    found.extend(_finding("CONTACT", m, confidence=0.7, needs_llm=True) for m in address.finditer(text))
    return found


def gov_id(text: str) -> list[Finding]:
    found: list[Finding] = []
    for match in re.finditer(r"\b\d{3}-\d{2}-\d{4}\b", text):
        if ssn_valid(match.group()):
            found.append(_finding("GOV_ID", match))
    for match in re.finditer(r"\b\d(?:\s*\d){12}\s*\d{2}\b", text):
        if nir_valid(match.group()):
            found.append(_finding("GOV_ID", match))
    passport_context = re.compile(r"(?i)(?:passport|passeport|pasaporte|reisepass)[^.\n]{0,40}\b([A-Z0-9]{7,12})\b")
    found.extend(_finding("GOV_ID", m, 1) for m in passport_context.finditer(text))
    return found


def network(text: str) -> list[Finding]:
    found: list[Finding] = []
    for match in re.finditer(r"(?<![\w-])(?:\d{1,3}\.){3}\d{1,3}(?![\w-])", text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        # Loopback is a local service address, while RFC1918 addresses identify internal hosts.
        if address.is_private and not address.is_loopback:
            found.append(_finding("NETWORK", match))
    return found


def source_code(text: str) -> list[Finding]:
    if re.search(r"(?i)traceback \(most recent call last\)|zerodivisionerror", text):
        return []
    # Stack traces are operational diagnostics, not proprietary source code.
    blocks = list(re.finditer(r"(?ms)(?:^```[^\n]*\n.*?^```$)|(?:^(?:\s{4,}.+|(?:def|class|function|SELECT|export class)\b.*(?:\n|$)){2,})|(?:^(?:SELECT|select)\b.*?;\s*$)", text))
    found = []
    for match in blocks:
        block = match.group()
        score = sum(bool(pattern.search(block)) for pattern in (
            re.compile(r"\b(def|class|function|SELECT|FROM|return)\b"),
            re.compile(r"[{};]"),
            re.compile(r"\n\s{2,}\S"),
            re.compile(r"\b(?:internal|secret|pricing|fraud|commission|weights|RATE_TABLE)\b", re.I),
        ))
        if score >= 2:
            found.append(_finding("SOURCE_CODE", match, confidence=0.7, needs_llm=True))
    return found


def all_findings(text: str) -> list[Finding]:
    return payment(text) + credential(text) + contact(text) + gov_id(text) + network(text) + source_code(text)
