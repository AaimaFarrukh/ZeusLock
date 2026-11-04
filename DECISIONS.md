# Detection decisions

- Loopback addresses are allowed; RFC1918 private addresses alert.
- An internal IP inside a credential URI produces both a credential finding and a nested network finding.
- Invalid card numbers alert only with explicit card context, at lower confidence.
- Invalid-card alerts default on (`ZEUSLOCK_ALERT_INVALID_CARDS=0` disables them) because a pasted receipt reference is otherwise indistinguishable from a typo.
- Findings use deterministic offsets; no model is allowed to invent offsets.
