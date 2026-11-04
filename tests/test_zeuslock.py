import unittest

from submission import detect
from zeuslock.normalize import normalize
from zeuslock.validators import entropy, iban_valid, luhn_valid, nir_valid, ssn_valid


class ValidatorTests(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(luhn_valid("4532015112830366"))
        self.assertFalse(luhn_valid("4532015112830367"))

    def test_iban_mod97(self):
        self.assertTrue(iban_valid("GB82 WEST 1234 5698 7654 32"))
        self.assertFalse(iban_valid("GB82 WEST 1234 5698 7654 33"))

    def test_nir_key(self):
        self.assertTrue(nir_valid("2 91 03 13 780 542 05"))
        self.assertFalse(nir_valid("2 91 03 13 780 542 06"))

    def test_ssn_ranges(self):
        self.assertTrue(ssn_valid("512-38-4417"))
        self.assertFalse(ssn_valid("000-38-4417"))

    def test_entropy(self):
        self.assertGreater(entropy("x7Q!m2P#z9"), entropy("aaaaaaaaaa"))


class DetectorTests(unittest.TestCase):
    def assertFinding(self, text, category, value):
        result = detect(text)
        self.assertEqual("alert", result["decision"])
        self.assertTrue(any(f["category"] == category and f["value"] == value for f in result["findings"]))
        for finding in result["findings"]:
            self.assertEqual(text[finding["start"]:finding["end"]], finding["value"])

    def test_card(self):
        self.assertFinding("Pay with 4532 0151 1283 0366.", "PAYMENT", "4532 0151 1283 0366")

    def test_iban(self):
        self.assertFinding("Transfer to GB82 WEST 1234 5698 7654 32.", "PAYMENT", "GB82 WEST 1234 5698 7654 32")

    def test_private_ip(self):
        self.assertFinding("Database is at 10.20.0.15.", "NETWORK", "10.20.0.15")

    def test_public_ip_is_clean(self):
        self.assertEqual("allow", detect("Use public resolver 1.1.1.1.")["decision"])

    def test_password_value_only(self):
        self.assertFinding("password: hunter2", "CREDENTIAL", "hunter2")

    def test_email(self):
        self.assertFinding("Contact a@company.example", "CONTACT", "a@company.example")

    def test_uuid_is_clean(self):
        self.assertEqual("allow", detect("request id 3f2b8c1e-9d4a-4c6b-8e21-7a5f0c9d2e14")["decision"])

    def test_stack_trace_is_clean(self):
        self.assertEqual("allow", detect("Traceback (most recent call last):\nZeroDivisionError")["decision"])

    def test_normalizer_preserves_mapping(self):
        normalized = normalize("x\u200by")
        self.assertEqual("xy", normalized.text)
        self.assertEqual((0, 3), normalized.span(0, 2))


if __name__ == "__main__":
    unittest.main()
