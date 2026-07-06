"""
Comprehensive test suite for the RPA Password Generator project.

Covers the following modules:
    - core.py      : Password, passphrase, pronounceable, and pattern generation
    - security.py  : Entropy calculation, strength evaluation, common-password checks
    - totp.py      : HOTP / TOTP generation, time-remaining, OTPAuth URI parsing
    - auditor.py   : Levenshtein distance, policy checks, batch auditing
    - vault.py     : Encrypted vault create / unlock / CRUD / search operations
"""

import unittest
import sys
import os

# ---------------------------------------------------------------------------
# Ensure the package directory is on sys.path so imports resolve correctly
# regardless of how the test runner is invoked.
# ---------------------------------------------------------------------------
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core import generate_password, generate_passphrase, generate_pronounceable, generate_pattern
from security import (
    SPECIAL_CHARS,
    AMBIGUOUS_CHARS,
    is_common_password,
    calculate_entropy,
    evaluate_strength,
)
from totp import hotp, totp, time_remaining, parse_otpauth_uri
from auditor import (
    levenshtein_distance,
    PasswordPolicy,
    check_policy,
    PasswordAuditor,
)
from vault import PasswordVault


# ═══════════════════════════════════════════════════════════════════════════
# Password Generation Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPasswordGeneration(unittest.TestCase):
    """Tests for core.generate_password()."""

    def test_default_password_length(self) -> None:
        """Default call should produce a 12-character password."""
        password = generate_password()
        self.assertEqual(len(password), 12)

    def test_custom_length(self) -> None:
        """Specifying length=24 should produce a 24-character password."""
        password = generate_password(length=24)
        self.assertEqual(len(password), 24)

    def test_digits_only(self) -> None:
        """With only digits enabled the result must be purely numeric."""
        password = generate_password(
            use_upper=False,
            use_lower=False,
            use_digits=True,
            use_special=False,
        )
        self.assertTrue(password.isdigit(), f"Expected all digits, got: {password!r}")

    def test_lowercase_only(self) -> None:
        """With only lowercase enabled the result must be all lowercase."""
        password = generate_password(
            use_upper=False,
            use_lower=True,
            use_digits=False,
            use_special=False,
        )
        self.assertTrue(password.islower(), f"Expected all lowercase, got: {password!r}")

    def test_minimum_length(self) -> None:
        """Length=4 should succeed; length=3 should raise ValueError."""
        password = generate_password(length=4)
        self.assertEqual(len(password), 4)
        with self.assertRaises(ValueError):
            generate_password(length=3)

    def test_no_char_type_raises(self) -> None:
        """Disabling every character type should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_password(
                use_upper=False,
                use_lower=False,
                use_digits=False,
                use_special=False,
            )

    def test_exclude_ambiguous(self) -> None:
        """50 passwords generated with exclude_ambiguous must not contain ambiguous chars."""
        for _ in range(50):
            password = generate_password(exclude_ambiguous=True)
            for ch in password:
                self.assertNotIn(
                    ch,
                    AMBIGUOUS_CHARS,
                    f"Ambiguous character {ch!r} found in password {password!r}",
                )

    def test_guaranteed_char_types(self) -> None:
        """With all types enabled each password must contain ≥1 of every type."""
        for _ in range(20):
            password = generate_password(
                use_upper=True,
                use_lower=True,
                use_digits=True,
                use_special=True,
            )
            self.assertTrue(
                any(c.isupper() for c in password),
                f"No uppercase character in {password!r}",
            )
            self.assertTrue(
                any(c.islower() for c in password),
                f"No lowercase character in {password!r}",
            )
            self.assertTrue(
                any(c.isdigit() for c in password),
                f"No digit in {password!r}",
            )
            self.assertTrue(
                any(c in SPECIAL_CHARS for c in password),
                f"No special character in {password!r}",
            )


# ═══════════════════════════════════════════════════════════════════════════
# Passphrase Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPassphrase(unittest.TestCase):
    """Tests for core.generate_passphrase()."""

    def test_word_count(self) -> None:
        """A 4-word passphrase with '-' separator should split into 4 parts."""
        passphrase = generate_passphrase(words_count=4, separator="-")
        words = passphrase.split("-")
        self.assertEqual(len(words), 4)

    def test_capitalize(self) -> None:
        """With capitalize=True every word should start with an uppercase letter."""
        passphrase = generate_passphrase(words_count=4, separator="-", capitalize=True)
        for word in passphrase.split("-"):
            self.assertTrue(
                word[0].isupper(),
                f"Word {word!r} does not start with an uppercase letter",
            )

    def test_min_words_raises(self) -> None:
        """words_count=1 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_passphrase(words_count=1)


# ═══════════════════════════════════════════════════════════════════════════
# Pronounceable Password Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPronounceable(unittest.TestCase):
    """Tests for core.generate_pronounceable()."""

    def test_length_no_separator(self) -> None:
        """With no separator the output length must equal the requested length."""
        password = generate_pronounceable(length=12, separator="")
        self.assertEqual(
            len(password),
            12,
            f"Expected length 12, got {len(password)} ({password!r})",
        )

    def test_consonant_vowel_pattern(self) -> None:
        """Characters should roughly alternate between consonants and vowels."""
        vowels = set("aeiou")
        consonants = set("bcdfghjklmnpqrstvwxyz")
        password = generate_pronounceable(length=10, separator="")
        lower_pw = password.lower()
        for i, ch in enumerate(lower_pw):
            if i % 2 == 0:
                self.assertIn(
                    ch, consonants,
                    f"Position {i} should be a consonant, got {ch!r}",
                )
            else:
                self.assertIn(
                    ch, vowels,
                    f"Position {i} should be a vowel, got {ch!r}",
                )

    def test_min_length_raises(self) -> None:
        """length=3 should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_pronounceable(length=3)


# ═══════════════════════════════════════════════════════════════════════════
# Pattern-based Password Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPattern(unittest.TestCase):
    """Tests for core.generate_pattern()."""

    def test_basic_pattern(self) -> None:
        """Pattern '?u?l?d?s' → 4 chars: upper, lower, digit, special."""
        password = generate_pattern("?u?l?d?s")
        self.assertEqual(len(password), 4)
        self.assertTrue(password[0].isupper(), f"[0] not upper: {password!r}")
        self.assertTrue(password[1].islower(), f"[1] not lower: {password!r}")
        self.assertTrue(password[2].isdigit(), f"[2] not digit: {password!r}")
        self.assertFalse(password[3].isalnum(), f"[3] should be special: {password!r}")

    def test_literal_characters(self) -> None:
        """Pattern 'ABC?d?d' → 'ABC' followed by two digits."""
        password = generate_pattern("ABC?d?d")
        self.assertEqual(len(password), 5)
        self.assertEqual(password[:3], "ABC")
        self.assertTrue(password[3].isdigit(), f"[3] not digit: {password!r}")
        self.assertTrue(password[4].isdigit(), f"[4] not digit: {password!r}")

    def test_empty_pattern_raises(self) -> None:
        """An empty pattern string should raise ValueError."""
        with self.assertRaises(ValueError):
            generate_pattern("")


# ═══════════════════════════════════════════════════════════════════════════
# Security / Entropy Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestSecurity(unittest.TestCase):
    """Tests for security.calculate_entropy() and friends."""

    def test_entropy_character_mode(self) -> None:
        """12-char lowercase password (pool 26) ≈ 56.4 bits of entropy."""
        entropy = calculate_entropy(
            "abcdefghijkl",
            mode="character",
            char_pool_size=26,
        )
        self.assertAlmostEqual(entropy, 56.4, places=1)

    def test_entropy_passphrase(self) -> None:
        """A 4-word passphrase should yield ≈ 40.0 bits of entropy."""
        entropy = calculate_entropy(
            "correct-horse-battery-staple",
            mode="passphrase",
            words_count=4,
        )
        self.assertAlmostEqual(entropy, 40.0, places=0)

    def test_common_password_detected(self) -> None:
        """Well-known common passwords must be flagged."""
        self.assertTrue(is_common_password("123456"))
        self.assertTrue(is_common_password("password"))

    def test_strength_levels(self) -> None:
        """'123456' should be very weak; a 120-bit entropy password very strong."""
        label_weak, _ = evaluate_strength("123456", entropy=0)
        self.assertIn("Compromised", label_weak)

        label_strong, _ = evaluate_strength("S3cur3_Pa$$w0rd!_2026", entropy=120)
        self.assertIn("Very Strong", label_strong)


# ═══════════════════════════════════════════════════════════════════════════
# TOTP / HOTP Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestTOTP(unittest.TestCase):
    """Tests for totp.hotp(), totp(), time_remaining(), parse_otpauth_uri()."""

    # RFC 4226 Appendix D test vector — counter 0
    _RFC_SECRET = b"12345678901234567890"

    def test_hotp_rfc_vector(self) -> None:
        """HOTP with the RFC 4226 test secret at counter=0 must produce '755224'."""
        code = hotp(self._RFC_SECRET, counter=0, digits=6, algorithm="sha1")
        self.assertEqual(code, "755224")

    def test_totp_deterministic(self) -> None:
        """TOTP at a fixed timestamp must return a deterministic 6-digit string."""
        code = totp(
            self._RFC_SECRET,
            time_step=30,
            digits=6,
            algorithm="sha1",
            current_time=59.0,
        )
        self.assertIsInstance(code, str)
        self.assertEqual(len(code), 6)
        self.assertTrue(code.isdigit(), f"Expected 6-digit string, got {code!r}")

    def test_time_remaining(self) -> None:
        """At t=59 with step=30 the remaining seconds should be 1."""
        remaining = time_remaining(time_step=30, current_time=59.0)
        self.assertEqual(remaining, 1)

    def test_parse_otpauth_uri(self) -> None:
        """Parsing a standard otpauth URI should extract the expected fields."""
        uri = (
            "otpauth://totp/Example:alice@example.com"
            "?secret=JBSWY3DPEHPK3PXP"
            "&issuer=Example"
            "&digits=6"
            "&period=30"
        )
        result = parse_otpauth_uri(uri)
        self.assertEqual(result["secret"], "JBSWY3DPEHPK3PXP")
        self.assertEqual(result["issuer"], "Example")
        self.assertEqual(result["digits"], 6)


# ═══════════════════════════════════════════════════════════════════════════
# Auditor Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAuditor(unittest.TestCase):
    """Tests for auditor.levenshtein_distance(), check_policy(), PasswordAuditor."""

    def test_levenshtein_distance(self) -> None:
        """Verify classic Levenshtein distance examples."""
        self.assertEqual(levenshtein_distance("kitten", "sitting"), 3)
        self.assertEqual(levenshtein_distance("", "abc"), 3)
        self.assertEqual(levenshtein_distance("abc", "abc"), 0)

    def test_policy_violation_min_length(self) -> None:
        """A 3-char password should violate a min_length=8 policy."""
        policy = PasswordPolicy(min_length=8)
        violations = check_policy("abc", policy)
        fields = [v.field for v in violations]
        self.assertIn("min_length", fields)

    def test_audit_batch_duplicates(self) -> None:
        """Duplicate passwords in a batch must cross-reference each other."""
        auditor = PasswordAuditor()
        results = auditor.audit_batch(["password123", "abcdef", "password123"])
        # Index 0 and index 2 are duplicates
        self.assertIn(2, results[0].duplicate_of)
        self.assertIn(0, results[2].duplicate_of)

    def test_audit_batch_similarity(self) -> None:
        """Passwords within the similarity threshold must flag each other."""
        auditor = PasswordAuditor(similarity_threshold=3)
        results = auditor.audit_batch(
            ["abcdef", "abcdeg"],
        )
        similar_indices = [idx for idx, dist in results[0].similar_to]
        self.assertIn(1, similar_indices)


# ═══════════════════════════════════════════════════════════════════════════
# Vault Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestVault(unittest.TestCase):
    """Tests for vault.PasswordVault CRUD operations."""

    def setUp(self) -> None:
        """Create a temporary vault file path in the project Outputs directory."""
        self.vault_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..",
            "Outputs",
            "test_vault.dat",
        )
        # Ensure the Outputs directory exists
        os.makedirs(os.path.dirname(self.vault_path), exist_ok=True)

    def tearDown(self) -> None:
        """Remove the temporary vault file if it exists."""
        if os.path.exists(self.vault_path):
            os.remove(self.vault_path)

    def test_create_and_unlock(self) -> None:
        """Creating, locking, then unlocking with the correct password should work."""
        vault = PasswordVault(self.vault_path)
        vault.create("master123")
        vault.lock()
        vault.unlock("master123")
        self.assertTrue(vault.is_unlocked())

    def test_wrong_password(self) -> None:
        """Unlocking with the wrong password should raise ValueError."""
        vault = PasswordVault(self.vault_path)
        vault.create("master123")
        vault.lock()
        with self.assertRaises(ValueError):
            vault.unlock("wrong_password")

    def test_add_and_retrieve(self) -> None:
        """Adding an entry and retrieving it by ID should return matching data."""
        vault = PasswordVault(self.vault_path)
        vault.create("master123")
        vault.unlock("master123")
        entry_id = vault.add_entry(
            site="GitHub",
            username="user",
            password="pass123",
        )
        entry = vault.get_entry(entry_id)
        self.assertEqual(entry["site"], "GitHub")

    def test_search_entries(self) -> None:
        """Searching 'git' should match both 'GitHub' and 'GitLab' entries."""
        vault = PasswordVault(self.vault_path)
        vault.create("master123")
        vault.unlock("master123")
        vault.add_entry(site="GitHub", username="user1", password="pass1")
        vault.add_entry(site="GitLab", username="user2", password="pass2")
        results = vault.search_entries("git")
        self.assertEqual(
            len(results),
            2,
            f"Expected 2 results for 'git', got {len(results)}: {results}",
        )


# ═══════════════════════════════════════════════════════════════════════════
# Entry Point
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    unittest.main()
