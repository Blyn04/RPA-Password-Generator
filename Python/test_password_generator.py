import unittest
import sys
import os

# Adjust path to import core and security modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core import (
    generate_password,
    generate_passphrase,
    generate_pronounceable,
    generate_pattern
)
from security import (
    calculate_entropy,
    evaluate_strength,
    is_common_password
)

class TestPasswordGenerator(unittest.TestCase):
    def test_generate_password(self):
        # Default behavior
        pwd = generate_password(length=12)
        self.assertEqual(len(pwd), 12)
        
        # Checking constraints
        pwd_digits_only = generate_password(length=8, use_upper=False, use_lower=False, use_digits=True, use_special=False)
        self.assertTrue(pwd_digits_only.isdigit())

    def test_generate_passphrase(self):
        phrase = generate_passphrase(words_count=4, separator="-")
        words = phrase.split("-")
        self.assertEqual(len(words), 4)

    def test_generate_pronounceable(self):
        pron = generate_pronounceable(length=12, separator="")
        self.assertEqual(len(pron), 12)
        # Alternate consonants and vowels check
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels = "aeiou"
        for i, char in enumerate(pron):
            if i % 2 == 0:
                self.assertIn(char.lower(), consonants)
            else:
                self.assertIn(char.lower(), vowels)

    def test_generate_pattern(self):
        pattern = "?u?l?d?s"
        pwd = generate_pattern(pattern)
        self.assertEqual(len(pwd), 4)
        self.assertTrue(pwd[0].isupper())
        self.assertTrue(pwd[1].islower())
        self.assertTrue(pwd[2].isdigit())
        self.assertFalse(pwd[3].isalnum())

    def test_calculate_entropy(self):
        # 12 chars lowercase character password
        # Pool size = 26. Entropy = 12 * log2(26) = 12 * 4.7004 = 56.4
        ent = calculate_entropy("abcdefghijkl", mode="character", char_pool_size=26)
        self.assertAlmostEqual(ent, 56.4, places=1)

        # Passphrase: 4 words -> 4 * 10 = 40 bits
        ent_phrase = calculate_entropy("hello-world-test-run", mode="passphrase", words_count=4)
        self.assertEqual(ent_phrase, 40.0)

    def test_is_common_password(self):
        self.assertTrue(is_common_password("123456"))
        self.assertTrue(is_common_password("password"))
        self.assertTrue(is_common_password("11111111"))
        self.assertFalse(is_common_password("S3cur3_Pa$$w0rd!_2026"))

    def test_evaluate_strength(self):
        # Common password is weak
        label, _ = evaluate_strength("123456")
        self.assertEqual(label, "Compromised / Very Weak")

        # High entropy password is very strong
        label, _ = evaluate_strength("S3cur3_Pa$$w0rd!_2026", entropy=120.0)
        self.assertEqual(label, "Very Strong")

if __name__ == "__main__":
    unittest.main()
