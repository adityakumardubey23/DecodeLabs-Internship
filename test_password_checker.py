import unittest

from password_checker import analyze, has_repeats, has_sequence


class PasswordCheckerTests(unittest.TestCase):

    def test_short_password_fails_immediately(self):
        self.assertEqual(analyze("Ab1!").label, "Weak")

    def test_empty_password_does_not_crash(self):
        self.assertEqual(analyze("").label, "Weak")

    def test_common_password_is_weak(self):
        self.assertEqual(analyze("password").label, "Weak")
        self.assertEqual(analyze("12345678").label, "Weak")

    def test_leet_speak_is_not_strong(self):
        self.assertNotEqual(analyze("P@ssw0rd!").label, "Strong")

    def test_missing_classes_cannot_be_strong(self):
        self.assertNotEqual(analyze("correcthorsebatterystaple").label, "Strong")

    def test_medium_example(self):
        self.assertEqual(analyze("Summer2024").label, "Medium")

    def test_strong_example(self):
        self.assertEqual(analyze("Xk9#mP2$vL7!qR4z").label, "Strong")

    def test_unicode_input_is_handled(self):
        report = analyze("Pässwörd-🔐-Zq7")
        self.assertIn(report.label, {"Weak", "Medium", "Strong"})

    def test_sequence_and_repeat_detection(self):
        self.assertTrue(has_sequence("xxQWERxx"))
        self.assertTrue(has_sequence("a4321b"))
        self.assertFalse(has_sequence("Xk9mP2"))
        self.assertTrue(has_repeats("abcccd"))
        self.assertFalse(has_repeats("abcabc"))


if __name__ == "__main__":
    unittest.main()
