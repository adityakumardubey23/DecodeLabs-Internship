#!/usr/bin/env python3
"""
Password Strength Checker  |  DecodeLabs Cyber Security - Project 1

Classifies a password as Weak, Medium or Strong using only string handling
and conditional logic (no third-party libraries).

What it checks
    * length (anything under 8 characters fails immediately)
    * uppercase letters, digits and symbols (lowercase is tracked too)
    * Unicode input (emoji, accents, other scripts) without crashing
    * common / leaked passwords, including "leet" tricks like P@ssw0rd
    * keyboard or alphabet runs (qwer, 1234, abcd) and repeats (aaa)
    * an estimated entropy in bits

Design notes
    * One linear pass over the string -> O(n) validation time.
    * The password is read with getpass, so it is never echoed on screen,
      and it is never written to disk or printed back.

Usage
    python password_checker.py           interactive mode
    python password_checker.py --demo    run a few built-in examples
"""

from __future__ import annotations

import getpass
import math
import sys
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Policy settings
# --------------------------------------------------------------------------
MIN_LENGTH = 8            # below this = immediate fail
GOOD_LENGTH = 12          # comfortable length
GREAT_LENGTH = 16         # long enough to earn full length points

STRONG_SCORE = 7          # score needed (out of 9) to be called Strong
MEDIUM_SCORE = 4          # score needed to be called Medium

# Size of each ASCII character pool, used for the entropy estimate.
POOL_LOWER = 26
POOL_UPPER = 26
POOL_DIGIT = 10
POOL_SYMBOL = 33          # punctuation + space
POOL_UNICODE = 100        # deliberately conservative guess for non-ASCII

# A small built-in list of very common passwords. In a real system you would
# load a much larger list (for example the top 100k from a public breach set).
COMMON_PASSWORDS = frozenset({
    "password", "passw0rd", "123456", "12345678", "123456789", "1234567890",
    "qwerty", "qwertyuiop", "abc123", "letmein", "welcome", "admin",
    "administrator", "login", "iloveyou", "monkey", "dragon", "football",
    "baseball", "master", "sunshine", "princess", "shadow", "superman",
    "batman", "trustno1", "hello", "freedom", "whatever", "secret",
    "changeme", "default", "guest", "root", "test", "user", "india",
    "cricket", "krishna", "ganesh", "123123", "111111", "000000",
})

# Characters people swap in to make a weak word look clever.
LEET_MAP = str.maketrans({
    "@": "a", "4": "a", "0": "o", "1": "i", "!": "i",
    "3": "e", "$": "s", "5": "s", "7": "t",
})

# Runs that make a password predictable.
SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
RUN_LENGTH = 4            # this many chars in a row from a sequence is flagged


# --------------------------------------------------------------------------
# Result container
# --------------------------------------------------------------------------
@dataclass
class Report:
    label: str                      # "Weak", "Medium" or "Strong"
    score: int                      # 0 - 9
    entropy_bits: float             # rough estimate
    feedback: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Helper functions
# --------------------------------------------------------------------------
def classify_characters(password: str) -> dict[str, bool]:
    """Single pass over the password, noting which character types appear."""
    kinds = {"lower": False, "upper": False, "digit": False,
             "symbol": False, "non_ascii": False}

    for ch in password:
        if ch.islower():
            kinds["lower"] = True
        elif ch.isupper():
            kinds["upper"] = True
        elif ch.isdigit():
            kinds["digit"] = True
        else:
            # punctuation, spaces, emoji, and caseless letters (e.g. Hindi,
            # Chinese) all land here and count as "symbol" variety.
            kinds["symbol"] = True
        if not ch.isascii():
            kinds["non_ascii"] = True

    return kinds


def estimate_entropy(length: int, kinds: dict[str, bool]) -> float:
    """Upper-bound entropy: length * log2(size of the character pool)."""
    pool = 0
    if kinds["lower"]:
        pool += POOL_LOWER
    if kinds["upper"]:
        pool += POOL_UPPER
    if kinds["digit"]:
        pool += POOL_DIGIT
    if kinds["symbol"]:
        pool += POOL_SYMBOL
    if kinds["non_ascii"]:
        pool += POOL_UNICODE
    if pool == 0:
        return 0.0
    return round(length * math.log2(pool), 1)


def has_sequence(password: str) -> bool:
    """True if the password contains a short keyboard / alphabet / number run."""
    low = password.lower()
    for i in range(len(low) - RUN_LENGTH + 1):
        chunk = low[i:i + RUN_LENGTH]
        for seq in SEQUENCES:
            if chunk in seq or chunk[::-1] in seq:
                return True
    return False


def has_repeats(password: str) -> bool:
    """True if any character appears three times in a row (e.g. 'aaa')."""
    return any(a == b == c for a, b, c in zip(password, password[1:], password[2:]))


def common_password_check(password: str) -> tuple[bool, bool]:
    """
    Returns (is_exact_match, contains_common_word).
    Both the plain and the 'de-leeted' version are tested, so P@ssw0rd is
    caught as a variation of 'password'.
    """
    plain = password.lower()
    leet = plain.translate(LEET_MAP)

    exact = plain in COMMON_PASSWORDS or leet in COMMON_PASSWORDS
    contains = any(
        word in plain or word in leet
        for word in COMMON_PASSWORDS
        if len(word) >= 5
    )
    return exact, contains


# --------------------------------------------------------------------------
# Core logic
# --------------------------------------------------------------------------
def analyze(password: str) -> Report:
    """Evaluate a password and return a Report."""
    length = len(password)
    kinds = classify_characters(password)
    entropy = estimate_entropy(length, kinds)
    tips: list[str] = []

    # Gate 1: too short = instant fail (brute-force risk grows exponentially
    # as length shrinks).
    if length < MIN_LENGTH:
        tips.append(f"Use at least {MIN_LENGTH} characters (you used {length}).")
        return Report("Weak", 0, entropy, tips)

    # Gate 2: a password straight off the common list is instantly weak.
    is_exact, contains_common = common_password_check(password)
    if is_exact:
        tips.append("This is a very common password and is guessed within seconds.")
        return Report("Weak", 0, entropy, tips)

    score = 0

    # Length points (1 - 3)
    if length >= GREAT_LENGTH:
        score += 3
    elif length >= GOOD_LENGTH:
        score += 2
    else:
        score += 1
        tips.append(f"Try {GOOD_LENGTH}+ characters for a real safety margin.")

    # Variety points (0 - 4)
    score += sum(kinds[k] for k in ("lower", "upper", "digit", "symbol"))

    missing = []
    if not kinds["upper"]:
        missing.append("an uppercase letter")
    if not kinds["digit"]:
        missing.append("a number")
    if not kinds["symbol"]:
        missing.append("a symbol")
    if not kinds["lower"]:
        tips.append("Mix in some lowercase letters as well.")
    if missing:
        tips.append("Add " + ", ".join(missing) + ".")

    # Entropy bonus (0 - 2)
    if entropy >= 60:
        score += 2
    elif entropy >= 45:
        score += 1

    # Penalties
    if contains_common:
        score -= 3
        tips.append("Built around a common word or leet-speak version of one.")
    if has_sequence(password):
        score -= 2
        tips.append("Avoid runs like 'abcd', '1234' or 'qwer'.")
    if has_repeats(password):
        score -= 1
        tips.append("Avoid repeating the same character three times in a row.")

    score = max(0, min(9, score))

    # Final label. Strong needs a high score AND every mandatory class AND no
    # common-word base, so a high score alone cannot sneak a bad password in.
    if score >= STRONG_SCORE and not missing and not contains_common:
        label = "Strong"
    elif score >= MEDIUM_SCORE:
        label = "Medium"
    else:
        label = "Weak"

    if label == "Strong" and not tips:
        tips.append("Looks great. Store it in a password manager.")

    return Report(label, score, entropy, tips)


# --------------------------------------------------------------------------
# Display
# --------------------------------------------------------------------------
def render(report: Report) -> str:
    filled = report.score
    bar = "#" * filled + "-" * (9 - filled)
    lines = [
        "",
        f"  Strength : {report.label.upper()}   [{bar}] {report.score}/9",
        f"  Entropy  : ~{report.entropy_bits} bits (estimate)",
    ]
    if report.feedback:
        lines.append("  Tips:")
        lines.extend(f"    - {tip}" for tip in report.feedback)
    lines.append("")
    return "\n".join(lines)


def run_demo() -> None:
    samples = [
        "hello", "password", "abcdefgh", "Summer2024",
        "P@ssw0rd!", "Tr0ub4dor&3", "Xk9#mP2$vL7!qR4z", "Mera-Bharat-2026!",
    ]
    print("DEMO MODE - these are sample passwords, not real ones.")
    for pw in samples:
        print(f"\nPassword: {pw}")
        print(render(analyze(pw)))


def run_interactive() -> None:
    print("=" * 50)
    print("  DecodeLabs Password Strength Checker")
    print("  Your input is hidden and never stored.")
    print("  Press Enter on an empty line to quit.")
    print("=" * 50)

    while True:
        try:
            pw = getpass.getpass("\nEnter a password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            return
        if pw == "":
            print("Goodbye!")
            return
        print(render(analyze(pw)))


def main() -> None:
    if "--demo" in sys.argv[1:]:
        run_demo()
    else:
        run_interactive()


if __name__ == "__main__":
    main()
