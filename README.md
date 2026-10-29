# 🔐 Password Strength Checker

**DecodeLabs Cyber Security Internship, Project 1 (Batch 2026)**

A small command-line tool that tells you whether a password is **Weak**, **Medium** or **Strong**, and explains why. It's written in plain Python with no external libraries, so it runs anywhere Python 3.8+ is installed.

I built this as the "defensive phase" starter project: the goal wasn't fancy hacking, it was getting the security logic right using only string handling and conditions.

---

## What it does

- Checks **length**. Anything under 8 characters fails straight away.
- Checks for **uppercase letters, digits and symbols** (and lowercase too).
- Handles **Unicode** (emoji, accents, Hindi, etc.) without breaking.
- Spots **common passwords**, including leet-speak tricks like `P@ssw0rd`.
- Flags **predictable patterns** such as `qwer`, `1234`, `abcd` and `aaa`.
- Gives a rough **entropy estimate** in bits.
- Prints a simple **score bar** and **tips** on how to improve.

## Quick start

```bash
git clone https://github.com/<your-username>/password-strength-checker.git
cd password-strength-checker

python password_checker.py          # interactive mode
python password_checker.py --demo   # see a few sample results
python -m unittest -v               # run the tests
```

In interactive mode your typing is hidden (it uses `getpass`), and pressing Enter on an empty line quits.

## Example output

```
Password: Summer2024

  Strength : MEDIUM   [#####----] 5/9
  Entropy  : ~59.5 bits (estimate)
  Tips:
    - Try 12+ characters for a real safety margin.
    - Add a symbol.
```

```
Password: Xk9#mP2$vL7!qR4z

  Strength : STRONG   [#########] 9/9
  Entropy  : ~105.1 bits (estimate)
  Tips:
    - Looks great. Store it in a password manager.
```

## How the scoring works

The score runs from 0 to 9.

| Part | Points |
|------|--------|
| Length 8-11 / 12-15 / 16+ | 1 / 2 / 3 |
| Each character type present (lower, upper, digit, symbol) | +1 each |
| Entropy of 45+ bits / 60+ bits | +1 / +2 |
| Contains a common word or leet version of one | -3 |
| Keyboard or alphabet run (4+ chars) | -2 |
| Same character 3 times in a row | -1 |

**Final label**

- **Weak**: fewer than 8 characters, an exact common password, or a score under 4
- **Medium**: score of 4 or more
- **Strong**: score of 7 or more **and** it has an uppercase letter, a number and a symbol **and** it isn't built on a common word

That last rule matters: a high score alone can't push a bad password into "Strong".

## Design decisions

- **One pass, O(n).** Character types are collected in a single loop, so validation time grows linearly with password length.
- **No echo, no storage.** The password is never printed back, logged or saved. One honest caveat: Python strings are immutable, so the value can't be wiped from memory on demand. For a production system you'd handle that more carefully.
- **No passwords on the command line.** I deliberately didn't add a `--password` flag, because shell history would record it.
- **Entropy is an estimate.** It assumes random characters from the detected pool, so it's an upper bound. Human-chosen passwords are usually weaker than the number suggests, which is why the pattern penalties exist.

## Project structure

```
.
├── password_checker.py        # main program
├── test_password_checker.py   # unit tests
└── README.md
```

## Limitations

- The common-password list is small (about 40 entries) to keep the repo light. A real deployment should load a large breach list.
- Long passphrases such as `correcthorsebatterystaple` are capped at Medium because they lack the required character types. That follows the project policy, but it's debatable in the real world.

## Ideas for next steps

- Load a big wordlist like `rockyou`-style top-N files from a text file
- Check against the Have I Been Pwned range API (k-anonymity)
- Add a passphrase mode that rewards length over character variety
- Feed validated passwords into Project 2 (hashing with Argon2id), the "gatekeeper" idea: validate first, hash second

## Author

Built by **<Aditya Dubey>** as part of the DecodeLabs Industrial Training Kit.

## License

MIT. Use it, learn from it, improve it.
