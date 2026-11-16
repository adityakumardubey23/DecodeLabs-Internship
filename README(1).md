# Caesar Cipher: Basic Encryption & Decryption

**DecodeLabs | Cyber Security | Project 2 (Batch 2026)**

A command-line Python tool that encrypts and decrypts text with a Caesar cipher, built to demonstrate **data confidentiality** through simple, reversible mathematics.

## Features

- **Encrypt** user text with a shift key.
- **Decrypt** ciphertext back to the original (same key, symmetric encryption).
- **Displays both** the encrypted and decrypted output, with an automatic **PASS/FAIL validation** that the round trip matches the original.
- **User-chosen shift key**, with input validation. Any integer works, including negative or large values (reduced with `% 26`).
- **Edge cases handled:** uppercase and lowercase are preserved; spaces, digits and punctuation pass through unchanged.
- **Brute-force demo** that tries all 25 keys, to show why Caesar is weak.

## Requirements

- Python 3.8+
- No external libraries

## How to Run

```bash
python caesar_cipher.py
```

Menu:

```
1. Encrypt + Decrypt (round trip)
2. Decrypt existing ciphertext
3. Brute-force demo (why Caesar is weak)
4. Exit
```

### Example

```
Enter text to encrypt: Hello, World! XYZ xyz 123
Enter shift key (integer, e.g. 3): 3

Original  : Hello, World! XYZ xyz 123
Key       : 3
Encrypted : Khoor, Zruog! ABC abc 123
Decrypted : Hello, World! XYZ xyz 123
Validation: PASS - decrypted text matches original
```

## How It Works

### IPO model

| Stage       | What happens                                          |
|-------------|-------------------------------------------------------|
| **Input**   | Plaintext + shift key from the user                   |
| **Process** | Shift each letter: `ord()` → math → `chr()`           |
| **Output**  | Ciphertext, then decrypted text for validation        |

### The math

Text must become numbers before it can become math: we don't shift letters, we shift integers (`A = 65`, `a = 97`).

```
Encrypt:  E_n(x) = (x + n) mod 26
Decrypt:  D_n(x) = (x - n) mod 26
```

Python implementation (per character):

```python
chr((ord(char) - base + shift) % 26 + base)   # base = 65 for 'A'-'Z', 97 for 'a'-'z'
```

Step by step for `'A'` with key 3: `65 → 0 → 3 → 3 % 26 = 3 → 68 → 'D'`.

The modulo handles the wrap-around: `Y (24) + 3 = 27`, `27 % 26 = 1`, which is `B`. Python's `%` always returns a non-negative result for a positive modulus, so decryption (a negative shift) wraps correctly too.

## Project Structure

```
caesar_cipher/
├── caesar_cipher.py   # Source code (encrypt, decrypt, CLI)
└── README.md          # This file
```

## Deliverables Checklist

- [x] Implement the IPO cycle
- [x] Apply the math: `ord()`, `chr()`, `% 26`
- [x] Handle edge cases (spaces / punctuation / digits / case)
- [x] Validate with the decryption function

## Security Note: Why Caesar Is a Lockbox, Not a Vault

1. **Tiny key space:** only 25 useful keys, so brute force is instant (see menu option 3).
2. **Pattern preservation:** each letter always maps to the same letter, so frequency analysis (e.g. `E` being the most common English letter) reveals the key.

**This is for learning only. Never use it to protect real data.** Modern systems use algorithms like **AES** (confusion + diffusion, 128-bit+ keys, XOR operations).

## Ideas to Extend

- Vigenère cipher (a keyword gives a different shift per letter)
- File encryption (read/write `.txt` files)
- Frequency-analysis auto-cracker
- GUI or web version

---

*Powered by DecodeLabs.*
