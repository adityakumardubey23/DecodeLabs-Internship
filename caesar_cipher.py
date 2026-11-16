"""
DecodeLabs - Cyber Security | Project 2
Basic Encryption & Decryption (Caesar Cipher)

IPO model:
    INPUT   -> plaintext + shift key (from the user)
    PROCESS -> shift each letter using ord(), chr() and % 26
    OUTPUT  -> ciphertext, then decrypted text to validate the round trip
"""


def shift_char(char: str, shift: int) -> str:
    """Shift a single character. Non-letters (spaces, digits, punctuation) pass through unchanged."""
    if char.isascii() and char.isupper():
        base = 65  # ord('A')
    elif char.isascii() and char.islower():
        base = 97  # ord('a')
    else:
        return char
    # subtract base -> add key -> wrap with modulo 26 -> add base back
    return chr((ord(char) - base + shift) % 26 + base)


def encrypt(plaintext: str, shift: int) -> str:
    """E_n(x) = (x + n) mod 26"""
    return "".join(shift_char(c, shift) for c in plaintext)


def decrypt(ciphertext: str, shift: int) -> str:
    """D_n(x) = (x - n) mod 26  (the reverse shift, same key)"""
    return "".join(shift_char(c, -shift) for c in ciphertext)


def get_shift() -> int:
    """Ask for a shift key and validate it. Any integer works; it is reduced mod 26."""
    while True:
        raw = input("Enter shift key (integer, e.g. 3): ").strip()
        try:
            return int(raw) % 26
        except ValueError:
            print("  Invalid key. Please enter a whole number.")


def get_text(prompt: str) -> str:
    """Ask for non-empty text."""
    while True:
        text = input(prompt)
        if text.strip():
            return text
        print("  Text cannot be empty.")


def run_round_trip() -> None:
    """Encrypt user text, decrypt it, display both, and validate."""
    plaintext = get_text("Enter text to encrypt: ")
    shift = get_shift()

    ciphertext = encrypt(plaintext, shift)
    decrypted = decrypt(ciphertext, shift)

    print("\n" + "=" * 50)
    print(f"Original  : {plaintext}")
    print(f"Key       : {shift}")
    print(f"Encrypted : {ciphertext}")
    print(f"Decrypted : {decrypted}")
    print("Validation:", "PASS - decrypted text matches original" if decrypted == plaintext else "FAIL")
    print("=" * 50 + "\n")


def run_decrypt_only() -> None:
    """Decrypt ciphertext the user already has."""
    ciphertext = get_text("Enter ciphertext to decrypt: ")
    shift = get_shift()
    print(f"\nDecrypted : {decrypt(ciphertext, shift)}\n")


def run_brute_force() -> None:
    """Show why Caesar is weak: only 25 possible keys, so try them all."""
    ciphertext = get_text("Enter ciphertext to brute-force: ")
    print()
    for key in range(1, 26):
        print(f"Key {key:2d}: {decrypt(ciphertext, key)}")
    print()


def main() -> None:
    print("=== DecodeLabs | Caesar Cipher Tool ===")
    actions = {
        "1": ("Encrypt + Decrypt (round trip)", run_round_trip),
        "2": ("Decrypt existing ciphertext", run_decrypt_only),
        "3": ("Brute-force demo (why Caesar is weak)", run_brute_force),
    }
    while True:
        print("Menu:")
        for k, (label, _) in actions.items():
            print(f"  {k}. {label}")
        print("  4. Exit")
        choice = input("Choose an option: ").strip()
        if choice == "4":
            print("Goodbye!")
            break
        if choice in actions:
            print()
            actions[choice][1]()
        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    main()
