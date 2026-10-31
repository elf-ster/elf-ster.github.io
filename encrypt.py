"""Draws the gift exchange and encrypts it into index.html:

    uv run encrypt.py

messages.json maps passphrases to givers and stays on your machine. The pairs
are drawn here, held only in memory, and never printed or saved in plain text.
Only the encrypted data in index.html gets published.

Every run draws NEW pairs. Once people have looked up their recipient, running
this again and publishing the result changes everyone's assignment.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import unicodedata
from pathlib import Path

from Crypto.Cipher import AES

ITERATIONS = 600000
ROOT = Path(__file__).parent
GENERATED_BLOCK = re.compile(r"(// BEGIN GENERATED[^\n]*\n).*?(\n[ \t]*// END GENERATED)", re.DOTALL)

# Must match the constants in index.html
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789 "
FIELD = 101  # Prime, and larger than the longest passphrase
MAX_ERRORS = 3
CHECK_SIZE = MAX_ERRORS * 2


def normalize(text):
    # Must match normalize() in index.html
    text = unicodedata.normalize("NFD", text).lower()
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"[^a-z0-9 ]", "", text)
    return re.sub(r" +", " ", text).strip()


def checksum(phrase):
    # Must match checksum() in index.html. This is a Reed-Solomon syndrome, which
    # lets the browser repair up to MAX_ERRORS wrong characters in a typed phrase.
    symbols = [ALPHABET.index(char) for char in phrase]
    return [
        sum(symbol * pow(i + 1, j + 1, FIELD) for i, symbol in enumerate(symbols)) % FIELD
        for j in range(CHECK_SIZE)
    ]


def to_base64(data):
    return base64.b64encode(data).decode("ascii")


# ##############################################################################
# ##############################################################################
# ####                                                                      ####
# ####                THE RANDOM ASSIGNMENT IS MADE RIGHT HERE              ####
# ####                                                                      ####
# ####  assign_recipients() is the only place that decides who gives to     ####
# ####  whom. It shuffles the list of participants with the operating       ####
# ####  system's secure random source, and reshuffles until nobody has       ####
# ####  drawn themselves.                                                   ####
# ####                                                                      ####
# ####  Because the recipients are a shuffled copy of the givers, everyone   ####
# ####  gives exactly once and receives exactly once.                       ####
# ####                                                                      ####
# ##############################################################################
# ##############################################################################
def assign_recipients(givers):
    recipients = list(givers)
    while any(giver == recipient for giver, recipient in zip(givers, recipients)):
        secrets.SystemRandom().shuffle(recipients)
    return recipients


def main():
    source = json.loads((ROOT / "messages.json").read_text(encoding="utf-8"))
    givers = list(source.values())
    if len(givers) < 2 or len(set(givers)) != len(givers):
        raise SystemExit("messages.json needs at least two people, each listed once")

    recipients = assign_recipients(givers)
    # Every message is padded to one size so its length cannot reveal the recipient
    size = 2 * max(len(json.dumps(name, ensure_ascii=False).encode("utf-8")) for name in givers) + 4
    salt = os.urandom(16)
    messages = {}

    # Must match unlock() in index.html
    for phrase, giver, recipient in zip(source, givers, recipients):
        message = json.dumps([giver, recipient], ensure_ascii=False).encode("utf-8").ljust(size)
        passphrase = normalize(phrase)
        if not 0 < len(passphrase) < FIELD:
            raise SystemExit(f"Passphrase must be 1 to {FIELD - 1} characters: {phrase!r}")

        bits = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, ITERATIONS, 32)
        iv = os.urandom(12)
        ciphertext, tag = AES.new(bits, AES.MODE_GCM, nonce=iv).encrypt_and_digest(message)
        messages[to_base64(hashlib.sha256(bits).digest())] = {
            "length": len(passphrase),
            "check": checksum(passphrase),
            "iv": to_base64(iv),
            "data": to_base64(ciphertext + tag),
        }

    encrypted = {"salt": to_base64(salt), "iterations": ITERATIONS, "messages": messages}
    block = f"  const ENCRYPTED = {json.dumps(encrypted, indent=2)};"

    page = ROOT / "index.html"
    html, replaced = GENERATED_BLOCK.subn(lambda match: match[1] + block + match[2], page.read_text(encoding="utf-8"))
    if replaced != 1:
        raise SystemExit("Could not find the generated block in index.html")
    page.write_text(html, encoding="utf-8")
    print(f"Encrypted {len(messages)} messages into index.html")


if __name__ == "__main__":
    main()
