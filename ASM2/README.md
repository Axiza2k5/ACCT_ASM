# Multi-Time Pad Breaker

This project implements a tool to break a Multi-Time Pad (MTP) encryption where the same key (One-Time Pad) has been reused to encrypt multiple messages.

## Overview

In a One-Time Pad (OTP) scheme, a key should only be used once. If the same key is used to encrypt multiple plaintexts (Multi-Time Pad), it introduces a vulnerability. XORing two ciphertexts together cancels out the key, leaving the XOR of the two plaintexts:

`C1 ⊕ C2 = (P1 ⊕ K) ⊕ (P2 ⊕ K) = P1 ⊕ P2`

This tool exploits this property and uses statistical heuristics (specifically guessing the location of space characters) to recover the shared key and decrypt the messages.

## Files

- `break_mtp.py`: The main Python script that performs the cryptanalysis and decryption.
- `ciphertext.txt`: A text file containing the hex-encoded ciphertexts, one per line.

## Usage

1. Ensure you have Python 3 installed.
2. Place your hex-encoded ciphertexts in `ciphertext.txt`.
3. Run the script:

```bash
python3 break_mtp.py
```

## How it Works

The script uses a "crib dragging" like approach focused on spaces:
1. It iterates through each position in the ciphertexts.
2. It hypothesizes that a specific ciphertext has a space character (`0x20`) at that position.
3. It derives a candidate key byte for that position.
4. It tests this candidate key byte against all other ciphertexts at the same position.
5. If the decrypted bytes for the other ciphertexts look like valid English characters (letters, punctuation), the key byte is accepted.
6. Finally, it uses the recovered key to decrypt all ciphertexts.

## Requirements

- Python 3.x
