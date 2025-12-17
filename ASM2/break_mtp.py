def decrypt(ciphertexts, key):
    # decryption
    for idx, ct in enumerate(ciphertexts):
        plaintext = []
        for i, byte in enumerate(ct):
            if key[i%len(key)] is not None:
                plaintext.append(chr(byte ^ key[i%len(key)]))
            else:
                plaintext.append("<?>")
        print(f"{''.join(plaintext)}")

def try_decrypt(ciphertexts):
    max_len = max(len(ct) for ct in ciphertexts)
    key = [None] * max_len

    # Recover key
    for i in range(max_len):
        # Filter ciphertexts that are long enough for this position
        current_cts = [ct for ct in ciphertexts if len(ct) > i]
        
        if not current_cts:
            continue

        # Try to find the space character
        # For each ciphertext c, assume c[i] is a space.
        # Then c[i] ^ k[i] = space (0x20) => k[i] = c[i] ^ 0x20
        # Check if this k[i] produces valid characters for other ciphertexts
        
        best_score = -1
        best_key_byte = None

        for ct in current_cts:
            # Hypothesis: ct[i] is a space
            current_key_byte = ct[i] ^ 0x20
            
            score = 0
            for other_ct in current_cts:
                # skip if other_ct is not long enough
                if len(other_ct) < i:
                    continue

                decrypted_byte = other_ct[i] ^ current_key_byte
                # Check if it's a valid English character (a-z, A-Z, space, punctuation)
                if (chr(decrypted_byte).isalpha() or 
                    decrypted_byte == 0x20 or
                    decrypted_byte in b",.?!'\"-"): 
                    score += 1

            # Update best key if this one is better
            if score > best_score:
                best_score = score
                best_key_byte = current_key_byte
        
        # If the best score is high enough (e.g., > 70% of ciphertexts look valid), accept it
        if best_score > len(current_cts) * 0.9: # Threshold can be tuned
            key[i] = best_key_byte

        # if key[i] can't be sure, leave it as None


    # Decrypt
    print("Recovered Key (hex):")
    print("".join(f"{k^0x20}" if k is not None else "<?>" for k in key))
    print("\nDecrypted Plaintexts:")

    decrypt(ciphertexts, key)

    print("\nRecovered Key (text):")
    print("".join(chr(k) if k is not None else "<?>" for k in key))



if __name__ == "__main__":
    with open('ciphertext.txt', 'r') as f:
        ciphertexts_hex = [line.strip() for line in f if line.strip()]
    ciphertexts = []
    for ct in ciphertexts_hex:
        ciphertexts.append(bytes.fromhex(ct))


    print("Try decrypt")
    try_decrypt(ciphertexts)

    print("\n\nDecrypt with key b'Wellerman' found by try_decrypt:\n")
    decrypt(ciphertexts,b'Wellerman')
