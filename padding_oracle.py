import requests
import base64
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

TARGET_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev/message/send?userId=group-3"
USER_ID = "group-3"

# Global token storage to simplify sharing
current_token = None
PARALLEL_GUESS_BATCH = 2  # Number of parallel guesses to send

def get_token(token = None):
    if not token:
        return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTZWN1cmVDaGF0IiwiaWF0IjoxNzY1ODIwODUxLCJleHAiOjE3NjU4MjExNTEsInN1YiI6Imdyb3VwLTMiLCJzaWQiOiIzY2U3MWQzOTY2MGRhMmQ4NjUwNzcwZjkyZTY3MTcyODRlNTkzYTM4Y2ZhNDJiN2Q5ZTdjZTczMjU0MjMzODA1IiwiYWxnb3JpdGhtIjoiZWNkaF8zIiwicHVibGljS2V5Ijp7IngiOiI2ODcxOTUzMTQwOTg2MTcwMDIxMzc4MzQxNjE0NDExODI3MjIzNjYwNTQ0ODEwOTc0MDI4MDYxODkxODA4MDk5MjEyNTE0ODA0ODA3MCIsInkiOiIxMDY5NDAzNDY0MTkxNDYxODUzNDI1MTEwMTg5NjIzODQzODAyMjA4NjQ4OTYwOTk1NzAyODkzOTc1MzgwMTkxMDAwMTA5MTg5MzUyMjQifSwiZW5jcnlwdGVkRGF0YSI6InM4SHR4LWxGcS1pbDdwT3RaVUdnYTRqUGFRVDNrbk9uZE9Vdy1ac080bVUwMkEwdFVkb1MxR0lJRG82NkR4OVNseDcwNFJXOEs4YmFVenc4NVEweWpGazc5bmE4SUhGb3hJYXBRWEZYSnVhU3JMMHZIVEFKNlpneTQwU2NWbkNoMmo2N0JfZ1RNYkdPWWN6Y2xLdmVjdlhUTGFiN2JsOEp3NzItbmFyaS0tZ0RSNWtLbW9lNkUzSVdSR3pVSHhnem4yUjlNc1F5bmJVMmVkUDFuWGJqa0tUcTM4a0QxYXVQNzJOTVowSm5wWlBZSU5WcjRRUkNpZnEwa2hhSmVHeFB0b1VlQVQyc2dELUlTXzB5bHZQSXQ1TUpFVTYxcFJ4SnltMUw1UERvUWVGYW5fbXdGelNONnUySUkyYW5aWjdIIiwiY3JlYXRlZEF0IjoxNzY1ODIwODUxMjE0LCJsYXN0QWN0aXZpdHkiOjE3NjU4MjA4NTEzNzd9.lcSWaiq3m4tyDFZ-pOb__Sh68PIiR65cJ-D7kvM9uec"
    # print("Getting new token...")
    payload = {"sessionToken":token,"encryptedMessage":"dY0Vr0m9hGo9BmCIReOlOAQI7M+R7xmx+jIqO1jZGPY=","messageSignature":{"r":"50052767446999115007139544558069022590329698892787276124929125769040409596919","s":"3015541346334751449345568818104215136357290177841669283539282635497697840668","messageHash":"48210227627143076923532643274900038989816371053307765416190221206156267718683","algorithm":"ECDSA-P256"},"clientSignaturePublicKey":{"x":"7695860974964638194165385659098743832703217848693275908770865929882303517494","y":"83299517118945450340363021820644025943644636754529826527517157261925840868137"}}
    headers = {'X-User-Id': USER_ID}
    try:
        response = requests.post(TARGET_URL, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()["sessionToken"]
    except Exception as e:
        # print(f"Error getting token: {e}")
        return None


def refresh_token():
    """Utility to refresh the shared session token multiple times."""
    global current_token
    new_token = get_token(token=current_token)
    current_token = new_token


def oracle_query(ciphertext_bytes, token):
    """
    Sends a ciphertext to the oracle and returns False if the padding is invalid, True otherwise.
    """
    ciphertext_base64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
    
    payload = {
        "sessionToken": token,
        "encryptedMessage": ciphertext_base64,
    }
    
    while True:
        try:
            response = requests.post(
                TARGET_URL,
                json=payload,
                headers={"x-user-id": USER_ID},
                timeout=10,
            )
            
            if response.status_code in [429, 430, 500, 502, 503, 504]:
                time.sleep(1)
                continue

            try:
                response_json = response.json()
            except requests.exceptions.JSONDecodeError:
                time.sleep(1)
                continue

            if "error" in response_json:         
                if response_json["error"] == "Invalid padding":
                    return False

            return True
        
        except requests.RequestException as e:
            # print(f"Request Error: {e}")
            time.sleep(1)
            continue


def generate_prioritized_guesses(byte_index, previous_block_byte, padding_value, is_last_block):
    """
    Generates a prioritized list of byte values to guess.
    - For the last byte of the last block, padding values are prioritized.
    - For other bytes, printable ASCII characters are prioritized.
    """
    guesses = []
    
    # Priority 1: Printable ASCII characters
    # plaintext_byte = (guess ^ padding_value) ^ previous_block_byte
    # guess = (plaintext_byte ^ previous_block_byte) ^ padding_value
    printable_chars = list(range(ord(' '), ord('~') + 1))
    
    # Priority 2: Common control characters
    control_chars = [0, 10, 13, 9] # NULL, LF, CR, TAB

    # Priority 3: Padding values (from 1 to 16)
    padding_guesses = []
    if is_last_block:
        for pad in range(1, 17):
            guess = (pad ^ previous_block_byte) ^ padding_value
            if guess not in padding_guesses:
                padding_guesses.append(guess)

    # Build the guess list based on priority
    if is_last_block and byte_index == 15:
        # For the very last byte, prioritize padding
        guesses.extend(g for g in padding_guesses if g not in guesses)

    # Add printable chars
    for char_code in printable_chars + control_chars:
        guess = (char_code ^ previous_block_byte) ^ padding_value
        if guess not in guesses:
            guesses.append(guess)
    
    # Add remaining padding guesses
    guesses.extend(g for g in padding_guesses if g not in guesses)

    # Add all other byte values as a fallback
    guesses.extend(i for i in range(256) if i not in guesses)
    
    return guesses


def attempt_guess(guess, byte_index, base_block_bytes, target_block, token):
    """Executes a single oracle guess for a crafted byte value."""
    crafted_block = bytearray(base_block_bytes)
    crafted_block[byte_index] = guess
    test_ciphertext = bytes(crafted_block) + target_block
    is_valid = oracle_query(test_ciphertext, token)
    return guess if is_valid else None



def padding_oracle_attack(ciphertext_bytes, block_size=16):
    global current_token
    # Initial token
    if not current_token:
        current_token = get_token()

    iv = ciphertext_bytes[:block_size]
    ciphertext_blocks = [ciphertext_bytes[i:i+block_size] for i in range(block_size, len(ciphertext_bytes), block_size)]
    
    plaintext = b''

    with ThreadPoolExecutor(max_workers=PARALLEL_GUESS_BATCH) as executor:
        # Process each block from last to first
        for block_index in range(len(ciphertext_blocks) - 1, -1, -1):
            target_block = ciphertext_blocks[block_index]
            previous_block = ciphertext_blocks[block_index - 1] if block_index > 0 else iv
            
            decrypted_block = b''
            print(f"\nAttacking block {block_index + 1}...")

            intermediate_state = bytearray(block_size)
            is_last_block = (block_index == len(ciphertext_blocks) - 1)

            # Decrypt each byte from last to first
            byte_index = block_size - 1
            while byte_index >= 0:
                padding_value = block_size - byte_index
                
                # Prepare prefix with known intermediate values
                known_mask = bytearray(block_size)
                for i in range(byte_index + 1, block_size):
                    known_mask[i] = intermediate_state[i] ^ padding_value

                base_block_bytes = bytes(known_mask)
                found_guess = None

                token_snapshot = current_token
                if not token_snapshot:
                    token_snapshot = get_token()
                    current_token = token_snapshot

                previous_block_byte = previous_block[byte_index]
                guesses = generate_prioritized_guesses(byte_index, previous_block_byte, padding_value, is_last_block)

                for i in range(0, len(guesses), PARALLEL_GUESS_BATCH):
                    batch = guesses[i:i + PARALLEL_GUESS_BATCH]
                    
                    # Create a visual representation of the characters being guessed
                    chars_to_try = "','".join([
                        chr((g ^ padding_value) ^ previous_block_byte)
                        if 32 <= ((g ^ padding_value) ^ previous_block_byte) <= 126
                        else '.'
                        for g in batch
                    ])
                    print(
                        f"\rTrying: '{chars_to_try}' at byte {byte_index} ",
                        end="\r",
                    )

                    future_to_guess = {
                        executor.submit(
                            attempt_guess,
                            guess,
                            byte_index,
                            base_block_bytes,
                            target_block,
                            token_snapshot,
                        ): guess
                        for guess in batch
                    }

                    for future in as_completed(future_to_guess):
                        guess_result = future.result()
                        if guess_result is not None:
                            found_guess = guess_result
                            break

                    if found_guess is not None:
                        break

                if found_guess is not None:
                    intermediate_byte = found_guess ^ padding_value
                    intermediate_state[byte_index] = intermediate_byte

                    plaintext_byte = intermediate_byte ^ previous_block[byte_index]
                    decrypted_block = bytes([plaintext_byte]) + decrypted_block

                    try:
                        char_repr = chr(plaintext_byte)
                        if not (32 <= plaintext_byte <= 126):
                            char_repr = '<non-printable>'
                    except:
                        char_repr = '<non-printable>'

                    # Clear the "Trying..." line before printing the result
                    print(" " * 80, end="\r")
                    print(f"Found byte {16 - byte_index}/{block_size}: {plaintext_byte:02x} ('{char_repr}')")
                    
                    # Handle padding propagation
                    if is_last_block and byte_index == 15 and 1 < plaintext_byte <= 16:
                        pad_len = plaintext_byte
                        print(f"  [+] Detected padding of length {pad_len}. Propagating...")
                        
                        # Correctly calculate and fill the rest of the decrypted block
                        for i in range(1, pad_len):
                            p_byte_index = 15 - i
                            p_padding_value = block_size - p_byte_index
                            
                            # We know the plaintext is `pad_len`, so we can find the intermediate byte
                            intermediate_state[p_byte_index] = pad_len ^ previous_block[p_byte_index]
                            
                            # We also need to update the known mask for the *next* guess
                            known_mask[p_byte_index] = intermediate_state[p_byte_index] ^ p_padding_value
                            
                            # Prepend the known padding byte to our result
                            decrypted_block = bytes([pad_len]) + decrypted_block

                        # Skip the bytes we just filled
                        byte_index -= (pad_len - 1)
                        
                    refresh_token()
                else:
                    print(f"  [!] Failed to find byte {16 - byte_index}!")
                    break
                
                byte_index -= 1
                
            plaintext = decrypted_block + plaintext

    return plaintext

if __name__ == "__main__":
    # Target ciphertext
    ciphertext_bytes_base64 = "dY0Vr0m9hGo9BmCIReOlOAQI7M+R7xmx+jIqO1jZGPY="

    # Run attack
    result = padding_oracle_attack(base64.b64decode(ciphertext_bytes_base64))
    print("\nDecrypted Result (Hex):", result.hex())
    try:
        # Attempt PKCS7 unpadding
        pad = result[-1]
        if pad > 0 and pad <= 16:
            print("Decrypted Message:", result[:-pad].decode('utf-8', errors='replace'))
        else:
            print("Decrypted Message (Raw):", result.decode('utf-8', errors='replace'))
    except:
        print("Decrypted Message (Raw):", result)
