import requests
import base64
import sys
import json
import time
import threading
from urllib.parse import quote

TARGET_URL = "https://crypto-assignment.dangduongminhnhat2003.workers.dev/message/send?userId=group-3"
USER_ID = "group-3"

# Global token storage to simplify sharing
current_token = None

LAST_REQUEST_TIME = 0
RATE_LIMIT_LOCK = threading.Lock()

def enforce_rate_limit():
    global LAST_REQUEST_TIME
    with RATE_LIMIT_LOCK:
        current_time = time.time()
        elapsed = current_time - LAST_REQUEST_TIME
        if elapsed < 1:
            time.sleep(1 - elapsed)
        LAST_REQUEST_TIME = time.time()


def get_token(token = None):
    payload = {"sessionToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJTZWN1cmVDaGF0IiwiaWF0IjoxNzY1ODk2NTE0LCJleHAiOjE3NjU4OTY4MTQsInN1YiI6Imdyb3VwLTMiLCJzaWQiOiIxM2U1MThmZTU3MjE2YTYyMGUzOGZlYWJlMzA1ZjZkMTYyM2Y0ZDY2YTIwNmMzOTczZGFlMjFkNWI2NTQxZmI0IiwiYWxnb3JpdGhtIjoiZWNkaF8zIiwicHVibGljS2V5Ijp7IngiOiI2NjQyODU3NDE5NjM1NTEyMzY2MDI5ODc3NzE0NTYyMjY3NTMzNDc2Mzk4ODY5NDM2MDg5OTA5NDUxNjg0MDkwNzMxNTQzMTE2NzgzNyIsInkiOiI3MDU3NjQxOTEyOTU1MDkyNDQxNDY3Mjk4NzM0NjY5MjgzODU4NjUwNzQxMzM5NzU4MzUxNjMxMjAxNzU1MDkyNjc0OTE2MTE3ODI0MSJ9LCJlbmNyeXB0ZWREYXRhIjoib29fM2VaNm91enRYc3ZHZHRGRjlqV2VvdkF0VkhsS0ZzSTRuTWNuYVZtWXdLYmYtWTNQUWNnOWVZNDJWNDJFZzRIbkgzejZkUkJnc29hb1IxWjhDOTNZdThJREdoWS1sYlI4bVd1SjlhNlZDd1FhV3Z5ZHhVbXpZVUJrRjlocGJMYjRNZEY2V2lWQ2hLdE5HRVYzX2RpWGRWSTIyeXZlVDk3Z0dPZ2FnbWl3VFh5NUlDX3RBbTUwbGFxX2xQSW1tMjdtdWtna0wwVnhLdkNyZEo4Y3VXSVc1OU96bzVZODlWb19mU2ZHNXhoWEZWQUxySDkwNlpDNTVNNjJmTkNyMEc2WHNZUkJ5bTlNb0ZFZ0lsa2h6Z2hzNnozd2pPUlY3OHE1VlpXdXVCdzgxOXRYY3VNM0p0OGJIbkcyY1FYVVAiLCJjcmVhdGVkQXQiOjE3NjU4OTY1MTM4MjcsImxhc3RBY3Rpdml0eSI6MTc2NTg5NjUxNDA3MX0.YJhyWIV4jYL3rXKs0seswnfxbeEUkmZ60Toy23VsF_w","encryptedMessage":"o1ENQOvV5+bZCMUQ\/S6pAgnuWKyfIaTUeG9+Wv6tTWo=","messageSignature":{"r":"90046965645765064189438931857172966658259996494808450306961688106604750898764","s":"25004094407105811876543790223683131683905969248704141430757406199554915248163","messageHash":"30044915836385976087286096452993035701666349012866199283670340553978528790417","algorithm":"ECDSA-P256"},"clientSignaturePublicKey":{"x":"62237244105861080570981654775756693709032421441820367981576337556529266550777","y":"106622038109168814312068160842053921545460754194661394291159518932546298483990"}}
    if not token:
        return payload["sessionToken"]
    
    payload["sessionToken"] = token
    # print("Getting new token...")
    headers = {'X-User-Id': USER_ID}
    try:
        enforce_rate_limit()
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
            enforce_rate_limit()
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
    - For other bytes, characters are prioritized in the order: lowercase, uppercase, numbers, symbols.
    """
    guesses = []

    # Define character sets by priority
    lower_chars = list(range(ord('a'), ord('z') + 1))
    upper_chars = list(range(ord('A'), ord('Z') + 1))
    digit_chars = list(range(ord('0'), ord('9') + 1))
    symbol_chars = list(range(ord(' '), ord('/') + 1)) + \
                   list(range(ord(':'), ord('@') + 1)) + \
                   list(range(ord('['), ord('`') + 1)) + \
                   list(range(ord('{'), ord('~') + 1))
    
    # Common control characters
    control_chars = [0, 10, 13, 9] # NULL, LF, CR, TAB

    # Ordered list of character sets for guessing
    char_sets_in_priority = [
        lower_chars,
        upper_chars,
        digit_chars,
        symbol_chars,
        control_chars
    ]

    # Priority: Padding values (from 1 to 16) for the last block
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

    # Add character guesses based on the defined priority
    for char_set in char_sets_in_priority:
        for char_code in char_set:
            guess = (char_code ^ previous_block_byte) ^ padding_value
            if guess not in guesses:
                guesses.append(guess)
    
    # Add remaining padding guesses that might not have been prioritized
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

            for guess in guesses:
                # Create a visual representation of the characters being guessed
                char_val = (guess ^ padding_value) ^ previous_block_byte
                char_repr = chr(char_val) if 32 <= char_val <= 126 else '<non-printable>'
                
                print(
                    f"\rTrying: '{char_repr}' at byte {byte_index} ",
                    end="\r",
                )

                guess_result = attempt_guess(
                    guess,
                    byte_index,
                    base_block_bytes,
                    target_block,
                    token_snapshot
                )
                
                if guess_result is not None:
                    found_guess = guess_result
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
    ciphertext_bytes_base64 = "o1ENQOvV5+bZCMUQ\/S6pAgnuWKyfIaTUeG9+Wv6tTWo="
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
