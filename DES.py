import json

# Load the lookup tables
with open('lookup_tables.json', 'r') as f:
    lookup_tables = json.load(f)


def int_to_bin(num: int, length: int) -> str:
    """
    Convert an integer to a binary string with a specified length.
    """
    return bin(num)[2:].zfill(length)


def bin_to_int(binary: str) -> int:
    """
    Convert a binary string to an integer.
    """
    return int(binary, 2)


def xor(a: str, b: str) -> str:
    """
    XOR operation between two binary strings.
    """
    return ''.join(['1' if a[i] != b[i] else '0' for i in range(len(a))])


def pad(text_bytes: bytes) -> bytes:
    """
    Apply PKCS#7 padding to the input bytes to make its length a multiple of 8 bytes.
    """
    pad_len = 8 - (len(text_bytes) % 8)
    padding = bytes([pad_len] * pad_len)
    return text_bytes + padding


def unpad(text_bytes: bytes) -> bytes:
    """
    Remove PKCS#7 padding from the input bytes.
    """
    if not text_bytes:
        raise ValueError("Input data is empty, cannot unpad.")
    pad_len = text_bytes[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding detected.")
    if text_bytes[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes.")
    return text_bytes[:-pad_len]


class KeyGenerator:
    def __init__(self, key: bytes):
        """
        Initialize KeyGenerator with a key of any length.
        The key is padded using PKCS#7 to 8 bytes.
        """
        self.key = self.prepare_key(key)
        self.key_bin = ''.join([int_to_bin(byte, 8) for byte in self.key])
        self.round_keys = self.generate_keys()

    def prepare_key(self, key: bytes) -> bytes:
        if len(key) < 8:
            return key.ljust(8, b'\0')
        elif len(key) > 8:
            return key[:8]
        return key

    def PC_1(self):
        """
        Permuted Choice 1 (PC-1) operation.
        """
        left = ''.join([self.key_bin[i - 1] for i in lookup_tables['pc_1_left']])
        right = ''.join([self.key_bin[i - 1] for i in lookup_tables['pc_1_right']])
        return left, right

    def PC_2(self, pre_key: str) -> str:
        """
        Permuted Choice 2 (PC-2) operation.
        """
        return ''.join([pre_key[i - 1] for i in lookup_tables['pc_2']])

    def shift_left(self, key_half: str, shifts: int) -> str:
        """
        Left shift the key_half by the specified number of shifts.
        """
        return key_half[shifts:] + key_half[:shifts]

    def generate_keys(self) -> list:
        """
        Generate 16 round keys.
        """
        left, right = self.PC_1()
        round_keys = []
        SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        for shift in SHIFT_SCHEDULE:
            left = self.shift_left(left, shift)
            right = self.shift_left(right, shift)
            combined = left + right
            round_key = self.PC_2(combined)
            round_keys.append(round_key)
        
        return round_keys


class DES:
    def __init__(self, key: bytes):
        """
        Initialize DES with a key of any length (bytes).
        """
        self.subkeys = KeyGenerator(key).round_keys

    def permute(self, text: str, table: list) -> str:
        """
        General permutation function based on the provided table.
        """
        return ''.join([text[i - 1] for i in table])
    
    def s_box_substitution(self, text: str) -> str:
        """
        S-box substitution.
        """
        substituted = ''

        for i in range(8):
            block = text[i*6:(i+1)*6]
            row = bin_to_int(block[0] + block[-1])
            col = bin_to_int(block[1:5])
            s_box_value = lookup_tables['s_box'][i][row * 16 + col]
            substituted += int_to_bin(s_box_value, 4)

        return substituted
    
    def round(self, half: str, subkey: str) -> str:
        """
        The DES round function.
        """
        expanded = self.permute(half, lookup_tables['e'])  # Expansion E
        xored = xor(expanded, subkey)     # XOR with subkey
        substituted = self.s_box_substitution(xored)  # S-box substitution
        permuted = self.permute(substituted, lookup_tables['p'])
               # Permutation P
        return permuted
    
    def feistel(self, left: str, right: str, subkey: str) -> tuple:
        """
        Perform one Feistel round.
        """
        new_right = xor(left, self.round(right, subkey))
        return right, new_right
    
    def process_block(self, block: bytes, mode: str) -> bytes:
        """
        Encrypt or decrypt a single 8-byte block.
        """
        if len(block) != 8:
            raise ValueError("Block size must be exactly 8 bytes.")
        
        # Convert block to binary string
        block_int = int.from_bytes(block, byteorder='big')
        block_bin = int_to_bin(block_int, 64)
        
        # Initial Permutation
        permuted = self.permute(block_bin, lookup_tables['ip'])
        
        left = permuted[:32]
        right = permuted[32:]
        
        # 16 DES rounds
        if mode == 'encryption':
            subkeys = self.subkeys
        elif mode == 'decryption':
            subkeys = self.subkeys[::-1]
        else:
            raise ValueError("Mode must be 'encryption' or 'decryption'")
        
        for subkey in subkeys:
            left, right = self.feistel(left, right, subkey)
        
        # Preoutput (Right + Left)
        preoutput = right + left
        
        # Final Permutation
        final_permutation = self.permute(preoutput, lookup_tables['fp'])
        final_int = bin_to_int(final_permutation)
        final_bytes = final_int.to_bytes(8, byteorder='big')
        
        return final_bytes
    
    def DES_algorithm(self, text: bytes, mode: str) -> bytes:
        """
        The main DES algorithm.
        Encrypt or decrypt the input text.
        For encryption, text is plaintext bytes.
        For decryption, text is ciphertext bytes.
        """
        
        if mode == 'encryption':
            # Apply PKCS#7 padding
            padded_text = pad(text)
            # Split into 8-byte blocks
            blocks = [padded_text[i:i+8] for i in range(0, len(padded_text), 8)]
        elif mode == 'decryption':
            # For decryption, input should be multiple of 8 bytes
            if len(text) % 8 != 0:
                raise ValueError("Ciphertext length must be a multiple of 8 bytes.")
            blocks = [text[i:i+8] for i in range(0, len(text), 8)]
        else:
            raise ValueError("Mode must be 'encryption' or 'decryption'")
        
        processed_blocks = []
        for block in blocks:
            processed_block = self.process_block(block, mode)
            processed_blocks.append(processed_block)
        
        if mode == 'decryption':
            # Concatenate decrypted blocks
            decrypted_data = b''.join(processed_blocks)
            # Remove padding
            try:
                unpadded_data = unpad(decrypted_data)
                return unpadded_data
            except ValueError as e:
                raise ValueError(f"Padding error during decryption: {e}")
        else:
            # For encryption, concatenate encrypted blocks
            return b''.join(processed_blocks)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string.
        Returns ciphertext as a hexadecimal string.
        """
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_bytes = self.DES_algorithm(plaintext_bytes, 'encryption')

        return ciphertext_bytes.hex()
    
    def decrypt(self, ciphertext_hex: str) -> str:
        """
        Decrypt a ciphertext hexadecimal string.
        Returns the plaintext string.
        """
        try:
            ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        except ValueError:
            raise ValueError("Invalid hex input for decryption")
        
        decrypted_bytes = self.DES_algorithm(ciphertext_bytes, 'decryption')
        return decrypted_bytes.decode('utf-8', errors='ignore')


if __name__ == '__main__':
    key = "1234567890"
    plaintext = "bonjour"

    des = DES(key.encode('utf-8'))
    
    # Encryption
    encrypted = des.encrypt(plaintext)
    print(f'Encrypted: {encrypted}')
    
    # Decryption
    decrypted = des.decrypt(encrypted)
    print(f'Decrypted: {decrypted}')