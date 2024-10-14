"""
Python implementation of Data Encryption Standard (DES) algorithm.
"""

import json

# Load the lookup tables
with open('lookup_tables.json', 'r') as f:
    lookup_tables = json.load(f)


def int_to_bin(num: int, length: int) -> str:
    """
    Convert an integer to a binary string.
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


class KeyGenerator:
    def __init__(self, key: str):
        self.key = key
        self.round_keys = self.generate_keys()

    def PC_1(self):
        """
        Permuted Choice 1 (PC-1) operation.
        """
        left = ''.join([self.key[i - 1] for i in lookup_tables['pc_1_left']])
        right = ''.join([self.key[i - 1] for i in lookup_tables['pc_1_right']])
        return left, right

    def PC_2(self, pre_key: str) -> str:
        """
        Permuted Choice 2 (PC-2) operation.
        """
        assert len(pre_key) == 56, "Pre-key must be 56 bits long"
        return ''.join([pre_key[i - 1] for i in lookup_tables['pc_2']])

    def generate_keys(self) -> list:
        """
        Generate 16 round keys.
        """
        assert len(self.key) == 64, "Key must be 64 bits long"

        left, right = self.PC_1()
        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        round_keys = []

        for i in range(16):
            left = left[shifts[i]:] + left[:shifts[i]]
            right = right[shifts[i]:] + right[:shifts[i]]
            combined = left + right
            round_keys.append(self.PC_2(combined))
        
        return round_keys


class DES:
    def __init__(self, key: int):
        key_bin = int_to_bin(key, 64)
        self.subkey = KeyGenerator(key_bin).round_keys
    
    def IP(self, text: str) -> str:
        """
        Initial Permutation (IP).
        """
        return ''.join([text[i - 1] for i in lookup_tables['ip']])
    
    def FP(self, text: str) -> str:
        """
        Final Permutation (FP).
        """
        return ''.join([text[i - 1] for i in lookup_tables['fp']])
    
    def rounds(self, left: str, right: str, subkey: str) -> tuple:
        """
        Perform one DES round.
        """
        return right, xor(left, self.f(right, subkey))
    
    def f(self, half: str, subkey: str) -> str:
        """
        The DES round function.
        """
        assert len(half) == 32, "Half-block must be 32 bits"
        assert len(subkey) == 48, "Subkey must be 48 bits"

        expanded = self.expand(half)  # Expand the half to 48 bits
        xored = xor(expanded, subkey)  # XOR the expanded half with the subkey
        substituted = self.s_box(xored)  # Substitute the XORed half with S-box
        permuted = self.p(substituted)  # Permute the substituted half

        return permuted
    
    def expand(self, half: str) -> str:
        """
        Expansion (E) function to expand 32 bits to 48 bits.
        """
        assert len(half) == 32, "Half-block must be 32 bits"
        return ''.join([half[i - 1] for i in lookup_tables['e']])
    
    def p(self, text: str) -> str:
        """
        Permutation (P) function.
        """
        assert len(text) == 32, "Text must be 32 bits"
        return ''.join([text[i - 1] for i in lookup_tables['p']])
    
    def s_box(self, text: str) -> str:
        """
        S-box substitution.
        """
        assert len(text) == 48, "Input to S-box must be 48 bits"
        blocks = [text[i:i + 6] for i in range(0, 48, 6)]  # Divide into 8 blocks of 6 bits
        substituted = ''

        for i in range(8):
            current_block = blocks[i]
            current_s_box = lookup_tables['s_box'][i]
            
            row = bin_to_int(current_block[0] + current_block[-1])
            col = bin_to_int(current_block[1:5])
            
            s_box_value = current_s_box[row * 16 + col]
            substituted += int_to_bin(s_box_value, 4)
        
        assert len(substituted) == 32, "Output from S-box must be 32 bits"
        return substituted
    
    def DES_algorithm(self, text: str, mode: str) -> str:
        """
        Main procedure of DES algorithm.
        """
        if mode not in ['encryption', 'decryption']:
            raise ValueError("Mode must be 'encryption' or 'decryption'")
        
        if mode == 'decryption':
            subkeys = self.subkey[::-1]
        else:
            subkeys = self.subkey

        if mode == 'encryption':
            # Convert plaintext to binary
            text_bytes = text.encode('utf-8')
            if len(text_bytes) > 8:
                raise ValueError("Text too long for single DES block (max 8 bytes)")
            text_bytes = text_bytes.ljust(8, b'\0')  # Pad to 8 bytes if necessary
            text_int = int.from_bytes(text_bytes, byteorder='big')
            text_bin = int_to_bin(text_int, 64)
        else:
            # Convert hex ciphertext to binary
            try:
                text_bytes = bytes.fromhex(text)
            except ValueError:
                raise ValueError("Invalid hex input for decryption")
            if len(text_bytes) > 8:
                raise ValueError("Text too long for single DES block (max 8 bytes)")
            text_int = int.from_bytes(text_bytes, byteorder='big')
            text_bin = int_to_bin(text_int, 64)

        # Initial Permutation
        processed_text = self.IP(text_bin)

        left, right = processed_text[:32], processed_text[32:]

        # 16 DES rounds
        for i in range(16):
            left, right = self.rounds(left, right, subkeys[i])
        
        # Preoutput (Right + Left)
        preoutput = right + left

        # Final Permutation
        final_permutation = self.FP(preoutput)
        final_int = bin_to_int(final_permutation)
        final_bytes = final_int.to_bytes(8, byteorder='big')

        if mode == 'decryption':
            # Remove padding and decode to string
            return final_bytes.rstrip(b'\0').decode('utf-8', errors='ignore')
        else:
            # Return encrypted data as hex string for readability
            return final_bytes.hex()


if __name__ == '__main__':
    # Example 64-bit key
    key = 0x133457799BBCDFF1

    # Ensure the key is 64 bits
    if not (0 <= key < 1 << 64):
        raise ValueError("Key must be a 64-bit integer")

    plaintext = 'bonjour'

    des = DES(key)
    
    # Encryption
    encrypted = des.DES_algorithm(plaintext, 'encryption')
    print(f'Encrypted: {encrypted}')
    
    # Decryption
    decrypted = des.DES_algorithm(encrypted, 'decryption')
    print(f'Decrypted: {decrypted}')
