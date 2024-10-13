'''
Python implementation of Data Encryption Standard (DES) algorithm.
'''

import json

with open('lookup_tables.json', 'r') as f:
    lookup_tables = json.load(f)

def int2bin(num: int, length: int):
    '''
    Convert an integer to binary string.
    '''
    return bin(num)[2:].zfill(length)

def bin2int(binary: str):
    '''
    Convert a binary string to integer.
    '''
    return int(binary, 2)

def xor(a: str, b: str):
    '''
    XOR operation.
    '''
    return ''.join(['1' if a[i] != b[i] else '0' for i in range(len(a))])

class KeyGenerator:
    def __init__(self, key: str):
        self.key = key
        self.round_keys = self.generate_keys()

    def PC_1(self):
        '''
        Permuted Choice 1 (PC-1) operation.
        '''
        return [self.key[i - 1] for i in lookup_tables['pc_1_left']], [self.key[i - 1] for i in lookup_tables['pc_1_right']]
    
    def PC_2(self, pre_key):
        assert len(pre_key) == 56 # Ensure that the pre_key must be 56 bits long
        return [pre_key[i - 1] for i in lookup_tables['pc_2']]

    def generate_key(self):
        '''
        Generate 16 round keys.
        '''
        assert len(self.key) == 64 # Ensure that the key must be 64 bits long

        left, right = self.PC_1()
        off = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        round_keys = []

        for i in range(16):
            left = left[off[i]:] + left[:off[i]]
            right = right[off[i]:] + right[:off[i]]
            round_keys.append(self.PC_2(left + right))
        
        return round_keys

