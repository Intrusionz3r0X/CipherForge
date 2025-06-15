#!/usr/bin/env python3

import argparse
import os
import sys
import pyfiglet
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class fg:
    BLACK   = '\033[30m'
    RED     = '\033[31m'
    GREEN   = '\033[32m'
    YELLOW  = '\033[33m'
    BLUE    = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN    = '\033[36m'
    WHITE   = '\033[37m'
    END   = '\033[39m'


def validate_file(path):
    if not os.path.isfile(path):
        print(f"{fg.RED}[!] shellcode not found: {path}{fg.END}")
        sys.exit(1)

def pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def rc4(data, key):
    keylen = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % keylen]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    encrypted = bytearray()
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        encrypted.append(data[n] ^ s[(s[i] + s[j]) % 256])
    return encrypted

def xor_encrypt(data, key):
    key = key * (len(data) // len(key)) + key[:len(data) % len(key)]
    return bytes([b ^ k for b, k in zip(data, key)])

def aes_encrypt(data, key):
    key = key.ljust(16, b'\x00')[:16]
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data))
    return cipher.iv + ct_bytes

def to_cpp_array(data, var_name="shellcode"):
    formatted = ", ".join(f"0x{b:02x}" for b in data)
    return f"unsigned char {var_name}[] = {{ {formatted} }};\nunsigned int {var_name}_len = {len(data)};"

def main():
    parser = argparse.ArgumentParser(description="Encrypt shellcode (RC4/XOR/AES) and output C++-compatible format.\nExample: %(prog)s -s shellcode.bin -k 'pass123' -m xor -c")
    parser.add_argument("-s", "--shellcode", required=True, help="Shellcode file path")
    parser.add_argument("-k", "--key", required=True, help="Encryption key")
    parser.add_argument("-o", "--output", help="Output file (optional)")
    parser.add_argument("-m", "--mode", required=True, choices=["rc4", "xor", "aes"], help="Encryption mode")
    parser.add_argument("-c", "--cpp", action="store_true", help="Output C++ format")
    parser.add_argument("-v", "--version", action="version", version="CipherForge 1.0")
    args = parser.parse_args()
    validate_file(args.shellcode)

    banner = pyfiglet.figlet_format("CipherForge", font="slant")
    print(f"{fg.RED}{banner}{fg.END}")
    print(" "*34+f"{fg.WHITE}Created by Intrusionz3r0{fg.END}\n")

    with open(args.shellcode, 'rb') as f:
        data = f.read()
    key = args.key.encode()

    if args.mode == "rc4":
        encrypted = rc4(data, key)
    elif args.mode == "xor":
        encrypted = xor_encrypt(data, key)
    elif args.mode == "aes":
        encrypted = aes_encrypt(data, key)

    if args.cpp:
        cpp_code = to_cpp_array(encrypted)
        print(f"{fg.GREEN}[+] C++ formatted shellcode:\n{fg.END}")
        print(cpp_code)
        if args.output:
            with open(args.output, "w") as f:
                f.write(cpp_code)
            print(f"{fg.GREEN}[+] Written to: {args.output}{fg.END}")
    else:
        out_file = args.output if args.output else f"{args.shellcode}.{args.mode}.enc"
        with open(out_file, "wb") as f:
            f.write(encrypted)
        print(f"{fg.GREEN}[+] Encrypted shellcode written to: {out_file}{fg.END}")

if __name__ == "__main__":
    main()
