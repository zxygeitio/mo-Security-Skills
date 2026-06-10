#!/usr/bin/env python3
"""CTF Crypto快速解密工具
用法: python3 ctf-crypto.py <模式> <输入>
"""

import sys
import base64
import binascii
import hashlib
import string
from collections import Counter

def rot13(text):
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + 13) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)

def caesar_brute(text):
    results = []
    for shift in range(1, 26):
        decoded = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                decoded.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                decoded.append(c)
        results.append((shift, ''.join(decoded)))
    return results

def rail_fence_decrypt(cipher, rails):
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(len(cipher)):
        fence[rail].append(i)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction *= -1
    result = [''] * len(cipher)
    index = 0
    for r in range(rails):
        for pos in fence[r]:
            result[pos] = cipher[index]
            index += 1
    return ''.join(result)

def atbash(text):
    result = []
    for c in text:
        if c.isalpha():
            if c.isupper():
                result.append(chr(ord('Z') - (ord(c) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)

def bacon_decode(text):
    bacon_dict = {
        'aaaaa': 'A', 'aaaab': 'B', 'aaaba': 'C', 'aaabb': 'D',
        'aabaa': 'E', 'aabab': 'F', 'aabba': 'G', 'aabbb': 'H',
        'abaaa': 'I', 'abaab': 'K', 'ababa': 'L', 'ababb': 'M',
        'abbaa': 'N', 'abbab': 'O', 'abbba': 'P', 'abbbb': 'Q',
        'baaaa': 'R', 'baaab': 'S', 'baaba': 'T', 'baabb': 'U',
        'babaa': 'W', 'babab': 'X', 'babba': 'Y', 'babbb': 'Z'
    }
    text = text.lower()
    result = []
    for i in range(0, len(text) - 4, 5):
        chunk = text[i:i+5]
        if chunk in bacon_dict:
            result.append(bacon_dict[chunk])
    return ''.join(result)

def morse_decode(text):
    morse_dict = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
        '...--': '3', '....-': '4', '.....': '5', '-....': '6',
        '--...': '7', '---..': '8', '----.': '9'
    }
    words = text.split(' / ')
    result = []
    for word in words:
        letters = word.split(' ')
        decoded_word = [morse_dict.get(l, '?') for l in letters]
        result.append(''.join(decoded_word))
    return ' '.join(result)

def xor_single_byte(cipher_hex):
    cipher_bytes = bytes.fromhex(cipher_hex)
    print("单字节XOR暴力破解:")
    for key in range(256):
        result = bytes([b ^ key for b in cipher_bytes])
        try:
            decoded = result.decode('ascii')
            if all(c in string.printable for c in decoded):
                print(f"Key {key:02x}: {decoded}")
        except:
            pass

def multi_base_decode(text):
    print("多层Base64解码尝试:")
    current = text
    for i in range(10):
        try:
            decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
            if decoded and decoded != current:
                print(f"Layer {i+1}: {decoded[:100]}...")
                current = decoded
            else:
                break
        except:
            break
    return current

def frequency_analysis(text):
    text = text.upper()
    freq = Counter(text)
    total = sum(freq.values())
    print("字母频率分析:")
    for char, count in freq.most_common():
        if char.isalpha():
            print(f"{char}: {count} ({count/total*100:.1f}%)")
    print("\n英文标准频率:")
    print("E: 12.7%  T: 9.1%  A: 8.2%  O: 7.5%  I: 7.0%")

def main():
    if len(sys.argv) < 3:
        print("CTF Crypto快速解密工具")
        print("=" * 40)
        print("用法: python3 ctf-crypto.py <模式> <输入>")
        print()
        print("模式:")
        print("  rot13        - ROT13解码")
        print("  caesar       - 凯撒密码暴力破解")
        print("  rail         - 栅栏密码解密")
        print("  atbash       - Atbash密码")
        print("  bacon        - 培根密码")
        print("  morse        - 摩尔斯电码")
        print("  base64       - Base64解码")
        print("  base32       - Base32解码")
        print("  hex          - Hex解码")
        print("  url          - URL解码")
        print("  freq         - 频率分析")
        print("  xor          - 单字节XOR破解")
        print("  multibase    - 多层Base64解码")
        sys.exit(1)
    
    mode = sys.argv[1].lower()
    input_text = sys.argv[2]
    
    print(f"模式: {mode}")
    print(f"输入: {input_text[:50]}...")
    print("=" * 40)
    
    if mode == "rot13":
        print(f"结果: {rot13(input_text)}")
    elif mode == "caesar":
        results = caesar_brute(input_text)
        for shift, decoded in results:
            print(f"Shift {shift:2d}: {decoded}")
    elif mode == "rail":
        rails = int(sys.argv[3]) if len(sys.argv) > 3 else 2
        print(f"结果: {rail_fence_decrypt(input_text, rails)}")
    elif mode == "atbash":
        print(f"结果: {atbash(input_text)}")
    elif mode == "bacon":
        print(f"结果: {bacon_decode(input_text)}")
    elif mode == "morse":
        print(f"结果: {morse_decode(input_text)}")
    elif mode == "base64":
        print(f"结果: {base64.b64decode(input_text).decode('utf-8', errors='ignore')}")
    elif mode == "base32":
        print(f"结果: {base64.b32decode(input_text).decode('utf-8', errors='ignore')}")
    elif mode == "hex":
        print(f"结果: {bytes.fromhex(input_text).decode('utf-8', errors='ignore')}")
    elif mode == "url":
        import urllib.parse
        print(f"结果: {urllib.parse.unquote(input_text)}")
    elif mode == "freq":
        frequency_analysis(input_text)
    elif mode == "xor":
        xor_single_byte(input_text)
    elif mode == "multibase":
        multi_base_decode(input_text)
    else:
        print(f"未知模式: {mode}")

if __name__ == "__main__":
    main()
