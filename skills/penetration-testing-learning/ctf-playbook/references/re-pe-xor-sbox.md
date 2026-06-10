# RE: PE Binary XOR + S-Box Substitution Cipher

## When to Use
CTF REVERSE题给出 Windows PE 可执行文件，strings发现 "Input:" / "Correct!" / "Wrong!"，程序对输入做自定义加密后比较。

## Step-by-Step: PE XOR+S-Box Reversal

### 1. Quick triage
```bash
file vuln.exe                    # PE32+ x86-64
strings vuln.exe | grep -iE "correct|wrong|input|flag|key|check"
```

### 2. Find .rdata section (data extraction)
```bash
objdump -s -j .rdata vuln.exe | head -30
```
Key data locations in .rdata:
- "Input: " / "Correct!" / "Wrong!" strings → confirms check-based RE
- XOR key (typically 4-16 bytes)
- S-Box / substitution table (typically 256 bytes)
- Expected encrypted output (length = flag length)

### 3. Disassemble to find check function
```bash
# Find references to "Correct!" / "Wrong!" strings
objdump -d vuln.exe | grep -E "lea.*0x[0-9a-f]+.*# 0x1400040[01]"
# Trace back to the comparison function
objdump -d vuln.exe | sed -n '/140001480/,/ret$/p' | head -40
```

### 4. Identify the algorithm
Typical XOR+S-box check loop (x86-64):
```asm
; r9 = expected_encrypted_data, r10 = xor_key, r11 = sbox
; r8 = loop index, rcx = input, edx = length
mov    %r8,%rax
and    $0x7,%eax              ; idx = i % key_length
movzbl (%r10,%rax,1),%eax    ; key_byte = key[idx]
xor    (%rcx,%r8,1),%al      ; xored = input[i] ^ key_byte
movzbl %al,%eax
movzbl (%r9,%r8,1),%ebx      ; expected = encrypted[i]
cmp    %bl,(%r11,%rax,1)     ; sbox[xored] == expected?
jne    fail
```

### 5. Extract data from PE binary (Python)
```python
import struct

with open('vuln.exe', 'rb') as f:
    data = f.read()

# Parse PE header to find .rdata
pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
opt_hdr_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
section_start = pe_offset + 24 + opt_hdr_size

for i in range(num_sections):
    off = section_start + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
    vaddr = struct.unpack_from('<I', data, off+12)[0]
    rawptr = struct.unpack_from('<I', data, off+20)[0]
    rawsize = struct.unpack_from('<I', data, off+16)[0]
    if name == '.rdata':
        rdata = data[rawptr:rawptr+rawsize]
        rdata_va = vaddr
        break

# Extract: key at VA offset 0x48, expected at 0x20, sbox at 0x60
base = 0x140004000  # .rdata VA (from objdump output)
xor_key = rdata[0x48:0x48+8]
expected = rdata[0x20:0x20+32]  # adjust length
sbox = rdata[0x60:0x60+256]
```

### 6. Reverse the cipher
```python
# Build reverse S-box: value -> index
reverse_sbox = {}
for i in range(256):
    if sbox[i] not in reverse_sbox:
        reverse_sbox[sbox[i]] = i

# Decode
flag = ''
for i in range(len(expected)):
    sbox_idx = reverse_sbox[expected[i]]
    flag += chr(sbox_idx ^ xor_key[i % 8])

print(flag)  # flag{xxxx}
```

## Key Insights
- PE .rdata section contains all crypto constants (key, sbox, expected)
- XOR key is typically 8 bytes, cycling over input
- S-box is a 256-byte permutation table (each byte 0-255 appears exactly once)
- Reverse: find expected_byte in sbox → get index → XOR with key → original char
- VA addresses from objdump match .rdata base + offset

## Pitfalls
- **S-box not a permutation**: If duplicate values exist, multiple indices may map to same byte. Try all combinations.
- **Expected data length unknown**: Try 32, 36, 40, 48 bytes. Flag typically ends with `}`.
- **Multiple encryption rounds**: Some programs do XOR → S-box → XOR again. Check for second pass in disassembly.
- **PE parsing on Linux**: Use `objdump -s -j .rdata` and `objdump -d` (both work on PE files).
- **Python3 path**: `/usr/local/bin/python3` may be a ropgadget wrapper. Use `/usr/bin/python3`.

## Reference
Real CTF example: 御网杯 rerere challenge
- PE32+ x86-64, 16KB
- 8-byte XOR key, 256-byte S-box, 32-byte expected
- Flag: 36 chars `flag{32_hex_chars}`
