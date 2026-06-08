# ChaCha20 CTF 解密

## 场景
CTF题使用ChaCha20流密码加密flag，需要从二进制中提取key/nonce/ciphertext并解密。

## ChaCha20 算法要点
- 32字节密钥 (key)
- 12字节随机数 (nonce)
- 常量: "expand 32-byte k" (16字节)
- Counter: 通常从0开始，某些实现从1开始
- 每轮生成64字节keystream，与明文XOR

## 从ELF .so中提取参数
```bash
# 1. 找ChaCha20常量
strings lib.so | grep "expand 32-byte"
# 2. 找常量在.rodata中的位置，追踪到函数
objdump -d lib.so | grep "0x61707865"  # "expa" hex
# 3. 反汇编函数，找key/nonce加载指令
# key: mov指令从.rodata地址加载32字节
# nonce: 从相邻地址加载12字节
# 4. 提取数据
python3 -c "
with open('lib.so','rb') as f: data=f.read()
key = data[KEY_OFFSET:KEY_OFFSET+32]
nonce = data[NONCE_OFFSET:NONCE_OFFSET+12]
print(f'Key: {key.hex()}')
print(f'Nonce: {nonce.hex()}')
"
```

## 手动ChaCha20解密 (无依赖)
```python
import struct

def chacha20_block(key, counter, nonce):
    constants = b"expand 32-byte k"
    state = list(struct.unpack('<16I', constants + key + struct.pack('<I', counter) + nonce))
    ws = list(state)
    def qr(a,b,c,d):
        ws[a] = (ws[a]+ws[b]) & 0xffffffff; ws[d] ^= ws[a]; ws[d] = ((ws[d]<<16)|(ws[d]>>16)) & 0xffffffff
        ws[c] = (ws[c]+ws[d]) & 0xffffffff; ws[b] ^= ws[c]; ws[b] = ((ws[b]<<12)|(ws[b]>>20)) & 0xffffffff
        ws[a] = (ws[a]+ws[b]) & 0xffffffff; ws[d] ^= ws[a]; ws[d] = ((ws[d]<<8)|(ws[d]>>24)) & 0xffffffff
        ws[c] = (ws[c]+ws[d]) & 0xffffffff; ws[b] ^= ws[c]; ws[b] = ((ws[b]<<7)|(ws[b]>>25)) & 0xffffffff
    for _ in range(10):
        qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15)
        qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14)
    return struct.pack('<16I', *((ws[i]+state[i]) & 0xffffffff for i in range(16)))

def chacha20_decrypt(key, nonce, ct, counter=0):
    result = bytearray()
    for i in range(0, len(ct), 64):
        block = chacha20_block(key, counter, nonce)
        chunk = ct[i:i+64]
        result.extend(bytes(a^b for a,b in zip(chunk, block)))
        counter += 1
    return bytes(result)

# 使用
key = bytes.fromhex('...')
nonce = bytes.fromhex('...')
ct = bytes.fromhex('...')
for c in [0, 1]:  # 试两种counter
    pt = chacha20_decrypt(key, nonce, ct, counter=c)
    print(f"counter={c}: {pt}")
```

## PITFALL: Counter参数
标准ChaCha20 RFC 7539用counter=0，但某些实现（如OpenSSL某些版本、自定义实现）从1开始。
如果counter=0解密结果是乱码，试counter=1。反之亦然。

## PITFALL: 密文存储位置
- 静态密文：在 .rodata 段，直接从文件读取
- 运行时密文：在 .bss 段，需要追踪初始化代码或动态调试
- 字符串形式：某些CTF把密文存为hex ASCII（如 "d097c3f6..."），需要 bytes.fromhex() 转换
