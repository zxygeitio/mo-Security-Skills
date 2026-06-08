# 伪装文件 + 嵌入编码提示 + XOR 解码

## 题型特征

- 文件头伪装成已知格式（RAR/ZIP/PNG等），但 `file` 命令报错或内容不完整
- 文件体包含明文提示，如 "FLAG IS HIDDEN IN BASE64 PLUS XOR"
- 末尾有编码数据（base64/hex/rot13），解码后仍不是明文
- 需要进一步解密（XOR/ROT/caesar等）

## 识别信号

1. `file` 报 "RAR archive data" 但 `unrar l` 报 "corrupt" 或 "unexpected end"
2. `xxd`/`strings` 在二进制文件头后看到英文提示文本
3. 提示文本中明确给出编码方式和密钥线索（如 "BASE64 PLUS XOR"）
4. 文件中嵌入假flag（如 `flag{00000000-...}`），带 "DO NOT TRUST THIS ONE" 等警告

## 解题流程

### Step 1: 二进制检查
```bash
file data.bin
xxd data.bin | head -30
strings data.bin
```
注意文件头之后是否有非结构化文本。

### Step 2: 提取嵌入数据
```bash
# 找 base64 特征（纯字母数字+/=结尾）
grep -oP '[A-Za-z0-9+/=]{20,}' data.bin

# 提取从某个偏移到文件末尾的数据
tail -c +OFFSET data.bin
```

### Step 3: 按提示解码链
```bash
# base64 解码
echo "BASE64STRING" | base64 -d | xxd

# 单字节 XOR 暴力（找 flag 模式）
echo "BASE64STRING" | base64 -d | /usr/bin/python3 -c "
import sys
data = sys.stdin.buffer.read()
for k in range(1, 256):
    r = bytes([b ^ k for b in data])
    try:
        s = r.decode('ascii')
        if 'flag' in s.lower() or 'ctf' in s.lower():
            print(f'key={k} (0x{k:02x}): {s}')
    except:
        pass
"
```

### Step 4: 验证 flag 格式
检查是否符合 `flag{uuid}` 或平台特定格式。

## 御网杯幻影题实战 (250分 MISC)

- 附件：shadow_09.zip → data.bin (185 bytes)
- 文件头：`52 61 72 21` (RAR magic) 但 unrar 报 corrupt
- 明文提示："REMEMBER: FLAG IS HIDDEN IN BASE64 PLUS XOR!"
- 假 flag：`flag{00000000-0000-0000-0000-000000000000}` + "DO NOT TRUST THIS ONE"
- base64 数据：`MDo3MS1nNzU0YjdhNXtjMGI1e2I1ZTV7bmc0MHtuNGUzN2Fmbm9gMzAr`
- base64 解码：`0:71-g754b7a5{c0b5{b5e5{ng40{n4e37afno`30+`
- XOR key=0x56 得到：`flag{1acb4a7c-5f4c-4c3c-81bf-8b3ea70896ef}`
- 题目声称10个文件，实际zip只含1个样本

## PITFALL: python3 被劫持

CTF 环境中 `/usr/local/bin/python3` 可能是工具 wrapper（如 ROPgadget），
执行 `python3` 会超时或产生意外行为。始终用 `/usr/bin/python3`。

## 常见 XOR key 值

| key | 含义 |
|-----|------|
| 0x56 | 'V' (常见单字节密钥) |
| 0x58 | 'X' (与提示中 XOR 一词相关) |
| 0x00-0xFF | 暴力枚举，用 flag{ 作为已知明文 |

## 已知明文加速

如果已知 flag 格式为 `flag{`，可以用前5字节与密文 XOR 推导 key：
```python
known = b'flag{'
cipher = decoded[:5]
key = bytes([c ^ k for c, k in zip(cipher, known)])
print(key)  # 如果是单字节重复key，所有字节相同
```
