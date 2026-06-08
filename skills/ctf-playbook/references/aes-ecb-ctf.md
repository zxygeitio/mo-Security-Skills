# AES-ECB CTF Pattern

## 识别

- 文件被检测为 "OpenPGP Secret Key" 但无法用GPG解析 → 可能是AES-ECB加密数据
- 第一字节 0x97 碰巧匹配OpenPGP packet tag (tag=5, secret key)，不代表是OpenPGP
- 密文长度是16的倍数 → 可能是AES block cipher
- 无重复块 → 明文无重复16字节段

## 解题思路

1. **已知明文攻击 (Known Plaintext)**
   - flag格式 `flag{...}` 已知前5字节 → 可验证key
   - 如果key是flag本身(循环加密) → 需要其他方法

2. **密钥来源搜索**
   - 文件名/挑战名作为key: `MD5(challenge_name)[:16]`
   - 文件CRC32/MD5/SHA作为key
   - 其他附件中包含key
   - 竞赛平台公告/hint

3. **暴力破解小密钥空间**
   - 单字节重复key: `bytes([b])*16`, b in 0-255
   - 2字节重复key: `bytes([b1,b2])*8`, 65536种
   - 3字节重复key: `bytes([b1,b2,b3])*5+b[:1]`, 16M种
   - 用Python + PyCryptodome:
     ```python
     from Crypto.Cipher import AES
     for b in range(256):
         key = bytes([b]) * 16
         cipher = AES.new(key, AES.MODE_ECB)
         dec = cipher.decrypt(data)
         if b'flag' in dec:
             print(f'Found: {dec}')
     ```

4. **文件本身作为密钥**
   - 文件某个偏移的16字节作为key
   - XOR两个块作为key: `bytes(a^b for a,b in zip(block0, block2))`

5. **编码而非加密**
   - 80字节可能不是AES而是其他编码(base64/base32/XOR/Vigenère)
   - 检查单字节XOR、位置相关XOR
   - 检查文件hash作为flag: `flag{md5_of_file}`

## PITFALL: file命令误报

`file`命令基于magic bytes匹配，0x97碰巧匹配OpenPGP secret key tag。
实际解析OpenPGP时应检查: version byte是否为0x04(v4)或0x03(v3)。

## PITFALL: AES-ECB无重复块不等于安全

ECB模式下相同明文块产生相同密文块。如果所有块都不同:
- 说明明文中没有重复的16字节段
- 不能通过pattern matching恢复明文
- 仍需要密钥才能解密

## 穷尽离线方法后的判断

当AES-ECB离线解密穷尽以下方法均失败时，大概率不是纯离线题：

1. 单字节/2字节/3字节重复key暴力 (256 + 65536 + 16M)
2. 文件名/题目名/比赛名 MD5/SHA256 作为key
3. 常见CTF key: YELLOW SUBMARINE, 0123456789abcdef, 1234567890123456等
4. 文件hash/CRC32作为key
5. 块间XOR/块作为key互相解密
6. 单字节XOR (256种)
7. Vigenere/位置相关XOR (已知明文flag{推导key)
8. 其他算法: DES/3DES/Blowfish/RC4/ChaCha20
9. 代码簿攻击思路 (但需要oracle)
10. NIST测试向量密钥

**此时应考虑**:
- 题目有配套在线服务 (ECB oracle/加密接口)
- 题目平台有额外提示/公告
- 需要与其他附件组合解题
- flag不是flag{...}格式 (可能是原始hex/base64)
- 加密方案不是标准AES-ECB (自定义算法)

## Python环境注意

`/usr/local/bin/python3` 可能是ropgadget wrapper，用 `/usr/bin/python3`。
PyCryptodome安装: `pip install --break-system-packages pycryptodome`
