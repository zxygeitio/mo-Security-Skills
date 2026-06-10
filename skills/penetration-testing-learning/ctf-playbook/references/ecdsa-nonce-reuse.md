# ECDSA Nonce Reuse Attack / ECDSA 随机数重用攻击

## 题型特征

- 题目给出：公钥 (pub_x, pub_y)、两条不同消息 (msg1, msg2)、两条签名 (r1,s1) (r2,s2)
- 关键线索：r1 == r2（说明 nonce k 被重用）
- 曲线通常是 SECP256k1 或 P-256
- 消息可能是 hex 编码的明文字符串

## 数学原理

ECDSA 签名公式：
```
s = k^(-1) * (z + r*d) mod n
```
其中 k=nonce, z=消息哈希, r=R.x mod n, d=私钥, n=曲线阶

当同一 k 用于两条不同消息：
```
s1 = k^(-1) * (z1 + r*d) mod n
s2 = k^(-1) * (z2 + r*d) mod n
```

消去 r*d：
```
s1 - s2 = k^(-1) * (z1 - z2) mod n
k = (z1 - z2) * (s1 - s2)^(-1) mod n
```

恢复私钥：
```
d = (s1 * k - z1) * r^(-1) mod n
```

## 解题流程

### Step 1: 提取参数
```python
import json, hashlib

with open('challenge.json') as f:
    data = json.load(f)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # SECP256k1

msg1 = bytes.fromhex(data['message1'])
msg2 = bytes.fromhex(data['message2'])
r  = data['signature1_r']
s1 = data['signature1_s']
s2 = data['signature2_s']
```

### Step 2: 确认 nonce 重用
```python
assert data['signature1_r'] == data['signature2_r'], "r 不同，nonce 未重用"
```

### Step 3: 计算消息哈希
```python
# 尝试多种哈希算法，用公钥验证确定哪个正确
hash_funcs = {
    'SHA-1': hashlib.sha1,
    'SHA-256': hashlib.sha256,
    'SHA-384': hashlib.sha384,
    'SHA-512': hashlib.sha512,
    'SHA3-256': hashlib.sha3_256,
    'MD5': hashlib.md5,
    'raw': None,  # 不哈希，直接用消息整数
}
```

### Step 4: 恢复私钥
```python
z1 = int(hashlib.sha256(msg1).hexdigest(), 16) % n
z2 = int(hashlib.sha256(msg2).hexdigest(), 16) % n

k = ((z1 - z2) * pow(s1 - s2, -1, n)) % n
d = ((s1 * k - z1) * pow(r, -1, n)) % n
```

### Step 5: 验证 — 椭圆曲线点乘 (关键！)
```python
# 必须验证 d*G 是否等于给定公钥
# 不验证 = 不知道哪个哈希算法是对的

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def modinv(a, m=p):
    return pow(a, m-2, m)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0]==Q[0] and P[1]!=Q[1]: return None
    if P==Q:
        lam = (3*P[0]*P[0] * modinv(2*P[1])) % p
    else:
        lam = ((Q[1]-P[1]) * modinv(Q[0]-P[0])) % p
    x = (lam*lam - P[0] - Q[0]) % p
    y = (lam*(P[0]-x) - P[1]) % p
    return (x, y)

def point_mul(k, P=None):
    if P is None: P = (Gx, Gy)
    R = None
    while k > 0:
        if k % 2 == 1:
            R = point_add(R, P)
        P = point_add(P, P)
        k //= 2
    return R

# 验证
pub = point_mul(d)
assert pub[0] == data['public_key_x'], "公钥不匹配，哈希算法可能不对"
```

### Step 6: 输出 flag
```python
print(f"flag{{ecdsa_nonce_reuse_{d:064x}}}")
```

## 完整解题脚本模板

```python
import json, hashlib

with open('challenge.json') as f:
    data = json.load(f)

n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def modinv(a, m=p): return pow(a, m-2, m)

def point_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0]==Q[0] and P[1]!=Q[1]: return None
    lam = (3*P[0]*P[0]*modinv(2*P[1]))%p if P==Q else ((Q[1]-P[1])*modinv(Q[0]-P[0]))%p
    x = (lam*lam-P[0]-Q[0])%p
    return (x, (lam*(P[0]-x)-P[1])%p)

def point_mul(k, P=(Gx,Gy)):
    R = None
    while k > 0:
        if k % 2 == 1: R = point_add(R, P)  # k&1 breaks in terminal heredoc (& = background)
        P = point_add(P, P)
        k //= 2
    return R

msg1 = bytes.fromhex(data['message1'])
msg2 = bytes.fromhex(data['message2'])
r, s1, s2 = data['signature1_r'], data['signature1_s'], data['signature2_s']

assert data['signature1_r'] == data['signature2_r']

for name, hfunc in [('SHA-256',hashlib.sha256),('SHA-1',hashlib.sha1),
                     ('SHA-512',hashlib.sha512),('raw',None)]:
    z1 = int.from_bytes(msg1,'big')%n if hfunc is None else int(hfunc(msg1).hexdigest(),16)%n
    z2 = int.from_bytes(msg2,'big')%n if hfunc is None else int(hfunc(msg2).hexdigest(),16)%n
    k = ((z1-z2)*pow(s1-s2,-1,n))%n
    d = ((s1*k-z1)*pow(r,-1,n))%n
    if point_mul(d)[0] == data['public_key_x']:
        print(f"[+] Hash: {name}, d = {hex(d)}")
        print(f"flag{{ecdsa_nonce_reuse_{d:064x}}}")
        break
```

## 常见曲线阶 n

| 曲线 | n |
|------|---|
| SECP256k1 | 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 |
| P-256 (prime256v1) | 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 |

## 常见哈希算法

CTF 中按使用频率排序：
1. SHA-256（最常见，ECDSA 默认）
2. SHA-1（老系统）
3. raw（不哈希，直接用消息整数 — 小消息常见）

## PITFALL: 必须验证公钥

不同哈希算法会算出不同的 d，但只有一个能通过 d*G == 公钥 的验证。
**不验证 = 可能提交了错误的 flag。** 尤其是题目没明确说用什么哈希时。

## PITFALL: 模逆运算

Python 3.8+ 支持 `pow(a, -1, n)` 直接求模逆。
如果环境不支持，用 `pow(a, n-2, n)` (当 n 是素数时)。
ecdsa 库不是必须的，纯 math 实现更可靠（避免依赖安装问题）。

## PITFALL: 终端 heredoc 中 & 被解释为后台运算符

Hermes terminal 工具的 heredoc 中，`&` 会被 shell 解释为后台执行符，导致命令失败。
**受影响的写法**: `if k & 1`, `k >>= 1` 中无此问题但 `&` 在条件表达式中会出错。
**解决方案**: 用 `k % 2 == 1` 代替 `k & 1`，用 `k //= 2` 代替 `k >>= 1`。
对于含 `&` 的复杂脚本，用 `write_file` 写到文件再用 `/usr/bin/python3 script.py` 执行。

## PITFALL: /usr/local/bin/python3 可能被劫持

CTF/PWN 环境中 `/usr/local/bin/python3` 可能是 ROPgadget wrapper。
始终使用 `/usr/bin/python3` 执行 Python 脚本。
