# RSA 小指数攻击 (Small Exponent Attack)

## 场景
RSA加密使用极小公钥指数 e（通常 e=3），且明文较短，导致 m^e < n。

## 原理
当 m^e < n 时：c = m^e mod n = m^e（无模运算取余）
直接对c开e次方根即可还原明文。

## 快速判断
```python
# 如果 flag{uuid} ≈ 42字符 ≈ 200 bits
# e=3 → m^3 ≈ 600 bits
# n = p*q ≈ 1024 bits (两个512位素数)
# m^3 < n 成立 → 直接开方
```

## 解密脚本
```python
# 方法1: gmpy2 (快)
import gmpy2
m, exact = gmpy2.iroot(c, e)
if exact:
    flag = int(m).to_bytes((int(m).bit_length()+7)//8, 'big')
    print(flag.decode())

# 方法2: 纯Python (无依赖)
def icbrt(n):
    lo, hi = 0, n
    while lo < hi:
        mid = (lo + hi) // 2
        cube = mid * mid * mid
        if cube < c:
            lo = mid + 1
        elif cube > c:
            hi = mid
        else:
            return mid
    return lo

m = icbrt(c)
assert m**3 == c
flag = m.to_bytes((m.bit_length()+7)//8, 'big')
print(flag.decode())

# 方法3: Python浮点近似 + 验证 (小数字时最快)
m = int(round(c ** (1/3)))
for delta in range(-10, 10):
    if (m+delta)**3 == c:
        print((m+delta).to_bytes(..., 'big').decode())
        break
```

## 变种
- e=3, m^3 > n 但 m^3 < 2n: c = m^3 - n, 需尝试 c + k*n 开方
- e=3 且有padding: m = flag_bytes + random_padding, 需要更复杂的Coppersmith方法
- 多个接收者同一明文不同n (Hastad广播攻击): CRT合并后开方
- 多个接收者同一明文+仿射噪声 (a_i*m+b_i)^3 mod n_i: CRT合并多项式→Coppersmith LLL → 详见 references/rsa-hastad-affine-attack.md
