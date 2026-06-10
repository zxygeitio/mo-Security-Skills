# RSA Hastad广播攻击 — 仿射变换变体 (Generalized Hastad with Affine Padding)

## 场景

同一明文 m 用 e=3 和 k≥3 个不同RSA模数加密，但每次加密前加了仿射噪声：
c_i = (a_i * m + b_i)^e mod n_i

其中 a_i, b_i 已知，n_i 不同，e=3。

## 与标准Hastad的区别

标准Hastad: c_i = m^3 mod n_i → CRT合并后直接开立方根
仿射变体: c_i = (a_i*m+b_i)^3 mod n_i → 多项式不同，无法直接CRT合并密文

## 解题核心思路

### 步骤1: CRT合并为单个多项式

将3个不同多项式 f_i(x) = (a_i*x+b_i)^3 - c_i 合并为一个 F(x) ≡ 0 (mod N)：

```python
N = n1 * n2 * n3
n23, n13, n12 = n2*n3, n1*n3, n1*n2

# CRT基
e1 = (n23 * pow(n23, -1, n1)) % N
e2 = (n13 * pow(n13, -1, n2)) % N
e3 = (n12 * pow(n12, -1, n3)) % N

# 展开 f_i = a_i^3*x^3 + 3*a_i^2*b_i*x^2 + 3*a_i*b_i^2*x + (b_i^3 - c_i)
F = []
for j in range(4):  # 4 coefficients: x^3, x^2, x, 1
    F.append((e1*f1[j] + e2*f2[j] + e3*f3[j]) % N)

# F(m) ≡ 0 (mod N)，F是3次多项式
```

### 步骤2: Coppersmith格构造 (LLL)

m ≈ 2^256 < N^{1/3} ≈ 2^1023，满足Coppersmith小根条件。

构造格矩阵 (h=1):
- 行1: F(x) 系数 → [0, F3, F2, F1, F0] (degree 3, pad to 5 cols)
- 行2: x*F(x) 系数 → [F3, F2, F1, F0, 0] (degree 4)
- 行3-7: N*x^j for j=0..4 → 对角矩阵 * N

列缩放: column j *= X^j (X = root bound, 如 2^300)

```python
from fpylll import IntegerMatrix, LLL

X = 1 << 300
h = 1
ncols = 3 + h + 1  # degree 3 + h + 1 = 5

rows = []
# x^j * F(x) for j=0..h
for j in range(h + 1):
    row = [0] * ncols
    for k in range(4):  # F has 4 coefficients
        power = 3 - k + j  # x^(3-k+j)
        row[power] = F[k]
    rows.append(row)
# N * x^j
for j in range(ncols):
    row = [0] * ncols
    row[j] = N
    rows.append(row)

# Column scaling
for i in range(len(rows)):
    for j in range(ncols):
        rows[i][j] *= X ** j

M = IntegerMatrix(len(rows), ncols)
for i in range(len(rows)):
    for j in range(ncols):
        M[i, j] = rows[i][j]

L = LLL.reduction(M)
```

### 步骤3: 提取根

LLL输出的短向量对应系数小的多项式 h(x)，满足 h(m)=0 (整数等式)。

```python
for idx in range(L.nrows):
    vec = [int(L[idx, j]) for j in range(ncols)]
    # 还原系数: coeff[j] = vec[j] / X^j
    coeffs = [vec[j] // (X**j) for j in range(ncols)]
    # coeffs = [c0, c1, c2, ...] 升幂排列
    # Newton法求根
    def evalp(m): return sum(coeffs[i] * m**i for i in range(len(coeffs)))
    def evaldp(m): return sum(i * coeffs[i] * m**(i-1) for i in range(1, len(coeffs)))
    
    for start in [2**128, 2**256, 2**300]:
        m = start
        for _ in range(1000):
            fv = evalp(m)
            if fv == 0:
                flag = long_to_bytes(m)
                print(f"FLAG: {flag}")
                break
            fpv = evaldp(m)
            if fpv == 0: m += 1; continue
            m_new = m - fv // fpv
            if m_new == m: break
            m = m_new
```

## 为什么能成功

- F(m) ≡ 0 (mod N) 且 |h(m)| < N (因为LLL找到的系数足够小)
- 所以 h(m) = 0 在整数上精确成立 (不是模N)
- h(m)=0 是整数多项式方程，可以直接求根

## 关键判断条件

| 条件 | 要求 |
|------|------|
| 加密次数 | k ≥ e (至少3次 for e=3) |
| 根大小 | m < N^{1/e} (N=n1*n2*...*nk) |
| 仿射参数 | a_i, b_i 必须已知 |

## 依赖安装

```bash
pip3 install fpylll cysignals --break-system-packages
# fpylll 需要 cysignals 依赖，缺了会报 ModuleNotFoundError
# fpylll IntegerMatrix + LLL.reduction 是核心API
```

## 完整求解流程模板

```
1. 读取参数 (n_i, a_i, b_i, c_i)
2. 计算 f_i 系数: A_i=a_i^3, B_i=3a_i^2*b_i, C_i=3a_i*b_i^2, D_i=b_i^3-c_i
3. CRT合并: F_j = (e1*f1[j] + e2*f2[j] + e3*f3[j]) % N
4. 构造格 (h=1, 11x5): x^j*F(x) rows + N*x^j rows, 列缩放 X^j
5. fpylll LLL.reduction
6. 还原多项式系数 (除以X^j)
7. Newton法求根 (多起始点: 2^64..2^300)
8. long_to_bytes(m) → flag
```

## 常见陷阱

1. **直接CRT合并系数不行**: CRT把不同多项式的系数合并后，系数~N大小，m^3 << N 但 coeff*m^3 >> N，无法直接求根
2. **纯Python LLL太慢**: 用fpylll (C后端)，不要手写浮点LLL
3. **/usr/local/bin/python3可能是ropgadget wrapper**: CTF PWN环境中用 /usr/bin/python3
4. **h=0不够**: k=d=3是边界情况，h=1更安全
5. **Newton法起始点**: 多试几个 2^64, 2^128, 2^192, 2^256, 2^300
