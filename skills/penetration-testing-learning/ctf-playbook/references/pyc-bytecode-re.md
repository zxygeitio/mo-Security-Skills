# Python .pyc Bytecode 逆向

## 场景
CTF给出 .pyc 文件，需要还原Python源码逻辑并提取flag。

## 工具
- `marshal` — Python内置，加载pyc中的code object
- `dis` — 反汇编字节码（有时对混淆的pyc会报错）
- `uncompyle6` / `decompyle3` — 自动反编译（需安装，可能不支持新版Python）

## 分析流程

### 1. 提取code object结构
```python
import marshal, struct, types

with open('challenge.pyc', 'rb') as f:
    f.read(16)  # 跳过header (Python 3.x: magic + flags + timestamp + size)
    code = marshal.load(f)

# 递归分析所有code object
def dump(co, indent=0):
    p = '  ' * indent
    print(f'{p}=== {co.co_name} ===')
    print(f'{p}  Consts: {co.co_consts}')
    print(f'{p}  Names: {co.co_names}')
    print(f'{p}  Varnames: {co.co_varnames}')
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            dump(c, indent + 1)

dump(code)
```

### 2. 从常量池提取关键数据
- 字符串常量（加密数据、密钥、编码后的flag）
- 数字常量（XOR密钥、偏移量）
- 嵌套code object（子函数的逻辑）

### 3. 常见混淆模式
- Base64 + XOR：先base64解码再XOR
- 多层嵌套函数
- 变量名混淆（`a`, `b`, `c` 代替有意义的名称）
- 字节码操作码被篡改（dis报错时需要手动解析）

### 4. 还原算法
从常量池和变量名推断算法：
- 看到 `chr()` + `join()` → 字符拼接
- 看到 `base64` in co_names → Base64编码/解码
- 看到数字常量 → XOR密钥或偏移
- 看到 `encoded_data` + `key` in co_varnames → 加密flag + 密钥

## 实战案例 (御网杯 py_obf_07)
```python
# 常量池中的关键数据：
# main.co_consts: (..., 'CAIPCRVeABgUC1wCX0NXHh1YQx4cBFZDBV1bC0MCWw9fHF5WXV8MBx4T', 110, ...)
# decrypt_flag.co_consts: (None, '', <genexpr>)
# decrypt_flag.co_names: ('base64', 'b64decode', 'join')
# genexpr.co_names: ('chr',)

# 还原：base64解码 + XOR key=110
import base64
encoded = 'CAIPCRVeABgUC1wCX0NXHh1YQx4cBFZDBV1bC0MCWw9fHF5WXV8MBx4T'
key = 110
decoded = base64.b64decode(encoded)
flag = ''.join(chr(b ^ key) for b in decoded)
# → flag{0nvze2l1-9ps6-prj8-k35e-l5a1r0831bip}
```

## PITFALLS
- Python 3.12+的pyc header是16字节，旧版可能不同
- `dis.dis()` 对混淆pyc可能报 "IndexError: tuple index out of range"，回退到手动分析常量池
- marshal.load() 只加载顶层code object，嵌套函数在 co_consts 中
