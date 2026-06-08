---
name: script-analysis-invisible-code
description: >-
  高级脚本分析与隐形代码检测 — Python/JS/VBA逆向 + Unicode零宽字符混淆检测 (Glassworm)
domain: cybersecurity
subdomain: malware-analysis
tags:
- script-analysis
- obfuscation
- unicode
- supply-chain
- reverse-engineering
version: '1.0'
author: zxygeitio
license: Apache-2.0
mitre_attack:
- T1027
- T1059
nist_csf:
- DE.CM-01
---
# 高级脚本分析与隐形代码检测

## 核心原理

跳过底层反汇编器，直接对脚本进行静态解码与逻辑反混淆。重点检测 Unicode 零宽/不可见字符混淆（如 Glassworm 攻击模式），这些字符可用作合法变量名或藏匿于缩进/注释中，在常规编辑器中实现视觉隐身。

## 触发条件

- EDR 捕捉异常进程活动，但传统静态扫描未发现恶意载荷
- 审查开源组件库（npm/PyPI）及 GitHub PR 时怀疑供应链投毒
- 代码审计中发现可疑但"看起来正常"的脚本文件
- 文件大小与可见内容不匹配（隐藏字符占用额外字节）

## 一、Unicode 零宽/不可见字符检测

### 1.1 已知危险 Unicode 字符

| Unicode | 名称 | 用途 | 宽度 |
|---------|------|------|------|
| U+200B | ZERO WIDTH SPACE | 变量名分隔/隐藏payload | 0 |
| U+200C | ZERO WIDTH NON-JOINER | 标识符混淆 | 0 |
| U+200D | ZERO WIDTH JOINER | 标识符混淆 | 0 |
| U+FEFF | ZERO WIDTH NO-BREAK SPACE (BOM) | 文件头注入 | 0 |
| U+2060 | WORD JOINER | 隐藏分隔 | 0 |
| U+00AD | SOFT HYPHEN | 隐藏字符 | 0 |
| U+034F | COMBINING GRAPHEME JOINER | 变量名混淆 | 0 |
| U+3164 | HANGUL FILLER | 空白变量名 | 视觉空白 |
| U+FFA0 | HALFWIDTH HANGUL FILLER | 空白变量名 | 视觉空白 |
| U+180E | MONGOLIAN VOWEL SEPARATOR | 空白变量名 | 视觉空白 |
| U+2800 | BRAILLE PATTERN BLANK | 空白变量名 | 视觉空白 |
| U+061C | ARABIC LETTER MARK | 方向控制 | 0 |
| U+200E/U+200F | LTR/RTL MARK | 文本方向攻击 | 0 |
| U+202A-U+202E | 方向覆盖字符 | 代码显示欺骗 | 0 |
| U+2066-U+2069 | 方向隔离符 | 代码显示欺骗 | 0 |

### 1.2 快速检测命令

```bash
# 方法1: Python 检测所有不可见字符
python3 -c "
import sys
INVISIBLE = set([
    0x200B,0x200C,0x200D,0xFEFF,0x2060,0x00AD,0x034F,
    0x3164,0xFFA0,0x180E,0x2800,0x061C,
    0x200E,0x200F,0x202A,0x202B,0x202C,0x202D,0x202E,
    0x2066,0x2067,0x2068,0x2069,0x2000,0x2001,0x2002,
    0x2003,0x2004,0x2005,0x2006,0x2007,0x2008,0x2009,0x200A
])
for fname in sys.argv[1:]:
    with open(fname,'rb') as f: data = f.read()
    text = data.decode('utf-8','replace')
    for i,ch in enumerate(text):
        if ord(ch) in INVISIBLE:
            line = text[:i].count('\n')+1
            ctx = text[max(0,i-20):i+20].replace('\n',' ')
            print(f'{fname}:{line} U+{ord(ch):04X} ctx: ...{ctx}...')
" file1.py file2.js

# 方法2: grep 批量扫描目录
grep -rP '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}\x{2066}-\x{2069}\x{FEFF}\x{00AD}\x{061C}\x{3164}\x{FFA0}\x{180E}\x{2800}]' --include="*.py" --include="*.js" --include="*.vbs" /path/to/scan/

# 方法3: hexdump 可视化
xxd file.py | grep -iE 'e2.80.8[bcdef]|ef.bb.bf|e2.80.a[0-9a]|e2.81[a6-9]|c2.ad|da.9c|ef.be.a0|e1.a0.ae|e2.a0.80|d8.9c'

# 方法4: file 命令异常检测
file --mime-encoding suspicious.py
# 正常 Python 应为 us-ascii 或 utf-8，异常编码需深入检查
```

### 1.3 Glassworm 模式检测

```bash
# Glassworm 特征: 变量名由不可见 Unicode 字符组成
# Python 3 允许标识符使用 Unicode 字符

# 检测脚本中是否存在纯不可见字符的标识符
python3 << 'PYEOF'
import ast, sys, tokenize, io

INVISIBLE_CHARS = set(range(0x200B, 0x2010)) | {0xFEFF, 0x2060, 0x00AD, 0x3164, 0xFFA0, 0x180E, 0x2800}

def check_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    
    # 方法1: 检查 tokenize 输出中的 NAME token
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(content).readline))
        for tok in tokens:
            if tok.type == tokenize.NAME:
                if any(ord(c) in INVISIBLE_CHARS for c in tok.string):
                    print(f"[!] INVISIBLE IDENTIFIER: '{tok.string}' (repr: {tok.string!r}) at line {tok.start[0]}")
    except tokenize.TokenError:
        pass
    
    # 方法2: 逐字符扫描
    lines = content.split('\n')
    for lineno, line in enumerate(lines, 1):
        for i, ch in enumerate(line):
            if ord(ch) in INVISIBLE_CHARS:
                ctx = line[max(0,i-15):i+15]
                print(f"[!] U+{ord(ch):04X} at {filepath}:{lineno}:{i} context: {ctx}")

for f in sys.argv[1:]:
    check_file(f)
PYEOF
suspicious.py
```

## 二、脚本反混淆技术

### 2.1 Python 脚本反混淆

```bash
# 基础美化 (修复压缩代码)
pip install autopep8 black
autopep8 --in-place --aggressive obfuscated.py

# 字符串解码 (base64/hex/rot13)
python3 -c "
import base64, codecs, sys
with open(sys.argv[1]) as f: content = f.read()
# Base64 解码
import re
for m in re.finditer(r'[A-Za-z0-9+/]{20,}={0,2}', content):
    try:
        decoded = base64.b64decode(m.group()).decode('utf-8','replace')
        if any(c.isalpha() for c in decoded):
            print(f'B64: {m.group()[:50]}... -> {decoded[:100]}')
    except: pass
# Hex 解码
for m in re.finditer(r'\\\\x([0-9a-f]{2})', content):
    pass  # 已在字符串字面量中
" obfuscated.py

# exec/eval 替换为 print (查看执行内容)
sed 's/exec(/print(#EXEC: /g; s/eval(/print(#EVAL: /g' obfuscated.py > deobf.py

# PyInstaller 打包文件解包
pip install pyinstxtractor
python3 pyinstxtractor.py suspicious.exe
# 输出目录中找到 .pyc 文件，再反编译:
pip install uncompyle6
uncompyle6 output/suspicious.pyc > suspicious.py
```

### 2.2 JavaScript 脚本反混淆

```bash
# 基础美化
npm install -g js-beautify
js-beautify obfuscated.js > pretty.js

# AST 分析 (高级)
npm install -g esprima escodegen
node -e "
const esprima = require('esprima');
const fs = require('fs');
const code = fs.readFileSync('obfuscated.js','utf8');
const ast = esprima.parseScript(code);
console.log(JSON.stringify(ast, null, 2));
" | head -200

# 常见 JS 混淆模式识别
grep -oP 'eval\(function\(p,a,c,k,e,d\)' obfuscated.js && echo "Packer 混淆 detected"
grep -oP '_0x[a-f0-9]+' obfuscated.js | sort -u | head -20  # 十六进制变量名
grep -oP 'String\.fromCharCode' obfuscated.js && echo "字符构造 detected"

# JSFuck 解码 (仅用 []()!+ 字符)
# 将 JSFuck 代码粘贴到浏览器控制台，替换 eval 为 console.log
```

### 2.3 VBA/宏 反混淆

```bash
# 提取 Office 文档中的宏
pip install oletools
olevba suspicious.docm  # 提取并分析 VBA 宏

# VBA 反混淆关键函数
grep -iE "Chr\(|ChrW\(|Asc\(|StrReverse\(|Replace\(|Environ\(" macro.vba

# 自动解码 Chr() 序列
python3 -c "
import re
with open('macro.vba') as f: content = f.read()
# 解码 Chr(数字) 序列
chars = re.findall(r'Chr\((\d+)\)', content)
if chars:
    decoded = ''.join(chr(int(c)) for c in chars)
    print(f'Decoded Chr() sequence: {decoded}')
# 解码 ChrW() (Unicode)
chars_w = re.findall(r'ChrW\(&H([0-9A-Fa-f]+)\)', content)
if chars_w:
    decoded_w = ''.join(chr(int(c,16)) for c in chars_w)
    print(f'Decoded ChrW() sequence: {decoded_w}')
"
```

## 三、供应链投毒检测

### 3.1 npm 包审计

```bash
# 安装前检查
npm audit
npm info <package> maintainers  # 检查维护者变更

# 静态分析已安装包
find node_modules -name "*.js" -exec grep -l "eval\|child_process\|require('http')" {} \;

# 检查 package.json 中的 install 脚本
find node_modules -name "package.json" -exec grep -l '"install"' {} \;
# install 脚本在 npm install 时自动执行，常被恶意利用

# typosquatting 检测 (包名相似性)
pip install typosquat
```

### 3.2 PyPI 包审计

```bash
pip install pip-audit safety
pip-audit  # 检查已安装包的已知漏洞

# 检查 setup.py 中的可疑代码
find /usr/lib/python*/dist-packages -name "setup.py" -exec grep -l "os.system\|subprocess\|eval\|exec" {} \;

# 检查 wheel 中的 post-install 脚本
unzip -l *.whl | grep -i "scripts/\|post"
```

### 3.3 GitHub PR 投毒检测

```bash
# 检查 PR 中的可疑变更模式:
# 1. 新增对 eval/exec/system 的调用
# 2. 新增对 HTTP 外联的调用
# 3. 修改 CI/CD 配置文件
# 4. 新增依赖但功能未变
# 5. 变量名使用非 ASCII 字符

# 自动化检查 PR diff:
gh pr diff <PR_NUMBER> | grep -iE "eval\(|exec\(|os\.system\|subprocess\|child_process\|fetch\(|axios\." 
```

## 四、工具链

| 工具 | 用途 | 安装 |
|------|------|------|
| oletools | VBA 宏分析 | `pip install oletools` |
| js-beautify | JS 美化 | `npm install -g js-beautify` |
| uncompyle6 | Python 反编译 | `pip install uncompyle6` |
| pyinstxtractor | PyInstaller 解包 | GitHub |
| semgrep | 语义代码扫描 | `pip install semgrep` |
| grype/syft | SBOM + 漏洞扫描 | GitHub releases |

## 参考

- Unicode 安全: https://unicode.org/reports/tr36/
- Glassworm: Unicode 零宽字符代码注入攻击
- Supply Chain Threats: https://slsa.dev/
