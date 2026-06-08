# Android APK + Native .so 逆向分析

## 适用场景
CTF Reverse题给出APK文件，核心加密逻辑在native (.so)库中。

## 工具链
- `unzip` 解包APK
- `strings` 提取字符串
- `objdump -d -M intel` 反汇编 .so（Intel语法更易读）
- `objdump -s -j .rodata` 导出数据段
- `readelf -S` 查看段布局（vaddr/offset/size）
- `readelf -s` / `objdump -T` 查符号表
- `xxd -s OFFSET -l LEN` 精确dump指定区域
- `grep -boa 'STRING' file.so` 找字符串在文件中的精确偏移
- `androguard` Python库分析DEX（pip install androguard，但很慢，优先用strings+objdump）

## 分析流程

### 0. 快速侦察 + 字符串分析
```bash
unzip -o app.apk -d apk_extracted
# 找native库
find apk_extracted -name "*.so" -type f
# 字符串分析 — 找密钥、密文、hex字符串、算法常量
strings libapp.so | grep -E "flag|key|encrypt|decrypt|des|aes|hex|12345678"
# 找hex编码的密文/flag（通常是64+十六进制字符的连续纯hex字符串）
strings libapp.so | grep -E '^[0-9a-f]{32,}$'
# 找可疑的短二进制数据（可能是S-Box、permutation table）
strings -n 8 libapp.so | head -30
```

### 1. APK解包 + DEX分析
```bash
unzip -o app.apk -d apk_extracted
# 找到 classes*.dex 和 lib/ 下的 .so
# 用 androguard 分析DEX中的类和方法（慢，备选）
```

### 2. 定位JNI方法
```bash
# 找导出的JNI函数
objdump -T libapp.so | grep "Java_"
# 如果没有导出，JNI_OnLoad中通过RegisterNatives动态注册
# 反汇编JNI_OnLoad找RegisterNatives调用，提取方法表
```

JNI方法表解析（详细步骤）：
```python
# 1. 找到JNI_OnLoad中的RegisterNatives调用
# RegisterNatives(env, class, methods, count) 参数布局：
#   movl $COUNT, 0xc(%esp)    # 方法数量
#   lea  METHODS(%ebx), %eax  # 方法表地址
#   mov  %eax, 0x8(%esp)
#   mov  CLASS, 0x4(%esp)
#   mov  ENV, (%esp)

# 2. 计算方法表的vaddr
# ebx = call指令后的pop地址 + 偏移量 (如 pop %ebx; add $0x33fc4, %ebx)
# 方法表vaddr = ebx + lea指令中的偏移

# 3. vaddr到file offset转换
# 用 readelf -S 找到包含该vaddr的段
# file_offset = vaddr - section_vaddr + section_file_offset
# 例: .data.rel.ro vaddr=0x571b0, file_offset=0x561b0 → 差值0x1000

# 4. 读取方法表 (每条12字节 for 32-bit)
import struct
pos = file_offset  # 方法表在文件中的位置
for i in range(num_methods):
    name_ptr = struct.unpack_from('<I', data, pos)[0]
    sig_ptr = struct.unpack_from('<I', data, pos+4)[0]
    fn_ptr = struct.unpack_from('<I', data, pos+8)[0]
    name = read_string_at_vaddr(name_ptr)  # 解引用读字符串
    sig = read_string_at_vaddr(sig_ptr)
    print(f'Method {i}: {name}{sig} -> {fn_ptr:#010x}')
    pos += 12
```

实例(ChaCha20 CrackMe)：
- 方法表在 file offset 0x561b4 (3条记录)
- Entry 0: a([B)[B -> 0x250b0 (加密)
- Entry 1: b([B)[B -> 0x251f0 (解密)
- Entry 2: c(String)Z -> 0x25330 (验证)

### 3. GOT-relative 地址计算（PIC代码核心技巧）

x86 32位PIC代码的 `call/pop/add` 模式：
```asm
call next          ; push return addr
next:
pop ebx            ; ebx = 当前指令地址
add ebx, OFFSET    ; ebx = GOT基址（通常等于 .got.plt 的vaddr）
```

之后所有数据引用都是 `ebx + displacement` 或 `ebx - displacement`：
```asm
lea eax, [ebx+0x125c]    ; 数据在 .data/.bss 段
lea esi, [ebx-0x47d7b]   ; 数据在 .rodata 段（地址 < GOT）
```

计算vaddr的方法：
- `ebx` 值 = `call` 目标地址 + 5(指令长度) + `add` 的立即数
- 目标vaddr = `ebx` ± 指令中的偏移量
- 然后用 `readelf -S` 找到对应段，转为 file offset

实例：
```
call 0x240fd → push 0x24102 → pop ebx → add ebx, 0x32cb7 → ebx = 0x56DB4
Key at [ebx-0x47d7b] = 0x56DB4 - 0x47D7B = 0xF039 (在 .rodata)
Expected at [ebx+0x125c] = 0x56DB4 + 0x125C = 0x58010 (在 .bss)
```

### 4. 定位加密算法
- `strings` 找 "expand 32-byte k" (ChaCha20)、"AES"、"DES" 等关键词
- `objdump -d` 反汇编，搜索常量加载指令（movl $0x61707865 = "expa"）
- 找到 `call` 到 PLT 的加密函数，追踪参数（输入、密钥、输出指针）

### 5. 提取密钥/Nonce/密文
- 密钥通常在 .rodata 段，通过指令中的地址引用
- vaddr到file offset转换：`file_offset = vaddr - (section_vaddr - section_file_offset)`
- 用 `grep -boa 'KEYSTRING' file.so` 快速定位密钥文件偏移
- 用 `xxd -s OFFSET -l 32 file.so` 查看周围数据
- 密文可能在 .rodata（静态）或 .bss（运行时由构造函数填充）

### 6. 解密
- 手动实现算法（如ChaCha20）或使用crypto库
- **注意counter参数**：ChaCha20的counter可能从0或1开始，两种都试

## ★ 验证逻辑逆向：数据流追踪法（反红鲱鱼）

**核心原则：不要假设函数名或调用就代表验证逻辑，必须追踪数据流。**

### 方法：追踪每个栈/寄存器变量的生命周期

1. **找到验证函数**（如 `verifyFlag`、`checkPassword`）
2. **标注每个 [ebp-X] 变量的含义**：
   - 在函数入口处，找到每个栈变量的赋值点
   - 写下：`[ebp-0x34] = input_string`、`[ebp-0x38] = output_buffer`
3. **在加密函数调用后**，检查后续比较/转换使用的是哪个变量
4. **关键判断**：比较的是加密输入还是加密输出？

### 案例：DES红鲱鱼 (御网杯 CrackMe_2_3)

验证函数调用链：
```
padded_input = pkcs7_pad(user_input)     → [ebp-0x34]
output_buf = malloc(padded_len)          → [ebp-0x38]
des_ecb_encrypt(padded_input, len, key, output_buf)  // 加密到output_buf
hex_str = bytesToHex(???, padded_len)    // 用的是哪个？
compare(hex_str, stored_hex)
```

**陷阱**：看到 `des_ecb_encrypt` 就认为需要解密。
**实际**：`bytesToHex` 的第二个参数来自 `[ebp-0x34]`（padded_input），不是 `[ebp-0x38]`（encrypted output）。
**结论**：DES加密从未被比较，是红鲱鱼！验证逻辑是 `hex(pad(input)) == stored_hex`。

### 红鲱鱼识别清单
- [ ] 加密函数的输出是否被后续代码引用？
- [ ] bytesToHex/toString 转换的是哪个缓冲区？
- [ ] 比较指令的两个操作数分别来自哪里？
- [ ] 如果去掉加密调用，程序逻辑是否改变？
- [ ] hex解码存储的"密文"是否是可读ASCII？如果是，很可能就是明文本身

### PKCS7填充快速验证
当存储的hex解码后尾部有重复字节（如 `\x07`×7）：
```python
decoded = bytes.fromhex(stored_hex)
pad_byte = decoded[-1]           # 填充字节值 = 填充长度
plaintext = decoded[:-pad_byte]  # 去掉填充
# 验证：len(plaintext) + pad_byte 应该是8的倍数
```

## PITFALLS

### /usr/local/bin/python3 可能是broken wrapper
如果 `python3 -c "print('hello')"` 卡住不动，检查：
```bash
cat /usr/local/bin/python3  # 可能是ropgadget wrapper
# 用 /usr/bin/python3 替代
```

### ChaCha20 counter参数
标准ChaCha20 counter从0开始，但某些实现从1开始。如果解密结果是乱码，尝试counter=1。

### androguard安装
```bash
pip install --break-system-packages androguard
# 用法：from androguard.core.dex import DEX
# 注意：很慢，优先用 strings + objdump 手动分析
```

### PE x86 .so的vaddr计算
32位ELF：.data.rel.ro段的vaddr和file offset通常差0x1000。
用 readelf -S 找到具体差值：`file_offset = vaddr - (section_vaddr - section_offset)`

### .bss 段的运行时初始化
.bss 段文件中大小为0（NOBITS），运行时才初始化。如果期望值在 .bss 中（如 std::string 全局变量），需要查看 .init_array 中的构造函数，它会在 main() 之前从 .rodata 复制数据到 .bss。

### std::string 在 32-bit ELF 中的大小
`sizeof(std::string)` 在 libc++ (NDK) 中为 12 字节。对象数组中每个元素间隔 0xC。
