# MISC 损坏压缩包解题参考

> CTF中常见的"损坏的压缩包"类题目，需要修复、分析或解码压缩包内容

## 分析流程

### Step 1: 基础检查
```bash
file archive.zip                    # 确认文件类型
xxd archive.zip | head -30          # 十六进制查看头部
zipinfo archive.zip                 # 查看zip内部结构
unzip -l archive.zip                # 列出文件
```

### Step 2: 结构分析 (hex dump关键字段)
```
Local File Header:  50 4b 03 04
Central Directory:  50 4b 01 02
End of Central Dir: 50 4b 05 06

关键偏移 (Local Header):
  0-3:   签名 PK\x03\x04
  4-5:   版本需求
  6-7:   通用标志位
  8-9:   压缩方法 (0=stored, 8=deflate)
  14-17: CRC-32
  18-21: 压缩后大小
  22-25: 原始大小
  26-27: 文件名长度
  28-29: 扩展字段长度
  30+:   文件名 + 文件数据
```

### Step 3: 常见损坏类型及修复

| 损坏类型 | 特征 | 修复方法 |
|---------|------|---------|
| CRC错误 | unzip报CRC mismatch | 修复CRC或暴力匹配 |
| Magic字节损坏 | 无法识别为zip | 修复504b签名 |
| 文件头被改 | 文件名/大小异常 | 对比hex修改正确值 |
| 伪加密 | flags bit 0设为1 | 用010 Editor改回0 |
| 数据截断 | 文件不完整 | 补全缺失字节 |
| 文件名编码 | 中文乱码 | unzip -O CP936 |

### Step 4: 提取内容后的解码

提取出的文件内容通常还需要解码：
```bash
# Base64
cat data.txt | base64 -d

# Hex
cat data.txt | xxd -r -p

# ROT13
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# XOR (暴力单字节)
for i in $(seq 0 255); do echo -n "key=$i: "; cat data.txt | python3 -c "import sys; print(bytes([b^$i for b in sys.stdin.buffer.read()]))"; done
```

### Step 5: CRC暴力 (当CRC被篡改时)
```python
import zlib
# 已知部分明文(如"flag{")，暴力搜索未知部分
target_crc = 0x72e56fcc  # zip中存储的CRC
known = b"flag{"
# 暴力剩余字节...
```

## 实战案例

### 案例: Base64编码内容
- zip正常提取，data.txt内容为 `bWJndQ==`
- base64解码 → `mbgu`
- flag格式: `flag{mbgu}`

### 案例: 伪加密
- zipinfo显示加密标志，但实际无密码
- 用010 Editor将通用标志位的bit 0从1改为0

### 案例: CRC篡改
- 存储的CRC与实际数据不匹配
- 修复CRC后重新提取得到正确内容

## 工具推荐
- `xxd` / `hexdump` — 十六进制分析
- `zipinfo` — zip结构信息
- `zip -FF` — 尝试修复zip结构
- `010 Editor` — 可视化编辑zip字段
- `fcrackzip` — zip密码暴力
- `pkcrack` — 已知明文攻击
- `binwalk` — 检测嵌入文件
