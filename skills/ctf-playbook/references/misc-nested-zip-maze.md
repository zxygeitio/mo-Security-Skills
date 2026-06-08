# MISC 嵌套压缩包迷宫解题参考

> CTF中"迷宫"类题目：多层嵌套压缩包，逐层解压提取最内层数据。与损坏压缩包不同，这类题zip本身完好，难点在于识别层数和最终payload编码。

## 识别特征

- 题目名含"迷宫/maze/嵌套/套娃"
- zip文件较小(几百字节~几KB)，解压出另一个zip
- 目录名逐层变化（layer1→secret3→.config/user/backup5/）
- 最内层通常是文本文件(.txt/.bin/.dat)，内容为编码数据

## 解题流程

### Step 1: 探测结构

```bash
# 列出第一层内容
unzip -l maze.zip

# 解压看是否还有zip
unzip -o maze.zip -d /tmp/maze_work
find /tmp/maze_work -name '*.zip' -o -name '*.gz' -o -name '*.tar' -o -name '*.bz2'
```

### Step 2: 批量逐层解压（推荐shell循环）

```bash
cd /tmp/maze_work && rm -rf *
cp /path/to/maze.zip .

for i in $(seq 1 500); do
  f=$(ls *.zip 2>/dev/null | head -1)
  [ -z "$f" ] && echo "No zip at step $i" && break
  unzip -o "$f" -d extracted_$i 2>/dev/null
  inner=$(find extracted_$i -name '*.zip' 2>/dev/null | head -1)
  if [ -z "$inner" ]; then
    echo "Step $i: reached leaf. Contents:"
    find extracted_$i -type f
    for ff in $(find extracted_$i -type f); do
      echo "--- $ff ---"
      cat "$ff"
    done
    break
  fi
  rm "$f"
  mv "$inner" .
  rm -rf extracted_$i
  [ $((i % 100)) -eq 0 ] && echo "Step $i..."
done
```

PITFALL: Python zipfile递归在层数很多时容易超时，shell循环更可靠。
- 如果shell循环也慢，先用 `seq 1 10` 小范围测试确认结构

### Step 3: 解码最内层payload

最内层文件通常是以下编码之一：

| 编码 | 特征 | 解码 |
|------|------|------|
| Base64 | 字母数字+/=结尾，长度4的倍数 | `base64 -d` |
| Hex | 0-9a-f，长度偶数 | `xxd -r -p` |
| Base32 | A-Z2-7，含=填充 | `base32 -d` |
| URL编码 | %XX序列 | `python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"` |
| 多层嵌套 | base64解码后仍是编码 | 循环解码直到可读 |

### Step 4: 识别最终数据

解码后常见类型：

```bash
# 如果是32位hex字符串 → MD5 hash
echo "e622093e1bbe5aacb0ce77f68d3d7e7d" | wc -c  # 32 chars = MD5

# 尝试破解MD5
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --force
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# 如果是64位hex → SHA-256
# 如果是可读字符串 → 直接作为flag内容
# 如果是二进制 → file命令识别类型
```

### 注意: payload末尾可能附带元数据

实战中遇到过：`ZTYyMjA5M2UxYmJl...N2Q=30`
- base64部分 `ZTYy...N2Q=` 解码为MD5 hash
- 末尾 `30` 是附加数据（可能是层数/版本号/干扰项）
- 正确做法：先解码base64部分，末尾数字单独处理

## 实战案例

### 案例: 迷宫(maze_06.zip) — 3层嵌套+base64+MD5

```
maze_06.zip (534B)
  └─ layer1/data2.zip (425B)
       └─ secret3/hidden4.zip (524B)
            └─ .config/user/backup5/vault.bin (46B)
                 内容: ZTYyMjA5M2UxYmJlNWFhY2IwY2U3N2Y2OGQzZDdlN2Q=30
                 base64解码 → e622093e1bbe5aacb0ce77f68d3d7e7d (MD5)
                 flag{e622093e1bbe5aacb0ce77f68d3d7e7d}
```

层数很少(3层)但目录名有迷惑性（.config/user/backup5模拟系统目录）。

## 常见变体

1. **百层迷宫**: 100+层，每层只有一个zip。用shell循环处理，不要用Python递归
2. **混合压缩**: zip→gz→tar→bz2→zip，循环中检查多种格式
3. **带密码**: 每层密码可能是上层文件名/目录名，或固定弱密码(123456)
4. **伪加密**: flags bit 0设为1但无实际密码，用010 Editor修改
5. **分支迷宫**: 一个zip内含多个zip，只有一个通往flag（通常按文件名规律判断）

## 工具

- `unzip -l` — 列出zip内容（不解压）
- `file` — 识别文件类型
- `xxd` — hex查看
- `base64 -d` / `base32 -d` — 解码
- `hashcat` / `john` — hash破解
- `binwalk` — 检测嵌入文件（辅助）
