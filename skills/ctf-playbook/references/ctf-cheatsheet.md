# CTF 完整知识库

> 详细内容请参考 `/root/ctf-cheatsheet.md` (15KB完整版)

## 目录

### Web安全
- SQL注入 (联合/报错/盲注/WAF绕过)
- XSS (反射/存储/DOM/绕过)
- 文件上传 (后缀/Content-Type/配置文件/竞争)
- 文件包含 (本地/远程/日志投毒)
- SSRF (协议利用/内网探测)
- XXE (外部实体/Blind XXE)
- 命令注入 (分隔符/空格绕过/关键字绕过)
- 反序列化 (PHP/Java/Python)
- JWT攻击 (无签名/密钥爆破/alg修改)

### Crypto
- 古典密码 (凯撒/维吉尼亚/栅栏/培根/摩尔斯/Atbash)
- RSA攻击 (小公钥指数/共模/因数分解/Wiener/Coppersmith)
- AES模式 (ECB/CBC/CTR/Padding Oracle)
- 哈希长度扩展
- 常见编码 (Base64/32/Hex/URL/Unicode)

### PWN
- 格式化字符串 (泄露/任意写)
- 栈溢出 (ROP/ret2libc/ret2csu)
- 堆利用 (fastbin/tcache/house of*)

### Misc
- 文件分析 (file/strings/binwalk)
- 图片隐写 (PNG高度/LSB/steghide)
- 音频隐写 (频谱图/SSTV/DTMF)
- 流量分析 (Wireshark过滤/文件提取)
- 压缩包破解 (伪加密/CRC爆破/密码)

### Reverse
- 静态分析 (IDA/Ghidra/strings)
- 动态调试 (gdb/pwndbg/ltrace)
- .NET/Java反编译

## 完整内容位置

`/root/ctf-cheatsheet.md` 包含:
- 每种漏洞的详细payload
- 绕过技巧
- 自动化脚本
- 在线工具链接
- 比赛策略
