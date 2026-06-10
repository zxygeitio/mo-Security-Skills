# CTF Writeup 模板 (御网杯格式)

## 标准格式 (用户偏好: 4步式)

```
题目名称：xxx
题目类型：WEB/Crypto/Misc/Reverse/PWN
难度：初级/中级/高级
分值：xxx分
靶机地址：xxx

一、解题过程

1. 获取到某某文件 — 描述访问目标、获取源码/文件的过程
2. 然后利用某某工具 — 描述使用的工具和分析过程
3. 再去利用某某编码/技术 — 描述编码/解码/构造payload等技术手段
4. 然后解出flag — 给出最终flag

二、漏洞分析

【1-2段简明的漏洞原理分析和危害说明】
```

## 填充指南

### 步骤1: 获取到
- Web: "访问靶机地址 http://x.x.x.x:port，获取到网页源码文件 index.php"
- PWN: "下载获取到题目附件 vuln.zip，解压得到 64 位 ELF 可执行文件 vuln"
- RE: "获取到题目附件 xxx.zip，解压得到 Windows 64 位 PE 可执行文件"
- Misc: "下载获取到题目附件 archive.zip"

### 步骤2: 利用工具
- Web: Burp Suite / curl / 浏览器开发者工具 / 源码审计
- PWN: objdump 反汇编 / checksec / ROPgadget / strings
- RE: objdump / IDA / Ghidra / strings / xxd
- Misc: xxd / binwalk / unzip / base64 / file

### 步骤3: 技术手段
- 一句话概括核心攻击技术 (如 "栈缓冲区溢出" / "PHP反序列化" / "XOR+S-Box逆向")
- 关键地址/偏移量/编码方式
- Payload 构造过程

### 步骤4: 解出flag
- 单独一行突出: flag{xxxxxxxx}

### 漏洞分析
- 1-2段: 漏洞根因 → 利用条件 → 危害说明
- 不用HTML，纯文本

## 御网杯规则要点 (2026)

- 平台: https://js.yuwangbei.cn
- 积分制: 按正确提交排序，前10名100%，11-100名90%，依次递减
- CTF题分上午/下午两批 (下午13:30)
- Writeup模板下载: 09:00-17:00 | 上传: 17:30-22:00
- 未提交writeup的题目扣分
- 雷同writeup取消成绩
- 不得攻击竞赛平台/分享flag
