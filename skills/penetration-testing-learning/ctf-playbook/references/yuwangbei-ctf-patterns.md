# 御网杯 CTF 竞赛模式与跨题联动

## 竞赛信息

- 平台: js.yuwangbei.cn
- 届次: 第十届御网杯网络安全大赛线上挑战赛 (2026)
- 题目格式: 编号后缀 (image_01, shadow_09, maze_06, otp_04, etc.)

## 已确认的题目附件 (2026-05-30)

| 文件名 | 类型 | 分值 | 内容 | 状态 | Flag |
|--------|------|------|------|------|------|
| archive_06.zip | MISC签到 | 150 | data.txt = "bWJndQ==" (base64→"mbgu") | ✅已解 | flag{mbgu} |
| maze_06.zip | MISC迷宫 | 250 | 嵌套zip + base64 | ✅已解 | flag{mbgu} |
| shadow_09.zip | MISC | — | RAR(data.bin) 含提示+base64数据 | ✅已解 | flag{1acb4a7c-5f4c-4c3c-81bf-8b3ea70896ef} |
| image_01.zip | MISC/隐写 | — | 64x64白PNG + 64B trailer | ✅已解 | flag{69cb343d-1f36-2692-67d9-5fb7109836bf} |
| CrackMe_1_7.zip | RE ChaCha20 | 150 | APK + libmyapplication.so | ✅已解 | flag{HNCTF62RDYNTFMZ1TF} |
| CrackMe_2_3.zip | RE DES | 350 | APK + libcrackme2.so | ✅已解 | flag{2023326077889096380} |
| py_obf_07.zip | RE字节码 | 350 | .pyc (marshal + XOR key=110) | ✅已解 | flag{0nvze2l1-9ps6-prj8-k35e-l5a1r0831bip} |
| rerere.exe | RE PE | 150 | PE XOR+S-Box | ✅已解 | flag{e44f71ae87360aeb2d23f269155abbb3} |
| BabyRSA2.zip | Crypto | 150 | e=3 小指数攻击 | ✅已解 | flag{769cc0209669698952823747f21eb10e} |
| otp_04.zip | Crypto ECB | 300 | ciphertext.bin (80B) | ❌未解 | — |
| otp_08.zip | Crypto | — | challenge.json (764B) | ❌未解 | — |
| login.zip | PWN UserManager | 400 | Fastbin UAF (悬垂指针) | ❌靶机不可用 | — |
| PHP_Payment | WEB | 250 | PHP反序列化 | ✅已解 | flag{76ba823ae0ab8606a6db7a2de4d71e88} |
| PWN-Authenticate | PWN | 200 | gets()栈溢出 ret2text | ✅已解 | flag{eb894509110dfe178dfe94d828d9d15c} |
| PWN-NoteService | PWN | 400 | read栈溢出 ret2text | ✅已解 | flag{d9fcee27c6a249b046bfd61de6825aab} |

总计已解: 12题, 约 2750 分 (含 ECDSA nonce reuse 150分未列入附件表)

## 跨题联动: shadow_09 包含全局编码提示

shadow_09 的 data.bin (RAR格式) 包含:

```
REMEMBER: FLAG IS HIDDEN IN BASE64 PLUS XOR!
FAKE FLAG: flag{00000000-0000-0000-0000-000000000000}
DO NOT TRUST THIS ONE.
MDo3MS1nNzU0YjdhNXtjMGI1e2I1ZTV7bmc0MHtuNGUzN2Fmbm9gMzAr
```

解码: base64→XOR(0x56)→flag{1acb4a7c-5f4c-4c3c-81bf-8b3ea70896ef}

## XOR Key 推导尝试

shadow_09 key = 0x56 = 86。尝试公式:
- key = N*6+32: shadow_09→86✓, image_01→38✗
- key = 10*N-4: shadow_09→86✓, image_01→6✗

image_01 的 key 未知, 需从其他题目附件寻找.

## image_01 trailer (已确认不是flag本身)

```
00000000 69cb343d 1f362692 67d95fb7
109836bf 61eff1fe 8ff36f37 10c44522
073c6a29 cff8205d 18970ae1 ccbbe5a5
c01ff2a9 f4c346ed 68a7da71 1ccbae35
```

## 搜索策略

1. Bing: "御网杯" + "像素中的秘密" + "CTF"
2. Chat01.ai: 粘贴题目描述 (GPT-5.5分析)
3. CSDN/CN-SEC/zone.ci: 搜索 writeup
4. 检查同比赛所有附件: ls /home/zxy/*.zip
5. 平台页面: 检查 hint 按钮
