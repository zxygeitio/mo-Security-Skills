# AnyShare 文档管理系统 CORS 误报模式 (2026-05-28 cdut.edu.cn实战)

## 指纹识别
- 路径: /anyshare/
- React SPA: `<html id="__anyshare">`, create-react-app
- Cookie: X-Forwarded-Prefix
- API前缀: /anyshare/api/v2/, /anyshare/api/v3/

## CORS 配置
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET,PUT,POST,DELETE,HEAD,OPTIONS
```

## ⚠️ 关键误报: CORS + SPA Fallback
虽然 CORS 配置为 `*` + Credentials:true，但：
1. 所有 API 路径返回 SPA HTML (6709字节 React shell)，不是 JSON
2. 浏览器规范不允许 `*` + Credentials:true 组合，会阻止跨域请求
3. 实际无法跨域读取任何敏感数据

**结论: 不建议提交。** CORS 配置意图错误但浏览器会阻止，且无真实API数据可读。

## SPA Fallback 验证方法
```bash
# 比较API路径和随机路径的响应
body1=$(curl -sk 'https://pan.cdut.edu.cn/anyshare/api/v2/system/info' | head -c 100)
body2=$(curl -sk 'https://pan.cdut.edu.cn/anyshare/nonexistent12345' | head -c 100)
[ "$body1" = "$body2" ] && echo "SPA FALLBACK - 所有路径返回同一页面"
```

## 如果API返回JSON而非HTML
如果实际部署中API返回JSON数据，则CORS `*` + Credentials 确实构成漏洞：
- 需要用 Accept: application/json 头测试
- 检查是否有认证态API返回用户文件列表/分享链接等

## 实战案例
- pan.cdut.edu.cn: 成都理工大学 AnyShare 网盘, CORS `*` + Credentials 但 SPA fallback
