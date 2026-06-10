# Vue/React SPA 真实 API 端点发现技术

适用场景：目标前端是 Vue/React SPA，API 路径和后端域名不明显，需要发现真实后端 API。

## XHR 拦截法

SPA 应用的前端会通过 axios/fetch 调用后端 API。在浏览器控制台拦截这些请求可发现真实 API 端点：

```javascript
// 安装拦截器
const origXHR = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    if (url && !url.includes('baidu') && !url.includes('geetest')) {
        console.log('XHR:', method, url);
    }
    return origXHR.call(this, method, url, ...rest);
};

// 或通过 Performance API 查看已完成的请求
performance.getEntriesByType('resource')
    .filter(r => r.initiatorType === 'xmlhttprequest' || r.initiatorType === 'fetch')
    .map(r => r.name)
    .filter(u => !u.includes('baidu') && !u.includes('geetest'));
```

## Vuex Store 检查

Vue 应用通常有 Vuex store，包含 API 配置和用户数据：

```javascript
const app = document.querySelector('#app');
if (app && app.__vue__) {
    const store = app.__vue__.$store;
    console.log('State keys:', Object.keys(store.state));
    console.log('Getters:', Object.keys(store.getters));
}
```

## 前端配置变量

SPA 常在 HTML 或 JS 中硬编码后端地址：

```javascript
// 检查 window 变量
var API = 'https://cloudapi.qiyuesuo.com';
var FILE_API = 'https://fileapi.qiyuesuo.com';
var PASSPORT = 'https://passport.qiyuesuo.com';
```

## 注意事项

- SPA 中所有路径返回 200 + 同一 HTML 是正常的(SPA fallback)，不要误报
- API 调用可能走不同的域名(如 cloud.qiyuesuo.com 前端调 cloudapi.qiyuesuo.com 后端)
- baseURL 为空字符串不代表没有后端，只是相对路径
- Performance API 只记录已完成的请求，需要页面有实际操作才会触发
