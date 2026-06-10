# 微信公众号漏洞情报提取技术

## 背景

微信公众号(mp.weixin.qq.com)是中文漏洞情报的重要来源，尤其是:
- 360漏洞研究院 — 漏洞风险通告专辑(209+篇)
- 奇安信CERT — 漏洞预警
- 安天CERT — APT分析+漏洞通告
- 微步在线 — 威胁情报

## 提取挑战

微信文章页面是 JS 渲染的，web_extract 常返回空内容。
专辑页面(mp.appmsgalbum)更是纯 JS，浏览器也难以提取链接。

## 解决方案

### 方法1: CN-SEC 中文网镜像

cn-sec.com 聚合了大量微信安全文章，且是标准 HTML 页面可直接提取。

```python
# 搜索模式
query = 'cn-sec.com "360漏洞研究院" "CVE-XXXX-XXXXX" 关键词'
```

提取: `web_extract(urls=["https://cn-sec.com/archives/XXXXX.html"])`

### 方法2: 知乎/FreeBuf 镜像

部分文章被转载到知乎专栏或 FreeBuf:
```
zhuanlan.zhihu.com/p/XXXXX
freebuf.com/articles/XXXXX
```

### 方法3: 直接提取微信文章

有时 web_extract 对微信文章有效(取决于文章渲染方式):
```python
web_extract(urls=["https://mp.weixin.qq.com/s?__biz=XXX&mid=XXX&idx=1&sn=XXX"])
```

成功率约30%，失败时 fallback 到方法1。

### 方法4: 浏览器交互

对于必须登录才能查看的文章:
1. browser_navigate 到文章 URL
2. browser_snapshot(full=True) 获取全文
3. 缺点: 慢，且微信反爬可能拦截

## 360漏洞研究院专辑

专辑ID: 4035482305153089539
公众号: Mzk0ODM3NTU5MA==
文章数: 209+(持续更新)

### 高价值文章分类

| 标签 | 含义 | 优先级 |
|------|------|--------|
| 【在野利用】 | 已被APT/攻击者利用 | 最高 |
| 【首发复现】 | 360首次复现 | 高 |
| 【已复现】 | 漏洞已复现 | 高 |
| 【稳定复现】 | 可靠复现 | 高 |
| 【技术细节已公开】 | PoC/EXP已公开 | 高 |
| 【风险提示】 | 无PoC但有风险 | 中 |

### 专辑URL模式

```
https://mp.weixin.qq.com/mp/appmsgalbum?__biz=Mzk0ODM3NTU5MA==&action=getalbum&album_id=4035482305153089539
```

### 搜索特定CVE的文章

```
cn-sec.com "360漏洞研究院" "CVE-XXXX-XXXXX"
```

## 其他漏洞情报源

| 来源 | URL | 特点 |
|------|-----|------|
| 360安全大脑 | ti.360.com | 漏洞库+威胁情报 |
| CNVD | cnvd.org.cn | 国家漏洞库 |
| CNNVD | cnnvd.org.cn | 国家信息安全漏洞库 |
| Sploitus | sploitus.exploit.com | CVE+PoC搜索引擎 |
| VulnCheck | vulncheck.com | 商业漏洞情报 |
| NVD | nvd.nist.gov | 美国国家漏洞库 |
