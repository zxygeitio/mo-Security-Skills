# SRC 快速目标评估工作流

## 脚本
- `src-fast-assess.py` — 60秒目标评估(子域名+指纹+优先攻击面)
- `src-cors-batch-test.py` — 批量CORS+认证绕过测试

## 用法
```bash
# 快速评估(60秒)
/usr/bin/python3 /root/.hermes/scripts/src-fast-assess.py <domain>

# 深度评估(含nuclei)
/usr/bin/python3 /root/.hermes/scripts/src-fast-assess.py <domain> --deep

# 批量CORS测试
/usr/bin/python3 /root/.hermes/scripts/src-cors-batch-test.py <url> --auth
```

## 输出目录
```
/tmp/src_assess_<domain>/
  subs.txt          - 子域名列表
  alive.txt         - 存活Web服务
  fingerprints.txt  - 指纹识别结果
  attack_surface.md - 攻击面报告(优先级排序)
  first_hits.sh     - 推荐的第一轮测试命令
```

## 下一步：子域价值分级

快筛产出 alive.txt 后，用 practical-next 做价值分级再决定测试顺序：

```bash
/usr/bin/python3 /root/.hermes/scripts/src-practical-next.py /tmp/src_assess_<domain>/ --tiers --show-skipped
```

自动过滤 CDN/static/www/news 等低价值目标，按 P0(api/auth) > P1(ehall/oa) > P2(app/mobile) 分级。

## 已知坑点

### 1. 裸域名不带www
某些教育目标裸域名(example.edu.cn)不可达，但 www.example.edu.cn 返回200。
脚本已自动添加 www 前缀，但如果只测裸域名可能误判为不可达。

### 2. subfinder/crt.sh 超时
subfinder 在部分网络环境下需要 25-40 秒。crt.sh 可能需要 20+ 秒。
脚本已设置 subfinder timeout=25s, crt.sh timeout=20s。
如果仍然超时，脚本会降级到只使用 www+裸域名。

### 3. curl 超时设置
探测使用 --max-time 8，指纹使用 --max-time 8。
在高延迟网络(如VPN)下可能需要增加。

### 4. 并发数
HTTP探活使用 20 并发，指纹识别串行。
如果目标有 100+ 子域名，探活阶段约需 40-60 秒。
