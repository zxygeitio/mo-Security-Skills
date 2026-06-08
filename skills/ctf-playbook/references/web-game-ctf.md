# Web游戏类CTF题解题参考

> 贪吃蛇、Flappy Bird、2048、打砖块等需要达到目标分数/完成特定操作的Web游戏题

## 通用解题流程

### Step 1: 源码分析 (必做)

```bash
curl -s URL | grep -i 'flag\|score\|check\|win\|token\|secret\|key'
```

浏览器console:
```javascript
document.documentElement.outerHTML  // 完整HTML
// 关注: <script>中的游戏逻辑、checkWin/submitScore函数、隐藏字段
```

关键点:
- score提交方式: FormData/JSON/URL参数
- 验证端点: index.php/api/submit/check
- 是否有token/session/signature校验

### Step 2: 路径A — 直接伪造请求 (最快)

```bash
curl -X POST 'http://TARGET/index.php' -F 'score=300'
curl -X POST 'http://TARGET/api/submit' -H 'Content-Type: application/json' -d '{"score":300}'
```

如果返回flag → 提交到平台验证

### Step 3: 路径B — 浏览器console注入

```javascript
// 方法1: 直接改分数变量
score = 300;
document.getElementById('score').innerText = 300;

// 方法2: 重写游戏速度(加速)
clearInterval(gameLoop);
gameLoop = setInterval(draw, 10);  // 10ms instead of 200ms

// 方法3: 让蛇不会死(穿墙)
function collisionBorder() { return false; }

// 然后触发游戏结束:
// 移动到边界外 或 碰到自己
d = "LEFT"; snake[0] = {x: 0, y: 10*box};
```

### Step 4: 路径C — 自动寻路脚本

贪吃蛇BFS自动寻路:
```javascript
// 简化版: 始终朝食物方向移动，避免撞墙
function autoPlay() {
    let head = snake[0];
    if (head.x < food.x && d !== "LEFT") { d = "RIGHT"; }
    else if (head.x > food.x && d !== "RIGHT") { d = "LEFT"; }
    else if (head.y < food.y && d !== "UP") { d = "DOWN"; }
    else if (head.y > food.y && d !== "DOWN") { d = "UP"; }
}
// 在draw()开头调用: autoPlay();
```

### Step 5: 检查隐藏机制

```bash
# 检查其他端点
curl -s http://TARGET/flag
curl -s http://TARGET/api/flag
curl -s http://TARGET/admin
curl -s http://TARGET/.git/HEAD
curl -s http://TARGET/source
curl -s http://TARGET/view-source:

# 检查HTTP响应头
curl -sI http://TARGET/

# 检查WebSocket(某些游戏用ws通信)
```

## 常见变体

| 变体 | 特征 | 应对 |
|------|------|------|
| 纯客户端验证 | POST score直接返回flag | 路径A |
| Session校验 | 需要先开始游戏再提交 | 路径B (浏览器内操作) |
| 签名校验 | 请求中有token/sign参数 | 分析JS找签名算法 |
| 时间校验 | 检查游戏时长是否合理 | 路径B + 控制速度 |
| 需要真实游戏 | 服务端跟踪每一步 | 路径C自动脚本 |
| 隐藏页面 | flag不在游戏中 | Step 5 检查 |

## 注意事项

- 先路径A尝试，10秒内解决；失败再B，最后C
- 服务端返回的flag被平台拒绝时，可能是伪造请求不够真实
- 对比正常游戏请求和伪造请求的差异（用浏览器Network面板）
- 有些题flag藏在游戏资源文件(JS/CSS/图片)中，不是通过POST获取
