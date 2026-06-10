# Browser Game CTF via API (Kolobok Pattern)

## Trigger
CTF题目是浏览器游戏(迷宫/贪吃蛇/收集类)，有sandbox限制的代码编辑器，但底层有REST API可用。

## Architecture
```
浏览器页面 ←→ REST API ←→ 游戏引擎(服务器)
  CodeMirror      /move_manual   物理模拟
  渲染层          /game_state    碰撞检测
  submit_kernel   /reset_game    敌人AI
```

## Step 1: 逆向API端点
```javascript
// 从页面JS中提取API
(() => {
  const s = document.querySelectorAll('script:not([src])');
  let code = '';
  s.forEach(x => { if(x.textContent.length > 100) code = x.textContent; });
  // 搜索 fetch('/ 调用
  return code.match(/fetch\(['"]\/[^'"]+/g);
})()
```

## Step 2: 提取游戏状态
```javascript
fetch('/game_state').then(r=>r.json()).then(d => {
  const s = d.state;
  // s.player_pos: [x, y]
  // s.visible: [{x, y, t}] - t: ' '=空, '#'=墙, 'S'=星, 'P'=玩家, 'R'/'F'/'E'=敌人, 'X'=出口
  // s.scales_collected / s.scales_total
  // s.escaped: 是否通关
  // s.step: 步数
  // s.view_radius: 视野半径(迷雾)
});
```

## Step 3: BFS寻路 + 敌人回避
```javascript
window._w = new Set(); // 墙壁集合
window._dead = new Set(); // 敌人危险区

function updateMap(state) {
  state.visible.forEach(c => {
    if (c.t === '#') window._w.add(c.x+','+c.y);
    if ('RFE'.includes(c.t)) {
      // 敌人本格+上下左右都标记为危险
      [[0,0],[1,0],[-1,0],[0,1],[0,-1]].forEach(([dx,dy]) => {
        window._dead.add((c.x+dx)+','+(c.y+dy));
      });
    }
  });
}

function bfs(start, goal, avoid) {
  const q = [{x:start[0], y:start[1], path:[]}];
  const vis = new Set([start[0]+','+start[1]]);
  const dirs = [{dx:1,dy:0},{dx:-1,dy:0},{dx:0,dy:1},{dx:0,dy:-1}];
  while (q.length) {
    const c = q.shift();
    if (c.x===goal.x && c.y===goal.y) return c.path;
    for (const d of dirs) {
      const nx=c.x+d.dx, ny=c.y+d.dy, k=nx+','+ny;
      if (nx>=0 && nx<20 && ny>=0 && ny<20 && !vis.has(k) && !window._w.has(k) && !avoid.has(k)) {
        vis.add(k);
        q.push({x:nx, y:ny, path:[...c.path, d]});
      }
    }
  }
  return null;
}
```

## Step 4: 自动收集循环 (30秒console超时内)
```javascript
async function autoCollect(n) {
  for (let i = 0; i < n; i++) {
    const r = await fetch('/game_state').then(r=>r.json());
    const s = r.state;
    updateMap(s);
    if (s.escaped) return 'ESCAPED!';
    if (s.scales_collected >= s.scales_total) return 'ALL DONE!';
    
    const pos = s.player_pos;
    const stars = s.visible.filter(c => c.t === 'S');
    
    if (stars.length) {
      let bestPath = null;
      for (const star of stars) {
        const p = bfs(pos, star, window._dead);
        if (p && (!bestPath || p.length < bestPath.length)) bestPath = p;
      }
      if (bestPath && bestPath.length) {
        await fetch('/move_manual', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify(bestPath[0])}).then(r=>r.json());
        continue;
      }
    }
    
    // 探索: 尝试4个方向
    const dirs = [{dx:1,dy:0},{dx:0,dy:1},{dx:-1,dy:0},{dx:0,dy:-1}];
    for (const d of dirs[(i%4)]) {
      const nx=pos[0]+d.dx, ny=pos[1]+d.dy;
      if (nx>=0&&nx<20&&ny>=0&&ny<20&&!window._w.has(nx+','+ny)&&!window._dead.has(nx+','+ny)) {
        await fetch('/move_manual', {method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify(d)}).then(r=>r.json());
        break;
      }
    }
  }
  const r = await fetch('/game_state').then(r=>r.json());
  return `scales:${r.state.scales_collected} pos:${r.state.player_pos}`;
}
autoCollect(15); // 每次调用15步(console 30s超时)
```

## Step 5: Kernel Sandbox绕过
sandbox通常禁止: `import`, `__name__`等dunder, 三元表达式, `while`, `return`, `or`
允许: `for range`, `if`, `len`, `abs`, `%`, `//`, `==`

```python
# 安全的kernel模板(避开敌人+墙壁)
def player_kernel(mapdata_ref, auxdata_ref, out_ref):
    h = len(mapdata_ref)
    w = len(mapdata_ref[0])
    cx = w // 2
    cy = h // 2
    # 检查四方向安全性
    r = mapdata_ref[cy][cx + 1] if cx + 1 < w else 35
    l = mapdata_ref[cy][cx - 1] if cx - 1 >= 0 else 35
    d = mapdata_ref[cy + 1][cx] if cy + 1 < h else 35
    u = mapdata_ref[cy - 1][cx] if cy - 1 >= 0 else 35
    # 32=空地, 35=墙, 83=星, 80=玩家, 82/70/69=敌人
    if r == 83: out_ref[0] = 2  # 右
    if l == 83: out_ref[0] = 1  # 左
    if d == 83: out_ref[0] = 4  # 下
    if u == 83: out_ref[0] = 3  # 上
```

**PITFALL: sandbox禁止的语法**
- `import` → 禁止，不能导入任何模块
- `__name__` 等dunder → 禁止
- `x if cond else y` 三元 → 禁止，用多个`if`替代
- `while` → 禁止
- `return` → 可能禁止(有些sandbox允许)
- `or` → 可能被限制，用多个`if`替代

**PITFALL: console 30秒超时**
每次`fetch('/game_state')`有网络延迟，15步约需15-25秒。超过30秒会超时丢失结果。分批调用`autoCollect(15)`。

**PITFALL: 死亡重置**
碰到敌人后进度完全重置(scales归零)。必须在BFS中加入敌人回避。敌人危险区=敌人位置±1格。

## 关联技能
- `references/web-game-ctf.md` — 客户端伪造score的简单游戏题
- `references/client-side-game-ctf.md` — 浏览器console操作游戏变量
