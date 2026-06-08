# Grid-Based Game CTF Patterns (Kolobok Jail, Maze, Dungeon)

> 网格游戏CTF: 20x20地图, 有墙壁/敌人/收集品, 通过API或kernel控制角色

## 架构模式

```
┌─────────────────────────────────────────┐
│ 浏览器前端 (Canvas/SVG渲染)              │
│   ↓ fetch API                           │
│ 游戏服务器 (Python/Node.js)              │
│   ├─ /game_state  → 返回可见区域         │
│   ├─ /move_manual → {dx, dy} 移动       │
│   ├─ /reset_game  → 重置                │
│   └─ /submit_kernel → 提交自动控制代码   │
│   ↓                                      │
│ 游戏引擎 (20x20网格 + 战争迷雾)          │
└─────────────────────────────────────────┘
```

## API交互模式 (比kernel更可靠)

```javascript
// 基础操作
fetch('/game_state').then(r=>r.json())  // 获取状态
fetch('/move_manual', {method:'POST', headers:{'Content-Type':'application/json'},
  body: JSON.stringify({dx:1, dy:0})})  // 移动

// 方向映射: {1,0}=右, {-1,0}=左, {0,1}=下, {0,-1}=上

// 批量移动 (Promise链)
Promise.resolve()
  .then(()=>fetch('/move_manual',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({dx:1,dy:0})}).then(r=>r.json()))
  .then(()=>fetch('/move_manual',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({dx:0,dy:-1})}).then(r=>r.json()))
```

## 地图元素识别

游戏状态中 `visible` 数组的 `t` 字段:
- `' '` (32) = 空地, 可通行
- `'#'` (35) = 墙壁, 不可通行
- `'S'` (83) = 收集品(星星/钥匙等)
- `'P'` (80) = 玩家
- `'R'`/`'F'`/`'E'` (82/70/69) = 敌人, 碰到会死
- `'X'` (88) = 出口

## 战争迷雾 (Fog of War)

- `view_radius`: 只能看到周围N格的元素
- 需要移动来探索地图
- 全局状态需要自己维护 (墙壁位置、已探索区域)

## 自动收集算法

### BFS寻路 + 敌人回避
```javascript
function bfs(start, goal, walls, dangerZones) {
  const q = [{x:start[0], y:start[1], path:[]}];
  const visited = new Set([start[0]+','+start[1]]);
  const dirs = [{dx:1,dy:0},{dx:-1,dy:0},{dx:0,dy:1},{dx:0,dy:-1}];
  while(q.length) {
    const c = q.shift();
    if(c.x===goal[0] && c.y===goal[1]) return c.path;
    for(const d of dirs) {
      const nx=c.x+d.dx, ny=c.y+d.dy, k=nx+','+ny;
      if(nx>=0 && nx<20 && ny>=0 && ny<20 && 
         !visited.has(k) && !walls.has(k) && !dangerZones.has(k)) {
        visited.add(k);
        q.push({x:nx, y:ny, path:[...c.path, d]});
      }
    }
  }
  return null; // 无路径
}
```

### 敌人安全距离
```javascript
// 敌人本体+周围1格都是危险区
function addDangerZones(enemies, danger) {
  enemies.forEach(e => {
    danger.add(e.x+','+e.y);
    danger.add((e.x+1)+','+e.y);
    danger.add((e.x-1)+','+e.y);
    danger.add(e.x+','+(e.y+1));
    danger.add(e.x+','+(e.y-1));
  });
}
```

### 探索策略
```javascript
// 没有可见星星时，探索未探索区域的边界
function findFrontier(explored, walls) {
  const frontier = [];
  const dirs = [{dx:1,dy:0},{dx:-1,dy:0},{dx:0,dy:1},{dx:0,dy:-1}];
  for(const k of explored) {
    const [x,y] = k.split(',').map(Number);
    for(const d of dirs) {
      const nx=x+d.dx, ny=y+d.dy, nk=nx+','+ny;
      if(nx>=0&&nx<20&&ny>=0&&ny<20 && !explored.has(nk) && !walls.has(nk))
        frontier.push({x:nx, y:ny});
    }
  }
  return frontier;
}
```

## Kernel Sandbox限制 (Kolobok Jail)

Python kernel在严格sandbox中运行:

**✅ 允许**: `for range`, `if/else`, `len`, `abs`, `//`, `%`, `==`, `!=`, `+`, `-`, `*`
**❌ 禁止**: `import`, `return`, `or`, `while`, 三元表达式 `x if c else y`, `__name__`等dunder, `lambda`

```python
# 有效的kernel (无return/or/while)
def player_kernel(mapdata_ref, auxdata_ref, out_ref):
    h = len(mapdata_ref)
    w = len(mapdata_ref[0])
    cx = w // 2
    cy = h // 2
    # 检查相邻格子
    r = mapdata_ref[cy][cx + 1]  # 右
    l = mapdata_ref[cy][cx - 1]  # 左
    d = mapdata_ref[cy + 1][cx]  # 下
    u = mapdata_ref[cy - 1][cx]  # 上
    # 有星星就去拿
    if r == 83:
        out_ref[0] = 2  # 右
    if l == 83:
        out_ref[0] = 1  # 左
    if d == 83:
        out_ref[0] = 4  # 下
    if u == 83:
        out_ref[0] = 3  # 上
```

## PITFALL

1. **Kernel sandbox卡死**: 当所有方向都是墙壁时，kernel会无限执行(step递增但玩家不移动)。需要检测卡住状态。
2. **敌人移动**: 敌人每回合都会移动，不能假设位置不变。每步前必须重新获取状态。
3. **死亡重置**: 碰到敌人后所有进度清零。必须把敌人回避放在最高优先级。
4. **Console 30秒超时**: 浏览器console的fetch链有30秒超时限制。每批最多15-20步操作。
5. **Session过期**: CTF平台的浏览器session经常过期。操作前先检查页面是否存活。
6. **死胡同陷阱**: 某些区域只有一个出入口，进去后敌人堵住出口就死定了。BFS应该标记单通道区域。
