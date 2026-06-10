# CTF 引擎开发调试记录

## Bug 1: urllib双重编码

**现象**: SQL注入payload `'` 被编码为 `%27`,但urllib.request.urlopen又编码一次变成 `%2527`,服务端收到的是字面 `%27` 而不是 `'`。

**根因**: `urllib.parse.quote("'")` → `"%27"`,拼入URL后 `urlopen` 不会再次编码已有 `%xx` 的部分。实际测试证明urllib不会双重编码。

**修复**: 直接用urllib.request,不用subprocess调curl:

```python
def _curl(url, timeout=5):
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.read().decode(errors="ignore")
    except Exception as e:
        return str(e)
```

## Bug 2: URL缺少路径

**现象**: test_sqli测试 `http://target?id=1'` 而不是 `http://target/sqli?id=1'`,所有注入测试返回首页内容。

**根因**: 方法内直接用 `f"{url}?{param}={enc}"` 拼URL,没有用端点发现的path。

**修复**: 
1. 添加 `discover_endpoints()` 方法扫描30+常见路径
2. 所有test方法接受 `paths` 参数
3. URL构建改为 `f"{url}{path}?{param}={enc}"`

## Bug 3: SQL错误模式不全

**现象**: SQLite的 `unrecognized token` 错误不被识别为SQL注入。

**根因**: 正则只匹配 MySQL/MSSQL/Oracle/PostgreSQL 的错误格式。

**修复**: 扩展正则:
```python
r"(?i)(sql syntax|mysql|ORA-|PG_|sqlite|Unclosed|microsoft.*ODBC|error in your|SQL Error|unrecognized token|near .{1,20}: syntax error)"
```

## Bug 4: subprocess shell转义

**现象**: 用 `sh(f"curl -sk '{url}'")` 时,URL中的 `'` 会断裂shell命令。

**根因**: 单引号内不能包含单引号,`curl 'http://target/sqli?id=1''` 语法错误。

**修复**: 不用subprocess调curl,改用Python urllib直接发请求。

## Bug 5: 方法签名不一致

**现象**: `test_sqli(url, loot, paths)` 调用时报 `takes 2 positional arguments but 3 were given`。

**根因**: sed替换只改了方法体内的URL,没改函数签名 `def test_sqli(url, loot):`。

**修复**: 统一所有test方法签名为 `def test_xxx(url, loot, paths=None):`

## Bug 6: for path循环缩进

**现象**: `NameError: name 'path' is not defined` — path变量在for循环外使用。

**根因**: sed添加 `for path in paths:` 时缩进不对,内层循环没嵌套进去。

**修复**: 用Python脚本整体替换方法体,确保缩进正确:
```python
for path in paths:
    for param in params:
        resp = _curl(f"{url}{path}?{param}={enc}")
```

## Bug 7: tkinter pack/grid混用

**现象**: GUI元素错位,按钮重叠。

**根因**: 同一容器内混用 `pack()` 和 `grid()`。

**修复**: 选择一种布局管理器坚持使用。本项目全部用 `pack()`,只有按钮网格用 `grid()` 且在独立Frame内。
