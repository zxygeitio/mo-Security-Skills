# 大型技能文件维护模式 (Large Skill File Maintenance)

## 何时触发

当 `skill_manage(action='patch')` 返回 `SKILL.md content is N characters (limit: 100,000)` 时。

## 根因诊断

超限通常由以下原因累积:
1. **重复section** — 同一厂商/模式被多次添加(如契约锁出现4次)
2. **详细内联** — 厂商专有模式直接写在SKILL.md而非references/
3. **参考资料膨胀** — 参考文件列表逐session增长不清理

## 修复流程

### Step 1: 诊断重复

```bash
# 查找重复section
grep -n "^## " SKILL.md | sort -t' ' -k2 | uniq -d -f1

# 查找某关键词出现次数
grep -c "关键词" SKILL.md

# 按section大小排序
awk '/^## /{if(s)printf "%6d %s\n",n,s; s=$0; n=0; next} {n+=length($0)+1} END{if(s)printf "%6d %s\n",n,s}' SKILL.md | sort -rn | head -20
```

### Step 2: 计划清理

优先级:
1. 删除重复section(保留最完整的那份)
2. 将厂商详细模式替换为reference指针(一行)
3. 合并重复的相关Skill/附录section
4. 精简参考资料列表(删除已被reference目录覆盖的条目)

### Step 3: 执行清理

**当skill_manage因大小限制无法patch时:**

```bash
# 用Python脚本读取、清理、写回
/usr/bin/python3 << 'PYEOF'
with open("SKILL.md", "r") as f:
    content = f.read()
lines = content.split('\n')

# 识别要保留/删除的行范围
# 重建文件: 保留好的部分 + 精简的reference指针 + 新增section
new_lines = []
# ... 逻辑构建 ...

new_content = '\n'.join(new_lines)
assert len(new_content) <= 100000, f"Still over: {len(new_content)}"

# 备份并替换
import shutil
shutil.copy("SKILL.md", "SKILL.md.bak")
with open("SKILL.md", "w") as f:
    f.write(new_content)
PYEOF
```

### Step 4: 验证

```bash
# 大小检查
wc -m SKILL.md  # chars (not bytes - 中文3字节/char)

# 重复检查
grep -c "^## 契约锁\|^## Qiyuesuo" SKILL.md  # 应为1
grep -c "^## 相关Skill" SKILL.md  # 应为1

# 关键section存在
grep -c "section_name" SKILL.md

# skill_view加载测试
# 用skill_view(name='xxx')验证可加载
```

## 注意事项

- `wc -c` 计字节(中文3字节/char), `wc -m` 计字符。skill_manage限制是字符数。
- `read_file` 工具有会话去重: 同一文件在同一会话中第二次读取返回 `{status: "unchanged"}`。需要用 `terminal(cat)` 绕过。
- 备份文件保留到验证通过后再删除。
- 清理后检查所有reference文件引用仍然有效。
