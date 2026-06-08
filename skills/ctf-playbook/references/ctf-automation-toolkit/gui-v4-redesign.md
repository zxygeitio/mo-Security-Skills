# GUI v3→v4→v4.1 重设计记录

## v3 (465行) → v4 (809行) → v4.1 (659行)

### v3 问题
- 通过ctf.sh间接调用,不直接集成engine.py
- 缺少结构化结果面板(漏洞/Flag/Loot)
- 缺少搜索/导出功能
- 缺少引擎选项控制

### v4 新增
- 直接调用engine.py,不走ctf.sh中转
- 漏洞面板(Treeview+详情)
- Flag面板(自动提取+扫描)
- Loot浏览器(文件树+预览)
- 搜索功能(输出区高亮)
- 导出功能(输出.txt/漏洞.json)
- 引擎选项(模式/超时/跳过项)
- 攻击完成回调自动刷新

### v4 → v4.1 (用户反馈驱动)
用户原话: "界面去除一些图表不要那么丑的要高级简图或者就不要。多注重后端能力"

改动:
1. 移除所有emoji图标(⚡🚩🔍🔐💥📦🛡■⏳等)
2. 改为纯ASCII大写标签(ATTACK/WEB/CRYPTO/PWN/MISC/DEFENSE)
3. 按钮文字精简(FULL ATTACK/SQLi/SSTI/Checksec/Stop)
4. 快捷栏改为小写纯文本(revshell/pty/suid/sudo/flag/nc)
5. 底部Flag输入改为"FLAG>"纯文本标签
6. 面板标签改为英文(OUTPUT/VULNS/FLAGS/LOOT)
7. 精简代码从809行→659行(去除冗余emoji处理)

### 关键教训
- tkinter在Linux下emoji渲染为方块或乱码,绝对不要用
- 用户偏好: 功能>美观, 后端能力>前端装饰
- 纯文本标签在所有平台一致渲染,不会出问题
