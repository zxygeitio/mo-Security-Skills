---
name: task-persistence
description: 通用任务状态持久化框架 - SQLite存储、中断恢复、进度追踪
---

# Task Persistence Framework

通用任务状态持久化框架，支持中断恢复和进度追踪。

## 核心功能

### 1. TaskDB 任务数据库
基于SQLite的任务持久化，支持创建、更新、查询、恢复。

```python
import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Optional

class TaskDB:
    def __init__(self, db_path: str = "tasks.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT,
            task_type TEXT,
            target TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP
        )''')
        conn.commit()
        conn.close()
    
    def create_task(self, agent: str, task_type: str, target: str) -> int:
        """创建任务，返回task_id"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""INSERT INTO tasks (agent, task_type, target, status)
                     VALUES (?, ?, ?, 'running')""",
                  (agent, task_type, target))
        conn.commit()
        task_id = c.lastrowid
        conn.close()
        return task_id
    
    def update_task_status(self, task_id: int, status: str, result: str = None):
        """更新任务状态"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if result:
            c.execute("""UPDATE tasks SET status=?, result=?, completed_at=CURRENT_TIMESTAMP
                         WHERE id=?""", (status, result, task_id))
        else:
            c.execute("""UPDATE tasks SET status=?, completed_at=CURRENT_TIMESTAMP
                         WHERE id=?""", (status, task_id))
        conn.commit()
        conn.close()
    
    def get_pending_tasks(self, agent: str = None) -> List[Dict]:
        """获取待处理任务（用于恢复）"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        if agent:
            c.execute("""SELECT * FROM tasks WHERE agent=? AND status IN ('running','pending')
                         ORDER BY created_at""", (agent,))
        else:
            c.execute("""SELECT * FROM tasks WHERE status IN ('running','pending')
                         ORDER BY created_at""")
        
        columns = ['id','agent','task_type','target','status','result','created_at','completed_at']
        results = [dict(zip(columns, row)) for row in c.fetchall()]
        conn.close()
        return results
    
    def mark_all_running_failed(self):
        """将所有running任务标记为failed（启动恢复时调用）"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE tasks SET status='failed' WHERE status='running'")
        conn.commit()
        conn.close()
```

### 2. ResumableOrchestrator 可恢复编排器
支持中断恢复的工作流编排器。

```python
class ResumableOrchestrator:
    def __init__(self, db: TaskDB, resume: bool = False):
        self.db = db
        self.resume = resume
        
        if resume:
            # 恢复模式：将running改为pending
            self.db.mark_all_running_failed()
    
    def run_phase(self, phase_name: str, agent: str, func, *args, **kwargs):
        """运行单个phase并记录task"""
        task_id = self.db.create_task(agent, phase_name, self.target)
        try:
            result = func(*args, **kwargs)
            self.db.update_task_status(task_id, 'completed', json.dumps(result, default=str))
            return result
        except Exception as e:
            self.db.update_task_status(task_id, 'failed', str(e))
            raise
    
    def run(self):
        # 1. 检查待恢复任务
        pending = self.db.get_pending_tasks()
        if pending:
            print(f"Found {len(pending)} pending tasks, resuming...")
        
        # 2. 正常执行流程
        result = self.run_phase('phase1', 'agent1', self.phase1)
```

### 3. 使用示例

```python
#!/usr/bin/env python3
"""完整使用示例"""
import json

db = TaskDB('workflow.db')

# 模拟工作流
def phase1():
    return {'data': [1, 2, 3]}

def phase2(data):
    return {'processed': sum(data['data'])}

# 创建编排器（首次运行）
orch = ResumableOrchestrator(db, resume=False)
task_id = db.create_task('orch', 'workflow', 'target.com')

try:
    result1 = orch.run_phase('phase1', 'agent1', phase1)
    result2 = orch.run_phase('phase2', 'agent2', phase2, result1)
    db.update_task_status(task_id, 'completed', json.dumps(result2))
except Exception as e:
    db.update_task_status(task_id, 'failed', str(e))
    print(f"Workflow failed: {e}")

# 模拟中断后恢复
print("\n--- 模拟中断后恢复 ---")
orch_resume = ResumableOrchestrator(db, resume=True)
pending = db.get_pending_tasks()
print(f"Pending tasks: {len(pending)}")
```

## 适用场景
- 长时间运行的扫描任务
- 多阶段数据处理流水线
- 网络不稳定环境下的批处理
- 任何需要中断恢复的工作流

## 数据库Schema

```sql
CREATE TABLE tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent TEXT,           -- Agent名称
    task_type TEXT,       -- 任务类型
    target TEXT,         -- 目标
    status TEXT DEFAULT 'pending',  -- pending/running/completed/failed
    result TEXT,         -- JSON结果
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP
);

CREATE INDEX idx_status ON tasks(status);
CREATE INDEX idx_agent ON tasks(agent);
```

## 注意事项
- result字段存储JSON字符串，使用json.dumps/loads
- 恢复时调用mark_all_running_failed()将未完成任务标记为failed
- 长时间运行的任务建议定期保存中间状态到result
