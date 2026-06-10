---
name: feishu
description: 飞书 (Feishu/Lark) REST API — 消息、文档、联系人、机器人管理
category: productivity
---

# 飞书 API Skill

## 认证
- App ID: `${FEISHU_APP_ID}` (从环境变量读取)
- App Secret: `${FEISHU_APP_SECRET}` (从环境变量读取，切勿硬编码)

> **安全警告**: App Secret 绝对不能硬编码在 SKILL.md 或脚本中。始终通过环境变量 `${FEISHU_APP_SECRET}` 引用。
> 如果要推送到 GitHub，必须确保 .env 在 .gitignore 中。
- 获取 Token: `POST https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal`
- Token 有效期 2 小时，需重新申请

## 环境变量（可选）
```bash
export FEISHU_APP_ID=your_app_id_here
export FEISHU_APP_SECRET=your_app_secret_here
```

## 常用 API

### 获取 tenant_access_token
```bash
curl -s -X POST "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal" \
  -H "Content-Type: application/json" \
  -d '{"app_id": "'$FEISHU_APP_ID'", "app_secret": "'$FEISHU_APP_SECRET'"}'
```

### 机器人信息
```bash
curl -s "https://open.feishu.cn/open-apis/bot/v3/info" \
  -H "Authorization: Bearer $TOKEN"
```

### 消息 (IM)
- 发消息: `POST https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id`
- 搜索消息: `GET https://open.feishu.cn/open-apis/im/v1/messages?container_id_type=chat&container_id=<chat_id>&page_size=20`
- 创建群: `POST https://open.feishu.cn/open-apis/im/v1/chats`
- 群列表: `GET https://open.feishu.cn/open-apis/im/v1/chats?page_size=50`

### 文档 (docx)
- 读取文档: `GET https://open.feishu.cn/open-apis/docx/v1/documents/{doc_token}`
- 文档内容块: `GET https://open.feishu.cn/open-apis/docx/v1/documents/{doc_token}/blocks`
- 创建文档: `POST https://open.feishu.cn/open-apis/docx/v1/documents`

### 云文档 (drive)
- 文件列表: `GET https://open.feishu.cn/open-apis/drive/v1/files?folder_token=<parent_token>&page_size=50`
- 下载文件: `GET https://open.feishu.cn/open-apis/drive/v1/files/{token}/download`

### 通讯录
- 用户信息: `GET https://open.feishu.cn/open-apis/contact/v3/users/{open_id}`
- 部门列表: `GET https://open.feishu.cn/open-apis/contact/v3/departments/{department_id}`

## 当前 Bot 已知信息
- Bot Name: `bot`
- Open ID: `ou_7c6fe2626d11d19a67630322b1f6e6dd`
- 所在群: `早报` (chat_id: `oc_d610b2041a4e73a148d74842dc82ab93`)

## 已知文档
- `📊 测试演示文稿` (docx): `OUI6dHGfQoxiMXxw6AXcx41pnqd`

## 长连接模式（接收消息）

飞书支持 WebSocket 长连接模式，Bot 可以主动连接飞书服务器接收消息，无需公网 Webhook。

### 安装 SDK
```bash
pip install lark-oapi --break-system-packages -U
```
版本：1.5.5+（旧版本有 bug）

### Python 完整示例（健壮版）
```python
#!/usr/bin/env python3
"""飞书长连接 Bot - 接收并回复消息"""
import lark_oapi as lark
import json, threading, time, traceback, os

APP_ID = os.environ.get("FEISHU_APP_ID", "your_app_id_here")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "your_app_secret_here")
lock = threading.Lock()
cli = None

def send_text(receive_id, text):
    """发消息（线程安全）"""
    with lock:
        cli.im.v1.message.create(
            receive_id_type="open_id",
            data=lark.im.v1.MessageCreateRequest(
                receive_id=receive_id,
                msg_type=lark.im.v1.MessageType.text,
                content=json.dumps({"text": text}),
            ),
        )

def handle_message(data):
    """处理收到的消息并回复"""
    try:
        event = data.event
        message = event.message
        sender = event.sender
        print(f"[收到消息] open_id={sender.sender_id.open_id}, type={message.message_type}")
        print(f"[消息内容] {message.content}")
        content = json.loads(message.content)
        text = content.get("text", "")
        reply = f"收到: {text[:50]}"
        send_text(sender.sender_id.open_id, reply)
        print(f"[已回复] {reply}")
    except Exception as e:
        print(f"[错误] {e}")
        traceback.print_exc()

def main():
    event_handler = (
        lark.EventDispatcherHandler.builder(APP_ID, APP_SECRET)
        .register_p2_im_message_receive_v1(handle_message)
        .build()
    )
    cli = lark.ws.Client(
        APP_ID, APP_SECRET,
        event_handler=event_handler,
        log_level=lark.LogLevel.DEBUG,  # 排查时用 DEBUG
    )
    print("[Bot] 正在连接飞书服务器...")
    cli.start()

if __name__ == "__main__":
    main()
```

### 启动 Bot（Kali 环境）
```bash
cd /root
env -i PATH=/usr/bin:/bin HOME=/root LANG=zh_CN.UTF-8 python3 /root/feishu_ws_bot.py > /tmp/feishu_bot.log 2>&1
```

注意：
- 必须用 `env -i` 清空环境变量，避免 `LC_ALL=en_US.UTF-8` 导致 locale 警告刷屏
- `LANG=zh_CN.UTF-8` 是最干净的组合
- `> /tmp/feishu_bot.log 2>&1` 把所有日志输出到文件
- 日志里的 `[Lark] [DEBUG] receive message` 是 SDK 收到消息的标志，有这条说明消息已到达 SDK
- 如果只有 `ping success` 和 `receive pong` 没有 `receive message`，说明事件订阅有问题

### 必须在开发者后台订阅事件
长连接模式需要在[飞书开发者后台](https://open.feishu.cn/app)手动订阅：
1. 进入应用 → **事件订阅**
2. 订阅方式选择 **使用长连接**
3. 点击「添加事件」→ 添加 **`im.message.receive_v1`**（接收消息）
4. 保存后重启 Bot

## 已知限制
- `tenant:tenant:readonly` 权限未开通，tenant info 查询被拒
- `im/v1/messages` 需要 `container_id_type=chat` 和 `container_id`
- 长连接模式必须先在开发者后台订阅 `im.message.receive_v1` 事件，否则收不到消息
- 消息 content 字段需要**双重 JSON 序列化**：先 `json.dumps` 再传给 API

## 调试排障：Bot 收不到消息的常见原因

### 1. Bot 有内置自动回复（容易误判）
即使不写任何代码，飞书开发者后台配置的 Bot 也会有自动回复能力。
**判断方法**：Bot 发了回复，但 `/tmp/feishu_bot.log` 里没有任何 `[Lark] [DEBUG] receive message` 日志。
这说明回复来自飞书内置 Bot 配置，不是你的 WebSocket handler。
**验证方法**：用 API 查询聊天记录：
```python
resp = requests.get(
    f"https://open.feishu.cn/open-apis/im/v1/messages?container_id_type=chat&container_id={chat_id}&page_size=10",
    headers={"Authorization": f"Bearer {token}"}
)
# 看消息列表里 Bot 的回复 sender_type=app，但 sender_id.id_type=app_id 的是你自己的代码发的
```

### 2. 群消息 vs 私聊
- 群里：Bot 默认只能收到 **@它** 的消息，普通消息不会触发
- 私聊：Bot 可以收到所有消息（需要事件订阅配置正确）

### 3. 验证 WebSocket 是否真正收到消息
```bash
# 检查日志是否有消息接收记录
grep "receive message" /tmp/feishu_bot.log

# 检查进程是否存活
ps aux | grep feishu_ws | grep -v grep

# 检查网络连接（如果断了说明连接异常）
ss -tp | grep 198.18
```

### 4. DEBUG 日志看 SDK 内部收到的内容
启动时加 `log_level=lark.LogLevel.DEBUG`，SDK 会打印：
- `receive message, message_type: event` = 收到事件（这是 SDK 层面的标志）
- `ping success` + `receive pong` = 只有心跳，没有消息事件

### 5. P2P 私聊和 Bot 对话
如果需要 Bot 接收私聊消息，先通过 API 给用户发一条消息建立 P2P 会话：
```python
resp = requests.post(
    "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=open_id",
    headers={"Authorization": f"Bearer {token}"},
    json={
        "receive_id": "ou_1dd4a1b1f9f9b7df3c86b7be0135a9c4",
        "msg_type": "text",
        "content": '{"text":"你好"}'
    }
)
# 返回的 chat_id 就是 P2P 会话 ID（如 oc_5f3b627b976b5f06e2c3b97a5c51e958）
```

### 6. 查询消息历史（排查哪些消息 Bot 真的收到了）
```python
# container_id_type 必须是 chat，不能是 p2p
resp = requests.get(
    f"https://open.feishu.cn/open-apis/im/v1/messages?container_id_type=chat&container_id={chat_id}&page_size=20",
    headers={"Authorization": f"Bearer {token}"}
)
```
注意：`container_id_type=p2p` **不支持**，会报 `invalid container_id_type: p2p`。

### 7. handler 异常被吞掉
SDK 的 EventDispatcher 在独立线程运行 callback，异常不会打印到日志。加 `try/except + traceback.print_exc()` 确保能看到错误。
