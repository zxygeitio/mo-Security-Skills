# Feishu (Lark) Gateway Specifics

## Connection Mode

Feishu uses WebSocket mode (`FEISHU_CONNECTION_MODE=websocket` in `.env`).
Connection URL pattern: `wss://msg-frontier.feishu.cn/ws/v2?...`

## Common Log Patterns

### Normal message flow
```
[Feishu] Received raw message type=text message_id=om_xxx
[Feishu] Inbound dm message received: id=om_xxx type=text chat_id=oc_xxx sender=user:ou_xxx text='...' media=0
[Feishu] Flushing text batch agent:main:feishu:dm:oc_xxx (N chars)
gateway.run: inbound message: platform=feishu user=XXX chat=oc_xxx msg='...'
gateway.run: response ready: platform=feishu chat=oc_xxx time=Xs api_calls=N response=N chars
[Feishu] Sending response (N chars) to oc_xxx
```

### Keepalive timeout → reconnect
```
[Lark] [ERROR] receive message loop exit, err: sent 1011 (internal error) keepalive ping timeout; no close frame received [conn_id=XXX]
ERROR Lark: receive message loop exit, err: sent 1011 (internal error) keepalive ping timeout; no close frame received
[Lark] [INFO] disconnected to wss://msg-frontier.feishu.cn/ws/v2?...
[Lark] [INFO] trying to reconnect for the Nth time
[Lark] [INFO] connected to wss://msg-frontier.feishu.cn/ws/v2?...
```

**Impact**: Each reconnect cycle takes ~10-15s. During reconnect, messages queue up and get processed with added delay.

### Unauthorized user warning
```
WARNING gateway.run: Unauthorized user: USER_ID (DISPLAY_NAME) on feishu
```
This does NOT block message processing — it's a warning only. Messages still get processed and responses sent.

## Env Variables

| Variable | Purpose |
|----------|---------|
| `FEISHU_APP_ID` | App ID from Feishu developer console |
| `FEISHU_APP_SECRET` | App secret |
| `FEISHU_DOMAIN` | `feishu` (China) or `lark` (international) |
| `FEISHU_CONNECTION_MODE` | `websocket` (default) or `webhook` |
| `FEISHU_ALLOW_ALL_USERS` | `true` to skip user allowlist |
| `FEISHU_ALLOWED_USERS` | Comma-separated user IDs |
| `FEISHU_GROUP_POLICY` | `open` or `restricted` |

## Feishu-specific Gotchas

1. **WebSocket keepalive**: Feishu's WS server expects periodic pings. If the gateway is blocked (e.g., by a CPU-hogging process), pings are missed → timeout → reconnect.
2. **User ID format**: Feishu user IDs are `ou_xxxxx` format. Chat IDs are `oc_xxxxx`. Message IDs are `om_xxxxx`.
3. **Reconnect is automatic**: No manual intervention needed, but repeated reconnects indicate underlying network or resource issues.
4. **Gateway restart blocked from inside**: `hermes gateway restart` refuses to run from within the gateway process. Use external shell or `systemctl --user restart hermes-gateway`.
