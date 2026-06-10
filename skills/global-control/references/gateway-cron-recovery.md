# Gateway/Cron Recovery Pattern

适用场景：系统巡检或用户要求“检查系统是否完整可用”时，发现 Cron job 已启用但不会自动触发。

## 识别信号

运行：

```bash
hermes cron status
hermes gateway status
systemctl --user status hermes-gateway --no-pager || true
```

典型故障输出：

- `Gateway is not running — cron jobs will NOT fire`
- `Unit hermes-gateway.service could not be found`
- Cron list 里有 active job，但自动调度不会发生。

## 判定

这通常不是 Cron job 配置坏，而是 Gateway 调度器没有安装/启动。Cron job 本身仍可通过工具或 CLI 手动 run；自动定时依赖 gateway service。

## 安全修复流程

优先安装 user service，不要默认安装 system service：

```bash
yes y | hermes gateway install --force
sleep 3
hermes gateway status
hermes cron status
systemctl --user status hermes-gateway --no-pager | head -80
```

预期结果：

- `hermes-gateway.service` 为 `active (running)`。
- `Systemd linger is enabled`。
- `Gateway is running — cron jobs will fire automatically`。

## Pitfalls

- `hermes gateway install` 会交互询问两次；非交互修复时用 `yes y | ...`，否则命令可能只打印 prompt 后退出而没有安装 service。
- 不要把可选平台未配置、allowlist warning、第三方 OAuth 未登录当作 gateway 核心故障；只要 gateway service running 且 cron status 表示 jobs will fire，即满足本机 Cron 调度需求。
- 不要记录“Gateway 坏了”这类负面结论；只记录恢复流程。

## No-agent Cron 脚本静默规则

脚本型 `no_agent=True` Cron 的交付语义是：stdout 非空会被直接投递；stderr/非零退出通常也会形成噪声或告警。因此用于每日情报、健康检查的脚本应满足：

- 正常成功且无需提醒时 stdout 为空。
- `--quiet` 模式下，外部源 rate limit、可降级失败等非致命 warning 静默或合并。
- 真正失败才非零退出。
- 外部 API rate limit 应停止后续同类查询，避免连续刷屏。

示例模式：

```python
def warn(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[warn] {message}", file=sys.stderr)

try:
    data = request_json(url)
except urllib.error.HTTPError as e:
    if e.code in (403, 429):
        warn("provider rate-limited; skipping remaining lookups", quiet)
        break
    warn(f"provider failed: {e}", quiet)
```
