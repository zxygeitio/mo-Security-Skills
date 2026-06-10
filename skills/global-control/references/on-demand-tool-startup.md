# On-demand tool startup for Hermes-controlled SRC/pentest workflows

## User preference encoded

The user expects Hermes to act as the local control plane. When Burp, HexStrike, MCP bridges, Gateway, VPN, or proxy tooling is required for the current task, Hermes should start/check/fix/degrade automatically instead of waiting for the user to open services by hand.

## Boundary

Only start tools when they are needed for the task. If a dependency is not needed, record it as an external service state rather than a system failure.

Examples:
- Burp proxy down during a normal report edit: not a failure.
- Burp proxy down before a capture/replay task: start Burp and verify `127.0.0.1:8080`.
- VPN tun0 down during public recon: not a failure.
- VPN tun0 down for in-scope internal SRC assets: connect using split tunnel and verify model API connectivity.

## Primary command

```bash
/root/.hermes/scripts/hermes-ensure-tools.sh --status
/root/.hermes/scripts/hermes-ensure-tools.sh --gateway --hexstrike
/root/.hermes/scripts/hermes-ensure-tools.sh --burp
/root/.hermes/scripts/hermes-ensure-tools.sh --all
```

## Workflow

1. Decide whether the component is required for the current task.
2. If required, run the least sufficient `hermes-ensure-tools.sh` mode.
3. Verify the real backend, not just MCP registration:
   - Burp MCP process exists AND Burp proxy listens on `127.0.0.1:8080` for capture tasks.
   - HexStrike MCP bridge exists AND API listens on `127.0.0.1:8888`.
   - Gateway runs if relying on MCP/Cron/Gateway-delivered tasks.
4. If startup fails, use a narrower fallback or equivalent terminal/browser flow; do not block waiting for user intervention unless the operation is unsafe, credential-dependent, or out of scope.
5. Final conclusions must come from Hermes verification, not from MCP tool self-reports alone.

## Pitfall

Do not report “MCP is broken” just because the backing GUI/service is not running. Diagnose in layers: Hermes MCP config → MCP server process → backing service port → actual task-level request.
