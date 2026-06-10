---
name: pentagi-recovery
description: Recovery procedures and configuration tips for PentAGI Docker deployment
---
# PentAGI Recovery & Configuration

## Managing PentAGI Containers

### Container Start Order (Critical)
When restarting PentAGI after config changes or crashes, always start in order:
```
docker stop pentagi pgvector scraper pgexporter
docker compose up -d pgvector    # wait ~8s until healthy
docker compose up -d pentagi     # start separately
docker compose up -d scraper pgexporter
```

Starting all at once with `docker compose up -d` can cause pentagi to crash-loop because it connects to pgvector before pgvector is fully ready.

### Database Password Issue
If pentagi keeps crashing with:
```
Unable to open database with gorm: pq: password authentication failed for user "postgres"
```

The postgres password in pgvector may be out of sync. Reset it:
```
docker exec pgvector psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'pentagisecret123'"
```

Then restart containers in order (pgvector first, then pentagi).

### Default Postgres Password
`pentagisecret123` — set in docker-compose.yml as `PENTAGI_POSTGRES_PASSWORD`

### Verify Container Health
```
docker ps --format "table {{.Names}}\t{{.Status}}"
docker logs pentagi 2>&1 | tail -5
```

Success indicators:
- pentagi: `Up XX seconds` (not Restarting)
- pgvector: `Up XX seconds (healthy)`
- pentagi log shows: `API server listening on 0.0.0.0:8443`

## Additional Stacks (Graphiti + Langfuse)

### Neo4j + Graphiti (Knowledge Graph)
```
cd ~/pentagi
docker compose -f docker-compose-graphiti.yml up -d neo4j
# Wait ~45s until neo4j is healthy
docker compose -f docker-compose-graphiti.yml up -d graphiti
```

### Langfuse (LLM Observability)
```
cd ~/pentagi
docker compose -f docker-compose-langfuse.yml up -d
# langfuse-web available at http://127.0.0.1:4000
```

### Neo4j Password Requirement (Critical)
Neo4j requires passwords >= 8 characters. If the password in `.env` is too short, neo4j will fail silently with:
```
Invalid value for password. The minimum password length is 8 characters.
```
Fix: Edit `NEO4J_PASSWORD` in `~/pentagi/.env` to be 8+ chars, then:
```
docker rm -f neo4j
docker compose -f docker-compose-graphiti.yml up -d neo4j
```

### Full Stack Status Check
```
docker ps --format "{{.Names}}\t{{.Status}}" | sort
```
All PentAGI core containers should show "Up" or "(healthy)". Langfuse containers show "Up" (no healthcheck). Langfuse health: `curl http://127.0.0.1:4000/api/public/health` returns 401 (normal = service ready).

## Resetting Admin Password

If the admin password is lost or the default `admin` doesn't work, reset it directly in the database:

**Method 1: Using htpasswd (recommended when bcrypt module is unavailable)**
```bash
# Generate bcrypt hash with htpasswd (convert $2y$ to $2a$)
HASH=$(htpasswd -nbBC 10 admin YourNewPassword 2>&1 | sed 's/\$2y/\$2a/')

# Update database
docker exec pgvector psql -U postgres -d pentagidb -c \
  "UPDATE users SET password = '$HASH', password_change_required = false WHERE mail='admin@pentagi.com'"
```

**Method 2: Using Python bcrypt**
```python
import bcrypt
hash = bcrypt.hashpw(b'YourNewPassword', bcrypt.gensalt(rounds=10)).decode()
# Use hash value (prefix must be $2a$, not $2b$)
```

Then update the database:
```bash
docker exec pgvector psql -U postgres -d pentagidb -c \
  "UPDATE users SET password = '\$2a\$10\$YOUR_HASH_HERE', password_change_required = false WHERE mail='admin@pentagi.com'"
```

**Known Working Password**: `Pentagi@2026`

Login at https://localhost:8443 with:
- Username: `admin@pentagi.com`
- Password: `Pentagi@2026` (or your reset password)

Note: The `\$` escape is required in the shell. If it fails, use single quotes around the hash instead.

## LLM API Configuration

MiniMax (OpenAI-compatible) example in `~/.env`:
```
OPEN_AI_KEY=your-api-key
OPEN_AI_SERVER_URL=https://api.minimaxi.com/v1
LLM_SERVER_PROVIDER=openai
```

Note: The `LLM_SERVER_CONFIG_PATH` should point to a custom provider YAML file (e.g., `/opt/pentagi/conf/custom.provider.yml`) that specifies model names.

**MiniMax Models**:
- `MiniMax-Text-01` - Standard text model
- `MiniMax-M2.7` - Latest MoE model (use this for best performance)

Example custom provider config (`example.custom.provider.yml`):
```yaml
simple:
  model: "MiniMax-M2.7"
  ...
primary_agent:
  model: "MiniMax-M2.7"
  ...
```

All agent types (assistant, adviser, reflector, searcher, coder, etc.) should use `MiniMax-M2.7` as the model.

After editing .env, restart containers in order (pgvector first).

## Security Hardening

### Docker Socket Container Escape (Issue #337)

**问题**: 当 `DOCKER_INSIDE=true` 时，host Docker socket 以读写模式挂载到 agent 容器。prompt 注入可让 agent 执行 `docker run --privileged -v /:/host` 完全控制 host。

**缓解措施**:
```bash
# .env 中设置
DOCKER_INSIDE=false          # 不挂载 Docker socket（最安全）
# 或
DOCKER_INSIDE=true           # 需要 Docker API 时
DOCKER_SOCKET_READONLY=true  # 挂载为 :ro，防止写操作
```

**验证**:
```bash
# 检查 agent 容器中 socket 是否只读
docker exec pentagi-terminal-1 mount | grep docker.sock
# 应显示 "ro" 而非 "rw"
```

**注意**: `:ro` 仍允许 Docker API 查询（inspect/logs/stats），但阻止 create/start/exec 等写操作。

### .env.example 默认值

2026-06-07 后的版本：`.env.example` 中 `DOCKER_INSIDE` 默认改为 `false`，新增 `DOCKER_SOCKET_READONLY=true`。旧版本需要手动修改。

## Known Issues

### Flow Creation Fails with `gpt-5.4-nano` Error
When creating a Flow in the PentAGI web UI, you may encounter:
```
failed to create flow worker: failed to get flow provider: failed to get primary docker image: API returned unexpected status code: 400: invalid params, unknown model 'gpt-5.4-nano'
```

**Cause**: PentAGI's internal Docker worker initialization uses a hardcoded `gpt-5.4-nano` model name that is NOT configurable via the custom provider YAML. This appears to be a bug in PentAGI itself.

**Status**: No known workaround. Check https://github.com/vxcontrol/pentagi/issues for fixes or updates.
