# Ninebot SRC Actuator / Prometheus 暴露复用模式

## 触发条件

Ninebot SRC 授权范围内出现以下资产关键词时优先检查：

- `api-*`、`*-gateway`、`*-test`、`*-dev`、`*-uat`、`iot-*`、`passport`、`auth`、`console`
- 典型域名：`*.ninebot.com`、`*.ninebot.cn`、`*.willand.com`、`*.navimow.com`、`*.segwaydiscovery.com` 等授权范围

## 高价值端点

低影响验证以下路径：

```bash
curl -sk 'https://TARGET/actuator'
curl -sk 'https://TARGET/actuator/health'
curl -sk 'https://TARGET/actuator/prometheus' | head -20
curl -sk 'https://TARGET/actuator/prometheus' | grep -Eo 'application="[^"]+"|region="[^"]+"|passport_region="[^"]+"|instance_name="[^"]+"|ip_addr="[^"]+"|client_id="[^"]+"|kafka_version="[^"]+"|spring_id="[^"]+"|topic="[^"]+"|passportROpType="[^"]+"|uri="[^"]+"|exception="[^"]+"' | sort -u | head -100
```

## 已验证可提交模式

### 1. IoT 测试环境 Prometheus 暴露

示例命中：`iot-biz-console-api-test.ninebot.com`

成立证据：

- `/actuator` HTTP 200，返回 `_links.prometheus`、`health`。
- `/actuator/prometheus` HTTP 200，约 79KB 指标。
- 指标泄露：`application="iot-ble-hub"`、`region="test"`、`client_id="producer-2"`、`kafka_version="3.1.2"`、`spring_id="kafkaProducerFactory.producer-2"`、Kafka topic、业务 URI、exception 类型。

### 2. Passport 账号系统 Prometheus 暴露

示例命中：

- `api-passport-bj.ninebot.com`
- `api-passport-ore.ninebot.com`

成立证据：

- `/actuator` HTTP 200，Content-Type 为 `application/vnd.spring-boot.actuator.v3+json`，返回 `_links.prometheus`、`health`。
- `/actuator/prometheus` HTTP 200：北京区域约 500KB，海外区域约 229KB。
- 指标泄露：
  - `application="passport2"`
  - `instance_name="bas-passport2-jdk11-bj-03"`
  - `instance_name="bas-passport2-jdk11-ore-001"`
  - 内网 IP：如 `ip_addr="10.64.24.207"`、`ip_addr="10.220.0.67"`
  - 区域：`passport_region="bj"`、`passport_region="ore"`
  - 数据源标签：`localMysql`、`localRedis`
  - 账号系统业务接口标签：`/v3/user/login`、`/v3/user/info`、`/v3/code/verify`、`/v3/user/pwd/findByPhone`、`/v3/user/pwd/verify`、`/v3/user/pwd/reset`、`/v4/code/phone`、`/v4/code/email`、`/v5/user/emailCodeLogin` 等。
  - 异常类型：`PassportException`、`MethodArgumentNotValidException`、`RequestRejectedException`、`BadRequest` 等。

定级建议：中危。理由：未直接暴露 env/heapdump/RCE，但泄露认证系统内部架构、内网 IP、部署区域、账号/验证码/密码重置接口清单、异常分支与数据源标签，能显著辅助攻击面定位。

## 误报 / 不建议提交边界

- `/v3/api-docs`、`swagger-ui.html`、`doc.html` 若返回 `access token invalid` / `Full authentication is required`，不是 Swagger 文档泄露。
- 只有 `/actuator/health` 返回 `{"status":"UP"}`，且没有 Prometheus/metrics/env/mappings 等敏感指标时，不建议单独提交。
- Fleet dev 前端 JS 暴露 `baseURL` 和 `/fleet/web/*` API 路径，但未授权接口大多返回 `Token not found`；仅 `getPrivacyAgreement` 返回版本号，危害不足，不建议单独提交。
- CORS 反射或 `Access-Control-Allow-Credentials` 只有在能读取敏感数据时才报告；认证失败响应不能包装成漏洞。
- SPA fallback 必须用随机路径对照 status/size/body；多路径同前端壳不算敏感路径暴露。

## 报告要点

报告中强调“不同业务系统/不同应用名/不同区域”以避免与已提交的同类 Actuator 漏洞被判重复。例如：

- `iot-biz-console-api-test`：应用 `iot-ble-hub`，测试环境 IoT/Kafka 指标。
- `api-passport-bj/ore`：应用 `passport2`，账号系统 bj/ore 区域认证接口指标。

截图建议：

1. `/actuator` 返回 `_links.prometheus`。
2. `/actuator/prometheus | head -20` 返回指标与 `application`、`instance_name`、`ip_addr`、`region`。
3. grep 标签提取命令展示业务 URI、异常类型、数据源标签。
4. 多区域/多域名时各截一张证明影响范围。
