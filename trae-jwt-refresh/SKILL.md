---
name: trae-jwt-refresh
display_name: "Trae JWT 刷新"
display_name_en: "Trae JWT Refresh"
description: "刷新 Trae 一键导入多开软件导出的 JSON 中的 JWT access_token。当用户提到\"刷新 Trae token\"、\"续期 JWT\"、\"一键导入多开 JSON 过期\"、\"刷新 trae 账号\"时触发。支持一键导入多开 JSON、trae-accounts JSON、环境变量 TRAE_ACCOUNTS、Trae 客户端 storage.json 多种输入格式。不适用：WorkBuddy 凭据加密改造→credential-encrypt-aesgcm。"
description_zh: "刷新 Trae 一键导入多开软件导出的 JSON 中的 JWT access_token，支持一键导入多开 JSON、trae-accounts JSON、环境变量与客户端 storage.json 多种输入。"
description_en: "Refresh JWT access tokens in JSON exported by the Trae one-click multi-instance tool, supporting multi-instance JSON, trae-accounts JSON, environment variables and the client's storage.json."
version: 1.0.0
author: "马欣/码心AI"
agent_created: true
---

# Trae JWT Refresh（增强版）

Refresh Trae SOLO CN JWTs from multiple input sources with device proof, token cache, and robust error handling.

## When to Use

Trigger when user asks to:
- Refresh Trae JWT / access_token
- Renew tokens in 一键导入多开 JSON
- Extend expiry of Trae accounts
- Batch refresh multiple Trae accounts
- Read tokens from Trae desktop client storage.json
- Check Trae credit balance
- Rotate device ID for 9074 errors

## Input Formats

支持四种输入格式：

### 1. 一键导入多开 JSON
```json
{
  "accounts": [
    {"name": "账号61", "token": "...", "refreshToken": "...", "deviceId": "...", "machineId": "..."}
  ]
}
```

### 2. 导出存档 JSON（cloudIdeJwt 字段）
```json
{
  "accountCount": 10,
  "accounts": [
    {"name": "auto_13781472", "cloudIdeJwt": "Cloud-IDE-JWT eyJ...",
     "refreshToken": "...", "deviceId": "...", "userId": "1378147261747963",
     "jwtExp": 1792640046, "jwtExpHours": 284.7}
  ]
}
```

> 说明：字段名为 `cloudIdeJwt` 的导出格式自动识别；写回时**只更新原文件已存在的字段**
> （`cloudIdeJwt` / `refreshToken` / `deviceId` / `jwtExp` / `jwtExpHours`），不新增 `accessToken`/`token`
> 等导入器不认识的字段。

### 3. 环境变量
```bash
TRAE_ACCOUNTS='[{"refreshToken":"...","uid":"账号1"}]'
```

### 4. Trae 客户端 storage.json
```bash
# 自动探测路径
--storage
# 或指定路径
--storage-path "C:\Users\...\AppData\Roaming\Trae CN\User\globalStorage\storage.json"
```

Key fields per account: `refreshToken` (必需), `accessToken`/`token` (可选), `userId`/`uid`, `deviceId`, `machineId`, `icubeAuth` (加密凭据), `storagePath`.

## Execution

```bash
# 基本用法（文件）
python scripts/refresh_trae_jwt.py --threshold 5 file1.json file2.json

# 从环境变量读取
python scripts/refresh_trae_jwt.py --env

# 从 Trae 客户端读取
python scripts/refresh_trae_jwt.py --storage

# 查询额度（只读，不续期）
python scripts/refresh_trae_jwt.py file.json --credits

# 查询额度并把结果回填到源文件（remainingCredits 等已存在字段）
python scripts/refresh_trae_jwt.py file.json --credits --write-back

# 强制刷新所有（包括未过期）
python scripts/refresh_trae_jwt.py file.json --all

# 强制换设备号（9074 后）
python scripts/refresh_trae_jwt.py file.json --rotate-device

# 干跑
python scripts/refresh_trae_jwt.py file.json --dry-run
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `files` | JSON 文件路径（支持一键导入多开 / 导出存档格式） |
| `--env` | 从环境变量 `TRAE_ACCOUNTS` 读取 |
| `--storage` | 从 Trae 客户端 `storage.json` 读取（自动探测路径） |
| `--storage-path` | 指定 `storage.json` 路径 |
| `--dry-run` | 只检查状态，不刷新（不写任何文件，含设备号文件） |
| `--threshold N` | 过期前 N 天触发刷新（默认 7 天，负数报错） |
| `--credits` | 查询额度余额（只读，不续期） |
| `--write-back` | 配合 `--credits`：把额度回填到源文件已存在字段 |
| `--sync-expire` | 配合 `--credits --write-back`：回填 `creditsExpireAt`（**默认开启**，规则已实证） |
| `--no-sync-expire` | 不回填 `creditsExpireAt` |
| `--rotate-device` | 强制换新设备号（用于 9074 后） |
| `--no-cache` | 跳过缓存读取（不修改缓存文件） |
| `--all` | 刷新所有账号（包括未过期的） |

### 额度字段语义（2026-10-20 实证）

`user_current_entitlement_list` 端点实返字段与旧假定不同，正确取值如下：

| 字段 | 来源 | 可靠度 |
|------|------|--------|
| 总额度 | `usage_summary.total_amount` | 实测 |
| 已用 | `usage_summary.consumed_amount` | 实测 |
| 剩余（=导出的 `remainingCredits`） | **`total_amount - consumed_amount`** | **精确重建验证** |
| 到期（=导出的 `creditsExpireAt`） | **`min(end_time)` 于 limit 有值且未耗尽的包** | 8/10 交叉验证 + 逐字段吻合 |

**`remainingCredits` 恒等式**（已数学证明）：

```
sum(limit - used) 于非耗尽包  ≡  sum(limit) - sum(used)  ≡  total_amount - consumed_amount
```

因**耗尽包恒有 `limit == used`**，其 `(limit - used) = 0` 对求和无贡献。
故两种口径等价 —— **真正的错误是「`sum(limit)` 只加不减」**（会高估：
`auto_16244406` 上给出 6900 = 全额度，而该账号已消耗 2821.97）。

**`creditsExpireAt` 语义**：最近到期的一张「仍有余额且额度已知」的卡。已耗尽包与
`limit` 缺失的包（如「免费」）均不参与。

> 旧脚本假定的 `Result.EntitlementList` / `UsedCount` / `AvailableCount` 在该端点**不存在**，
> 故恒返 0。
>
> ⚠️ **快照时间差**：导出值为导出时刻状态，回填时用查询时刻值会与导出值差「期间新增消耗」
> （实测 13 分钟内差 22.1）。属正常，非公式错误。

### 回归测试

```bash
python scripts/test_refresh_trae_jwt.py
```

32 个用例，全离线（不打网络），覆盖 JWT 解析、格式归一化、缓存路径、错误码翻译、
额度字段语义（含恒等式证明与反证）、写回幂等与「非对象元素不崩溃」等边界。

### 已知缺陷（未修，勿误信）

- **`scripts/trae_credit_monitor.py` 沿用旧的错误解析路径**：它读
  `Result.EntitlementList` / `UsedCount` / `AvailableCount`（该端点实返
  `usage_summary` + `user_entitlement_pack_list`），且不支持 `cloudIdeJwt` 字段格式
  → 输出**恒为 0**。额度查询请用 `refresh_trae_jwt.py --credits`。

## How It Works

```
读取输入（文件/环境变量/storage.json）
    ↓
应用 token 缓存（跳过未过期的）
    ↓
解码 JWT → 提取 user_id + exp
    ↓
检查过期阈值 → 决定是否刷新
    ↓
尝试 ExchangeToken：
  ① 新版端点（带设备证明）→ 成功则返回
  ② 旧版端点（无设备证明）→ fallback
    ↓
成功 → 写回缓存 + 写回源文件
失败 → 错误码翻译 + 自动 fallback
```

### 设备证明（ECDSA P-256）

新版 `ExchangeToken` 端点要求带设备签名（`20405 Device proof required`）。脚本使用纯 Python 标准库实现 ECDSA P-256 签名，无需安装 `cryptography`。

**⚠️ 重要提醒：脚本不会自动读取本地 storage.json 的设备密钥。**

原因：`20403 Token device not match` 是服务端硬校验——token 签发时的设备密钥与本地设备必须一致。如果账号 token 是在另一台机器上通过 OAuth 获取的，脚本自动读取本地 storage.json 拿到的是**错误设备的密钥**，会导致所有跨设备账号刷新失败，且无法通过换 ClientID / 换设备号绕过。

**正确做法**：设备密钥必须**显式提供**，来源优先级：
1. 账号字段 `deviceKeyPem` / `devicePubPem` / `deviceId`
2. 环境变量 `TRAE_DEVICE_KEY_PEM` / `TRAE_DEVICE_PUB_PEM` / `TRAE_DEVICE_ID`
3. `--storage` 模式读取 Trae 客户端时，会**附带**该客户端的设备密钥（这是显式操作，不是自动探测）

如果遇到 `20403`，不要尝试自动探测本地密钥，应让用户在**签发 token 的原设备**上导出密钥，或重新走 OAuth 登录。

一键导出设备密钥：
```bash
python scripts/trae_get_token.py --export-keys
```

### Token 缓存

缓存文件：`.trae_token_cache.json`（脚本同目录；可用 `TRAE_TOKEN_CACHE` 覆盖路径）

缓存逻辑：
- 续期成功后自动写回缓存
- 读取时优先用缓存中有效期更大的 token
- 避免同一账号在多处同时刷新导致 token 互相顶失效
- `--no-cache` 只跳过**读取**并禁止写回，**不清空**缓存文件

### 9074 自动换号

`9074` = 服务端记住当前设备号（参与用户太多），不是传统限流。

脚本处理：
1. 命中 9074 → 自动生成全新设备号（15–16 位数字）
2. 持久化到 `.trae_device_ids.json`
3. 用新设备号重试一次
4. 仍失败 → 按账号冷却（早窗 12 分钟 / 平时 55 分钟）

### 产品线回退

| ClientID | PlatformCode | 说明 |
|----------|-------------|------|
| `ono9krqynydwx5` | IDE_PC | CN TRAE（默认） |
| `en1oxy7wnw8j9n` | IDE_PC / SOLO_PC | CN SOLO（fallback） |

续期时自动在两种产品线之间回退，无论 token 来自哪个客户端都能续。

## Error Handling

| Code | 含义 | 脚本处理 |
|------|------|---------|
| `20405` | 设备证明缺失 | 自动切换到新版端点 + 提示配置设备密钥 |
| `10101` | ClientID 不匹配 | 自动 fallback 到另一 ClientID |
| `20403` | 设备与 token 不匹配 | **不自动处理**；提示用户在签发原设备导出密钥或重新 OAuth |
| `20101` | refreshToken 已失效 | 提示重新提取 token |
| `9074` | 设备号被记住 | 自动换新设备号重试 |
| `10001` | 实体不存在 | ClientID 或端点错误 |

## Known Limits

- `20101` / 设备密钥不匹配：需重新走 OAuth 登录提取新 token
- **`20403 Token device not match`：token 签发设备与当前本地设备密钥不一致，无法自动修复。不要在脚本里加自动读取本地 storage.json 的逻辑，那样会把错误设备的密钥用于所有跨设备账号，导致全部 20403。正确做法是让用户在签发 token 的原设备导出密钥，或重新 OAuth。**
- 多账号同时刷新同一账号会导致 token 互相顶失效（脚本有缓存 + 冷却机制缓解）
- 解密 `storage.json` 需要 AES-128-CBC 密钥（脚本内置，无需额外依赖）

## Reference

See `references/trae_auth.md` for endpoint details, ClientID origins, and troubleshooting history.

## Related Files

- `scripts/refresh_trae_jwt.py` — 主脚本（多格式输入 + 设备证明 + 缓存 + 9074 换号 + 额度查询/回填）
- `scripts/test_refresh_trae_jwt.py` — 离线回归测试（32 用例，`python test_refresh_trae_jwt.py`）
- `scripts/trae_get_token.py` — 从 Trae 客户端提取 token + 导出设备密钥
- `scripts/trae_credit_monitor.py` — 积分监控（**⚠️ 解析路径已过时，恒返 0**，详见上节）
- `references/trae_auth.md` — 端点/ClientID/错误码/设备证明原理/排查历史

> 脚本运行时产物（均不入版本库）：`.trae_token_cache.json`（**含真实凭据**）、
> `.trae_device_ids.json`、`__pycache__/`。
