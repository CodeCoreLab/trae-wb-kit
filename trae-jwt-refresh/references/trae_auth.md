# Trae Auth Reference（增强版）

## Endpoints

### 旧版 ExchangeToken（无设备证明）
```
POST https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken
```

Request body:
```json
{
  "ClientID": "ono9krqynydwx5",
  "RefreshToken": "...",
  "ClientSecret": "-",
  "UserID": "2398496840757595"
}
```

### 新版 ExchangeToken（带设备证明）
```
POST https://api.trae.cn/trae/api/v3/oauth/ExchangeToken
```

Request body:
```json
{
  "ClientID": "ono9krqynydwx5",
  "RefreshToken": "...",
  "ClientSecret": "",
  "DeviceProof": {
    "Timestamp": 1728394800,
    "Nonce": "abc123...",
    "Signature": "MEUCIQD..."
  },
  "DeviceInfo": {
    "DeviceID": "578879150460771",
    "MachineID": "abc-def-123",
    "PlatformCode": "IDE_PC",
    "DeviceType": "PC",
    "DeviceName": "DESKTOP-XXXX",
    "ClientVersion": "1.107.1",
    "DevicePublicKey": "-----BEGIN PUBLIC KEY-----\n..."
  },
  "IDEVersion": "1.107.1",
  "req_source": 1
}
```

Response success (200):
```json
{
  "Result": {
    "Token": "eyJhbG...",
    "RefreshToken": "WKsxYY...",
    "TokenExpireAt": 1792640013093,
    "RefreshExpireAt": 1806982413093,
    "ClientID": "ono9krqynydwx5"
  }
}
```

## ClientIDs

| ClientID | PlatformCode | Product | 来源 |
|----------|-------------|---------|------|
| `ono9krqynydwx5` | IDE_PC | CN TRAE | autumnsentiment/trae2api-cn 默认值 |
| `en1oxy7wnw8j9n` | IDE_PC / SOLO_PC | CN SOLO | L0NE-6/Trae-AutoCheckin 发现（SOLO 客户端） |
| `7o2d894p7dr0o4` | - | JWT `tenant_id` | NOT 有效 OAuth ClientID（返回 404） |

**回退链顺序**：
1. `TRAE_CLIENT_ID` 环境变量（如果设置）
2. `ono9krqynydwx5` + IDE_PC（CN TRAE 默认）
3. `en1oxy7wnw8j9n` + IDE_PC（旧 token / CN SOLO 兜底）
4. `en1oxy7wnw8j9n` + SOLO_PC（CN SOLO 专用）

## Error Codes

| Code | HTTP | 含义 | 处理策略 |
|------|------|------|---------|
| `20405` | 400 | Device proof required | 自动切换到新版端点 + 提示配置设备密钥 |
| `10101` | 400 | client mismatch | 自动 fallback 到另一 ClientID |
| `20403` | 400 | 设备与 token 不匹配 | 提示检查设备密钥来源机器 |
| `20101` | 401 | refresh token invalid | Token 已失效，需重新 OAuth 登录 |
| `9074` | 400 | 参与用户太多（限流） | 自动换新设备号重试 |
| `10001` | 404 | entity not found | ClientID 或端点错误 |
| `9095` | 200 | 今日已签 | 签到接口返回，非错误 |

> `20101`（HTTP 401）与 `10101`（HTTP 400）于 2026-10-20 用无效 token / 错误 ClientID 实测复核。
> 错误体结构：`ResponseMetadata.Error.Code`（**字符串**，非 int）+ `.Message` +
> `.Data["__Message.error"]`（更细的业务说明）。

## 额度查询（`user_current_entitlement_list`）

```
POST https://api.trae.cn/trae/api/v2/pay/user_current_entitlement_list
Body: {"req_source": 1}
Headers: Authorization: Cloud-IDE-JWT <token>, x-device-id, x-device-type, x-os-version, x-app-version
```

**实返结构（2026-10-20 实测）**：

```json
{
  "usage_summary": {"total_amount": 7850, "consumed_amount": 4140.06, "consumption_ratio": 0.53},
  "user_entitlement_pack_list": [
    {"display_desc": "老用户福利", "status": 1,
     "entitlement_base_info": {"quota": {"credits_limit": 2000}, "end_time": 1792507403,
                               "product_extra": {"package_extra": {"quota": {"credits_limit": 2000}}}},
     "usage": {"credits_amount": 2000}}
  ]
}
```

| 目标字段 | 取值 | 验证 |
|---------|------|------|
| 总额度 | `usage_summary.total_amount` | 实测 |
| 已用 | `usage_summary.consumed_amount` | 实测 |
| **剩余（= 导出的 `remainingCredits`）** | **`total_amount − consumed_amount`** | **恒等式证明 + 精确重建** |
| **到期（= 导出的 `creditsExpireAt`）** | **`min(end_time)` 于 limit 有值且未耗尽的包** | 权威值逐字符吻合 + 8/10 交叉验证 |

**`remainingCredits` 恒等式**（数学等价，非巧合）：
```
sum(limit − used) 于非耗尽包  ≡  sum(limit) − sum(used)  ≡  total_amount − consumed_amount
```
因**耗尽包恒有 `limit == used`** → 其 `(limit − used) = 0` 对求和无贡献。
区别于错误实现「`sum(limit)` 只加不减」——后者在 `auto_16244406` 上给出 6900（= 全额度），
而该账号已消耗 2821.97。

**`creditsExpireAt` 语义**：最近到期的一张「仍有余额且额度已知」的卡。已耗尽包与
`limit` 缺失的包（如「免费」）不参与。

> **旧假定已证伪**：`Result.EntitlementList` / `UsedCount` / `AvailableCount` 在该端点
> **不存在**（该结构属另一接口形态）→ 沿用旧解析会**恒返 0**。
> `trae_credit_monitor.py` 仍用旧路径，故其输出不可信。
>
> **快照时间差**：导出值是导出**时刻**状态，用查询时刻值回填会与导出值差「期间新增消耗」
> （实测 36 分钟差 22.1）。属正常，非公式错误。
> **设备号位数**：实测 `deviceId` 为 **15 位**数字（旧实现按 16 位校验会误判）。

## Device Proof 原理

Trae 新版 ExchangeToken 要求带 ECDSA P-256 签名，防止机器滥用。

签名构造：
```
canonical = "POST" + "\n" + path + "\n" + client_id + "\n" + refresh_token + "\n" + timestamp + "\n" + nonce
signature = ECDSA_P256_SHA256(private_key_pem, canonical.encode())
```

设备密钥来源：
1. Trae 客户端 `storage.json` → `iCubeAuthInfo://icube-dc:<deviceId>` → 解密 → `privateKeyPEM` / `publicKeyPEM`
2. 环境变量 `TRAE_DEVICE_KEY_PEM` / `TRAE_DEVICE_PUB_PEM`
3. 账号字段 `deviceKeyPem` / `devicePubPem`

解密算法：AES-128-CBC + SHA-512 KDF（纯标准库实现，无需 cryptography）。

## 9074 限流机制

**不是传统限流** —— 服务端按设备号记住参与签到的用户。

- 空请求体 → 9074
- 缺少 `req_source: 1` → 9074
- 缺少设备头（`x-device-id` 等）→ 9074
- 同一设备号反复请求 → 越记越死

**正确处理**：
1. 命中 9074 → 换全新 16 位设备号
2. 新号按账号种子生成（`SHA256(uid + ":rotate:" + timestamp)`）
3. 持久化到 `.trae_device_ids.json`
4. 立即重试一次
5. 仍失败 → 冷却（早窗 12 分钟 / 平时 55 分钟）

## Token 缓存

缓存文件：`.trae_token_cache.json`

格式：
```json
{
  "2398496840757595": {
    "accessToken": "eyJ...",
    "refreshToken": "WKsxYY...",
    "expiresAt": 1792640013,
    "updatedAt": 1728394800
  }
}
```

- 按 `userId` 归位
- 有效期更大的 token 覆盖旧的
- 续期成功后自动写回

## JWT Payload Structure

```json
{
  "data": {
    "id": "2398496840757595",
    "source": "refresh_token",
    "source_id": "...",
    "tenant_id": "7o2d894p7dr0o4",
    "type": "user"
  },
  "exp": 1791882300,
  "iat": 1791428941
}
```

- `data.id` → UserID for ExchangeToken
- `tenant_id` → NOT the OAuth ClientID（返回 404）
- `exp` / `iat` → standard Unix timestamps

## Troubleshooting History

- 2026-10-20: 导出格式加 `tags` 字段（客户端 3.7.0→3.7.13）；`exportedAt` 增时区偏移
- 2026-10-20: **证伪**额度端点旧解析路径（`Result.EntitlementList` 不存在），确立
  `total−consumed` 与 `min(end_time) 于未耗尽包` 两条规则（详见「额度查询」节）
- 2026-10-20: 修 14 处缺陷（JWT 补位串解码、`cloudIdeJwt` 支持、非 dict 元素崩溃、
  错误码 int/str 键、缓存路径死分支、deviceId 15 位、退出码语义等）
- 2026-10-20: 新增离线回归测试 `test_refresh_trae_jwt.py`（32 用例）
- 2026-10-08: 发现 67-70 使用 CN SOLO ClientID，不是 CN TRAE
- 2026-10-08: 确认 JWT `tenant_id` 不是有效 ClientID（404）
- 2026-10-08: Account 66 refresh_token 已失效（20101），无法恢复
- 2026-10-08: 添加设备证明支持（ECDSA P-256 纯标准库实现）
- 2026-10-08: 添加 9074 自动换号机制
- 2026-10-08: 支持多种输入格式（一键导入多开 / trae-accounts / 环境变量 / storage.json）
- 2026-10-08: 添加 token 缓存避免不必要的续期
