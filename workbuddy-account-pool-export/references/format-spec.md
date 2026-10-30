# 账号池导出格式 — 字段与格式参考

> 本文件为 `workbuddy-account-pool-export` skill 的格式权威定义。
> 判据来源：`workbuddy_accounts_2026-10-26.json`（2906 B，1 账号，官方桌面端导出）字节级解构。
> 旧版格式（2026-10-20 样本，无 `refresh_expires_at_ms`、`updated_at` 无时区）见 `../references/archive/2026-10-20-format/`。

## 原始样本特征（实测，2026-10-26 样本）

| 项 | 实测值 |
|----|--------|
| 文件大小 | 2906 B |
| 编码 | UTF-8，无 BOM |
| 换行 | LF，29 处 |
| 文件末尾 | **无换行符**（末字节为 `}`） |
| 缩进 | 2 空格 |
| 中文处理 | 原样（`ensure_ascii=False`），如 `"缱绻"` |
| 反序列化再序列化 | `json.dumps(doc, ensure_ascii=False, indent=2)` 可完全还原 |

## 拓扑结构

```
{
  "accounts": [
    {
      "access_token_expires_at": int,
      "credential": {
        "access_token": str,
        "domain": str,
        "expires_at_ms": int,
        "refresh_expires_at_ms": int,
        "refresh_token": str,
        "uid": str,
        "updated_at": str
      },
      "edition_type": str,
      "group_id": str,
      "id": str,
      "nickname": str,
      "note": str,
      "phone_masked": str,
      "refresh_token_expires_at": int,
      "tags": [str],
      "uid": str
    }
  ],
  "exported_at": str,
  "include_credentials": bool,
  "kind": str,
  "version": int
}
```

## 样本实例值

| 字段 | 样本值 |
|------|--------|
| `access_token_expires_at` | `1795165122` |
| `credential.expires_at_ms` | `1795165122235` |
| `credential.refresh_expires_at_ms` | `1795337922235` |
| `credential.domain` | `www.workbuddy.cn` |
| `credential.updated_at` | `2026-10-23T16:58:42+08:00` |
| `credential.uid` | `c608bf3e-cf2a-4da5-8f23-d19e7d862e5c` |
| `edition_type` | `体验版` |
| `group_id` | `""` |
| `id` | `wb-55cbb7e90870` |
| `nickname` | `缱绻` |
| `note` | `""` |
| `phone_masked` | `""` |
| `refresh_token_expires_at` | `1795337922` |
| `tags` | `[]` |
| `uid` | `c608bf3e-cf2a-4da5-8f23-d19e7d862e5c` |
| `exported_at` | `2026-10-26T10:36:05+08:00` |
| `include_credentials` | `true` |
| `kind` | `aiwork-workbuddy-pool` |
| `version` | `1` |

## 时间字段关系（样本实测）

| 关系 | 校验 |
|------|------|
| `credential.expires_at_ms == access_token_expires_at × 1000` | 1795165122235 ≈ 1795165122 × 1000 ✅（毫秒截断到秒） |
| `credential.refresh_expires_at_ms == refresh_token_expires_at × 1000` | 1795337922235 ≈ 1795337922 × 1000 ✅ |
| `exported_at` 晚于全部 token 时间戳 | 2026-10-26 > 2026-10-23 ✅ |
| `credential.updated_at` = 令牌刷新写入时刻（本地时间，秒级，**带 `+08:00` 时区偏移**） | ✅ |
| 三种时间表示法 | 秒整数 / 毫秒整数 / 带偏移 ISO 字符串 |

## 令牌类型（样本 JWT 头解构）

| 令牌 | alg | typ | scope |
|------|-----|-----|-------|
| `access_token` | RS256 | Bearer | `openid profile offline_access email` |
| `refresh_token` | HS512 | Offline | `openid acr profile basic web-origin roles offline_access email` |

两者 `iss` 均为 `https://www.workbuddy.cn/auth/realms/copilot`，`azp` 为 `console`，
`sub` 等于账号 `uid`。

## 同 realm 异域（2026-10-26 补充）

同一 Keycloak realm `copilot` 存在两个签发域：`www.workbuddy.cn`（桌面端主域）与
`copilot.tencent.com`（CodeBuddy 企业切换账号）。扁平池工具导出的账号 `domain` 为
`copilot.tencent.com`，映射入本格式时保留原域，不强制改写为 `www.workbuddy.cn`。

## 与脚本槽位定义的对应

脚本内 `TOP_SLOTS` / `ACCOUNT_SLOTS` / `CREDENTIAL_SLOTS` 三元组即本文件拓扑结构的唯一实现，
键序完全一致。变更格式时须同步修改脚本常量与本文件，两者不一致视为缺陷。
