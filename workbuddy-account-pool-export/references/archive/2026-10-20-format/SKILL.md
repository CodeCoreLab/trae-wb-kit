---
name: workbuddy-account-pool-export
description: |
  WorkBuddy 账号池导出文件（aiwork-workbuddy-pool v1）的稳定生成器。
  当用户提到"账号池导出"、"workbuddy_accounts_*.json"、"账号导出格式"、"access_token_expires_at / refresh_token / uid 字段"、
  "生成账号导出 JSON"、"按这个格式再出一份"、"补充账号到导出文件"时触发。
  核心能力：给定 access_token_expires_at、access_token、id 等字段值，输出与原格式**字节级一致**的结构
  （键序固定、2 空格缩进、LF、UTF-8 无 BOM、尾部换行）。
  可复用于：单账号生成、多账号追加、字段缺失保留占位符、对外分享前脱敏。
  不适用：凭据加解密→credential-encrypt-aesgcm；凭据位置查询→CREDENTIALS_INDEX.yaml / credential_client。
metadata:
  workbuddy:
    location: user
    agent_created: "true"
---

# workbuddy-account-pool-export — 账号池导出格式稳定生成器

## 用途

把散落的字段值（access_token、id、过期时间等）装配成 WorkBuddy 账号池导出 JSON。
输出结构、键序、缩进、换行、编码全部固定，**每次调用只传值，不传结构**。

## 触发条件

满足任一即加载本 skill：

| 触发信号 | 示例话术 |
|---------|---------|
| 指到导出文件 | "按 `workbuddy_accounts_2026-10-20.json` 的格式再生成一份" |
| 列举字段名 | "把 access_token_expires_at、access_token、id 填进去生成" |
| 追加账号 | "再补一个账号到账号池导出里" |
| 字段缺失 | "这个账号没有 refresh_token，怎么处理" |
| 分享前处理 | "把 token 脱敏后给我一份" |

## 执行入口

```bash
python <skill-dir>/scripts/build_account_pool.py --set KEY=VALUE [...] --out <path>
```

始终优先走脚本，不要手写 JSON —— 手写会破坏键序与字节一致性。

### CLI 参数

| 参数 | 作用 |
|------|------|
| `--set KEY=VALUE` | 字段赋值，可重复。支持路径语法（见下） |
| `--in <file.json>` | 从 JSON 文件读字段值（值可被 `--set` 覆盖） |
| `--out <path>` | 输出路径，默认 `./workbuddy_accounts_<今天>.json` |
| `--strict` | 必填槽位为空时直接报错退出（默认宽松，保留占位符） |
| `--mask` | 脱敏后输出（token/uid/note/掩码手机号 → `<REDACTED>`） |
| `--verify-ref <file.json>` | 与参考文件做结构对账（键路径集合一致即通过） |
| `--trailing-newline` | 末尾追加 1 个 LF（默认与参考样本一致，不加） |
| `--quiet` | 只输出 JSON 正文，不打印日志（便于管道消费） |

### 字段路径语法

| 写法 | 落点 |
|------|------|
| `id=wb-xxxx` | 账号对象顶层字段 |
| `credential.access_token=eyJ...` | 嵌套 credential 下的字段 |
| `tags[0]=prod` | 数组元素 |
| `accounts[1].id=wb-yyyy` | 第二个账号（追加场景） |

## 输出结构（固定）

### 顶层键序（不可变）

| # | 键 | 类型 | 缺省行为 |
|---|----|------|---------|
| 1 | `accounts` | array | 至少 1 个元素 |
| 2 | `exported_at` | string | 省略时取当前本地时间 ISO-8601（带时区） |
| 3 | `include_credentials` | boolean | 缺省 `true` |
| 4 | `kind` | string | 缺省 `"aiwork-workbuddy-pool"` |
| 5 | `version` | integer | 缺省 `1` |

### `accounts[]` 对象键序（不可变）

| # | 键 | 类型 | 缺失处理 |
|---|----|------|---------|
| 1 | `access_token_expires_at` | integer（epoch 秒） | 占位 `null` |
| 2 | `credential` | object | 递归占位 |
| 3 | `edition_type` | string | `__PENDING__:edition_type` |
| 4 | `group_id` | string | 空串（原样本合法空值） |
| 5 | `id` | string | `__PENDING__:id` |
| 6 | `nickname` | string | `__PENDING__:nickname` |
| 7 | `note` | string | 空串（原样本合法空值） |
| 8 | `phone_masked` | string | 空串（原样本合法空值） |
| 9 | `refresh_token_expires_at` | integer（epoch 秒） | `null`（“未知”合法表达，不计入占位告警） |
| 10 | `tags` | array | `[]`（原样本合法空值） |
| 11 | `uid` | string | `__PENDING__:uid` |

### `accounts[].credential` 键序（不可变）

| # | 键 | 类型 | 缺失处理 |
|---|----|------|---------|
| 1 | `access_token` | string | `__PENDING__:access_token` |
| 2 | `domain` | string | 缺省 `"www.workbuddy.cn"`（自动填充，不计入告警） |
| 3 | `expires_at_ms` | integer（epoch 毫秒） | 由 `access_token_expires_at × 1000` 推导；无源则 `null` |
| 4 | `refresh_token` | string | `__PENDING__:refresh_token` |
| 5 | `uid` | string | 继承账号级 `uid`；两者皆无则 `__PENDING__:uid` |
| 6 | `updated_at` | string（`YYYY-MM-DDTHH:MM:SS`） | `__PENDING__:updated_at` |

### 序列化格式（字节级约束）

| 项 | 值 |
|----|----|
| 缩进 | 2 空格 |
| 换行 | LF（`\n`） |
| 文件末尾 | **无换行符**（与参考样本一致）；需要时用 `--trailing-newline` 追加 1 个 LF |
| 编码 | UTF-8，**无 BOM** |
| 非 ASCII | 不转义（`ensure_ascii=False`，中文昵称原样输出） |
| 键序 | 完全由上述表格决定，与传入顺序无关 |

校验规则：默认 `json.dumps(doc, ensure_ascii=False, indent=2)` 即最终文件内容（2852 B 样本已字节级复现）。

## 命名规范

| 对象 | 规范 | 示例 |
|------|------|------|
| 文件名 | `workbuddy_accounts_<YYYY-MM-DD>.json` | `workbuddy_accounts_2026-10-20.json` |
| `id` 前缀 | `wb-` + 12 位十六进制 | `wb-55cbb7e90870` |
| `uid` | 小写 UUID v4（36 字符） | `c608bf3e-cf2a-4da5-8f23-d19e7d862e5c` |
| `nickname` / `edition_type` / `note` | 中文原样保留，不转码 | `缱绻` / `体验版` |
| 时间戳（秒） | `access_token_expires_at`、`refresh_token_expires_at` | `1794553176` |
| 时间戳（毫秒） | `credential.expires_at_ms` | `1794553176000` |
| 时间字符串 | `credential.updated_at`，秒级精度、无时区后缀 | `2026-09-14T15:29:55` |
| 导出时刻 | `exported_at`，带时区偏移 | `2026-10-20T08:48:57+08:00` |

## 占位符规则

| 槽位类型 | 占位符 | 理由 |
|---------|-------|------|
| string | `__PENDING__:<字段名>` | 可见、可 grep、可被后续替换 |
| integer | `null` | 保持 JSON 合法且类型可辨 |
| array | `[]` | 与"确实为空"语义一致，保留键 |
| boolean | `false` | 同上 |
| object | `{}` | 递归占位 |

**故意留空的字段（`group_id` / `note` / `phone_masked` / `tags` / `refresh_token_expires_at`）不套 `__PENDING__`**，
按原样本写空串、空数组或 `null` —— 这是"合法空值"，与"未提供的缺失槽位"语义不同，因此不计入占位告警。
`credential.domain` 自带默认值 `www.workbuddy.cn`，同样不计入告警。

## 缺失与空值处理

| 情形 | 默认（宽松）行为 | `--strict` 行为 |
|------|-----------------|----------------|
| 必填槽位空：`id` / `access_token_expires_at` / `credential.access_token` | 保留占位符，日志 warning，退出码 0 | 报错，退出码 2 |
| 非必填槽位空 | 保留占位符或空值 | 同左（strict 只拦必填） |
| 显式传空串 `--set nickname=` | **原样保留空串**（用户给的空值是有效值） | 同上 |
| `--set` 传空串给整数槽（如 `refresh_token_expires_at=`） | 视为缺失 → `null` | 必填槽位则报错 |
| `credential` 整体未传 | 生成 6 个槽位的 `credential` 对象，不省略键 | 必填 `credential.access_token` 缺失 → 报错 |
| 传 `0` 给整数槽 | 视为有效值（时间戳 0 合法） | 同上 |

**默认宽松**：字段未齐也应产出结构完整、可直接补齐的文件。仅当用户明确要求"字段不全就失败"时才加 `--strict`。

## 自动推导（减少重复录入）

| 推导 | 条件 | 结果 |
|------|------|------|
| `credential.uid` ← `uid` | 仅传其一 | 双向补全 |
| `credential.expires_at_ms` ← `access_token_expires_at` | 仅传其一 | `秒 × 1000` |
| `access_token_expires_at` ← `credential.expires_at_ms` | 仅传其一且 `≥10^11` | `毫秒 ÷ 1000` |
| `updated_at` 偏移写法 | `--set credential.updated_at=-36h` | 当前本地时间 `-36h`，输出秒级 ISO |
| `updated_at` 传 10/13 位整数 | epoch | 转本地秒级 ISO |
| `exported_at=now` | 关键字 | 当前本地时间带偏移 |

秒/毫秒自动判别：整数 `≥ 10^11` 视为毫秒（≈ 1973 年后的毫秒值），否则视为秒。

## 调用示例

### 示例 1：最小可跑（仅必填字段）

**输入**

```bash
python scripts/build_account_pool.py \
  --set id=wb-55cbb7e90870 \
  --set access_token_expires_at=1794553176 \
  --set credential.access_token=eyJhbGciOiJSUzI1NiIs... \
  --out ./workbuddy_accounts_2026-10-20.json
```

**输出**（实际字段值已截断，结构完整）

```json
{
  "accounts": [
    {
      "access_token_expires_at": 1794553176,
      "credential": {
        "access_token": "eyJhbGciOiJSUzI1NiIs...",
        "domain": "www.workbuddy.cn",
        "expires_at_ms": 1794553176000,
        "refresh_token": "__PENDING__:refresh_token",
        "uid": "__PENDING__:uid",
        "updated_at": "__PENDING__:updated_at"
      },
      "edition_type": "__PENDING__:edition_type",
      "group_id": "",
      "id": "wb-55cbb7e90870",
      "nickname": "__PENDING__:nickname",
      "note": "",
      "phone_masked": "",
      "refresh_token_expires_at": null,
      "tags": [],
      "uid": "__PENDING__:uid"
    }
  ],
  "exported_at": "2026-10-20T09:09:00+08:00",
  "include_credentials": true,
  "kind": "aiwork-workbuddy-pool",
  "version": 1
}
```

映射要点：`access_token_expires_at` → 顶层槽位 1；`expires_at_ms` 自动 `×1000`；
`domain` 自动填 `www.workbuddy.cn`。若同时传 `--set uid=<uuid>`，两处 uid 均自动补全、不再出现占位符。

### 示例 2：对齐原样本的完整字段

```bash
python scripts/build_account_pool.py \
  --set 'nickname=缱绻' \
  --set 'edition_type=体验版' \
  --set 'id=wb-55cbb7e90870' \
  --set 'uid=c608bf3e-cf2a-4da5-8f23-d19e7d862e5c' \
  --set 'access_token_expires_at=1794553176' \
  --set 'refresh_token_expires_at=1797145176' \
  --set 'credential.access_token=<JWT_ACCESS>' \
  --set 'credential.refresh_token=<JWT_REFRESH>' \
  --set 'credential.domain=www.workbuddy.cn' \
  --set 'credential.expires_at_ms=1794553176000' \
  --set 'credential.updated_at=2026-09-14T15:29:55' \
  --set 'exported_at=2026-10-20T08:48:57+08:00' \
  --out ./workbuddy_accounts_2026-10-20.json
```

`credentials.uid` 自动继承 `uid`，无需重复传入。

### 示例 3：多账号追加

```bash
python scripts/build_account_pool.py --in ./workbuddy_accounts_2026-10-20.json \
  --set 'accounts[1].id=wb-a1b2c3d4e5f6' \
  --set 'accounts[1].nickname=第二账号' \
  --set 'accounts[1].access_token_expires_at=1795000000' \
  --set 'accounts[1].credential.access_token=<JWT>' \
  --out ./workbuddy_accounts_2026-10-20.json
```

### 示例 4：结构自检（与参考文件对账）

```bash
python scripts/build_account_pool.py --in ./new.json \
  --verify-ref ./workbuddy_accounts_2026-10-20.json \
  --out /tmp/check.json
# → structure matches reference: ./workbuddy_accounts_2026-10-20.json
```

### 示例 5：分享前脱敏

```bash
python scripts/build_account_pool.py --in ./workbuddy_accounts_2026-10-20.json \
  --mask --out ./workbuddy_accounts_masked.json
```

## 验收清单

每次生成后核对：

1. 顶层键序 = `accounts, exported_at, include_credentials, kind, version`
2. `accounts[]` 11 个键按表序齐全（含占位项）
3. `credential` 6 个键按表序齐全
4. 中文未被转成 `\uXXXX`
5. `expires_at_ms == access_token_expires_at * 1000`（两者皆有值时）
6. 需要字节级校验时：`build_account_pool.py --in <参考文件> --out <副本>` → 与参考文件逐字节相等

## 边界

- **不负责**凭据加密 → `credential-encrypt-aesgcm`
- **不负责**凭据检索 → `CREDENTIALS_INDEX.yaml` + `credential_client`
- **不校验**JWT 签名与过期真实性（只做结构装配与时间格式归一）
- 生成的含 token 文件**禁止**推送到任何 Git 仓库；对外分享必须先 `--mask`
