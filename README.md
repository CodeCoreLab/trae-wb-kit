# Trae WB Kit

码心工具箱（Trae WB Kit）包含两款面向 Trae / WorkBuddy 生态的 Python 命令行工具，无第三方依赖，Python 3.8+ 即跑。

---

## 工具清单

| 工具 | 用途 | 入口 |
|------|------|------|
| **trae-jwt-refresh** | 批量刷新 Trae SOLO CN JWT access_token | `trae-jwt-refresh/scripts/refresh_trae_jwt.py` |
| **workbuddy-account-pool-export** | 生成字节级一致的 WorkBuddy 账号池导出 JSON | `workbuddy-account-pool-export/scripts/build_account_pool.py` |

---

## 快速上手

### 1. trae-jwt-refresh

支持四种输入格式：一键导入多开 JSON、导出存档 JSON（`cloudIdeJwt` 字段）、环境变量 `TRAE_ACCOUNTS`、Trae 客户端 `storage.json`。

```bash
# 批量续期（过期前 7 天触发刷新）
python trae-jwt-refresh/scripts/refresh_trae_jwt.py --threshold 5 accounts.json

# 查询额度并回填到源文件
python trae-jwt-refresh/scripts/refresh_trae_jwt.py accounts.json --credits --write-back

# 离线回归测试（32 条）
python trae-jwt-refresh/scripts/test_refresh_trae_jwt.py
```

**核心特性：**
- 内置 ECDSA P-256 设备证明 + AES-128-CBC 解密，适配新版 ExchangeToken `20405` 校验
- Token 缓存避免多实例互相顶失效；`9074` 错误自动生成新设备号重试
- `20405`/`10101`/`9074` 自动降级，`20403` 设备不匹配提示人工介入
- 错误码自动翻译 + 冷却窗口遵守（早窗 12 分钟 / 平时 55 分钟）

### 2. workbuddy-account-pool-export

把零散字段装配成结构固定的 WorkBuddy 账号池 JSON，键序、缩进、换行、编码全部固定，字节级一致。

```bash
# 生成账号池导出文件
python workbuddy-account-pool-export/scripts/build_account_pool.py \
  --set id=wb-55cbb7e90870 \
  --set credential.access_token=eyJ... \
  --set access_token_expires_at=1794553176 \
  --out ./workbuddy_accounts_2026-10-20.json

# 分享前脱敏
python workbuddy-account-pool-export/scripts/build_account_pool.py \
  --in accounts.json --mask --out accounts_masked.json
```

**核心特性：**
- 固定 2 空格缩进、LF 换行、UTF-8 无 BOM、末尾无换行，2852 B 参考样本可逐字节复现
- 顶层 5 键、`accounts` 数组 11 键、`credential` 对象 7 键，键序完全由规范决定
- 未传入槽位自动写入 `__PENDING__:字段名`，`--strict` 一键转硬校验
- 秒/毫秒 × 1000 双向换算、uid 双向补全、`--set credential.updated_at=-36h` 相对时间语法

---

## 目录结构

```
trae-wb-kit/
├── README.md
├── LICENSE
├── .gitignore
├── trae-jwt-refresh/
│   ├── SKILL.md
│   ├── references/
│   │   └── trae_auth.md
│   └── scripts/
│       ├── refresh_trae_jwt.py
│       ├── test_refresh_trae_jwt.py
│       ├── trae_credit_monitor.py
│       └── trae_get_token.py
└── workbuddy-account-pool-export/
    ├── SKILL.md
    ├── references/
    │   ├── format-spec.md
    │   └── archive/
    │       └── 2026-10-20-format/
    │           ├── SKILL.md
    │           ├── build_account_pool.py
    │           └── format-spec.md
    └── scripts/
        └── build_account_pool.py
```

---

## 运行环境

- Python 3.8+
- 纯标准库实现，无需 `pip install`

---

## 作者

马欣 / 码心AI

---

## License

MIT — 详见 [LICENSE](LICENSE) 文件。
