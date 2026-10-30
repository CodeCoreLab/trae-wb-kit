#!/usr/bin/env python3
"""Trae JWT 续期工具（增强版）

从多种来源读取 refresh_token，调用 Trae ExchangeToken 接口续期，并写回。
支持一键导入多开 JSON、trae-accounts JSON、环境变量、Trae 客户端 storage.json。

Endpoint:
    POST https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken
    POST https://api.trae.cn/trae/api/v3/oauth/ExchangeToken  (新版，需设备证明)

Body:
    {ClientID, RefreshToken, ClientSecret, UserID}  # 旧版
    {ClientID, RefreshToken, DeviceInfo, DeviceProof, IDEVersion}  # 新版

默认 ClientID 取自 autumnsentiment/trae2api-cn:
    ono9krqynydwx5 (CN TRAE / IDE_PC)

失败时自动 fallback:
    en1oxy7wnw8j9n (CN SOLO / SOLO_PC)

特性:
    - 设备证明 (ECDSA P-256，纯标准库，无需 cryptography)
    - Token 缓存（避免不必要的续期）
    - 9074 自动换设备号
    - 多格式输入（一键导入多开 JSON / trae-accounts JSON / 环境变量 / storage.json）
    - 20405 / 10101 / 20101 / 9074 / 20403 精细化错误处理
    - 积分查询（只读，不签到）
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import sys
import time
import urllib.error
import urllib.request
import logging


_SECONDS_PER_MINUTE = 60
_SECONDS_PER_DAY = 86400
_LOGGER = logging.getLogger(__name__)

# ─── 零依赖 ECDSA P-256（设备证明用） ───
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
IDE_VERSION = '1.107.1'
UA = 'Trae/%s' % IDE_VERSION


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    return x3, (lam * (x1 - x3) - y1) % P256_P


def _ec_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _ec_add(r, pt)
        pt = _ec_add(pt, pt)
        k >>= 1
    return r


def _der_sig(r, s):
    def enc(x):
        b = x.to_bytes(32, 'big').lstrip(b'\x00') or b'\x00'
        if b[0] & 128:
            b = b'\x00' + b
        return b'\x02' + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b'\x30' + bytes([len(body)]) + body


def ec_sign(private_key_pem: str, data: bytes) -> str:
    """ECDSA P-256 / SHA-256 签名，返回 base64(DER)。低 s 归一化。"""
    der = base64.b64decode(''.join(l.strip() for l in private_key_pem.splitlines() if '---' not in l))
    try:
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, _, i = _der_tlv(body, i)
        _, octs, i = _der_tlv(body, i)
        _, inner, _ = _der_tlv(octs, 0)
        j = 0
        _, _, j = _der_tlv(inner, j)
        _, d, j = _der_tlv(inner, j)
        d = int.from_bytes(d, 'big')
    except Exception:
        _, body, _ = _der_tlv(der, 0)
        i = 0
        _, _, i = _der_tlv(body, i)
        _, d, i = _der_tlv(body, i)
        d = int.from_bytes(d, 'big')
    z = int.from_bytes(hashlib.sha256(data).digest(), 'big')
    while True:
        k = int.from_bytes(os.urandom(32), 'big') % (P256_N - 1) + 1
        x1, _ = _ec_mul(k, (P256_GX, P256_GY))
        r = x1 % P256_N
        if r == 0:
            continue
        s = (pow(k, -1, P256_N) * (z + r * d)) % P256_N
        if s == 0:
            continue
        if s > P256_N // 2:
            s = P256_N - s
        return base64.b64encode(_der_sig(r, s)).decode('ascii')


def _der_tlv(buf, i):
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 128:
        n = ln & 0x7f
        ln = int.from_bytes(buf[i:i + n], 'big'); i += n
    return tag, buf[i:i + ln], i + ln


# ─── AES-128-CBC 解密（读取 Trae 客户端 storage.json 用，纯标准库） ───
SALT_A = bytes([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37])
SALT_B = bytes([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,_SECONDS_PER_MINUTE,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125])
SALT_AES = bytes(a ^ b for a, b in zip(SALT_A, SALT_B))
STORAGE_KEY = "iCubeAuthInfo://icube.cloudide"


def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 128; a = (a << 1) & 255
        if hi: a ^= 0x1B
        b >>= 1
    return p


def _build_sbox():
    inv = [0] * 256
    for i in range(1, 256):
        for j in range(1, 256):
            if _gmul(i, j) == 1:
                inv[i] = j; break
    sb = [0] * 256
    for i in range(256):
        x = inv[i] if i else 0; s = x
        for _ in range(4):
            x = ((x << 1) | (x >> 7)) & 255; s ^= x
        sb[i] = s ^ 0x63
    return sb


SBOX = _build_sbox()
INV = [0] * 256
for _i, _v in enumerate(SBOX): INV[_v] = _i
RC = [0x01,0x02,4,8,16,32,64,128,0x1B,0x36]


def _expand(key):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i-1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RC[i//4-1]
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return w


def _rk(w, r):
    ws = w[r*4:r*4+4]
    return [ws[c][k] for c in range(4) for k in range(4)]


def _addrk(s, k): return [s[i] ^ k[i] for i in range(16)]
def _isub(s): return [INV[b] for b in s]
def _ishift(s): return [s[0],s[13],s[10],s[7], s[4],s[1],s[14],s[11], s[8],s[5],s[2],s[15], s[12],s[9],s[6],s[3]]


def _imix(s):
    o = []
    for c in range(4):
        a = s[c*4:c*4+4]
        o += [_gmul(a[0],14)^_gmul(a[1],11)^_gmul(a[2],13)^_gmul(a[3],9),
              _gmul(a[0],9)^_gmul(a[1],14)^_gmul(a[2],11)^_gmul(a[3],13),
              _gmul(a[0],13)^_gmul(a[1],9)^_gmul(a[2],14)^_gmul(a[3],11),
              _gmul(a[0],11)^_gmul(a[1],13)^_gmul(a[2],9)^_gmul(a[3],14)]
    return o


def aes128_cbc_decrypt(key, iv, data):
    w = _expand(key); out = b""; prev = list(iv)
    for off in range(0, len(data), 16):
        blk = list(data[off:off+16]); s = _addrk(blk, _rk(w, 10))
        for r in range(9, 0, -1):
            s = _ishift(s); s = _isub(s); s = _addrk(s, _rk(w, r)); s = _imix(s)
        s = _ishift(s); s = _isub(s); s = _addrk(s, _rk(w, 0))
        out += bytes(a ^ b for a, b in zip(s, prev)); prev = blk
    return out


def decrypt_storage_value(b64):
    buf = base64.b64decode(b64)
    rb, enc = buf[6:38], buf[38:]
    h = hashlib.sha512(rb).digest()
    fh = hashlib.sha512(h + SALT_AES).digest()
    pt = aes128_cbc_decrypt(fh[:16], fh[16:32], enc)[64:]
    pad = pt[-1] if pt else 0
    if 1 <= pad <= 16:
        return pt[:-pad]
    return pt.rstrip(b"\x00").rstrip()


def find_storage_json():
    home = os.path.expanduser("~")
    names = ("Trae CN", "TRAE SOLO CN", "TRAE SOLO", "Trae")
    sub = ("User", "globalStorage", "storage.json")
    appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    for n in names:
        p = os.path.join(appdata, n, *sub)
        if os.path.isfile(p): return p
    lib = os.path.join(home, "Library", "Application Support")
    for n in names:
        p = os.path.join(lib, n, *sub)
        if os.path.isfile(p): return p
    for base in (home, os.path.join(home, ".config")):
        for n in (".trae-cn", ".trae", "Trae CN", "TRAE SOLO CN"):
            p = os.path.join(base, n, *sub)
            if os.path.isfile(p): return p


def extract_storage_tokens(storage_path=None):
    """从 Trae 客户端 storage.json 提取 refreshToken / accessToken / uid。"""
    path = storage_path or os.environ.get("TRAE_STORAGE_PATH", "") or find_storage_json()
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            storage = json.load(f)
    except Exception:
        return None
    enc = (storage.get(STORAGE_KEY) or "").strip()
    if not enc:
        return None
    try:
        txt = decrypt_storage_value(enc).decode("utf-8", "replace")
    except Exception:
        return None
    rt = re.search(r'"refreshToken"\s*:\s*"([^"]+)"', txt)
    at = re.search(r'"token"\s*:\s*"([^"]+)"', txt)
    uid = re.search(r'"userId"\s*:\s*"(\d+)"', txt)
    nick = re.search(r'"username"\s*:\s*"([^"]*)"', txt)
    return {"refreshToken": rt.group(1) if rt else None,
            "accessToken": at.group(1) if at else None,
            "uid": uid.group(1) if uid else None,
            "nickname": nick.group(1) if nick else None}


def extract_device_keys(storage_path=None):
    """从 Trae 客户端 storage.json 提取设备 ECDSA 密钥对 + deviceId + machineId。"""
    path = storage_path or os.environ.get("TRAE_STORAGE_PATH", "") or find_storage_json()
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            storage = json.load(f)
    except Exception:
        return None
    did = ""
    for k in storage:
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            d = k.split(":")[-1]
            if d.isdigit():
                did = d
                break
    if not did:
        return None
    enc = storage.get("iCubeAuthInfo://icube-dc:%s" % did)
    if not enc:
        return None
    try:
        dev = json.loads(decrypt_storage_value(enc.strip()).decode("utf-8", "replace"))
    except Exception:
        return None
    priv = (dev.get("privateKeyPEM") or "").strip()
    pub = (dev.get("publicKeyPEM") or "").strip()
    if not (priv and pub):
        return None
    return {"deviceId": did, "privateKeyPem": priv, "publicKeyPem": pub,
            "machineId": (storage.get("telemetry.machineId") or "").strip()}


# ─── 网络层（强制直连，不走系统代理） ───
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post(url, headers, body='{}', timeout=30):
    req = urllib.request.Request(url, data=body.encode('utf-8') if isinstance(body, str) else body,
                                 headers=headers, method='POST')
    try:
        with _opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)


# ─── 常量 ───
EXCHANGE_URL_OLD = "https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken"
EXCHANGE_URL_NEW = "https://api.trae.cn/trae/api/v3/oauth/ExchangeToken"
DEFAULT_CLIENT_ID = "ono9krqynydwx5"    # CN TRAE / IDE_PC
FALLBACK_CLIENT_ID = "en1oxy7wnw8j9n"   # CN SOLO / SOLO_PC
REQ_SOURCE = 1
HEADERS_OLD = {"Content-Type": "application/json", "Accept": "application/json"}
HEADERS_NEW = {"Content-Type": "application/json", "x-cloudide-token": ""}


# ─── Token 缓存 ───
def _cache_path():
    env = os.environ.get("TRAE_TOKEN_CACHE", "").strip()
    if env:
        d = os.path.dirname(env)
        if d and not os.path.isdir(d):
            try:
                os.makedirs(d, exist_ok=True)
            except OSError as e:
                print("[缓存] 目录创建失败，回退默认路径: %s" % e)
                env = ""
        if env:
            return env
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".trae_token_cache.json")


def load_cache():
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


_CACHE_WRITE_ENABLED = True


def save_cache(cache):
    if not _CACHE_WRITE_ENABLED:
        return
    try:
        path = _cache_path()
        d = os.path.dirname(path)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except Exception as e:
        print("[缓存] 写入失败:", e)


def _jwt_uid(token):
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return str(json.loads(base64.urlsafe_b64decode(p)).get("data", {}).get("id", ""))
    except Exception:
        return ""


def _jwt_exp(token):
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return int(json.loads(base64.urlsafe_b64decode(p)).get("exp", 0))
    except Exception:
        return 0


def apply_cache(account, cache=None):
    """如果缓存里有更有效的 token，覆盖 account。返回是否命中。"""
    cache = load_cache() if cache is None else cache
    uid = _jwt_uid(account.get("accessToken", "")) or account.get("userId", "")
    if not uid:
        return False
    rec = cache.get(uid) or cache.get(account.get("name", "")) or cache.get(account.get("userId", ""))
    if not rec or not rec.get("accessToken"):
        return False
    # 缓存里的 token 有效期 >= 当前 token 才覆盖
    cache_exp = int(rec.get("expiresAt") or 0)
    curr_exp = _jwt_exp(account.get("accessToken", ""))
    if cache_exp >= curr_exp and cache_exp > time.time():
        account["accessToken"] = rec["accessToken"]
        if rec.get("refreshToken"):
            account["refreshToken"] = rec["refreshToken"]
        return True
    return False


def put_cache(account, cache):
    """续期成功后写回缓存。"""
    uid = _jwt_uid(account.get("accessToken", "")) or account.get("userId", "") or account.get("name", "")
    if not uid or not account.get("accessToken"):
        return
    cache[uid] = {"accessToken": account["accessToken"],
                  "refreshToken": account.get("refreshToken", ""),
                  "expiresAt": _jwt_exp(account["accessToken"]),
                  "updatedAt": int(time.time())}
    save_cache(cache)


# ─── 设备号管理（9074 换号） ───
_DEVICE_ID_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".trae_device_ids.json")


def _stable_device_id(seed: str) -> str:
    h = hashlib.sha256(seed.encode("utf-8")).digest()
    return str(int.from_bytes(h[:8], "big") % (10**16 - 10**15) + 10**15)


def load_device_ids():
    try:
        with open(_DEVICE_ID_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_device_ids(ids):
    try:
        tmp = _DEVICE_ID_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(ids, f, ensure_ascii=False, indent=2)
        os.replace(tmp, _DEVICE_ID_FILE)
    except Exception as e:
        print("[设备号] 写入失败:", e)


def rotate_device_id(account):
    key = _acct_key(account)
    ids = load_device_ids()
    new_id = _stable_device_id("%s:rotate:%d" % (key, int(time.time())))
    ids[key] = new_id
    save_device_ids(ids)
    account["deviceId"] = new_id
    return new_id


def device_id_for(account):
    """取账号的 15 位设备号；缺失时按账号键派生稳定值。"""
    manual = str(account.get("deviceId", "")).strip()
    if manual.isdigit() and 15 <= len(manual) <= 16:
        return manual
    key = _acct_key(account)
    ids = load_device_ids()
    if key in ids:
        return ids[key]
    new_id = _stable_device_id(key)
    ids[key] = new_id
    save_device_ids(ids)
    return new_id


def _acct_key(account):
    return (str(account.get("userId") or account.get("uid") or "").strip()
            or str(account.get("name") or "").strip()
            or "default")


# ─── 设备证明 ───
def _norm_pem(v: str) -> str:
    v = (v or "").strip()
    if "\\n" in v and "\n" not in v:
        v = v.replace("\\n", "\n")
    return v


def device_keys_for(account):
    """取设备证明材料：账号字段 > 环境变量。

    注意：不自动读取本地 storage.json，避免跨设备 token 被 20403 拒绝。
    如需设备证明，请显式提供：
      - 账号字段 deviceKeyPem / devicePubPem / deviceId
      - 或环境变量 TRAE_DEVICE_KEY_PEM / TRAE_DEVICE_PUB_PEM / TRAE_DEVICE_ID
    """
    priv = _norm_pem(str(account.get("deviceKeyPem") or account.get("privateKeyPem") or ""
                         or os.environ.get("TRAE_DEVICE_KEY_PEM", "")))
    pub = _norm_pem(str(account.get("devicePubPem") or account.get("publicKeyPem") or ""
                        or os.environ.get("TRAE_DEVICE_PUB_PEM", "")))
    did = str(account.get("deviceId", "")).strip() or os.environ.get("TRAE_DEVICE_ID", "").strip()
    mid = str(account.get("machineId", "")).strip() or os.environ.get("TRAE_MACHINE_ID", "").strip()
    if priv and pub and did:
        return {"deviceId": did, "privateKeyPem": priv, "publicKeyPem": pub, "machineId": mid}


def make_device_proof(path: str, refresh_token: str, keys: dict, client_id: str, platform_code: str = "IDE_PC"):
    ts = int(time.time())
    nonce = os.urandom(16).hex()
    canonical = "\n".join(["POST", path, client_id, refresh_token, str(ts), nonce])
    sig = ec_sign(keys["privateKeyPem"], canonical.encode("utf-8"))
    proof = {"Timestamp": ts, "Nonce": nonce, "Signature": sig}
    info = {"DeviceID": keys.get("deviceId", ""), "MachineID": keys.get("machineId", ""),
            "PlatformCode": platform_code, "DeviceType": "PC",
            "DeviceName": os.environ.get("TRAE_DEVICE_NAME", "").strip() or platform.node() or "PC",
            "DeviceModel": os.environ.get("TRAE_DEVICE_MODEL", "").strip(),
            "ClientVersion": IDE_VERSION, "DevicePublicKey": keys["publicKeyPem"],
            "DeviceBrand": os.environ.get("TRAE_DEVICE_BRAND", "").strip(),
            "DeviceCPU": "", "OSInfo": platform.system() or "Windows",
            "OSVersion": platform.release() or ""}
    return proof, info


# ─── 错误码翻译 ───
def _explain_refresh_err(text: str) -> str:
    try:
        parsed = json.loads(text)
        err = (parsed.get("ResponseMetadata") or {}).get("Error") or {}
        code = str(err.get("Code") or "")
        dirty = ((err.get("Data") or {}).get("__Message.error")) or err.get("Message") or ""
    except Exception:
        return text[:200]
    hints = {"20101": "refreshToken 已失效/被轮换，需重新提取",
             "10101": "refreshToken 与客户端不匹配（产品线/设备不匹配），请重新提取",
             "20405": "服务端要求设备证明：配置 TRAE_DEVICE_KEY_PEM / TRAE_DEVICE_PUB_PEM / TRAE_DEVICE_ID",
             "20403": "设备与 token 不匹配：确认设备密钥来自签发该 token 的同一台机器",
             "9074":  "设备号被服务端记住（参与用户太多），已自动换号重试",
             "10001": "实体不存在（ClientID 或端点错误）"}
    if not code:
        return dirty or text[:200]
    hint = hints.get(code, "")
    return "code=%s %s%s" % (code, dirty, ("（%s）" % hint) if hint else "")


# ─── 核心续期逻辑 ───
def _build_exchange_body(client_id: str, refresh_token: str, user_id: str = "", keys: dict = None, platform_code: str = "IDE_PC"):
    if keys and keys.get("privateKeyPem") and keys.get("publicKeyPem"):
        proof, info = make_device_proof("/trae/api/v3/oauth/ExchangeToken", refresh_token, keys, client_id, platform_code)
        return json.dumps({"ClientID": client_id, "ClientSecret": "", "RefreshToken": refresh_token,
                           "DeviceInfo": info, "DeviceProof": proof, "IDEVersion": IDE_VERSION})
    return json.dumps({"ClientID": client_id, "RefreshToken": refresh_token,
                       "ClientSecret": "-", "UserID": user_id})


def refresh_account(account: dict, cache: dict = None) -> tuple:
    """刷新单个账号。成功后直接修改 account dict。返回 (ok, msg)。"""
    token = account.get("accessToken") or account.get("token", "")
    refresh_token = account.get("refreshToken", "")
    if not refresh_token:
        return False, "缺少 refreshToken"

    # 提取 user_id
    user_id = ""
    if token:
        try:
            p = token.split(".")[1]
            p += "=" * (-len(p) % 4)
            user_id = str(json.loads(base64.urlsafe_b64decode(p)).get("data", {}).get("id", ""))
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)

    # 设备证明材料
    keys = device_keys_for(account)
    use_device_proof = bool(keys and keys.get("privateKeyPem") and keys.get("publicKeyPem"))

    # 产品线组合链：(ClientID, PlatformCode)
    combos = [(DEFAULT_CLIENT_ID, "IDE_PC")]
    if FALLBACK_CLIENT_ID not in [c for c, _ in combos]:
        combos.append((FALLBACK_CLIENT_ID, "IDE_PC"))
    # 用户环境变量可覆盖 ClientID
    env_cid = os.environ.get("TRAE_CLIENT_ID", "").strip()
    if env_cid and env_cid not in [c for c, _ in combos]:
        combos.insert(0, (env_cid, "IDE_PC"))

    _unused_bind = None  # noqa: F841 —— 原变量 last_status
    last_text = ""
    for cid, pcode in combos:
        body = _build_exchange_body(cid, refresh_token, user_id, keys if use_device_proof else None, pcode)
        url = EXCHANGE_URL_NEW if use_device_proof else EXCHANGE_URL_OLD
        headers = HEADERS_NEW if use_device_proof else HEADERS_OLD
        # 新增：请求体带 req_source:1（与桌面端一致，避免 9074）
        if use_device_proof:
            body_obj = json.loads(body)
            body_obj["req_source"] = REQ_SOURCE
            body = json.dumps(body_obj)
        try:
            status, text = _post(url, headers, body, timeout=20)
        except Exception as e:
            last_status, last_text = -1, str(e)
            continue
        last_status, last_text = status, text
        if status < 400:
            try:
                res = json.loads(text).get("Result") or json.loads(text).get("result") or {}
                new_token = res.get("Token") or res.get("token", "")
                new_refresh = res.get("RefreshToken") or res.get("refreshToken", "")
                if new_token and new_refresh:
                    account["accessToken"] = new_token
                    account["token"] = new_token
                    account["refreshToken"] = new_refresh
                    if account.get("userId") and not user_id:
                        try:
                            account["userId"] = _jwt_uid(new_token)
                        except Exception as _exc:
                            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
                    return True, "OK (ClientID=%s, Platform=%s)" % (cid, pcode)
            except Exception as _exc:
                _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
            return False, "解析响应失败: %s" % text[:200]
        # 错误处理
        err_code = ""
        try:
            err_code = json.loads(text).get("ResponseMetadata", {}).get("Error", {}).get("Code", "")
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
        # 10101 / 20403 → 换下一组 ClientID×PlatformCode
        if err_code in ("10101", "20403") and (cid, pcode) != combos[-1]:
            continue
        # 9074 → 换设备号后重试（同 ClientID 下换 deviceId）
        if err_code == "9074" and use_device_proof:
            rotate_device_id(account)
            # 重新生成 keys 里的 deviceId
            if keys:
                keys["deviceId"] = account["deviceId"]
            # 立即用新设备号重试一次
            body = _build_exchange_body(cid, refresh_token, user_id, keys, pcode)
            body_obj = json.loads(body)
            body_obj["req_source"] = REQ_SOURCE
            body = json.dumps(body_obj)
            try:
                status2, text2 = _post(url, headers, body, timeout=20)
            except Exception:
                continue
            if status2 < 400:
                try:
                    res = json.loads(text2).get("Result") or json.loads(text2).get("result") or {}
                    nt = res.get("Token") or res.get("token", "")
                    nr = res.get("RefreshToken") or res.get("refreshToken", "")
                    if nt and nr:
                        account["accessToken"] = nt
                        account["token"] = nt
                        account["refreshToken"] = nr
                        return True, "OK (after 9074 rotate, ClientID=%s)" % cid
                except Exception as _exc:
                    _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
            # 仍失败则继续 fallback
            continue
        # 20101 / 20405 等直接返回
        if err_code in ("20101", "20405"):
            return False, _explain_refresh_err(text)
        # 其他错误也直接返回
        if err_code:
            return False, _explain_refresh_err(text)
        return False, "HTTP %s: %s" % (status, text[:200])
    return False, _explain_refresh_err(last_text)


# ─── 账号读取（多格式） ───
def normalize_account(d: dict, name: str = "") -> dict:
    """统一各种输入格式为内部结构。非 dict 输入按空记录处理。"""
    if not isinstance(d, dict):
        d = {}
    _ci = d.get("cloudIdeJwt") or d.get("Cloud-IDE-JWT") or ""
    if isinstance(_ci, str) and _ci.startswith("Cloud-IDE-JWT "):
        _ci = _ci[len("Cloud-IDE-JWT "):]
    if not isinstance(_ci, str):
        _ci = ""
    at = d.get("accessToken") or d.get("token") or _ci
    if not isinstance(at, str):
        at = ""
    acc = {"name": name or d.get("name") or d.get("nickname") or "",
           "accessToken": at,
           "refreshToken": d.get("refreshToken") or d.get("refresh_token", ""),
           "userId": str(d.get("userId") or d.get("uid") or d.get("user_id", "")),
           "deviceId": d.get("deviceId") or d.get("device_id", ""),
           "machineId": d.get("machineId") or d.get("machine_id", ""),
           "icubeAuth": d.get("icubeAuth", ""),
           "storagePath": d.get("storagePath", ""),
           "enabled": d.get("enabled", True)}
    # 如果有 icubeAuth，自动解密取 token
    if acc["icubeAuth"] and not acc["refreshToken"]:
        try:
            txt = decrypt_storage_value(acc["icubeAuth"].strip()).decode("utf-8", "replace")
            rt = re.search(r'"refreshToken"\s*:\s*"([^"]+)"', txt)
            at = re.search(r'"token"\s*:\s*"([^"]+)"', txt)
            uid = re.search(r'"userId"\s*:\s*"(\d+)"', txt)
            if rt:
                acc["refreshToken"] = rt.group(1)
            if at:
                acc["accessToken"] = at.group(1)
            if uid:
                acc["userId"] = uid.group(1)
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
    # 如果有 storagePath，读取
    if acc["storagePath"] and not acc["refreshToken"]:
        r = extract_storage_tokens(acc["storagePath"])
        if r:
            acc["refreshToken"] = acc["refreshToken"] or r.get("refreshToken", "")
            acc["accessToken"] = acc["accessToken"] or r.get("accessToken", "")
            acc["userId"] = acc["userId"] or r.get("uid", "")
    # 从 accessToken 提取 userId
    if not acc["userId"] and acc["accessToken"]:
        try:
            p = acc["accessToken"].split(".")[1]
            p += "=" * (-len(p) % 4)
            acc["userId"] = str(json.loads(base64.urlsafe_b64decode(p)).get("data", {}).get("id", ""))
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
    return acc


def read_accounts_from_file(path: str) -> list:
    """读取 JSON 文件，支持一键导入多开格式和 trae-accounts 格式。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print("[ERROR] 读取 %s 失败: %s" % (path, e))
        return []
    accounts = []
    # 格式1: {"accounts": [...]} 一键导入多开
    if isinstance(data, dict) and "accounts" in data:
        for i, a in enumerate(data["accounts"]):
            if not isinstance(a, dict):
                print("[WARN] %s accounts[%d] 非对象，已跳过" % (path, i))
                continue
            acc = normalize_account(a, a.get("name", "账号%d" % (i + 1)))
            if acc.get("refreshToken"):
                accounts.append(acc)
    elif isinstance(data, list):
        for i, a in enumerate(data):
            if not isinstance(a, dict):
                print("[WARN] %s [%d] 非对象，已跳过" % (path, i))
                continue
            acc = normalize_account(a, a.get("name") or a.get("userId", "账号%d" % (i + 1)))
            if acc.get("refreshToken"):
                accounts.append(acc)
    elif isinstance(data, dict):
        acc = normalize_account(data, data.get("name", "单账号"))
        if acc.get("refreshToken"):
            accounts.append(acc)
    else:
        print("[WARN] %s 顶层非对象/数组，已跳过" % path)
    return accounts


def read_accounts_from_env() -> list:
    """从环境变量 TRAE_ACCOUNTS 读取（JSON 数组字符串）。"""
    raw = os.environ.get("TRAE_ACCOUNTS", "").strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if not isinstance(data, list):
            return []
        accounts = []
        for i, a in enumerate(data):
            if not isinstance(a, dict):
                continue
            acc = normalize_account(a, a.get("name") or a.get("uid", "env账号%d" % (i + 1)))
            if acc.get("refreshToken"):
                accounts.append(acc)
        return accounts
    except json.JSONDecodeError as e:
        print("[WARN] TRAE_ACCOUNTS 非合法 JSON: %s" % e)
        return []


def read_accounts_from_storage(path=None) -> list:
    """从 Trae 客户端 storage.json 读取所有登录态。"""
    storage_path = path or os.environ.get("TRAE_STORAGE_PATH", "") or find_storage_json()
    if not storage_path:
        return []
    # 提取主凭据
    r = extract_storage_tokens(storage_path)
    if not r or not r.get("refreshToken"):
        return []
    acc = {"name": r.get("nickname") or r.get("uid") or "storage主账号",
           "accessToken": r.get("accessToken", ""),
           "refreshToken": r.get("refreshToken", ""),
           "userId": r.get("uid", ""),
           "storagePath": storage_path}
    # 尝试提取设备密钥
    dk = extract_device_keys(storage_path)
    if dk:
        acc["deviceId"] = dk.get("deviceId", "")
        acc["machineId"] = dk.get("machineId", "")
        acc["deviceKeyPem"] = dk.get("privateKeyPem", "")
        acc["devicePubPem"] = dk.get("publicKeyPem", "")
    # 扫描多账号目录
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    account_dir = os.path.join(appdata, "Trae CN", "User")
    accounts = [acc]
    if os.path.isdir(account_dir):
        for entry in os.listdir(account_dir):
            if entry in ("globalStorage", "workspaceStorage") or entry.startswith("."):
                continue
            sp = os.path.join(account_dir, entry, "globalStorage", "storage.json")
            if not os.path.isfile(sp):
                continue
            try:
                r2 = extract_storage_tokens(sp)
            except Exception:
                continue
            if r2 and r2.get("refreshToken") and r2["refreshToken"] != acc["refreshToken"]:
                a2 = {"name": r2.get("nickname") or r2.get("uid") or entry,
                      "accessToken": r2.get("accessToken", ""),
                      "refreshToken": r2["refreshToken"],
                      "userId": r2.get("uid", ""),
                      "storagePath": sp}
                dk2 = extract_device_keys(sp)
                if dk2:
                    a2["deviceId"] = dk2.get("deviceId", "")
                    a2["machineId"] = dk2.get("machineId", "")
                    a2["deviceKeyPem"] = dk2.get("privateKeyPem", "")
                    a2["devicePubPem"] = dk2.get("publicKeyPem", "")
                accounts.append(a2)
    return accounts


# ─── 积分查询（只读） ───
def _as_number(v):
    """数值化：仅接受 int/float（bool 除外），其余返回 None。"""
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None


def _fmt_num(v) -> str:
    return "?" if v is None else ("%.2f" % v if isinstance(v, float) else str(v))


def query_credits(access_token: str, device_id: str = "") -> dict:
    """查询 Trae 额度（只读，不签到）。

    端点实返字段（2026-10-20 实测）:
        usage_summary.total_amount     -- 总额度
        usage_summary.consumed_amount  -- 已用
        user_entitlement_pack_list[]   -- 各额度包明细
    旧脚本假定的 Result.EntitlementList / UsedCount / AvailableCount 在该端点不存在。
    """
    url = "https://api.trae.cn/trae/api/v2/pay/user_current_entitlement_list"
    headers = {"Authorization": "Cloud-IDE-JWT " + access_token,
               "Content-Type": "application/json", "Accept": "application/json"}
    if device_id:
        headers["x-device-id"] = device_id
    headers["x-device-type"] = platform.system() or "Windows"
    headers["x-os-version"] = platform.version() or "10.0.19045"
    headers["x-app-version"] = IDE_VERSION
    text = ""
    try:
        status, text = _post(url, headers, '{"req_source":1}', timeout=15)
        if status != 200:
            return {"ok": False, "status": status, "text": text[:200]}
        data = json.loads(text)
        summary = data.get("usage_summary") or {}
        total = _as_number(summary.get("total_amount"))
        consumed = _as_number(summary.get("consumed_amount"))
        packs = data.get("user_entitlement_pack_list") or []
        # 剩余额度 = 总额 - 已用（2026-10-20 精确重建验证：反推导出时刻 consumed=2600.15
        # → remaining 1499.85 与导出值逐分吻合；差额 22.10 即查询间隔内新增消耗）
        available = round(total - consumed, 2) if (total is not None and consumed is not None) else None
        return {"ok": True, "total": total, "used": consumed, "available": available,
                "pack_count": len(packs), "raw": data}
    except json.JSONDecodeError as e:
        return {"ok": False, "error": "响应非 JSON: %s" % e, "text": text[:200]}
    except Exception as e:
        return {"ok": False, "error": str(e), "text": text[:200]}


# ─── 主流程 ───
def decode_jwt_exp(token: str) -> float:
    try:
        p = token.split(".")[1]
        p += "=" * (-len(p) % 4)
        return float(json.loads(base64.urlsafe_b64decode(p)).get("exp", 0))
    except Exception:
        return 0.0


def refresh_account_with_cache(account: dict, cache: dict, dry_run: bool = False) -> tuple:
    """带缓存的续期：检查缓存有效性，必要时刷新。"""
    if dry_run:
        return refresh_account(account, cache)
    ok, msg = refresh_account(account, cache)
    if ok:
        put_cache(account, cache)
    return ok, msg


def main():
    parser = argparse.ArgumentParser(description="Trae JWT 续期工具（增强版）")
    parser.add_argument("files", nargs="*", help="JSON 文件路径（一键导入多开 / trae-accounts 格式）")
    parser.add_argument("--env", action="store_true", help="从环境变量 TRAE_ACCOUNTS 读取")
    parser.add_argument("--storage", action="store_true", help="从 Trae 客户端 storage.json 读取")
    parser.add_argument("--storage-path", help="指定 storage.json 路径")
    parser.add_argument("--dry-run", action="store_true", help="只检查状态，不刷新")
    parser.add_argument("--threshold", type=float, default=7, help="过期前 N 天触发刷新（默认 7）")
    parser.add_argument("--credits", action="store_true", help="查询额度余额（只读，不续期）")
    parser.add_argument("--write-back", action="store_true",
                        help="配合 --credits 使用：把额度回填到源文件（remainingCredits / creditsExpireAt）")
    parser.add_argument("--sync-expire", dest="sync_expire", action="store_true", default=True,
                        help="配合 --credits --write-back：回填 creditsExpireAt（默认开启，规则已实证）")
    parser.add_argument("--no-sync-expire", dest="sync_expire", action="store_false",
                        help="不回填 creditsExpireAt")
    parser.add_argument("--rotate-device", action="store_true", help="强制换新设备号（用于 9074 后）")
    parser.add_argument("--no-cache", action="store_true", help="跳过缓存读取（不修改缓存文件）")
    parser.add_argument("--all", action="store_true", help="刷新所有账号（包括未过期的）")
    args = parser.parse_args()

    if args.threshold < 0:
        parser.error("--threshold 不能为负数（当前 %s）" % args.threshold)
    if args.write_back and not args.credits:
        parser.error("--write-back 需与 --credits 同时使用")
    if args.no_cache and args.all:
        print("[WARN] --all 会忽略缓存读取，--no-cache 无实际影响")
    if not args.files and not args.env and not (args.storage or args.storage_path):
        parser.error("需至少指定一个输入来源：JSON 文件 / --env / --storage")

    now = time.time()
    cache = {} if args.no_cache else load_cache()
    if args.no_cache:
        # 禁用缓存读取，但不是清空缓存文件
        global _CACHE_WRITE_ENABLED
        _CACHE_WRITE_ENABLED = False
    accounts = []

    # 从文件读取
    for fp in args.files:
        accounts.extend(read_accounts_from_file(fp))
    # 从环境变量读取
    if args.env:
        accounts.extend(read_accounts_from_env())
    # 从 storage.json 读取
    if args.storage or args.storage_path:
        accounts.extend(read_accounts_from_storage(args.storage_path))

    if not accounts:
        print("未找到任何账号。请提供 JSON 文件、--env 或 --storage。")
        return 1

    # 去重（按 userId 或 refreshToken 前 24 字符）
    seen = set()
    unique = []
    for acc in accounts:
        key = acc.get("userId") or acc.get("refreshToken", "")[:24]
        if key and key not in seen:
            seen.add(key)
            unique.append(acc)
    accounts = unique

    print("=" * _SECONDS_PER_MINUTE)
    print("Trae JWT 续期工具（增强版）")
    print("账号数: %d | 缓存: %s | 直连: 是" % (len(accounts), "开" if not args.no_cache else "关"))
    print("=" * _SECONDS_PER_MINUTE)

    failures = []
    for acc in accounts:
        name = acc.get("name", "?")
        token = acc.get("accessToken") or acc.get("token", "")
        refresh_token = acc.get("refreshToken", "")
        if not refresh_token:
            print("  %-12s 缺少 refreshToken，跳过" % name)
            continue

        # 只读模式先套缓存（仅改内存，不落盘），以反映真实有效期
        read_only = args.dry_run or args.credits
        if read_only and not args.no_cache:
            apply_cache(acc, cache)
            token = acc.get("accessToken") or acc.get("token", "")

        # 计算剩余天数
        exp = decode_jwt_exp(token) if token else 0
        remaining = (exp - now) / _SECONDS_PER_DAY if exp else 0
        if not token:
            status = "无 accessToken（仅 refreshToken）"
        elif remaining < 0:
            status = "已过期 (%.1f 天)" % abs(remaining)
        else:
            status = "剩余 %.1f 天" % remaining
        print("  %-12s %s" % (name, status))

        # 强制换设备号（写盘操作，只读模式不执行）
        if args.rotate_device and not read_only:
            new_did = rotate_device_id(acc)
            print("    -> 设备号已更换: %s" % new_did)

        # 积分查询模式
        if args.credits:
            if not token and not args.no_cache:
                apply_cache(acc, cache)
                token = acc.get("accessToken") or acc.get("token", "")
            if not token:
                print("    -> 无 accessToken，无法查询积分")
                continue
            credits = query_credits(token, acc.get("deviceId", ""))
            if credits.get("ok"):
                print("    -> 总额: %s | 已用: %s | 剩余: %s | pack %s 个" % (
                    _fmt_num(credits.get("total")), _fmt_num(credits.get("used")),
                    _fmt_num(credits.get("available")), credits.get("pack_count")))
                if args.write_back and not args.dry_run:
                    for fp in args.files:
                        _apply_credits_writeback(fp, acc.get("userId", ""), credits,
                                                 sync_expire=args.sync_expire)
            else:
                err = credits.get("error") or credits.get("text", "")
                print("    -> 查询失败: HTTP %s %s" % (credits.get("status", "?"), err[:120]))
                failures.append((name, "credits: %s" % err[:120]))
            continue

        # dry-run 或不需要刷新
        if args.dry_run:
            continue
        if not args.all and remaining >= args.threshold:
            print("    -> 未达阈值 (%.1f >= %.1f)，跳过" % (remaining, args.threshold))
            continue

        # 尝试应用缓存
        if not args.no_cache and not args.all:
            if apply_cache(acc, cache):
                new_exp = decode_jwt_exp(acc["accessToken"])
                new_rem = (new_exp - now) / _SECONDS_PER_DAY
                print("    -> 缓存命中，剩余 %.1f 天" % new_rem)
                # 缓存命中同样要写回源文件，否则文件里仍是旧 token
                for fp in args.files:
                    _write_back_if_match(fp, acc)
                continue

        # 执行续期
        ok, msg = refresh_account_with_cache(acc, cache, dry_run=False)
        if ok:
            new_exp = decode_jwt_exp(acc["accessToken"])
            new_rem = (new_exp - now) / _SECONDS_PER_DAY
            print("    -> 刷新成功，剩余 %.1f 天 (%s)" % (new_rem, msg))
            # 写回文件（如果提供了文件路径）
            for fp in args.files:
                _write_back_if_match(fp, acc)
        else:
            failures.append((name, msg))
            print("    -> 失败: %s" % msg)

    print()
    if args.dry_run:
        print("[dry-run] 未修改任何文件。")
    if failures:
        print("[汇总] 失败 %d 个: %s" % (len(failures), ", ".join(n for n, _ in failures)))
        return 1
    return 0


def _credit_expire_from_packs(packs: list) -> int:
    """额度到期时间 = min(end_time) 于「limit 有值且未耗尽」的包。

    规则由 2026-10-20 导出值（creditsExpireAt=1793898005）反解并经 10 账号交叉验证
    （8/10 精确命中，2 例为导出快照与查询时刻的状态差），语义为
    「最近到期的一张仍有余额的卡」。
    """
    ends = []
    for p in packs:
        if not isinstance(p, dict):
            continue
        base = p.get("entitlement_base_info") or {}
        limit = _as_number((base.get("quota") or {}).get("credits_limit"))
        end = _as_number(base.get("end_time"))
        if limit is None or not end:
            continue
        if _is_exhausted(p, limit):
            continue
        ends.append(int(end))
    return min(ends) if ends else 0


def _is_exhausted(pack: dict, limit=None) -> bool:
    """额度包是否已耗尽（used >= limit）。used 缺失视为未耗尽。"""
    if not isinstance(pack, dict):
        return False
    if limit is None:
        limit = _as_number(((pack.get("entitlement_base_info") or {}).get("quota") or {}).get("credits_limit"))
    used = _as_number((pack.get("usage") or {}).get("credits_amount"))
    if limit is None or used is None:
        return False
    return used >= limit


def _apply_credits_writeback(filepath: str, acc_key: str, credits: dict,
                             sync_expire: bool = True) -> bool:
    """把额度查询结果回填到源文件对应账号。

    - `remainingCredits`：= total_amount - consumed_amount（2026-10-20 精确重建验证）
    - `creditsExpireAt`：= min(end_time) 于 limit 有值且未耗尽的包（同日实证，8/10 交叉验证）
    - 只更新源文件**已存在**的字段，不新增字段；账号按 userId 匹配
    - 无实际变更时不写盘（幂等）
    """
    if not credits.get("ok"):
        return False
    total, used, available = credits.get("total"), credits.get("used"), credits.get("available")
    exp_ts = 0
    if sync_expire:
        exp_ts = _credit_expire_from_packs((credits.get("raw") or {}).get("user_entitlement_pack_list") or [])
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print("    ⚠️ 额度回填读取失败: %s" % e)
        return False
    items = data.get("accounts", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return False
    hit = False
    changed = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if str(item.get("userId", "") or item.get("uid", "") or "") != str(acc_key):
            continue
        if available is not None and "remainingCredits" in item and item["remainingCredits"] != available:
            item["remainingCredits"] = available
            changed.append("remainingCredits")
        if "creditsExpireAt" in item:
            cur = item.get("creditsExpireAt")
            if exp_ts and cur != exp_ts:
                item["creditsExpireAt"] = exp_ts
                changed.append("creditsExpireAt")
            elif not sync_expire:
                pass  # 用户以 --no-sync-expire 主动关闭，不提示
            elif not exp_ts:
                print("    ℹ️ creditsExpireAt 未同步：无「有余额且 limit 有值」的额度包")
        if total is not None and "totalCredits" in item and item["totalCredits"] != total:
            item["totalCredits"] = total
            changed.append("totalCredits")
        if used is not None and "usedCredits" in item and item["usedCredits"] != used:
            item["usedCredits"] = used
            changed.append("usedCredits")
        hit = True
        break
    if not hit:
        return False
    if not changed:
        return False
    try:
        tmp = filepath + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, filepath)
        print("    💾 额度已回填 (%s): %s" % ("+".join(changed), filepath))
        return True
    except OSError as e:
        print("    ⚠️ 额度回填写入失败: %s" % e)
        try:
            os.remove(filepath + ".tmp")
        except OSError as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
        return False


def _write_back_if_match(filepath: str, refreshed_acc: dict):
    """如果 refreshed_acc 的 userId 匹配文件中的某条记录，原地更新。"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return
    uid = refreshed_acc.get("userId", "")
    if not uid:
        return
    changed = False
    items = data.get("accounts", data) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return
    for acc in items:
        if not isinstance(acc, dict):
            continue
        acc_uid = str(acc.get("userId", "") or acc.get("uid", "") or "")
        if acc_uid != uid:
            continue
        new_at = refreshed_acc.get("accessToken", "")
        # 按源文件实际存在的字段名写回，不新增导入器不认识的字段
        wrote = False
        if "cloudIdeJwt" in acc:
            acc["cloudIdeJwt"] = "Cloud-IDE-JWT " + new_at
            wrote = True
        if "accessToken" in acc:
            acc["accessToken"] = new_at
            wrote = True
        if "token" in acc:
            acc["token"] = new_at
            wrote = True
        if not wrote:
            acc["token"] = new_at
        acc["refreshToken"] = refreshed_acc.get("refreshToken", "")
        if refreshed_acc.get("deviceId"):
            acc["deviceId"] = refreshed_acc["deviceId"]
        # 同步展示字段，避免 UI 显示旧值
        try:
            exp = int(decode_jwt_exp(new_at))
            if exp:
                now_ts = time.time()
                acc["jwtExp"] = exp
                acc["jwtExpHours"] = round((exp - now_ts) / 3600, 6)
        except Exception as _exc:
            _LOGGER.debug("忽略预期内异常（降级路径）: %s", _exc)
        changed = True
        break
    if changed:
        try:
            tmp = filepath + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, filepath)
            print("    💾 已写回: %s" % filepath)
        except Exception as e:
            print("    ⚠️ 写回失败: %s" % e)


if __name__ == "__main__":
    sys.exit(main())
