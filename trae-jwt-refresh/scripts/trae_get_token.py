#!/usr/bin/env python3
"""Trae Token 提取器

一键从 Trae 官方客户端本地数据里解出 refreshToken / accessToken，
免抓包、免装依赖（纯 Python 标准库，自己实现 AES-128-CBC）。

使用方法：
  python trae_get_token.py                    # 提取主账号 refreshToken
  python trae_get_token.py --accounts         # 一键生成 TRAE_ACCOUNTS JSON
  python trae_get_token.py --export-keys      # 导出设备密钥（新版续期必需）
  python trae_get_token.py --storage-path "..." # 指定 storage.json 路径
"""
import base64, hashlib, json, os, re, sys



SALT_A = bytes([82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,162,73,109,139,209,37])
SALT_B = bytes([31,221,168,51,136,7,199,49,177,18,16,89,39,128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,225,105,20,99,85,33,12,125])
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
RC = [0x01,0x02,4,8,16,0x20,64,128,0x1B,0x36]


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


def extract(path):
    s = json.load(open(path, encoding="utf-8"))
    enc = s.get(STORAGE_KEY)
    if not enc: return None
    txt = decrypt_storage_value(enc).decode("utf-8", "replace")
    rt = re.search(r'"refreshToken"\s*:\s*"([^"]+)"', txt)
    at = re.search(r'"token"\s*:\s*"([^"]+)"', txt)
    uid = re.search(r'"userId"\s*:\s*"(\d+)"', txt)
    nick = re.search(r'"username"\s*:\s*"([^"]*)"', txt)
    return {"refreshToken": rt.group(1) if rt else None,
            "accessToken": at.group(1) if at else None,
            "uid": uid.group(1) if uid else None,
            "nickname": nick.group(1) if nick else None}


def extract_device_keys(path):
    s = json.load(open(path, encoding="utf-8"))
    did = ""
    for k in s:
        if k.startswith("iCubeAuthInfo://icube-dc:"):
            d = k.split(":")[-1]
            if d.isdigit():
                did = d
                break
    if not did:
        return None
    enc = s.get("iCubeAuthInfo://icube-dc:%s" % did)
    if not enc:
        return None
    try:
        dev = json.loads(decrypt_storage_value(enc.strip()).decode("utf-8", "replace"))
    except Exception:
        return None
    priv = (dev.get("privateKeyPEM") or "").strip()
    pub = (dev.get("publicKeyPEM") or "").strip()
    if priv and pub:
        return {"deviceId": did, "privateKeyPem": priv, "publicKeyPem": pub,
                "machineId": (s.get("telemetry.machineId") or "").strip()}


def export_keys_mode(storage_path=None):
    k = extract_device_keys(storage_path or find_storage_json())
    if not k:
        print("[X] 没找到设备密钥。请先在 Trae 客户端登录一次，再运行本脚本。")
        return 1
    print("=" * 64)
    print("设备密钥（来源: %s）" % (storage_path or find_storage_json()))
    print("=" * 64)
    print("TRAE_DEVICE_ID=%s" % k["deviceId"])
    print("TRAE_MACHINE_ID=%s" % k["machineId"])
    print()
    print("TRAE_DEVICE_KEY_PEM=%s" % k["privateKeyPem"].replace("\n", "\\n"))
    print()
    print("TRAE_DEVICE_PUB_PEM=%s" % k["publicKeyPem"].replace("\n", "\\n"))
    print("=" * 64)
    print("提示：PEM 里的换行已写成 \\n，直接整行复制即可。")
    return 0


def accounts_mode(storage_path=None):
    """把本机登录态 + 账号目录里的凭据合成 TRAE_ACCOUNTS JSON 数组。"""
    entries, seen = [], set()
    def add(rec):
        key = rec.get("uid") or rec.get("refreshToken", "")[:24]
        if not rec.get("refreshToken") or key in seen:
            return
        seen.add(key)
        n = len(entries) + 1
        rec.setdefault("uid", "账号%d" % n)
        rec.setdefault("name", rec["uid"])
        entries.append(rec)
    # 从 storage.json 提取
    for p in [storage_path, find_storage_json()]:
        if not p: continue
        try:
            r = extract(p)
        except Exception as e:
            print("[!] 解析失败 %s: %s" % (p, e), file=sys.stderr); continue
        if not r or not r.get("refreshToken"): continue
        add({"accessToken": r.get("accessToken") or "",
             "refreshToken": r["refreshToken"],
             "uid": r.get("uid") or "",
             "name": r.get("nickname") or r.get("uid") or ""})
    if not entries:
        print("[X] 没找到任何可用账号。请先在 Trae 客户端登录一次。")
        return 1
    line = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    print("=" * 64)
    print("TRAE_ACCOUNTS  (共 %d 个账号，整行复制到环境变量)" % len(entries))
    print("=" * 64)
    for i, e in enumerate(entries, 1):
        print("  %d) %s  UID %s" % (i, e.get("name") or "-", e.get("uid") or "-"))
    print("-" * 64)
    print(line)
    print("=" * 64)
    return 0


def main():
    args = sys.argv[1:]
    if not args:
        args = ["--help"]
    low = [a.lower() for a in args]
    if "--export-keys" in low or "--keys" in low or "-k" in low:
        path = None
        if "-p" in low:
            idx = low.index("-p")
            if idx + 1 < len(args):
                path = args[idx + 1]
        elif "--storage-path" in low:
            idx = low.index("--storage-path")
            if idx + 1 < len(args):
                path = args[idx + 1]
        return export_keys_mode(path)
    if "--accounts" in low or "-a" in low:
        path = None
        if "-p" in low:
            idx = low.index("-p")
            if idx + 1 < len(args):
                path = args[idx + 1]
        elif "--storage-path" in low:
            idx = low.index("--storage-path")
            if idx + 1 < len(args):
                path = args[idx + 1]
        return accounts_mode(path)
    # 默认：提取单个 refreshToken
    path = None
    if "-p" in low:
        idx = low.index("-p")
        if idx + 1 < len(args):
            path = args[idx + 1]
    elif "--storage-path" in low:
        idx = low.index("--storage-path")
        if idx + 1 < len(args):
            path = args[idx + 1]
    found = False
    for p in [path, find_storage_json()]:
        if not p: continue
        try:
            r = extract(p)
        except Exception as e:
            print("[!] 解析失败 %s: %s" % (p, e)); continue
        if not r or not r.get("refreshToken"): continue
        found = True
        print("=" * 64)
        print("[来源] %s" % p)
        if r.get("uid"):
            print("[账号] %s (UID %s)" % (r.get("nickname") or "-", r["uid"]))
        print("-" * 64)
        print("TRAE_REFRESH_TOKEN = %s" % r["refreshToken"])
        print("=" * 64)
    if not found:
        print("[X] 没找到可用的 refreshToken。请先打开 Trae 客户端并登录一次。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
