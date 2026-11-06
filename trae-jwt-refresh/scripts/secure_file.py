#!/usr/bin/env python3
"""凭据落盘的访问控制收紧（POSIX 0600 / Windows 收紧 ACL）。

为什么需要
----------
Trae 的 accessToken / refreshToken / 设备私钥都是长期有效的凭据。一旦缓存文件
对同机其他用户可读，等价于凭据泄露。

各平台的访问控制模型不同，所以收紧方式也不同：

* **POSIX**：文件权限位就是访问控制，用 ``0600``（仅属主可读写）即可。
  ``os.open(..., mode)`` 会被 umask 削弱，且 ``os.replace`` 之后目标文件可能
  仍带着目录继承下来的属性，因此最终统一再收一次。
* **Windows**：没有 POSIX 权限位，访问控制由 ACL 决定，且默认**继承父目录**；
  父目录通常对 Users 组可读，于是新建的凭据文件也对其他用户可读。这里用
  ``icacls`` 显式收紧：只保留「当前用户 + SYSTEM + Administrators」，并去掉
  继承项。顺序必须是「先授权、再去继承」——反过来一旦授权失败，就会得到
  一个「没有继承权限也没有显式权限」的文件，用户自己都打不开。

若 ``icacls`` 不可用或执行失败，权限只能依赖父目录 ACL；此时调用方应在
日志/文档中提示把凭据文件放在用户私有目录（见各仓 SKILL.md 的说明）。
"""

import json
import os
import stat
import subprocess

# 仅属主可读写（文件）/ 0700（目录）
PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700

# icacls 授权语法：文件用 F，目录用 (OI)(CI)F（对子项继承）
_FILE_GRANT = "F"
_DIR_GRANT = "(OI)(CI)F"


def current_user_ident():
    """返回当前用户的 icacls 授权标识。

    优先拼 "DOMAIN\\用户名"（域账号必须带域名前缀，否则 icacls 可能匹配到
    同名本地账号），拼不出域名前缀就退回裸用户名。
    """
    name = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if not name:
        return ""
    domain = os.environ.get("USERDOMAIN") or ""
    return (domain + "\\" + name) if domain else name


def _run_icacls(args):
    """执行 icacls，返回 (是否成功, 错误说明)。"""
    try:
        proc = subprocess.run(["icacls"] + args, capture_output=True)
    except OSError as e:
        return False, "icacls 不可用: %s" % e
    if proc.returncode != 0:
        msg = (proc.stdout + proc.stderr).decode("mbcs", "replace").strip()
        return False, msg or ("icacls 退出码 %d" % proc.returncode)
    return True, ""


def restrict_windows_acl(path, is_dir=False):
    """Windows：把访问控制收紧到当前用户 + SYSTEM + Administrators，并去掉继承。

    SYSTEM / Administrators 用 ``*SID`` 授权：这两个内置组名在非英文 Windows
    上是本地化的（"管理员" 等），按名字授权会失败，而 SID 在任何语言下唯一。
    S-1-5-18 = SYSTEM，S-1-5-32-544 = Administrators。

    返回 (是否成功, 错误说明)。
    """
    ident = current_user_ident()
    if not ident:
        return False, "无法确定当前用户身份"
    grant = _DIR_GRANT if is_dir else _FILE_GRANT
    ok, err = _run_icacls([path, "/grant",
                           "%s:%s" % (ident, grant),
                           "*S-1-5-18:%s" % grant,
                           "*S-1-5-32-544:%s" % grant])
    if not ok:
        # 授权失败就到此为止：保留继承权限（暴露面没变小，但也没把用户锁在门外）
        return False, err
    ok, err = _run_icacls([path, "/inheritance:r"])
    if not ok:
        return False, err
    return True, ""


def restrict_private(path, is_dir=False):
    """按平台收紧访问控制。返回 (是否成功, 错误说明)。"""
    if os.name == "nt":
        return restrict_windows_acl(path, is_dir=is_dir)
    mode = PRIVATE_DIR_MODE if is_dir else PRIVATE_FILE_MODE
    try:
        os.chmod(path, mode)
    except OSError as e:
        return False, str(e)
    return True, ""


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    return parent


def write_private_text(path, text):
    """原子写入文本，并把访问控制收紧到仅属主可读写。

    返回 (是否收紧成功, 错误说明)。写入失败会向上抛错。
    """
    path = os.path.abspath(path)
    _ensure_parent(path)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, path)
    # replace 之后目标文件可能仍继承目录属性，统一再收一次
    return restrict_private(path)


def write_private_json(path, obj):
    """原子写入 JSON（UTF-8 / ensure_ascii=False / 2 空格缩进），并收紧权限。"""
    return write_private_text(path, json.dumps(obj, ensure_ascii=False, indent=2))


def write_text_preserving_mode(path, text):
    """原子写入文本，但**保留目标文件原有权限位**。

    用于写回用户自己的源文件：用户可能已经把含凭据的文件收紧到 0600，
    ``os.replace`` 会把新临时文件的默认权限（0644）带过去，反而把权限放宽了。
    文件不存在时按 0600 创建（凭据文件默认就该只有属主可读）。

    Windows 上没有「保留权限位」这回事：``os.replace`` 之后目标文件继承的是
    所在目录的 ACL（与修改前行为一致，不做额外收紧——源文件是用户自己的
    文件，是否共享由用户决定；需要收紧的是本工具自己生成的凭据缓存，
    走 write_private_text / write_private_json）。
    """
    path = os.path.abspath(path)
    _ensure_parent(path)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mode = PRIVATE_FILE_MODE
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    if os.name != "nt":
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
    os.replace(tmp, path)
    return True, ""
