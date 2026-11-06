#!/usr/bin/env python3
"""凭据文件权限收紧的回归测试（A40）。

覆盖：
  · refresh_trae_jwt.save_cache 写出的 token 缓存文件对同机其他用户不可读
  · refresh_trae_jwt.save_device_ids 写出的设备号文件同样收紧
  · secure_file.write_private_text / write_private_json 的权限行为
  · 写回用户源文件时保留原有权限位（不能被 os.replace 放宽）

全部离线，unittest 直接运行：
    python test_secure_file.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secure_file  # noqa: E402
import refresh_trae_jwt as R  # noqa: E402


def icacls_text(path):
    out = subprocess.run(["icacls", path], capture_output=True)
    return out.stdout.decode("mbcs", "replace")


def assert_not_world_readable(self, path):
    """断言文件对同机其他用户不可读。

    Windows 上没有 POSIX 权限位，访问控制完全由 ACL 决定：
      · 必须**没有继承项**（继承项在 icacls 输出里带 ``(I)`` 标记）——
        继承来的 ACE 意味着权限跟着父目录走，父目录对 Users 组可读时
        凭据文件就对其他用户可读；
      · 且不得出现 BUILTIN\\Users / Authenticated Users / Everyone 这类
        「其他已认证用户」主体。
    POSIX 上直接看权限位：组/其他位必须为 0。
    """
    self.assertTrue(os.path.isfile(path), "文件未生成: %s" % path)
    if os.name == "nt":
        text = icacls_text(path)
        self.assertNotIn("(I)", text,
                         "ACL 仍是继承项（未去掉继承）:\n%s" % text)
        for bad in ("BUILTIN\\Users", "Authenticated Users", "Everyone"):
            self.assertNotIn(bad, text,
                             "ACL 仍对其他用户开放 (%s):\n%s" % (bad, text))
    else:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0,
                         "权限位应收紧为 0600，实际 %o" % mode)


class TestSecureFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="trae-secure-test-")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        for name in os.listdir(self.tmp):
            try:
                os.remove(os.path.join(self.tmp, name))
            except OSError:
                pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass

    def test_write_private_text_restricts_permissions(self):
        p = os.path.join(self.tmp, "secret.txt")
        secure_file.write_private_text(p, "hello")
        assert_not_world_readable(self, p)
        with open(p, encoding="utf-8") as f:
            self.assertEqual(f.read(), "hello")

    def test_write_private_json_restricts_permissions(self):
        p = os.path.join(self.tmp, "secret.json")
        secure_file.write_private_json(p, {"refreshToken": "rt-secret"})
        assert_not_world_readable(self, p)
        with open(p, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["refreshToken"], "rt-secret")

    def test_no_tmp_leftover(self):
        p = os.path.join(self.tmp, "secret.json")
        secure_file.write_private_json(p, {"a": 1})
        self.assertFalse(os.path.exists(p + ".tmp"))

    def test_preserving_mode_keeps_existing_permission_bits(self):
        """写回用户源文件时不得把用户收紧过的权限放宽回去。"""
        p = os.path.join(self.tmp, "accounts.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write("{}")
        if os.name != "nt":
            os.chmod(p, 0o600)
            before = stat.S_IMODE(os.stat(p).st_mode)
            secure_file.write_text_preserving_mode(p, '{"x":1}')
            mode = stat.S_IMODE(os.stat(p).st_mode)
            self.assertEqual(mode, before, "写回后权限被放宽为 %o" % mode)
        else:
            # Windows 无 POSIX 权限位：语义是「保持原有 ACL 不变」
            before = icacls_text(p)
            secure_file.write_text_preserving_mode(p, '{"x":1}')
            after = icacls_text(p)
            self.assertEqual(
                [ln.strip() for ln in after.splitlines() if ":" in ln and ")" in ln],
                [ln.strip() for ln in before.splitlines() if ":" in ln and ")" in ln],
                "写回后 ACL 发生变化:\n前:\n%s\n后:\n%s" % (before, after))
        with open(p, encoding="utf-8") as f:
            self.assertEqual(f.read(), '{"x":1}')


class TestCacheFilePermissions(unittest.TestCase):
    """token 缓存里是真实凭据，落盘必须收紧权限。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="trae-cache-test-")
        self.addCleanup(self._cleanup)
        self._old = os.environ.get("TRAE_TOKEN_CACHE")
        os.environ["TRAE_TOKEN_CACHE"] = os.path.join(self.tmp, ".trae_token_cache.json")
        self.addCleanup(self._restore)

    def _restore(self):
        if self._old is None:
            os.environ.pop("TRAE_TOKEN_CACHE", None)
        else:
            os.environ["TRAE_TOKEN_CACHE"] = self._old

    def _cleanup(self):
        for name in os.listdir(self.tmp):
            try:
                os.remove(os.path.join(self.tmp, name))
            except OSError:
                pass
        try:
            os.rmdir(self.tmp)
        except OSError:
            pass

    def test_cache_file_is_not_world_readable(self):
        R.save_cache({"uid1": {"accessToken": "at", "refreshToken": "rt"}})
        assert_not_world_readable(self, os.environ["TRAE_TOKEN_CACHE"])

    def test_cache_content_unchanged(self):
        R.save_cache({"uid1": {"accessToken": "at", "refreshToken": "rt"}})
        with open(os.environ["TRAE_TOKEN_CACHE"], encoding="utf-8") as f:
            self.assertEqual(json.load(f)["uid1"]["refreshToken"], "rt")

    def test_device_ids_file_is_not_world_readable(self):
        old = R._DEVICE_ID_FILE
        R._DEVICE_ID_FILE = os.path.join(self.tmp, ".trae_device_ids.json")
        try:
            R.save_device_ids({"k": "1234567890123456"})
            assert_not_world_readable(self, R._DEVICE_ID_FILE)
        finally:
            R._DEVICE_ID_FILE = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
