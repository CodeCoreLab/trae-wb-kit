#!/usr/bin/env python3
"""trae_get_token.py 回归测试（A41：凭据不得明文打印到 stdout）。

覆盖：
  · export-keys / --accounts / 默认模式都**不把**私钥 PEM、refreshToken、accessToken
    打印到 stdout（只打印 sha256 前 8 位指纹）
  · 完整凭据写入权限收紧的文件（POSIX 0600 / Windows 去掉 ACL 继承）

全部离线（不读 storage.json，用假的提取结果），unittest 直接运行：
    python test_trae_get_token.py
"""
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trae_get_token as G  # noqa: E402


FAKE_PEM = ("-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQFAKESECRET\n"
            "-----END PRIVATE KEY-----")
FAKE_PUB = ("-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAESECRET\n"
            "-----END PUBLIC KEY-----")
FAKE_RT = "rt-FAKE-SECRET-REFRESH-TOKEN-0123456789"
FAKE_AT = "at-FAKE-SECRET-ACCESS-TOKEN-9876543210"


def sha8(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def assert_private(self, path):
    """断言文件对同机其他用户不可读。

    Windows：不得残留继承项（icacls 输出里的 ``(I)`` 标记），也不得出现
    BUILTIN\\Users / Authenticated Users / Everyone 这类其他用户主体。
    POSIX：组/其他权限位必须为 0。
    """
    self.assertTrue(os.path.isfile(path), "文件未生成: %s" % path)
    if os.name == "nt":
        out = subprocess.run(["icacls", path], capture_output=True)
        text = out.stdout.decode("mbcs", "replace")
        self.assertNotIn("(I)", text,
                         "ACL 仍是继承项（未去掉继承）:\n%s" % text)
        for bad in ("BUILTIN\\Users", "Authenticated Users", "Everyone"):
            self.assertNotIn(bad, text,
                             "ACL 仍对其他用户开放 (%s):\n%s" % (bad, text))
    else:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode & 0o077, 0,
                         "权限位应收紧为 0600，实际 %o" % mode)


class SecureOutputBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="trae-get-token-test-")
        self.addCleanup(self._cleanup)
        self._old_env = os.environ.get("TRAE_EXPORT_DIR")
        os.environ["TRAE_EXPORT_DIR"] = self.tmp
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._old_env is None:
            os.environ.pop("TRAE_EXPORT_DIR", None)
        else:
            os.environ["TRAE_EXPORT_DIR"] = self._old_env

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

    def run_capture(self, fn, *a, **kw):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = fn(*a, **kw)
        return rc, buf.getvalue()


class TestExportKeysNoPlaintext(SecureOutputBase):
    def setUp(self):
        super().setUp()
        self._orig_keys = G.extract_device_keys
        self._orig_find = G.find_storage_json
        G.extract_device_keys = lambda p: {
            "deviceId": "1234567890123456",
            "machineId": "machine-abc",
            "privateKeyPem": FAKE_PEM,
            "publicKeyPem": FAKE_PUB,
        }
        G.find_storage_json = lambda: os.path.join(self.tmp, "storage.json")
        self.addCleanup(self._restore)

    def _restore(self):
        G.extract_device_keys = self._orig_keys
        G.find_storage_json = self._orig_find

    def test_private_key_not_printed(self):
        rc, out = self.run_capture(G.export_keys_mode)
        self.assertEqual(rc, 0)
        self.assertNotIn("FAKESECRET", out, "私钥明文被打到 stdout:\n%s" % out)
        self.assertNotIn("BEGIN PRIVATE KEY", out)
        self.assertNotIn(FAKE_PEM, out)

    def test_fingerprint_printed_instead(self):
        rc, out = self.run_capture(G.export_keys_mode)
        self.assertIn(sha8(FAKE_PEM), out, "应打印私钥指纹:\n%s" % out)
        self.assertIn(sha8(FAKE_PUB), out, "应打印公钥指纹:\n%s" % out)

    def test_full_key_written_to_restricted_file(self):
        rc, out = self.run_capture(G.export_keys_mode)
        path = os.path.join(self.tmp, "trae_device_keys.env")
        self.assertTrue(os.path.isfile(path), "未写出密钥文件:\n%s" % out)
        with open(path, encoding="utf-8") as f:
            body = f.read()
        self.assertIn("TRAE_DEVICE_KEY_PEM=", body)
        self.assertIn("FAKESECRET", body, "文件里应保留完整私钥供 source 使用")
        assert_private(self, path)

    def test_no_tmp_leftover(self):
        self.run_capture(G.export_keys_mode)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "trae_device_keys.env.tmp")))


class TestAccountsNoPlaintext(SecureOutputBase):
    def setUp(self):
        super().setUp()
        self._orig_extract = G.extract
        self._orig_find = G.find_storage_json
        G.extract = lambda p: {
            "refreshToken": FAKE_RT,
            "accessToken": FAKE_AT,
            "uid": "1378147261747963",
            "nickname": "测试账号",
        }
        G.find_storage_json = lambda: os.path.join(self.tmp, "storage.json")
        self.addCleanup(self._restore)

    def _restore(self):
        G.extract = self._orig_extract
        G.find_storage_json = self._orig_find

    def test_tokens_not_printed(self):
        rc, out = self.run_capture(G.accounts_mode)
        self.assertEqual(rc, 0)
        self.assertNotIn(FAKE_RT, out, "refreshToken 明文被打到 stdout:\n%s" % out)
        self.assertNotIn(FAKE_AT, out, "accessToken 明文被打到 stdout:\n%s" % out)

    def test_fingerprint_printed_instead(self):
        rc, out = self.run_capture(G.accounts_mode)
        self.assertIn(sha8(FAKE_RT), out)

    def test_full_json_written_to_restricted_file(self):
        rc, out = self.run_capture(G.accounts_mode)
        path = os.path.join(self.tmp, "trae_accounts.json")
        self.assertTrue(os.path.isfile(path), "未写出账号文件:\n%s" % out)
        with open(path, encoding="utf-8") as f:
            entries = json.loads(f.read())
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["refreshToken"], FAKE_RT)
        assert_private(self, path)


class TestDefaultModeNoPlaintext(SecureOutputBase):
    def setUp(self):
        super().setUp()
        self._orig_extract = G.extract
        self._orig_find = G.find_storage_json
        self._orig_argv = sys.argv
        G.extract = lambda p: {
            "refreshToken": FAKE_RT,
            "accessToken": FAKE_AT,
            "uid": "1378147261747963",
            "nickname": "测试账号",
        }
        G.find_storage_json = lambda: os.path.join(self.tmp, "storage.json")
        sys.argv = ["trae_get_token.py"]
        self.addCleanup(self._restore)

    def _restore(self):
        G.extract = self._orig_extract
        G.find_storage_json = self._orig_find
        sys.argv = self._orig_argv

    def test_refresh_token_not_printed(self):
        rc, out = self.run_capture(G.main)
        self.assertEqual(rc, 0)
        self.assertNotIn(FAKE_RT, out, "refreshToken 明文被打到 stdout:\n%s" % out)
        self.assertNotIn(FAKE_AT, out)

    def test_fingerprint_printed_instead(self):
        rc, out = self.run_capture(G.main)
        self.assertIn(sha8(FAKE_RT), out)

    def test_full_token_written_to_restricted_file(self):
        rc, out = self.run_capture(G.main)
        path = os.path.join(self.tmp, "trae_refresh_token.env")
        self.assertTrue(os.path.isfile(path), "未写出 token 文件:\n%s" % out)
        with open(path, encoding="utf-8") as f:
            body = f.read()
        self.assertIn(FAKE_RT, body)
        assert_private(self, path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
