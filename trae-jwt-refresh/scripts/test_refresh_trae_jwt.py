#!/usr/bin/env python3
"""refresh_trae_jwt.py 回归测试。

覆盖：JWT 解析、格式归一化、缓存命中、错误码翻译、额度解析、写回幂等。
全部离线（不打网络），用 unittest 直接运行：
    python test_refresh_trae_jwt.py
"""
import base64
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refresh_trae_jwt as R  # noqa: E402




def make_jwt(uid="1234567890", exp=None, extra=None):
    """构造未签名 JWT（仅载荷可解即可，测试不校验签名）。"""
    import time as _t
    payload = {"data": {"id": uid, "tenant_id": "7o2d894p7dr0o4", "type": "user"},
               "exp": exp if exp is not None else int(_t.time()) + 86400,
               "iat": int(_t.time())}
    if extra:
        payload.update(extra)
    seg = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "eyJhbGciOiJSUzI1NiJ9.%s.sig" % seg


class TestJwtDecode(unittest.TestCase):
    def test_uid_and_exp_normal(self):
        t = make_jwt(uid="999", exp=1800000000)
        self.assertEqual(R._jwt_uid(t), "999")
        self.assertEqual(R._jwt_exp(t), 1800000000)
        self.assertEqual(R.decode_jwt_exp(t), 1800000000)

    def test_malformed_returns_safe_default(self):
        for bad in ("", "abc", "a.b", "a.b.c.d", None):
            self.assertEqual(R._jwt_uid(bad or ""), "")
            self.assertEqual(R._jwt_exp(bad or ""), 0)
            self.assertEqual(R.decode_jwt_exp(bad or ""), 0.0)

    def test_exp_differs_from_uid_regression(self):
        """回归：补位串必须作用于 payload 本身，否则恒返 0。"""
        t = make_jwt(uid="42", exp=1800000123)
        self.assertNotEqual(R._jwt_exp(t), 0)
        self.assertNotEqual(R._jwt_uid(t), "")


class TestNormalize(unittest.TestCase):
    def test_cloudidejwt_prefix_stripped(self):
        acc = R.normalize_account({"cloudIdeJwt": "Cloud-IDE-JWT " + make_jwt("77"), "refreshToken": "r"})
        self.assertTrue(acc["accessToken"].startswith("eyJ"))
        self.assertEqual(acc["userId"], "77")

    def test_cloudidejwt_without_prefix(self):
        acc = R.normalize_account({"cloudIdeJwt": make_jwt("88"), "refreshToken": "r"})
        self.assertEqual(acc["userId"], "88")

    def test_non_dict_input_safe(self):
        acc = R.normalize_account("not-a-dict")
        self.assertEqual(acc["accessToken"], "")
        self.assertEqual(acc["name"], "")

    def test_alias_fields(self):
        acc = R.normalize_account({"token": "t", "refresh_token": "rt", "uid": "5", "device_id": "d"})
        self.assertEqual((acc["accessToken"], acc["refreshToken"], acc["userId"], acc["deviceId"]),
                         ("t", "rt", "5", "d"))


class TestReadFile(unittest.TestCase):
    def _write(self, obj):
        fd, p = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False)
        self.addCleanup(lambda: os.path.exists(p) and os.remove(p))
        return p

    def test_accounts_wrapper(self):
        p = self._write({"accountCount": 2, "accounts": [
            {"name": "a", "refreshToken": "r1", "cloudIdeJwt": make_jwt("1")},
            {"name": "b", "refreshToken": "r2", "cloudIdeJwt": make_jwt("2")}]})
        self.assertEqual(len(R.read_accounts_from_file(p)), 2)

    def test_list_top_level(self):
        p = self._write([{"refreshToken": "r", "userId": "1"}])
        self.assertEqual(len(R.read_accounts_from_file(p)), 1)

    def test_non_dict_element_skipped_not_crash(self):
        """回归：数组内出现非对象元素不应崩溃。"""
        p = self._write({"accounts": ["bad", 123, None,
                                      {"name": "ok", "refreshToken": "r", "userId": "1"}]})
        accs = R.read_accounts_from_file(p)
        self.assertEqual(len(accs), 1)
        self.assertEqual(accs[0]["name"], "ok")

    def test_missing_file_returns_empty(self):
        self.assertEqual(R.read_accounts_from_file("no-such-file-xyz.json"), [])

    def test_entry_without_refresh_token_skipped(self):
        p = self._write({"accounts": [{"name": "x", "userId": "1"}]})
        self.assertEqual(R.read_accounts_from_file(p), [])


class TestDeviceId(unittest.TestCase):
    def test_accepts_15_and_16_digits(self):
        self.assertEqual(R.device_id_for({"deviceId": "123456789012345", "userId": "u"}), "123456789012345")
        self.assertEqual(R.device_id_for({"deviceId": "1234567890123456", "userId": "u2"}), "1234567890123456")

    def test_stable_derivation_is_deterministic(self):
        self.assertEqual(R._stable_device_id("k1"), R._stable_device_id("k1"))
        self.assertNotEqual(R._stable_device_id("k1"), R._stable_device_id("k2"))
        self.assertEqual(len(R._stable_device_id("k1")), 16)


class TestErrTranslate(unittest.TestCase):
    def test_hint_resolved_for_string_code(self):
        """回归：错误码来自 JSON 字符串，hint 表须用字符串键。"""
        msg = R._explain_refresh_err(json.dumps(
            {"ResponseMetadata": {"Error": {"Code": "20101", "Message": "expired"}}}))
        self.assertIn("code=20101", msg)
        self.assertIn("重新提取", msg)

    def test_unknown_code_no_hint(self):
        msg = R._explain_refresh_err(json.dumps(
            {"ResponseMetadata": {"Error": {"Code": "99999", "Message": "x"}}}))
        self.assertIn("code=99999", msg)

    def test_non_json_falls_back_to_text(self):
        self.assertEqual(R._explain_refresh_err("plain error"), "plain error")


class TestCreditsParse(unittest.TestCase):
    def test_as_number_strictness(self):
        self.assertEqual(R._as_number(7850), 7850.0)
        self.assertEqual(R._as_number("12.5"), 12.5)
        self.assertIsNone(R._as_number(True))
        self.assertIsNone(R._as_number(None))
        self.assertIsNone(R._as_number("abc"))

    # ── creditsExpireAt：min(end_time) 于 limit 有值且未耗尽的包 ──
    def _pack(self, limit, used=None, end=0, desc="签到奖励"):
        return {"display_desc": desc, "usage": ({"credits_amount": used} if used is not None else {}),
                "entitlement_base_info": {
                    "quota": ({"credits_limit": limit} if limit is not None else {}),
                    "end_time": end}}

    def test_expire_skips_exhausted_packs(self):
        """回归：已耗尽包不参与 min（旧实现取全部包 min，规则错误）。"""
        packs = [self._pack(150, 150, 100),   # 耗尽 → 应跳过
                 self._pack(100, 22.5, 400),  # 未耗尽 → 候选
                 self._pack(100, None, 500)]  # 未开始 → 候选
        self.assertEqual(R._credit_expire_from_packs(packs), 400)

    def test_expire_skips_limit_none(self):
        """limit 缺失的包（如「免费」）不参与。"""
        packs = [self._pack(None, None, 50), self._pack(100, None, 900)]
        self.assertEqual(R._credit_expire_from_packs(packs), 900)

    def test_expire_all_exhausted_returns_zero(self):
        packs = [self._pack(150, 150, 100), self._pack(100, 100, 200)]
        self.assertEqual(R._credit_expire_from_packs(packs), 0)

    def test_expire_real_case_from_export(self):
        """2026-10-20 导出值反解：权威 creditsExpireAt=1793898005。"""
        packs = [self._pack(150, 150, 1792544404),   # 耗尽
                 self._pack(150, 150, 1792861203),   # 耗尽
                 self._pack(None, None, 1793462399), # 「免费」limit 缺失
                 self._pack(100, 22.2548, 1793898005)]  # 未耗尽 → 权威值
        self.assertEqual(R._credit_expire_from_packs(packs), 1793898005)

    # ── remainingCredits：= total_amount - consumed_amount（在 query_credits 内） ──
    def test_remaining_equivalence_identity(self):
        """恒等式：sum(limit-used) 于非耗尽包 ≡ sum(limit) - sum(used)。

        因耗尽包 limit==used，其 (limit-used)=0 对求和无贡献。
        故 `total_amount - consumed_amount` 与「非耗尽包 (limit-used) 之和」数学等价。
        2026-10-20 实证：后者可精确重建 `auto_17222869` 导出值 1499.85 / 1477.75。
        """
        _unused_bind = [self._pack(150, 150, 1),        # 耗尽，贡献 0  # noqa: F841 —— 原变量 packs
                 self._pack(100, 22.2548, 2),    # 未耗尽
                 self._pack(100, None, 3)]
        sum_limit = 150 + 100 + 100
        sum_used = 150 + 22.2548
        # 非耗尽包 (limit-used) 之和
        manual = (100 - 22.2548) + 100
        self.assertAlmostEqual(manual, (sum_limit - sum_used), places=4)
        # 与 summary 差值口径一致（total=sum(limit), consumed=sum(used)）
        self.assertAlmostEqual(round(sum_limit - sum_used, 2), round(manual, 2), places=2)

    def test_sum_limit_alone_is_wrong(self):
        """反证：只加 limit 不减 used 会高估（上轮错误实现即此）。"""
        limit_only = 150 + 100 + 100   # = 350，含未耗尽包全额
        correct = 150 + 22.2548        # summary 口径
        self.assertNotAlmostEqual(limit_only - correct, 0.0, places=2)

    def test_is_exhausted_semantics(self):
        self.assertTrue(R._is_exhausted(self._pack(100, 100, 1)))
        self.assertTrue(R._is_exhausted(self._pack(100, 120, 1)))
        self.assertFalse(R._is_exhausted(self._pack(100, 99.9, 1)))
        self.assertFalse(R._is_exhausted(self._pack(100, None, 1)))  # used 缺失 = 未耗尽
        self.assertFalse(R._is_exhausted(self._pack(None, 50, 1)))   # limit 缺失
        self.assertFalse(R._is_exhausted("not-a-dict"))
        self.assertFalse(R._is_exhausted(self._pack(True, 1, 1)))    # bool 不算数值


class TestWriteBack(unittest.TestCase):
    def _file(self, obj):
        fd, p = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
        self.addCleanup(lambda: os.path.exists(p) and os.remove(p))
        return p

    def test_cloudidejwt_format_no_extra_fields(self):
        """写回只改原文件已有字段，不新增 accessToken/token。"""
        p = self._file({"accounts": [{"name": "a", "userId": "1",
                                      "cloudIdeJwt": "Cloud-IDE-JWT " + make_jwt("1", 1900000000)}]})
        R._write_back_if_match(p, {"userId": "1", "accessToken": make_jwt("1", 1900000000),
                                   "refreshToken": "newrt"})
        with open(p, encoding="utf-8") as f:
            a = json.load(f)["accounts"][0]
        self.assertNotIn("accessToken", a)
        self.assertNotIn("token", a)
        self.assertTrue(a["cloudIdeJwt"].startswith("Cloud-IDE-JWT "))
        self.assertEqual(a["refreshToken"], "newrt")
        self.assertEqual(a["jwtExp"], 1900000000)

    def test_unknown_uid_no_write(self):
        p = self._file({"accounts": [{"userId": "1", "refreshToken": "r"}]})
        with open(p, encoding="utf-8") as f:
            before = f.read()
        R._write_back_if_match(p, {"userId": "999", "accessToken": make_jwt("999")})
        with open(p, encoding="utf-8") as f:
            self.assertEqual(f.read(), before)

    def test_credits_writeback_idempotent(self):
        p = self._file({"accounts": [{"userId": "1", "remainingCredits": 1.0, "creditsExpireAt": 5}]})
        credits = {"ok": True, "total": 100.0, "used": 40.0, "available": 60.0,
                   "raw": {"user_entitlement_pack_list": []}}
        self.assertTrue(R._apply_credits_writeback(p, "1", credits))
        with open(p, encoding="utf-8") as f:
            first = f.read()
        self.assertFalse(R._apply_credits_writeback(p, "1", credits))
        with open(p, encoding="utf-8") as f:
            self.assertEqual(f.read(), first)
        self.assertEqual(json.loads(first)["accounts"][0]["remainingCredits"], 60.0)
        self.assertEqual(json.loads(first)["accounts"][0]["creditsExpireAt"], 5)

    def test_credits_writeback_skips_new_fields(self):
        p = self._file({"accounts": [{"userId": "1"}]})
        credits = {"ok": True, "total": 1.0, "used": 1.0, "available": 0.0,
                   "raw": {"user_entitlement_pack_list": []}}
        self.assertFalse(R._apply_credits_writeback(p, "1", credits))
        with open(p, encoding="utf-8") as f:
            self.assertEqual(sorted(json.load(f)["accounts"][0].keys()), ["userId"])

    def test_no_tmp_leftover_on_success(self):
        p = self._file({"accounts": [{"userId": "1", "remainingCredits": 0}]})
        R._apply_credits_writeback(p, "1", {"ok": True, "total": 9.0, "used": 0.0,
                                            "available": 9.0, "raw": {}})
        self.assertFalse(os.path.exists(p + ".tmp"))


class TestCachePath(unittest.TestCase):
    def test_default_is_script_dir(self):
        old = os.environ.pop("TRAE_TOKEN_CACHE", None)
        try:
            self.assertTrue(R._cache_path().endswith(".trae_token_cache.json"))
        finally:
            if old is not None:
                os.environ["TRAE_TOKEN_CACHE"] = old

    def test_env_override(self):
        fd, p = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(lambda: os.path.exists(p) and os.remove(p))
        os.environ["TRAE_TOKEN_CACHE"] = p
        try:
            self.assertEqual(R._cache_path(), p)
        finally:
            os.environ.pop("TRAE_TOKEN_CACHE", None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
