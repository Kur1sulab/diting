# -*- coding: utf-8 -*-
"""资产归属边界回归（Python 侧，与 engine-go/subdomain/scope_boundary_test.go 同表钉 parity）。

缺口：_from_crtsh / _from_certspotter 用裸 name.endswith(domain) 过滤，
没有 "." 边界——target=example.com 时 notexample.com / evilexample.com
这类形似 apex 的无关域被当成子域收进 subdomains.txt，下游 verify /
portscan / 报告打到范围外资产。多 SAN 证书（共享主机/CDN）的
name_value / dns_names 是真实投递路径。

修复后期望：apex + 真子域保留（*. 通配归一、大小写去重），形似域剔除。
与 modules/jsintel.py extract_domains（d == t or d.endswith("." + t)）同规则。
"""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from modules import subdomain  # noqa: E402

NAMES = ["example.com", "mail.example.com", "*.example.com",
         "notexample.com", "evilexample.com", "MAIL.example.com"]
WANT = ["example.com", "mail.example.com"]


class ScopeBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.orig_fetch = subdomain.netutil.fetch
        self.orig_check = subdomain.netutil.check_http_url
        subdomain.netutil.check_http_url = lambda u, allow_private=False: u

    def tearDown(self):
        subdomain.netutil.fetch = self.orig_fetch
        subdomain.netutil.check_http_url = self.orig_check

    def _stub(self, body):
        subdomain.netutil.fetch = lambda url, timeout=30, **kw: {
            "ok": True, "status": 200, "body": body}

    def test_crtsh_multisan_boundary(self):
        self._stub(json.dumps([{"name_value": "\n".join(NAMES)}]))
        got = subdomain._from_crtsh("example.com")
        self.assertEqual(got, WANT,
                         "范围外域混入子域清单: %r（notexample.com / evilexample.com 不是 example.com 的子域）" % got)

    def test_certspotter_multisan_boundary(self):
        self._stub(json.dumps([{"dns_names": NAMES}]))
        got = subdomain._from_certspotter("example.com")
        self.assertEqual(got, WANT,
                         "范围外域混入子域清单: %r" % got)


if __name__ == "__main__":
    unittest.main()
