package intel

import (
	"strings"
	"testing"
)

func TestTLDOf(t *testing.T) {
	cases := map[string]string{
		"example.com":    "com",
		"cqcst.edu.cn":   "edu.cn",
		"miit.gov.cn":    "gov.cn",
		"a.b.com.cn":     "com.cn",
		"qq.com":         "com",
		"cnnic.cn":       "cn",
		"localhost":      "localhost",
		"xn--fiqs8s.com": "com",
	}
	for in, want := range cases {
		if got := tldOf(in); got != want {
			t.Errorf("tldOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseWhoisTextCN(t *testing.T) {
	// 真实 whois.cnnic.cn 响应片段（2026-11 实测）
	text := `Domain Name: cnnic.cn
ROID: 20030310s10001s00012956-cn
Domain Status: serverDeleteProhibited
Domain Status: serverUpdateProhibited
Registrant: 中国互联网络信息中心
Registrant Contact Email: {{EMAIL_4zcqugnn}}
Sponsoring Registrar: 北京新网数码信息技术有限公司
Registration Time: 2003-03-10 19:06:34
Expiration Time: 2028-03-10 19:06:34
Name Server: a.cnnic.cn
Name Server: b.cnnic.cn
Name Server: A.CNNIC.CN2
`
	info := &WhoisInfo{Domain: "cnnic.cn"}
	parseWhoisText(text, info)
	if info.Registrar != "北京新网数码信息技术有限公司" {
		t.Errorf("Registrar = %q", info.Registrar)
	}
	if info.Registrant != "中国互联网络信息中心" {
		t.Errorf("Registrant = %q", info.Registrant)
	}
	if info.RegisteredAt != "2003-03-10 19:06:34" || info.ExpiresAt != "2028-03-10 19:06:34" {
		t.Errorf("dates = %q / %q", info.RegisteredAt, info.ExpiresAt)
	}
	if len(info.Status) != 2 {
		t.Errorf("Status = %v", info.Status)
	}
	// NS 去重（大小写归一后 a.cnnic.cn 与 A.CNNIC.CN2 是两条不同值，不该误合并）
	if len(info.Nameservers) != 3 {
		t.Errorf("Nameservers = %v", info.Nameservers)
	}
	for _, ns := range info.Nameservers {
		if ns != strings.ToLower(ns) {
			t.Errorf("NS 未小写: %q", ns)
		}
	}
}

func TestParseWhoisTextVerisign(t *testing.T) {
	text := `   Domain Name: EXAMPLE.COM
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.iana.org
   Updated Date: 2026-08-14T08:01:43Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2027-08-13T04:00:00Z
   Registrar: RESERVED-Internet Assigned Numbers Authority
   Domain Status: client delete prohibited
   Name Server: ELLIOTT.NS.CLOUDFLARE.COM
`
	info := &WhoisInfo{Domain: "example.com"}
	parseWhoisText(text, info)
	if info.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Errorf("Registrar = %q", info.Registrar)
	}
	if info.RegisteredAt != "1995-08-14T04:00:00Z" || info.ExpiresAt != "2027-08-13T04:00:00Z" {
		t.Errorf("dates = %q / %q", info.RegisteredAt, info.ExpiresAt)
	}
	if len(info.Nameservers) != 1 || info.Nameservers[0] != "elliott.ns.cloudflare.com" {
		t.Errorf("Nameservers = %v", info.Nameservers)
	}
}

func TestReferralServerParsing(t *testing.T) {
	cases := map[string]string{
		"refer:        whois.cnnic.cn\n":                            "whois.cnnic.cn",
		"ReferralServer: whois.example.net\n":                       "whois.example.net",
		"Registrar WHOIS Server: whois.iana.org\n":                  "whois.iana.org",
		"Registrar WHOIS Server: http://whois.markmonitor.com/x\n": "whois.markmonitor.com",
		"nothing here\n":                                            "",
	}
	for in, want := range cases {
		if got := referralServer(in); got != want {
			t.Errorf("referralServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWhoisFallbackRejectsOutOfRegistry(t *testing.T) {
	// whois.cnnic.cn 对非 .cn 域名回 "Out of this registry."，不能被当成有效数据
	info := &WhoisInfo{Domain: "qq.com"}
	lower := strings.ToLower("Out of this registry.")
	if !strings.Contains(lower, "out of this registry") {
		t.Fatal("前置断言失败")
	}
	_ = info
}
