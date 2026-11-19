package subdomain

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 与 tests/test_scope_boundary.py 同表钉 parity：同一 fixture、同一期望。
var scopeBoundaryNames = []string{
	"example.com", "mail.example.com", "*.example.com",
	"notexample.com", "evilexample.com", "MAIL.example.com",
}

var scopeBoundaryWant = []string{"example.com", "mail.example.com"}

// TestCollectNamesScopeBoundary —— 修复前失败：裸 HasSuffix(name, suffix)
// 把 notexample.com / evilexample.com 当成 example.com 的子域收进
// subdomains.txt，下游 verify / portscan / 报告全部打到范围外资产。
// apex 与真子域（含大小写去重、*. 通配归一）必须保留。
func TestCollectNamesScopeBoundary(t *testing.T) {
	got := collectNames(1, func(int) []string { return scopeBoundaryNames }, "example.com")
	if strings.Join(got, "|") != strings.Join(scopeBoundaryWant, "|") {
		t.Fatalf("collectNames 边界过滤:\n got  = %v\n want = %v", got, scopeBoundaryWant)
	}
}

// TestCertChannelsScopeBoundary —— 端到端走 FromCrtSh / FromCertspotter：
// 多 SAN 证书 fixture（crt.sh name_value / certspotter dns_names 同名集），
// 两通道都必须只留 apex + 真子域。
func TestCertChannelsScopeBoundary(t *testing.T) {
	withStubs(t, func() {
		crtBody := `[{"name_value":"example.com\nmail.example.com\n*.example.com\nnotexample.com\nevilexample.com"}]`
		crtSrv := crtShStub(t, crtBody, 0)
		defer crtSrv.Close()
		csBody := `[{"dns_names":["example.com","mail.example.com","*.example.com","notexample.com","evilexample.com"]}]`
		csSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(csBody))
		}))
		defer csSrv.Close()
		CrtShURL = crtSrv.URL + "/?q=%%25.%s&output=json"
		CertspotterURL = csSrv.URL + "/?domain=%s&include_subdomains=true&expand=dns_names"

		got := FromCrtSh("example.com", 3)
		if strings.Join(got, "|") != strings.Join(scopeBoundaryWant, "|") {
			t.Fatalf("FromCrtSh 边界过滤:\n got  = %v\n want = %v", got, scopeBoundaryWant)
		}
		got, err := FromCertspotter("example.com")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, "|") != strings.Join(scopeBoundaryWant, "|") {
			t.Fatalf("FromCertspotter 边界过滤:\n got  = %v\n want = %v", got, scopeBoundaryWant)
		}
	})
}
