package intel

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
)

// TestPassiveSourceScopeBoundary —— 资产归属边界回归（修复前失败）。
//
// 缺口：六个免 key 被动源都用裸 strings.HasSuffix(name, target) 过滤主机名，
// 没有 "." 边界——target=example.com 时 notexample.com / evilexample.com
// 这类「形似 apex 的无关域」会被当成子域收进 assets.json / assets.txt /
// intel.md，下游 verify / portscan / report 随之打到范围外资产。
//
// 真实投递路径：crt.sh / certspotter 按「证书含任一目标身份」匹配，多 SAN
// 证书（共享主机 / CDN 常见）的 name_value / dns_names 会同时携带无关域；
// 被动 DNS / urlscan 数据同理可能混入形似域。
//
// 断言：apex 与真子域保留（含 *. 通配归一），形似域必须剔除。
// 与 jsintel.ExtractDomains（h == t || HasSuffix(h, "."+t)）同规则。
func TestPassiveSourceScopeBoundary(t *testing.T) {
	cases := []struct {
		name string
		body string
		fn   func(context.Context, string, Options) ([]Record, error)
	}{
		{"crtsh",
			`[{"name_value":"example.com\nmail.example.com\n*.example.com\nnotexample.com\nevilexample.com"}]`,
			queryCrtSh},
		{"certspotter",
			`[{"dns_names":["example.com","mail.example.com","*.example.com","notexample.com","evilexample.com"]}]`,
			queryCertSpotter},
		{"hackertarget",
			"example.com,93.184.216.34\nmail.example.com,93.184.216.35\nnotexample.com,1.2.3.4\nevilexample.com,5.6.7.8\n",
			queryHackerTarget},
		{"rapiddns",
			`<table><tr><td>example.com</td><td>A</td><td>2026-11-19</td></tr>` +
				`<tr><td>mail.example.com</td><td>A</td><td>2026-11-19</td></tr>` +
				`<tr><td>notexample.com</td><td>A</td><td>2026-11-19</td></tr>` +
				`<tr><td>evilexample.com</td><td>A</td><td>2026-11-19</td></tr></table>`,
			queryRapidDNS},
		{"urlscan",
			`{"results":[{"page":{"domain":"example.com"}},{"page":{"domain":"mail.example.com"}},` +
				`{"page":{"domain":"notexample.com"}},{"page":{"domain":"evilexample.com"}}]}`,
			queryURLScan},
		{"subdomaincenter",
			`["example.com","mail.example.com","*.example.com","notexample.com","evilexample.com"]`,
			querySubdomainCenter},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := stub(t, c.name, func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(c.body))
			})
			// crtsh 的 endpoint 是 fmt.Sprintf 模板（必须含 %s），其余源直接拼 URL。
			ep := srv.URL
			if c.name == "crtsh" {
				ep = srv.URL + "/?q=%%25.%s&output=json"
			}
			recs, err := c.fn(context.Background(), "example.com",
				Options{Endpoints: map[string]string{c.name: ep}})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, r := range recs {
				got = append(got, r.Host)
			}
			sort.Strings(got)
			want := []string{"example.com", "mail.example.com"}
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("范围外域混入资产清单:\n got  = %v\n want = %v\n（notexample.com / evilexample.com 不是 example.com 的子域）", got, want)
			}
		})
	}
}
