package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/diting/engine-go/jsonx"
	"github.com/Kur1sulab/diting/engine-go/netutil"
)

// TestReportRendersWAFSection 钉住「被拦 ≠ 不存在」这句结论必须进报告。
// 只在 waf.json 有命中时出现；没跑 verify 的项目不许凭空多出一节。
func TestReportRendersWAFSection(t *testing.T) {
	out := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if _, err := netutil.SafeWrite(out, name, content); err != nil {
			t.Fatal(err)
		}
	}
	write("subdomains.txt", "a.example.com\nb.example.com\n")
	write("subdomains_live.json", jsonx.Compact([]map[string]any{
		{"host": "a.example.com", "ips": []string{"1.2.3.4"}, "alive": true,
			"http": map[string]any{"scheme": "https", "status": 403, "title": "Just a moment...",
				"final_url": "https://a.example.com/",
				"waf": map[string]any{"vendor": "cloudflare", "confidence": "high",
					"challenge": "js_challenge",
					"evidence":  []string{"header:cf-ray=8f2a-LAX", "cookie:__cf_bm"}}}},
		{"host": "b.example.com", "ips": []any{}, "alive": false, "http": map[string]any{}},
	}))
	write("waf.json", jsonx.Compact(map[string]any{
		"generated_at": "2026-11-23T00:00:00+08:00",
		"stats": map[string]any{
			"alive": 2, "http_responded": 1, "waf_detected": 1,
			"by_vendor":     map[string]any{"cloudflare": 1},
			"by_confidence": map[string]any{"high": 1},
			"by_challenge":  map[string]any{"js_challenge": 1},
		},
		"assets": []map[string]any{
			{"host": "a.example.com", "ips": []string{"1.2.3.4"}, "scheme": "https",
				"status": 403, "final_url": "https://a.example.com/",
				"waf": map[string]any{"vendor": "cloudflare", "confidence": "high",
					"challenge": "js_challenge",
					"evidence":  []string{"header:cf-ray=8f2a-LAX", "cookie:__cf_bm"}}},
		},
	}))

	md := RenderMD(Collect(out, "example.com"))
	for _, want := range []string{
		"### 2.1 WAF / bot 挑战",
		"被拦 ≠ 不存在",
		"cloudflare",
		"js_challenge",
		"header:cf-ray=8f2a-LAX",
	} {
		if !strings.Contains(md, want) {
			t.Fatalf("报告缺少 %q:\n%s", want, md)
		}
	}
}

// TestReportNoWAFSectionWhenEmpty 没有 waf.json 时不许出现 WAF 小节
// （否则每个老项目都会多一条「0 命中」，等于噪声）。
func TestReportNoWAFSectionWhenEmpty(t *testing.T) {
	out := t.TempDir()
	if _, err := netutil.SafeWrite(out, "subdomains.txt", "a.example.com\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := netutil.SafeWrite(out, "subdomains_live.json", jsonx.Compact([]map[string]any{
		{"host": "a.example.com", "ips": []string{"1.2.3.4"}, "alive": true,
			"http": map[string]any{"scheme": "https", "status": 200, "waf": nil}},
	})); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "waf.json")); err == nil {
		t.Fatal("前置条件：不应有 waf.json")
	}
	md := RenderMD(Collect(out, "example.com"))
	if strings.Contains(md, "WAF / bot 挑战") {
		t.Fatalf("无 waf.json 时不该出现 WAF 小节:\n%s", md)
	}
}
