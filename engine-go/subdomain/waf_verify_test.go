package subdomain

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/diting/engine-go/waf"
)

// captureStdout 捕获 Stdout 期间的 fmt.Printf 输出（本包内自用，避免跨包依赖测试文件）。
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// wafSite 起一个本地靶站，模拟被 Cloudflare 拦住的资产。
// 全程 127.0.0.1 + httptest，离线、无外网依赖。
func wafSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "8f2a1b3c4d5e-LAX")
		w.Header().Set("CF-Mitigated", "challenge")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: ".7Q2xYzAbC123", Path: "/"})
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Just a moment...</title></head>" +
			"<body><script src=/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1></script></body></html>"))
	})
	return httptest.NewServer(mux)
}

// TestHTTPProbeAttachesWAF 是整条链路的接缝测试：
// 真实 HTTP 响应 → netutil.Fetch（含多值 Set-Cookie）→ waf.Detect → ProbeResult.WAF。
func TestHTTPProbeAttachesWAF(t *testing.T) {
	srv := wafSite(t)
	defer srv.Close()
	port := portOf(t, srv.URL)

	got := HTTPProbe("127.0.0.1", 3e9, port)
	if got.Status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403（WAF 拦截页本身就是一个有效响应）", got.Status)
	}
	if got.WAF == nil {
		t.Fatal("被 CF 拦住的响应必须带上 waf 属性，否则又会退化成「目标不存在」")
	}
	if got.WAF.Vendor != "cloudflare" || got.WAF.Confidence != waf.ConfHigh {
		t.Fatalf("waf = %s, want cloudflare/high", got.WAF.String())
	}
	if got.WAF.Challenge != waf.ChalJS {
		t.Fatalf("challenge = %q, want js_challenge", got.WAF.Challenge)
	}
	// 证据链里必须能看见 Cookie：这正是 netutil 新增 Cookies 旁路的意义，
	// 若仍走 Headers["set-cookie"] 单值，多 Cookie 站点会漏判。
	joined := strings.Join(got.WAF.Evidence, "|")
	if !strings.Contains(joined, "__cf_bm") {
		t.Fatalf("证据缺 __cf_bm，多值 Set-Cookie 可能又被折叠了: %v", got.WAF.Evidence)
	}
}

// TestHTTPProbeCleanSiteHasNoWAF 反向断言：干净站点不许凭空长出 WAF 属性。
func TestHTTPProbeCleanSiteHasNoWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Hello</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	got := HTTPProbe("127.0.0.1", 3e9, portOf(t, srv.URL))
	if got.Status != 200 {
		t.Fatalf("status = %d", got.Status)
	}
	if got.WAF != nil {
		t.Fatalf("干净站点不应有 waf 属性，实际 %s（%v）", got.WAF.String(), got.WAF.Evidence)
	}
}

// TestVerifyRowJSONWAFContract 钉住落盘形态：
//   - 有 WAF 的存活行：http 里带 waf 对象；
//   - 存活但无 WAF：http.waf 为 null（区分「探过、没有」与「没探」）；
//   - 死亡行：http 仍是 {}，与 Python 逐字节一致（存量 fix1 断言不许破）。
func TestVerifyRowJSONWAFContract(t *testing.T) {
	withWAF := VerifyRow{
		Host: "a.example.com", IPs: []string{"1.2.3.4"}, Alive: true,
		HTTP: ProbeResult{
			Scheme: "https", Status: 403, Title: "Just a moment...",
			WAF: &waf.Attribute{Vendor: "cloudflare", Confidence: waf.ConfHigh,
				Challenge: waf.ChalJS, Evidence: []string{"header:cf-ray=abc-LAX"}},
		},
	}
	b, err := json.Marshal(withWAF)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"waf":{"vendor":"cloudflare","confidence":"high","challenge":"js_challenge"`) {
		t.Fatalf("waf 对象未按契约落盘: %s", b)
	}

	noWAF := withWAF
	noWAF.HTTP.WAF = nil
	b2, _ := json.Marshal(noWAF)
	if !strings.Contains(string(b2), `"waf":null`) {
		t.Fatalf("探活成功但无 WAF 时应显式 null: %s", b2)
	}

	dead := VerifyRow{Host: "..", Alive: false}
	b3, _ := json.Marshal(dead)
	if string(b3) != `{"host":"..","ips":[],"alive":false,"http":{}}` {
		t.Fatalf("死亡行形态漂移（会破 parity）: %s", b3)
	}
}

// TestWriteWAFSummarySchema 验证产物接线：waf.json 必须可被下游直接解析，
// 且命中/未命中/unknown 三类都按契约落盘。全程内存构造，不碰网络。
func TestWriteWAFSummarySchema(t *testing.T) {
	out := t.TempDir()
	nowStamp = func() string { return "2026-11-23T00:00:00+08:00" }
	defer func() { nowStamp = func() string { return "" } }()

	rows := []VerifyRow{
		{Host: "a.example.com", IPs: []string{"1.2.3.4"}, Alive: true,
			HTTP: ProbeResult{Scheme: "https", Status: 403, FinalURL: "https://a.example.com/",
				WAF: &waf.Attribute{Vendor: "cloudflare", Confidence: waf.ConfHigh,
					Challenge: waf.ChalJS, Evidence: []string{"header:cf-ray=abc-LAX"}}}},
		{Host: "b.example.com", IPs: []string{"1.2.3.4"}, Alive: true,
			HTTP: ProbeResult{Scheme: "https", Status: 200, FinalURL: "https://b.example.com/"}},
		{Host: "c.example.com", Alive: false},
		{Host: "d.example.com", IPs: []string{"1.2.3.4"}, Alive: true,
			HTTP: ProbeResult{Scheme: "http", Status: 403,
				WAF: &waf.Attribute{Vendor: waf.VendorUnknown, Confidence: waf.ConfLow,
					Challenge: waf.ChalNone, Evidence: []string{"status:403 + body:非法请求"}}}},
	}
	writeWAFSummary(out, rows)

	raw, err := os.ReadFile(filepath.Join(out, "waf.json"))
	if err != nil {
		t.Fatalf("必须产出 waf.json: %v", err)
	}
	var doc waf.Summary
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("waf.json 不是合法 Summary: %v\n%s", err, raw)
	}
	if doc.GeneratedAt != "2026-11-23T00:00:00+08:00" {
		t.Fatalf("generated_at = %q", doc.GeneratedAt)
	}
	if doc.Stats.Alive != 4 || doc.Stats.HTTPResponded != 3 || doc.Stats.WAFDetected != 2 {
		t.Fatalf("stats = %+v, want alive=4 http=3 waf=2", doc.Stats)
	}
	if doc.Stats.ByVendor["cloudflare"] != 1 || doc.Stats.ByVendor["unknown"] != 1 {
		t.Fatalf("by_vendor = %v", doc.Stats.ByVendor)
	}
	if doc.Stats.ByChallenge["js_challenge"] != 1 || doc.Stats.ByChallenge["none"] != 1 {
		t.Fatalf("by_challenge = %v", doc.Stats.ByChallenge)
	}
	// assets 只含判出 WAF 的，且按 host 排序（产物要可 diff）。
	if len(doc.Assets) != 2 || doc.Assets[0].Host != "a.example.com" || doc.Assets[1].Host != "d.example.com" {
		t.Fatalf("assets = %+v", doc.Assets)
	}
	// 未命中的资产不许出现在 assets 里（避免 Kara 把干净资产也走绕行分支）。
	for _, a := range doc.Assets {
		if a.Host == "b.example.com" {
			t.Fatal("无 WAF 的资产不应进 assets")
		}
	}
}

// TestPrintWAFSummaryHasBlockedHint 钉住 CLI 文案：必须明说「被拦 ≠ 不存在」。
func TestPrintWAFSummaryHasBlockedHint(t *testing.T) {
	st := waf.Stats{
		Alive: 3, HTTPResponded: 3, WAFDetected: 2,
		ByVendor:     map[string]int{"cloudflare": 1, "unknown": 1},
		ByConfidence: map[string]int{"high": 1, "low": 1},
		ByChallenge:  map[string]int{"js_challenge": 1, "none": 1},
	}
	out := captureStdout(t, func() { printWAFSummary(st, "waf.json") })
	for _, want := range []string{"2/3", "被拦 ≠ 不存在", "cloudflare", "js_challenge", "unknown"} {
		if !strings.Contains(out, want) {
			t.Fatalf("CLI 输出缺 %q:\n%s", want, out)
		}
	}
}
