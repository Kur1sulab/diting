package fingerprint

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/diting/engine-go/waf"
)

// TestRunFingerprintBlockedByWAF 是本次改动的病灶复现：
// WAF 返回 403 时，旧实现只打印「请求失败」并把空数组写进 fingerprint.json，
// 使用者看到的是「目标没响应」——这就是把「被拦」误报成「不存在」。
// 新行为：明确报出 WAF 判定，并落 waf.json。
func TestRunFingerprintBlockedByWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "8f2a1b3c4d5e-LAX")
		w.Header().Set("CF-Mitigated", "challenge")
		http.SetCookie(w, &http.Cookie{Name: "__cf_bm", Value: "abc", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html><head><title>Just a moment...</title></head>" +
			"<script src=/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1></script></html>"))
	}))
	defer srv.Close()

	out := t.TempDir()
	RunFingerprint(srv.URL, out)

	// fingerprint.json 形态不变（Python parity）：被拦时就是空数组。
	raw, err := os.ReadFile(filepath.Join(out, "fingerprint.json"))
	if err != nil {
		t.Fatalf("fingerprint.json 必须仍然产出: %v", err)
	}
	var hits []Hit
	if err := json.Unmarshal(raw, &hits); err != nil {
		t.Fatalf("fingerprint.json 形态漂移: %v\n%s", err, raw)
	}
	if len(hits) != 0 {
		t.Fatalf("403 页面不该产出技术指纹: %v", hits)
	}

	// waf.json 必须产出且判出 cloudflare。
	wraw, err := os.ReadFile(filepath.Join(out, "waf.json"))
	if err != nil {
		t.Fatalf("被 WAF 拦截时必须落 waf.json: %v", err)
	}
	var sum waf.Summary
	if err := json.Unmarshal(wraw, &sum); err != nil {
		t.Fatalf("waf.json 解析失败: %v\n%s", err, wraw)
	}
	if sum.Stats.WAFDetected != 1 || sum.Stats.HTTPResponded != 1 {
		t.Fatalf("stats = %+v", sum.Stats)
	}
	if len(sum.Assets) != 1 || sum.Assets[0].WAF == nil {
		t.Fatalf("assets = %+v", sum.Assets)
	}
	if sum.Assets[0].WAF.Vendor != "cloudflare" || sum.Assets[0].WAF.Confidence != waf.ConfHigh {
		t.Fatalf("waf = %s", sum.Assets[0].WAF.String())
	}
	if !strings.HasPrefix(sum.Assets[0].Scheme, "http") {
		t.Fatalf("scheme 应取自 URL: %q", sum.Assets[0].Scheme)
	}
}

// TestRunFingerprintCleanSiteNoWAF 干净站点：waf.json 照写，但 assets 为空。
func TestRunFingerprintCleanSiteNoWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Hi</title></head><body>ok</body></html>"))
	}))
	defer srv.Close()

	out := t.TempDir()
	RunFingerprint(srv.URL, out)

	wraw, err := os.ReadFile(filepath.Join(out, "waf.json"))
	if err != nil {
		t.Fatalf("waf.json 应无条件产出（区分「探过、没有」与「没探」）: %v", err)
	}
	var sum waf.Summary
	if err := json.Unmarshal(wraw, &sum); err != nil {
		t.Fatal(err)
	}
	if sum.Stats.WAFDetected != 0 || len(sum.Assets) != 0 {
		t.Fatalf("干净站点不该有 WAF: %+v", sum.Stats)
	}
}
