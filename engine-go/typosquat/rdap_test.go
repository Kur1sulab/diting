package typosquat

// rdap_test.go —— RDAP 解析 / 缓存 / 429 退避 / 404 语义（httptest 本地桩，零外网）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

const rdapFixture = `{
  "ldhName": "example.com",
  "status": ["active"],
  "events": [
    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2026-08-14T07:01:31Z"}
  ],
  "entities": [
    {"roles": ["registrar"], "vcardArray": ["vcard", [
      ["version", {}, "text", "4.0"],
      ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]
    ]]},
    {"roles": ["registrant"], "vcardArray": ["vcard", [
      ["version", {}, "text", "4.0"],
      ["fn", {}, "text", "REDACTED FOR PRIVACY"]
    ]]}
  ],
  "nameservers": [{"ldhName": "a.iana-servers.net"}, {"ldhName": "b.iana-servers.net"}]
}`

func startRDAPStub(t *testing.T) (*httptest.Server, *int64, *int64) {
	t.Helper()
	var total, limitedCalls int64
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/bootstrap", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&total, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprintf(w, `{"services":[[["com","net"],[%q]]]}`, srvURL+"/")
	})
	mux.HandleFunc("/domain/example.com", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&total, 1)
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, rdapFixture)
	})
	mux.HandleFunc("/domain/missing.com", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&total, 1)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"errorCode":404,"title":"Not Found"}`)
	})
	mux.HandleFunc("/domain/limited.com", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&total, 1)
		if atomic.AddInt64(&limitedCalls, 1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"errorCode":429,"title":"Too Many Requests"}`)
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, rdapFixture)
	})
	mux.HandleFunc("/domain/backoff.com", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&total, 1)
		if atomic.AddInt64(&limitedCalls, 1) <= 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // 无 Retry-After → 指数退避
			return
		}
		w.Header().Set("Content-Type", "application/rdap+json")
		fmt.Fprint(w, rdapFixture)
	})
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)
	return srv, &total, &limitedCalls
}

func testRDAPClient(t *testing.T, srv *httptest.Server, dir string) *RDAPClient {
	t.Helper()
	c := NewRDAPClient(RDAPOptions{
		QPS: 1000, CacheDir: dir, BootstrapURL: srv.URL + "/bootstrap",
		BaseBackoff: time.Millisecond, MaxRetries: 3, Timeout: 5 * time.Second,
	})
	c.HTTP = srv.Client()
	return c
}

func TestRDAPLookupAndParse(t *testing.T) {
	srv, total, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	ctx := context.Background()

	info := c.Lookup(ctx, "example.com")
	if info.Error != "" {
		t.Fatalf("RDAP 查询失败: %s", info.Error)
	}
	wantReg := time.Date(1995, 8, 14, 4, 0, 0, 0, time.UTC)
	if !info.RegisteredAt.Equal(wantReg) {
		t.Fatalf("注册日期应 %v, got %v", wantReg, info.RegisteredAt)
	}
	wantExp := time.Date(2027, 8, 13, 4, 0, 0, 0, time.UTC)
	if !info.ExpiresAt.Equal(wantExp) {
		t.Fatalf("到期日应 %v, got %v", wantExp, info.ExpiresAt)
	}
	if info.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("注册商解析错误: %q", info.Registrar)
	}
	if info.Registrant != "REDACTED FOR PRIVACY" {
		t.Fatalf("注册人解析错误: %q", info.Registrant)
	}
	if len(info.Nameservers) != 2 || len(info.Status) != 1 {
		t.Fatalf("NS/status 解析错误: %+v", info)
	}

	// 第二次：内存缓存命中，零网络
	before := atomic.LoadInt64(total)
	info2 := c.Lookup(ctx, "example.com")
	if !info2.Cached || !info2.RegisteredAt.Equal(wantReg) {
		t.Fatalf("缓存命中失败: %+v", info2)
	}
	if atomic.LoadInt64(total) != before {
		t.Fatal("缓存命中不应发请求")
	}
}

func TestRDAPDiskCachePersistence(t *testing.T) {
	srv, total, _ := startRDAPStub(t)
	dir := t.TempDir()
	c1 := testRDAPClient(t, srv, dir)
	if info := c1.Lookup(context.Background(), "example.com"); info.Error != "" {
		t.Fatal(info.Error)
	}
	before := atomic.LoadInt64(total)
	// 新客户端（新进程模拟）：磁盘缓存 + bootstrap 均应命中，零网络
	c2 := testRDAPClient(t, srv, dir)
	info := c2.Lookup(context.Background(), "example.com")
	if !info.Cached || info.Registrar == "" {
		t.Fatalf("磁盘缓存未生效: %+v", info)
	}
	if atomic.LoadInt64(total) != before {
		t.Fatalf("磁盘缓存命中不应发请求: %d → %d", before, atomic.LoadInt64(total))
	}
}

func TestRDAPNotFound(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	info := c.Lookup(context.Background(), "missing.com")
	if !info.NotFound || info.Error == "" {
		t.Fatalf("404 应标记 NotFound: %+v", info)
	}
}

func TestRDAPBackoff429(t *testing.T) {
	srv, _, limited := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	info := c.Lookup(context.Background(), "limited.com")
	if info.Error != "" || info.RegisteredAt.IsZero() {
		t.Fatalf("429 退避后应成功: %+v", info)
	}
	if atomic.LoadInt64(limited) < 2 {
		t.Fatal("应发生重试")
	}
}

func TestRDAPBackoff503Exponential(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	start := time.Now()
	info := c.Lookup(context.Background(), "backoff.com")
	if info.Error != "" {
		t.Fatalf("503 指数退避后应成功: %+v", info)
	}
	if time.Since(start) < time.Millisecond {
		t.Fatal("应至少退避一个基数")
	}
}

func TestRDAPUnsupportedTLD(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	info := c.Lookup(context.Background(), "something.invalidtld")
	if info.Error == "" {
		t.Fatal("bootstrap 无该 TLD 应报错而非 panic")
	}
}

func TestParseRDAPBadJSON(t *testing.T) {
	if _, err := parseRDAP([]byte("not json")); err == nil {
		t.Fatal("非 JSON 应报错")
	}
	info, err := parseRDAP([]byte(`{"ldhName":"x.com"}`))
	if err != nil || !info.RegisteredAt.IsZero() {
		t.Fatalf("缺 events 应留零值: %+v %v", info, err)
	}
}

func TestEnrichRDAPRescores(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	// 桩返回 example.com 的注册日期（1995，老域）→ 富化后分数应下降
	led := NewLedger("example.com")
	led.Entries["example.com"] = &Entry{
		Domain: "example.com", Fuzzers: []string{FuzzReplacement},
		Resolved: true, HasMX: true, Ownership: OwnershipUnknown, Score: 68, Level: "high",
	}
	n, failed, err := EnrichRDAP(context.Background(), led, c, 60, 5, "")
	if err != nil || n != 1 || failed != 0 {
		t.Fatalf("富化应 1 条 / 失败 0 条: n=%d failed=%d err=%v", n, failed, err)
	}
	e := led.Entries["example.com"]
	if e.RDAP == nil || e.RDAP.RegisteredAt.IsZero() {
		t.Fatal("RDAP 信息未写入台账")
	}
	// 老域（>3y=5）+ MX30 + 未知18 + 相似5 = 58 → medium，低于富化前 68
	if e.Score != 58 || e.Level != "medium" {
		t.Fatalf("富化后应重算为 58/medium, got %d/%s", e.Score, e.Level)
	}
	// 再跑一次：已有注册日期 → 跳过
	n2, f2, _ := EnrichRDAP(context.Background(), led, c, 60, 5, "")
	if n2 != 0 || f2 != 0 {
		t.Fatalf("已富化条目不应重复查询: n=%d failed=%d", n2, f2)
	}
}

// TestEnrichRDAPFailureNotInflation 查询失败（超时/404/TLS）不得落库、不得重算分数。
// 曾经的缺陷：失败时写入零值 RDAPInfo，Scoring 把 0001-01-01 当成「极老域名」，
// 结果网络越差分数越高——失败变成加分项。
func TestEnrichRDAPFailureNotInflation(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	c := testRDAPClient(t, srv, t.TempDir())
	led := NewLedger("example.com")
	// missing.com 在桩里返回 404（Lookup 会写 Error）
	led.Entries["missing.com"] = &Entry{
		Domain: "missing.com", Fuzzers: []string{FuzzReplacement},
		Resolved: true, HasMX: false, Ownership: OwnershipUnknown, Score: 38, Level: "low",
	}
	n, failed, err := EnrichRDAP(context.Background(), led, c, 30, 5, "")
	if err != nil {
		t.Fatalf("不应返回错误: %v", err)
	}
	if n != 0 || failed != 1 {
		t.Fatalf("应 0 条富化 / 1 条失败, got n=%d failed=%d", n, failed)
	}
	e := led.Entries["missing.com"]
	if e.RDAP != nil {
		t.Fatalf("查询失败不应写入 RDAP 结构: %+v", e.RDAP)
	}
	if e.Score != 38 || e.Level != "low" {
		t.Fatalf("查询失败不应重算分数: %d/%s", e.Score, e.Level)
	}
}

func TestRDAPCacheJSONShape(t *testing.T) {
	srv, _, _ := startRDAPStub(t)
	dir := t.TempDir()
	c := testRDAPClient(t, srv, dir)
	c.Lookup(context.Background(), "example.com")
	// 缓存文件应是合法 JSON（原子写）
	var m map[string]rdapCacheEntry
	b, err := os.ReadFile(dir + "/rdap-cache.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("缓存非合法 JSON: %v", err)
	}
	if _, ok := m["example.com"]; !ok {
		t.Fatal("缓存缺条目")
	}
}
