package intel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stub 起一个测试服务并把它登记为某源的 endpoint。
func stub(t *testing.T, name string, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestFOFAParse(t *testing.T) {
	t.Setenv("FOFA_KEY", "k")
	srv := stub(t, "fofa", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("key") != "k" {
			t.Errorf("缺 key: %v", q)
		}
		if q.Get("size") != "2" {
			t.Errorf("size = %q", q.Get("size"))
		}
		if !strings.Contains(q.Get("fields"), "title") {
			t.Errorf("fields 缺 title: %q", q.Get("fields"))
		}
		_, _ = w.Write([]byte(`{"error":false,"results":[
			["a.example.com:443","10.0.0.1",443,"https","后台登录","nginx","example.com"],
			["b.example.com","10.0.0.2",80,"http","","Apache","example.com"]]}`))
	})
	recs, err := queryFOFA(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"fofa": srv.URL}, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("条数 = %d", len(recs))
	}
	if recs[0].Host != "a.example.com:443" || recs[0].Port != 443 || recs[0].Title != "后台登录" {
		t.Fatalf("首条解析错: %+v", recs[0])
	}
	if recs[0].Source != "fofa" {
		t.Fatalf("source = %q", recs[0].Source)
	}
}

func TestFOFAErrorPropagates(t *testing.T) {
	t.Setenv("FOFA_KEY", "k")
	srv := stub(t, "fofa", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":true,"errmsg":"[-700] 账号无效"}`))
	})
	_, err := queryFOFA(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"fofa": srv.URL}})
	if err == nil || !strings.Contains(err.Error(), "账号无效") {
		t.Fatalf("err = %v", err)
	}
}

func TestHunterParse(t *testing.T) {
	t.Setenv("HUNTER_KEY", "k")
	srv := stub(t, "hunter", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-key") != "k" {
			t.Errorf("缺 api-key")
		}
		// Hunter 的 search 参数必须是 base64url（无 padding），不能是标准 base64
		if s := r.URL.Query().Get("search"); strings.Contains(s, "=") {
			t.Errorf("search 应为 base64url: %q", s)
		}
		_, _ = w.Write([]byte(`{"code":200,"data":{"arr":[
			{"domain":"a.example.com","ip":"10.0.0.1","port":443,"protocol":"https","web_title":"OA","component":"nginx"}]}}`))
	})
	recs, err := queryHunter(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"hunter": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Port != 443 || recs[0].Title != "OA" {
		t.Fatalf("解析错: %+v", recs)
	}
}

func TestHunterNon200(t *testing.T) {
	t.Setenv("HUNTER_KEY", "k")
	srv := stub(t, "hunter", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":401,"message":"令牌过期"}`))
	})
	_, err := queryHunter(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"hunter": srv.URL}})
	if err == nil || !strings.Contains(err.Error(), "令牌过期") {
		t.Fatalf("err = %v", err)
	}
}

func TestQuakeParseAndTokenHeader(t *testing.T) {
	t.Setenv("QUAKE_TOKEN", "tok")
	srv := stub(t, "quake", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Quake 必须 POST，实得 %s", r.Method)
		}
		if r.Header.Get("X-QuakeToken") != "tok" {
			t.Errorf("缺 X-QuakeToken")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, ok := body["include"]; ok {
			t.Errorf("include 白名单极严，不应传: %v", body["include"])
		}
		_, _ = w.Write([]byte(`{"code":0,"data":[
			{"ip":"10.0.0.9","port":8443,"hostname":"vpn.example.com","domain":"example.com",
			 "service":{"name":"https","http":{"title":"SSL VPN","server":"nginx"}},
			 "location":{"country_cn":"中国"},"time":"2026-11-18T00:00:00Z"}]}`))
	})
	recs, err := queryQuake(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"quake": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Title != "SSL VPN" || recs[0].Port != 8443 {
		t.Fatalf("解析错: %+v", recs[0])
	}
}

func TestQuakeRateLimitMessage(t *testing.T) {
	t.Setenv("QUAKE_TOKEN", "tok")
	srv := stub(t, "quake", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":429,"message":"q3005 超出频率限制"}`))
	})
	_, err := queryQuake(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"quake": srv.URL}})
	if err == nil || !strings.Contains(err.Error(), "限频") {
		t.Fatalf("err = %v", err)
	}
}

func TestCrtShParseAndWildcardStrip(t *testing.T) {
	srv := stub(t, "crtsh", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"name_value":"*.example.com\na.example.com","common_name":"*.example.com","not_before":"2026-01-01"},
			{"name_value":"b.example.com","common_name":"b.example.com","not_before":"2026-02-02"}]`))
	})
	recs, err := queryCrtSh(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"crtsh": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	// *.example.com 剥通配符后是 apex example.com（本身也是有效资产），
	// 加上 a/b 两条，共 3 条；同一主机名重复出现要合并。
	if len(recs) != 3 {
		t.Fatalf("应去重成 3 条，实得 %d: %+v", len(recs), recs)
	}
	for _, r := range recs {
		if strings.HasPrefix(r.Host, "*.") {
			t.Fatalf("通配符未剥离: %q", r.Host)
		}
	}
}

func TestHackerTargetCSV(t *testing.T) {
	srv := stub(t, "hackertarget", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("a.example.com,10.0.0.1\nb.example.com,10.0.0.2\nother.com,10.0.0.3\n"))
	})
	recs, err := queryHackerTarget(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"hackertarget": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("应过滤掉非本域，实得 %d", len(recs))
	}
	if recs[0].IP != "10.0.0.1" {
		t.Fatalf("IP 解析错: %+v", recs[0])
	}
}

func TestURLScanParse(t *testing.T) {
	srv := stub(t, "urlscan", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"results":[
			{"page":{"domain":"a.example.com","ip":"10.0.0.1","server":"nginx","status":"200"},
			 "task":{"url":"https://a.example.com","time":"2026-11-18T00:00:00Z"}},
			{"page":{"domain":"noise.org","ip":"1.2.3.4"}}]}`))
	})
	recs, err := queryURLScan(context.Background(), "example.com",
		Options{Endpoints: map[string]string{"urlscan": srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].IP != "10.0.0.1" {
		t.Fatalf("解析错: %+v", recs)
	}
}

func TestRunDedupAndOrder(t *testing.T) {
	t.Setenv("FOFA_KEY", "k")
	srvA := stub(t, "fofa", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":false,"results":[["same.example.com","10.0.0.1",443,"https","","","example.com"]]}`))
	})
	srvB := stub(t, "hackertarget", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("same.example.com,10.0.0.1\nother.example.com,10.0.0.2\n"))
	})
	out := t.TempDir()
	rep, err := Run("example.com", out, Options{
		Sources: []string{"fofa", "hackertarget"},
		Endpoints: map[string]string{
			"fofa": srvA.URL, "hackertarget": srvB.URL,
		},
		Log: func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	// FOFA 的 same.example.com 行 host 无端口、protocol=https，与 hackertarget 的
	// （host=same.example.com, ip 同, port 0, protocol 空）不同 → 不合并，共 3 条
	if len(rep.Records) != 3 {
		t.Fatalf("记录数 = %d，期望 3: %+v", len(rep.Records), rep.Records)
	}
	for _, f := range []string{"assets.json", "assets.txt", "intel.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("缺产物 %s: %v", f, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "assets.txt"))
	if !strings.Contains(string(b), "|") {
		t.Fatalf("assets.txt 应为 host|ip|port|protocol 行: %q", string(b))
	}
}

func TestUnknownSourceReportsError(t *testing.T) {
	rep, err := Run("example.com", t.TempDir(), Options{
		Sources: []string{"nope"},
		Log:     func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Sources) != 1 || rep.Sources[0].Status != "error" {
		t.Fatalf("未知源应报 error: %+v", rep.Sources)
	}
	if !strings.Contains(rep.Sources[0].Message, "未知数据源") {
		t.Fatalf("message = %q", rep.Sources[0].Message)
	}
}

func TestWhoisParseRDAP(t *testing.T) {
	boot := stub(t, "boot", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"services":[[["com"],["` + "$BASE" + `"]]]}`))
	})
	// bootstrap 里要写死真实地址，先起 rdap 服务再拼
	rdap := stub(t, "rdap", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"ldhName":"EXAMPLE.COM","status":["client transfer prohibited"],
			"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},
			          {"eventAction":"expiration","eventDate":"2026-08-13T04:00:00Z"}],
			"nameservers":[{"ldhName":"A.IANA-SERVERS.NET"},{"ldhName":"B.IANA-SERVERS.NET"}],
			"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]]}]}`))
	})
	bootSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"services":[[["com"],["` + rdap.URL + `"]]]}`))
	}))
	defer bootSrv.Close()
	oldBoot := BootstrapURL
	BootstrapURL = bootSrv.URL
	t.Cleanup(func() {
		BootstrapURL = oldBoot
		resetRDAPCache()
	})
	resetRDAPCache()

	info := Whois(context.Background(), "example.com", Options{})
	if info.Error != "" {
		t.Fatalf("err = %s", info.Error)
	}
	if info.Registrar == "" || len(info.Nameservers) != 2 || info.RegisteredAt == "" {
		t.Fatalf("解析不完整: %+v", info)
	}
	if info.ExpiresAt == "" {
		t.Fatalf("到期时间缺失: %+v", info)
	}
	_ = boot
}

func TestKeysFileFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.env")
	if err := os.WriteFile(path, []byte("# comment\nexport FOFA_KEY=\"filekey\"\nQUAKE_TOKEN = tok123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DITING_KEYS_FILE", path)
	t.Setenv("FOFA_KEY", "")
	t.Setenv("QUAKE_TOKEN", "")
	resetKeysCache()
	if got := Env("FOFA_KEY"); got != "filekey" {
		t.Fatalf("FOFA_KEY = %q", got)
	}
	if got := Env("QUAKE_TOKEN"); got != "tok123" {
		t.Fatalf("QUAKE_TOKEN = %q", got)
	}
	st := Status("FOFA_KEY")
	if !st.Configured || st.Origin == "" {
		t.Fatalf("status = %+v", st)
	}
	if strings.Contains(st.Masked, "filekey") {
		t.Fatalf("脱敏失败: %q", st.Masked)
	}
}

func TestConfiguredRespectsFree(t *testing.T) {
	p, ok := ProviderByName("crtsh")
	if !ok || !Configured(p) {
		t.Fatalf("免 key 源应恒可用")
	}
	p, _ = ProviderByName("fofa")
	t.Setenv("FOFA_KEY", "")
	resetKeysCache()
	if Configured(p) {
		t.Fatalf("无 key 时 fofa 应判未配置")
	}
}
