package jsintel

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/atlas/engine-go/mockweb"
)

// ── mask_value ──

func TestMaskValue(t *testing.T) {
	cases := map[string]string{
		"":             "****",
		"abcd":         "****",
		"abcde":        "abcd****",
		"  abcd  ":     "****",
		"FAKEKEY_0001": "FAKE****",
		"密码密码密码":       "密码密码****", // 按字符计长（Python len 语义）
	}
	for in, want := range cases {
		if got := MaskValue(in); got != want {
			t.Errorf("MaskValue(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── normalize_endpoint（平移 test_jsintel.py:TestNormalizeEndpoint） ──

func TestNormalizeEndpoint(t *testing.T) {
	cases := map[string]string{
		"/api/v1/users":        "/api/v1/users",
		"api/v1/users":         "/api/v1/users",
		"/api/u?x=1#frag":      "/api/u",
		"https://a.com/v3/pay": "/v3/pay",
		"/admin/":              "/admin",
		"/static/app.js":       "",
		"/assets/main.css":     "",
		"/img/logo.png":        "",
		"/fonts/a.woff2":       "",
		"/a.map":               "",
		"/api/${id}/x":         "",
		"/":                    "",
		"":                     "",
		"https://a.com/":       "",
		"/a":                   "/a",
		"//x.com/y":            "//x.com/y", // Python 侧同样不走绝对 URL 分支
	}
	for in, want := range cases {
		if got := NormalizeEndpoint(in); got != want {
			t.Errorf("NormalizeEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── extract_endpoints（平移 TestExtractEndpoints） ──

func TestExtractEndpoints(t *testing.T) {
	js := "fetch('/api/v1/users').then();\n" +
		"axios.post(\"/api/v2/login\");\n" +
		"axios({url:'/api/v3/me'});\n" +
		"$.get('/v1/notify');\n" +
		"var a='/api/v1/users';\n" + // 与 fetch 重复，应去重
		"var b='/static/app.js';\n" // 静态资源应滤掉
	want := []string{"/api/v1/users", "/api/v2/login", "/api/v3/me", "/v1/notify"}
	if got := ExtractEndpoints(js); !reflect.DeepEqual(got, want) {
		t.Fatalf("ExtractEndpoints = %v, want %v", got, want)
	}
}

func TestExtractEndpointsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("var x")
		b.WriteString(strings.Repeat("y", i%3))
		b.WriteString("='/p")
		b.WriteString(strings.Repeat("q", i%2))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(itoaPad(i))
		b.WriteString("';\n")
	}
	got := ExtractEndpoints(b.String())
	if len(got) != 800 {
		t.Fatalf("端点线索应截断为 800 条，得 %d", len(got))
	}
	if !sortedStrings(got) {
		t.Fatal("端点线索必须有序")
	}
}

func itoaPad(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	if i < 100 {
		return string(rune('0'+i/10)) + string(rune('0'+i%10))
	}
	return string(rune('0'+i/100)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10))
}

func sortedStrings(v []string) bool {
	for i := 1; i < len(v); i++ {
		if v[i-1] > v[i] {
			return false
		}
	}
	return true
}

func TestExtractEndpointsUnicodeWordBoundary(t *testing.T) {
	// Python \bfetch/\baxios 是 Unicode 词边界：CJK 紧贴时不算边界；间隔空格才算。
	if got := ExtractEndpoints("请fetch('api/x')"); len(got) != 0 {
		t.Fatalf("CJK 紧贴 fetch 不应命中: %v", got)
	}
	if got := ExtractEndpoints("请 axios('api/y')"); !reflect.DeepEqual(got, []string{"/api/y"}) {
		t.Fatalf("空格分隔 axios 应命中: %v", got)
	}
	if got := ExtractEndpoints("请$.get('api/z')"); !reflect.DeepEqual(got, []string{"/api/z"}) {
		t.Fatalf("$ 分支无 \\b，CJK 紧贴也应命中: %v", got)
	}
}

// ── extract_sensitive（平移 TestExtractSensitive 三例） ──

func TestExtractSensitiveMaskedEverywhere(t *testing.T) {
	js := "var cfg = {password: '" + mockweb.FakePw + "'};\nvar ok = 1;"
	rows := ExtractSensitive(js, "app.js", sensitiveCap)
	if len(rows) != 1 {
		t.Fatalf("应命中 1 条，得 %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.File != "app.js" || r.Line != 1 || r.Key != "password" {
		t.Fatalf("位置/键不符: %+v", r)
	}
	if r.Value != mockweb.FakePw[:4]+"****" {
		t.Fatalf("值未按前 4 位打码: %q", r.Value)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), mockweb.FakePw) {
		t.Fatal("全量值不得出现在输出")
	}
	if !strings.Contains(r.Snippet, mockweb.FakePw[:4]+"****") {
		t.Fatalf("片段里的值也要打码: %q", r.Snippet)
	}
}

func TestExtractSensitiveAkSkAndBlocklist(t *testing.T) {
	sk := "AKIA" + "FAKE" + "KEY" + "0001"
	js := "var a = {sk: '" + sk + "'};\n" +
		"var b = {token: 'undefined'};\n" + // 占位符，跳过
		"var c = {ak: '1234'};\n" + // 纯数字短串，跳过
		"var d = token_fetch('x');\n" // token_fetch 不是敏感键
	rows := ExtractSensitive(js, "x.js", sensitiveCap)
	if len(rows) != 1 || rows[0].Key != "sk" {
		t.Fatalf("应只命中 sk，得 %+v", rows)
	}
	if rows[0].Value != "AKIA****" {
		t.Fatalf("ak/sk 值应打码: %q", rows[0].Value)
	}
}

func TestExtractSensitiveMinifiedSingleLine(t *testing.T) {
	auth := "Bearer " + "Fake" + "Bearer" + "Token0001"
	js := "a=1;var cfg={authorization:'" + auth + "'};b=2;"
	rows := ExtractSensitive(js, "min.js", sensitiveCap)
	if len(rows) != 1 || rows[0].Line != 1 {
		t.Fatalf("应命中 1 条 line=1，得 %+v", rows)
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), auth) {
		t.Fatal("全量值不得出现在输出")
	}
}

func TestExtractSensitiveDedupAndCap(t *testing.T) {
	pw1, pw2 := "zzTop"+"0001", "zzTop"+"0002"
	dup := "a={password:'" + pw1 + "'};b={password:'" + pw2 + "'};"
	rows := ExtractSensitive(dup, "d.js", sensitiveCap)
	if len(rows) != 1 {
		t.Fatalf("同一文件同行同键应去重，得 %d", len(rows))
	}
	multi := "a={password:'" + pw1 + "'};\n" +
		"b={token:'" + "tok" + "0002" + "'};\n" +
		"c={secret:'" + "sec" + "0003" + "'};\n" +
		"d={api_key:'" + "key" + "0004" + "'};\n"
	if got := ExtractSensitive(multi, "m.js", 2); len(got) != 2 {
		t.Fatalf("cap=2 应截断为 2 条，得 %d", len(got))
	}
	// 行号按换行累计。
	js := "var a=1;\nvar b=2;\nvar c={password:'" + "line" + "0005" + "'};"
	rows = ExtractSensitive(js, "ln.js", sensitiveCap)
	if len(rows) != 1 || rows[0].Line != 3 {
		t.Fatalf("行号应为 3，得 %+v", rows)
	}
}

func TestExtractSensitiveUnicodeWordBoundary(t *testing.T) {
	pwKey := "pass" + "word"
	// Python 的 \b 是 Unicode 词边界：CJK 紧贴 key 时属于「词内」，不应命中；
	// Go RE2 原生 \b 只认 ASCII，会误报——findSecretMatches 已按 Python 回查。
	for _, js := range []string{
		"密码" + pwKey + ":'FakeCJKValue0001'",
		"字" + "tok" + "en" + ":'FakeCJKValue0002'",
	} {
		if rows := ExtractSensitive(js, "cjk.js", sensitiveCap); len(rows) != 0 {
			t.Errorf("CJK 紧贴 key 不应命中: %q -> %+v", js, rows)
		}
	}
	rows := ExtractSensitive("密码 "+pwKey+":'FakeCJKValue0003'", "cjk.js", sensitiveCap)
	if len(rows) != 1 || rows[0].Key != pwKey {
		t.Fatalf("空格分隔应命中: %+v", rows)
	}
	// 值里含 CJK：按字符打码前 4 位。
	rows = ExtractSensitive("var a={token:'中文值abc1234'};", "cjk.js", sensitiveCap)
	if len(rows) != 1 || rows[0].Value != "中文值a****" {
		t.Fatalf("CJK 值打码不符: %+v", rows)
	}
}

func TestExtractSensitiveLineQuirks(t *testing.T) {
	// Python 行号表只按 \n 计，片段却取 splitlines（lone \r / \f 也算分行）——
	// 复刻该 quirk：password 报 line=2 但片段取到上一行 "b"；token 报 line=3、
	// 片段取到 password 行。jsintel.py 实测输出即如此。
	js := "a\rb\npassword:'FAKE_CR_0001'\nc\fd={token:'tok0002'}"
	rows := ExtractSensitive(js, "cr.js", sensitiveCap)
	if len(rows) != 2 {
		t.Fatalf("应命中 2 条，得 %+v", rows)
	}
	if rows[0].Line != 2 || rows[0].Snippet != "b" {
		t.Fatalf("lone \\r 行号/片段 quirk 不符: %+v", rows[0])
	}
	if rows[1].Line != 3 || !strings.Contains(rows[1].Snippet, "password:'FAKE****'") {
		t.Fatalf("\\f 行号/片段 quirk 不符: %+v", rows[1])
	}
}

// ── extract_domains（平移 TestExtractDomains） ──

func TestExtractDomainsClassify(t *testing.T) {
	js := "fetch('https://api.xycovo.com/v1');\n" +
		"var cdn='https://cdn.thirdparty.cn/x';\n" +
		"var intra='http://10.0.0.5:8080/metrics';\n"
	d := ExtractDomains(js, "xycovo.com")
	if !reflect.DeepEqual(d.Subdomains, []string{"api.xycovo.com"}) {
		t.Fatalf("subdomains = %v", d.Subdomains)
	}
	if !reflect.DeepEqual(d.Thirdparty, []string{"cdn.thirdparty.cn"}) {
		t.Fatalf("thirdparty = %v", d.Thirdparty)
	}
	if !reflect.DeepEqual(d.InternalIPs, []string{"10.0.0.5"}) {
		t.Fatalf("internal_ips = %v", d.InternalIPs)
	}
}

func TestExtractDomainsPublicNoiseIgnored(t *testing.T) {
	d := ExtractDomains("ver='1.2.3.4'; host='https://a.example.com/x'", "example.com")
	if len(d.InternalIPs) != 0 || len(d.Thirdparty) != 0 {
		t.Fatalf("公网 IP/版本号不得误收: %+v", d)
	}
	d = ExtractDomains("a='http://8.8.4.4/x'; b='http://192.168.1.9/y'; c='http://172.16.0.7/z'; d='http://127.0.0.1/w'", "x.com")
	want := []string{"127.0.0.1", "172.16.0.7", "192.168.1.9"}
	if !reflect.DeepEqual(d.InternalIPs, want) {
		t.Fatalf("内网 IP 归类 = %v, want %v", d.InternalIPs, want)
	}
}

func TestExtractDomainsUnicodeWordBoundary(t *testing.T) {
	// Python IP 正则的 \b 同样是 Unicode 语义：CJK 紧贴数字不算边界。
	if d := ExtractDomains("内网10.0.0.5", "x.com"); len(d.InternalIPs) != 0 {
		t.Fatalf("CJK 紧贴 IP 不应收录: %+v", d)
	}
	if d := ExtractDomains("内网 10.0.0.5", "x.com"); !reflect.DeepEqual(d.InternalIPs, []string{"10.0.0.5"}) {
		t.Fatalf("空格分隔 IP 应收录: %+v", d)
	}
}

// ── extract_scripts（平移 TestExtractScripts） ──

func TestExtractScriptsHTMLParsing(t *testing.T) {
	html := `<html><head><script src="https://cdn.a.com/x.js"></script>` +
		`<script src="//b.com/y.js"></script>` +
		`<script src="/js/app.js?v=2"></script></head>` +
		`<body><script>var x="/api/keep";</script>` +
		`<script src="/img/empty.gif"></script></body></html>`
	page := "https://example.com/dir/page"
	ext, inline := ExtractScripts(html, page)
	want := []string{"https://cdn.a.com/x.js", "https://b.com/y.js",
		"https://example.com/js/app.js?v=2"}
	if !reflect.DeepEqual(ext, want) {
		t.Fatalf("外链 JS = %v, want %v", ext, want)
	}
	if len(inline) != 1 {
		t.Fatalf("内联段数 = %d, want 1", len(inline))
	}
	// 序号按 HTML 中所有 <script> 计：前三个是外链，内联体是第 4 个。
	if inline[0].Label != "inline#4" {
		t.Fatalf("内联标签 = %q, want inline#4", inline[0].Label)
	}
	if !strings.Contains(inline[0].Text, "/api/keep") {
		t.Fatalf("内联内容不符: %q", inline[0].Text)
	}
}

func TestExtractScriptsSkipsDataAndJavascript(t *testing.T) {
	html := `<script src="data:text/javascript,var x=1"></script>` +
		`<script src="JavaScript:void(0)"></script>` +
		`<script src="./rel/a.js"></script>`
	ext, _ := ExtractScripts(html, "http://h/dir/p")
	if !reflect.DeepEqual(ext, []string{"http://h/dir/rel/a.js"}) {
		t.Fatalf("外链 JS = %v", ext)
	}
}

// ── render_txt ──

func TestRenderTxt(t *testing.T) {
	st := 200
	r := Result{
		Base:          "http://h/x",
		PageStatus:    &st,
		Scripts:       ScriptStats{External: 2, Inline: 1, Downloaded: 1, Failed: 1},
		Endpoints:     []string{"/api/a"},
		EndpointsFull: []string{"http://h/api/a"},
		Sensitive: []Sensitive{{File: "a.js", Line: 3, Key: "password",
			Value: "FAKE****", Snippet: "password='FAKE****'"}},
		Domains: Domains{Subdomains: []string{"api.h"}, Thirdparty: []string{}, InternalIPs: []string{"10.0.0.5"}},
	}
	txt := RenderTxt(r)
	for _, want := range []string{
		"# JS 情报清单 — http://h/x",
		"- 页面状态: 200",
		"- 外链 JS: 2（下载成功 1 / 失败 1），内联 1 段",
		"## API 端点线索（1 条）",
		"  http://h/api/a",
		"## 敏感线索（1 处，仅位置提示，值为打码）",
		"- [a.js:3] password = FAKE****  |  `password='FAKE****'`",
		"- 子域/同域: api.h",
		"- 第三方域: -",
		"- 内网 IP: 10.0.0.5",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("txt 缺少 %q\n---\n%s", want, txt)
		}
	}
	// 页面状态为 None 的降级形态。
	if !strings.Contains(RenderTxt(emptyResult("x")), "- 页面状态: None") {
		t.Fatal("空结果应渲染 page_status: None")
	}
}

// ── 全流程（mockweb 靶站；平移 TestJsintelAgainstMock） ──

func TestRunJSIntelAgainstMock(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	out := t.TempDir()
	res, err := RunJSIntel(srv.URL+"/jssite", out, 6, 60, 10*time.Second)
	if err != nil {
		t.Fatalf("RunJSIntel: %v", err)
	}
	eps := map[string]bool{}
	for _, e := range res.Endpoints {
		eps[e] = true
	}
	for _, need := range []string{"/api/v1/users", "/api/v2/login", "/v3/pay", "/weather/beijing"} {
		if !eps[need] {
			t.Errorf("漏报端点: %s", need)
		}
	}
	for _, noise := range []string{"/static/logo.png", "/assets/main.css"} {
		if eps[noise] {
			t.Errorf("静态资源误报: %s", noise)
		}
	}
	if !contains(res.EndpointsFull, srv.URL+"/api/v1/users") {
		t.Errorf("endpoints_full 缺少可直接复用的绝对 URL: %v", res.EndpointsFull)
	}
	if res.PageStatus == nil || *res.PageStatus != 200 {
		t.Fatalf("page_status = %v", res.PageStatus)
	}
	if res.Scripts.External != 1 || res.Scripts.Inline != 1 ||
		res.Scripts.Downloaded != 1 || res.Scripts.Failed != 0 {
		t.Fatalf("scripts 计数不符: %+v", res.Scripts)
	}

	// 隐私纪律：JSON/TXT 落盘文件都不得含全量值。
	rawJSON, err := os.ReadFile(filepath.Join(out, "jsintel.json"))
	if err != nil {
		t.Fatalf("jsintel.json: %v", err)
	}
	rawTxt, err := os.ReadFile(filepath.Join(out, "jsintel.txt"))
	if err != nil {
		t.Fatalf("jsintel.txt: %v", err)
	}
	for _, secret := range []string{mockweb.FakePw, mockweb.FakeToken, mockweb.FakeAppID} {
		if strings.Contains(string(rawJSON), secret) {
			t.Errorf("输出 JSON 泄露了全量值: %s", secret)
		}
		if strings.Contains(string(rawTxt), secret) {
			t.Errorf("输出 TXT 泄露了全量值: %s", secret)
		}
	}
	if !strings.Contains(string(rawJSON), mockweb.FakePw[:4]+"****") {
		t.Error("输出 JSON 应含打码值")
	}

	// 敏感线索定位（外链 + 内联）。
	loc := map[string]bool{}
	for _, s := range res.Sensitive {
		loc[s.File+"|"+s.Key] = true
	}
	for _, need := range []string{"/jssite/static/app.js|password", "/jssite/static/app.js|appid"} {
		if !loc[need] {
			t.Errorf("敏感线索缺少 %s: %+v", need, res.Sensitive)
		}
	}
	foundInlineToken := false
	for _, s := range res.Sensitive {
		if s.Key == "token" && strings.HasPrefix(s.File, "inline#") {
			foundInlineToken = true
		}
	}
	if !foundInlineToken {
		t.Error("内联脚本里的 token 也应被定位")
	}
	if !contains(res.Domains.Thirdparty, "api.example-cdn.com") {
		t.Errorf("第三方域缺失: %+v", res.Domains)
	}
	if !contains(res.Domains.InternalIPs, "10.0.0.5") {
		t.Errorf("内网 IP 缺失: %+v", res.Domains)
	}
}

func TestRunJSIntelWAFDegradesGracefully(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	out := t.TempDir()
	res, err := RunJSIntel(srv.URL+"/waf", out, 6, 60, 10*time.Second)
	if err != nil {
		t.Fatalf("RunJSIntel: %v", err)
	}
	if res.PageStatus == nil || *res.PageStatus != 403 {
		t.Fatalf("page_status = %v, want 403", res.PageStatus)
	}
	if len(res.Endpoints) != 0 || len(res.Sensitive) != 0 {
		t.Fatalf("WAF 站点应输出空结果: %+v", res)
	}
	if res.Error == "" {
		t.Fatal("降级结果应带 error")
	}
	if _, err := os.Stat(filepath.Join(out, "jsintel.json")); err != nil {
		t.Fatalf("降级也必须落盘空结果: %v", err)
	}
}

func TestRunJSIntelSoft404NoCrash(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	res, err := RunJSIntel(srv.URL+"/soft404", t.TempDir(), 6, 60, 10*time.Second)
	if err != nil {
		t.Fatalf("RunJSIntel: %v", err)
	}
	if res.PageStatus == nil || *res.PageStatus != 200 {
		t.Fatalf("page_status = %v", res.PageStatus)
	}
	if len(res.Endpoints) != 0 {
		t.Fatalf("SPA 外壳不应产出端点线索: %v", res.Endpoints)
	}
	// 404 页同样返回 ok=true（Python HTTPError 分支语义），body 非空 → 计入
	// downloaded；重点是「不崩 + 不产端点」。
	if res.Scripts.External != 1 || res.Scripts.Downloaded != 1 {
		t.Fatalf("scripts 计数不符: %+v", res.Scripts)
	}
}

// ── 下载器：保序 / max_files / 二进制跳过 ──

func TestDownloadScriptsOrderLimitAndBinary(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("var a='/api/a';"))
	})
	mux.HandleFunc("/b.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("var b='/api/b';"))
	})
	mux.HandleFunc("/bin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	urls := []string{srv.URL + "/a.js", srv.URL + "/bin.js", srv.URL + "/b.js"}
	rows := DownloadScripts(context.Background(), urls, 99, 5*time.Second, 3)
	if len(rows) != 3 {
		t.Fatalf("行数 = %d, want 3", len(rows))
	}
	for i, u := range urls {
		if rows[i].URL != u {
			t.Fatalf("结果必须与输入同序: row[%d]=%s, want %s", i, rows[i].URL, u)
		}
	}
	if !rows[0].OK || !strings.Contains(rows[0].Text, "/api/a") {
		t.Fatalf("a.js 应下载成功: %+v", rows[0])
	}
	if rows[1].OK && rows[1].Text != "" {
		t.Fatalf("二进制内容应清空 text: %+v", rows[1])
	}
	if rows[1].Error == "" {
		t.Fatalf("二进制内容应记 error: %+v", rows[1])
	}
	if rows[2].Text == "" {
		t.Fatalf("b.js 应下载成功: %+v", rows[2])
	}

	// max_files 截断（保序取前 N）。
	rows = DownloadScripts(context.Background(), urls, 1, 5*time.Second, 2)
	if len(rows) != 2 || rows[1].URL != urls[1] {
		t.Fatalf("max_files=2 应只取前两条: %+v", rows)
	}
	if got := DownloadScripts(context.Background(), urls, 6, 5*time.Second, 0); len(got) != 0 {
		t.Fatalf("max_files=0 应返回空: %+v", got)
	}
}

// ── 取消能力 ──

func TestRunJSIntelContextCanceled(t *testing.T) {
	srv := mockweb.New()
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := t.TempDir()
	_, err := RunJSIntelContext(ctx, srv.URL+"/jssite", out, 6, 60, 10*time.Second)
	if err == nil {
		t.Fatal("已取消的 ctx 应返回错误")
	}
	if _, statErr := os.Stat(filepath.Join(out, "jsintel.json")); statErr == nil {
		t.Fatal("取消后不得落盘")
	}
}

func contains(v []string, want string) bool {
	for _, s := range v {
		if s == want {
			return true
		}
	}
	return false
}
