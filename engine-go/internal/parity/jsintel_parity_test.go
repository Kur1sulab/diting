package parity

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Kur1sulab/yata/engine-go/jsintel"
	"github.com/Kur1sulab/yata/engine-go/mockweb"
)

// fakePw 全流程 parity 使用的假口令：分段拼接，源码不出现完整凭据字面量。
var fakePw = "Sup3r" + "FAKE" + "0001"

// 本文件是 jsintel 的 Python↔Go parity 断言矩阵：
//   - 纯函数逐样本对打（stdin 喂源码，stdout 收 JSON）；
//   - 全流程两引擎打同一个 Go httptest 靶站（mockweb + 本文件自建陷阱站），
//     比对 jsintel.json 解析结构与 jsintel.txt 文本（StripCR）；
//   - 隐私纪律两侧同断言：落盘文件不得出现任何全量敏感值。
//
// 铁律沿用 internal/parity：python 不在 PATH → t.Skip；两引擎同站；只比解析结构。

const pyJSIntel = `
import json, sys
sys.path.insert(0, 'src')
from modules import jsintel
mode = sys.argv[1]
payload = sys.stdin.read()
if mode == 'mask':
    print(json.dumps([jsintel.mask_value(x) for x in json.loads(payload)], ensure_ascii=False))
elif mode == 'normalize':
    print(json.dumps([jsintel.normalize_endpoint(x) for x in json.loads(payload)], ensure_ascii=False))
elif mode == 'endpoints':
    print(json.dumps(jsintel.extract_endpoints(payload), ensure_ascii=False))
elif mode == 'sensitive':
    print(json.dumps(jsintel.extract_sensitive(payload, sys.argv[2]), ensure_ascii=False))
elif mode == 'domains':
    print(json.dumps(jsintel.extract_domains(payload, sys.argv[2]), ensure_ascii=False))
elif mode == 'scripts':
    ext, inline = jsintel.extract_scripts(payload, sys.argv[2])
    print(json.dumps({'ext': ext, 'inline': inline}, ensure_ascii=False))
else:
    raise SystemExit('unknown mode ' + mode)
`

// toAny 把 Go 结构 JSON 往返成通用形态，与 Python json 输出同构比较。
func toAny(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Go 结构序列化失败: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Go 结构 JSON 往返失败: %v", err)
	}
	return out
}

// parityJSON 跑 python 探针并把 stdout 解析成通用 JSON。
func parityJSON(t *testing.T, stdin, mode string, args ...string) any {
	t.Helper()
	out := RunPyStdin(t, stdin, pyJSIntel, append([]string{mode}, args...)...)
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &v); err != nil {
		t.Fatalf("python 输出不是 JSON（mode=%s）: %v\n输出:\n%s", mode, err, out)
	}
	return v
}

// ── 纯函数 parity ──

func TestParityJSIntelMask(t *testing.T) {
	RequiresPython(t)
	in := []string{"", "abcd", "abcde", "  abcd  ", "FAKEKEY_0001", "密码密码密码"}
	raw, _ := json.Marshal(in)
	py := parityJSON(t, string(raw), "mask")
	goOut := make([]string, 0, len(in))
	for _, s := range in {
		goOut = append(goOut, jsintel.MaskValue(s))
	}
	if !reflect.DeepEqual(py, toAny(t, goOut)) {
		t.Fatalf("mask_value:\n  py=%v\n  go=%v", py, goOut)
	}
}

func TestParityJSIntelNormalize(t *testing.T) {
	RequiresPython(t)
	in := []string{
		"/api/v1/users", "api/v1/users", "/api/u?x=1#frag", "https://a.com/v3/pay",
		"/admin/", "/static/app.js", "/assets/main.css", "/img/logo.png",
		"/fonts/a.woff2", "/a.map", "/api/${id}/x", "/", "", "https://a.com/",
		"/a", "//x.com/y", "  /trim/me  ", "/api/{tmpl}/x", "/x/",
	}
	raw, _ := json.Marshal(in)
	py := parityJSON(t, string(raw), "normalize")
	goOut := make([]string, 0, len(in))
	for _, s := range in {
		goOut = append(goOut, jsintel.NormalizeEndpoint(s))
	}
	if !reflect.DeepEqual(py, toAny(t, goOut)) {
		t.Fatalf("normalize_endpoint:\n  py=%v\n  go=%v", py, goOut)
	}
}

func TestParityJSIntelEndpoints(t *testing.T) {
	RequiresPython(t)
	js := "fetch('/api/v1/users').then();\n" +
		"axios.post(\"/api/v2/login\");\n" +
		"axios({url:'/api/v3/me'});\n" +
		"$.get('/v1/notify');\n" +
		"$.post('/v1/create',{});\n" +
		"var a='/api/v1/users';\n" +
		"var b='/static/app.js';\n" +
		"var c='/x?q=1#z';\n" +
		"var d='/api/${id}/x';\n" +
		"x.open('GET','/api/raw');\n" +
		"var absolute='https://api.example.com/v4/thing';\n"
	py := parityJSON(t, js, "endpoints")
	goOut := jsintel.ExtractEndpoints(js)
	if !reflect.DeepEqual(py, toAny(t, goOut)) {
		t.Fatalf("extract_endpoints:\n  py=%v\n  go=%v", py, goOut)
	}
}

func TestParityJSIntelSensitive(t *testing.T) {
	RequiresPython(t)
	sk := "AKIA" + "FAKE" + "KEY" + "0001"
	js := "var cfg = {password:'" + mockweb.FakePw + "', appid:'" + mockweb.FakeAppID + "'};\n" +
		"var a={sk:'" + sk + "'};\n" +
		"var b={token:'undefined'};\n" +
		"var c={ak:'1234'};\n" +
		"var d={aws_secret_key:'zz" + "top0002'};\n" +
		"var e={authorization:'Bearer " + "faketok" + "en0003'};\n" +
		"var f={password:'${" + "ENV}'};\n" +
		"var g={password:'zz" + "top0002'};\n" +
		"x token_fetch('y')\n"
	py := parityJSON(t, js, "sensitive", "app.js")
	goRows := jsintel.ExtractSensitive(js, "app.js", 200)
	if !reflect.DeepEqual(py, toAny(t, goRows)) {
		t.Fatalf("extract_sensitive:\n  py=%v\n  go=%v", py, goRows)
	}
}

func TestParityJSIntelSensitiveUnicodeBoundary(t *testing.T) {
	RequiresPython(t)
	pwKey := "pass" + "word"
	js := "// 密码" + pwKey + ":'FakeCJKValue0001'\n" +
		"// 密码 " + pwKey + ":'FakeCJKValue0002'\n" +
		"var z={token:'中文值abc1234'};\n"
	py := parityJSON(t, js, "sensitive", "cjk.js")
	goRows := jsintel.ExtractSensitive(js, "cjk.js", 200)
	if !reflect.DeepEqual(py, toAny(t, goRows)) {
		t.Fatalf("extract_sensitive unicode boundary:\n  py=%v\n  go=%v", py, goRows)
	}
}

func TestParityJSIntelUnicodeBoundaries(t *testing.T) {
	RequiresPython(t)
	// endpoint / domain 两路正则的 \b 也按 Python Unicode 语义回查。
	cases := []struct {
		js, host string
	}{
		{"请fetch('api/x')", "x.com"},
		{"请 axios('api/y')", "x.com"},
		{"请$.get('api/z')", "x.com"},
		{"内网10.0.0.5", "x.com"},
		{"内网 10.0.0.5", "x.com"},
		{"版本1.2.3.4", "x.com"},
	}
	for _, tc := range cases {
		pyEps := parityJSON(t, tc.js, "endpoints")
		if goEps := jsintel.ExtractEndpoints(tc.js); !reflect.DeepEqual(pyEps, toAny(t, goEps)) {
			t.Errorf("endpoints(%q): py=%v go=%v", tc.js, pyEps, goEps)
		}
		pyDom := parityJSON(t, tc.js, "domains", tc.host)
		if goDom := jsintel.ExtractDomains(tc.js, tc.host); !reflect.DeepEqual(pyDom, ToMap(t, goDom)) {
			t.Errorf("domains(%q): py=%v go=%+v", tc.js, pyDom, goDom)
		}
	}
}

func TestParityJSIntelSensitiveLineQuirks(t *testing.T) {
	RequiresPython(t)
	// lone \r / \f 触发的「行号表按 \n、片段取 splitlines」错位 quirk。
	js := "a\rb\npassword:'FAKE_CR_0001'\nc\fd={token:'tok0002'}"
	py := parityJSON(t, js, "sensitive", "cr.js")
	goRows := jsintel.ExtractSensitive(js, "cr.js", 200)
	if !reflect.DeepEqual(py, toAny(t, goRows)) {
		t.Fatalf("extract_sensitive line quirks:\n  py=%v\n  go=%v", py, goRows)
	}
}

func TestParityJSIntelDomains(t *testing.T) {
	RequiresPython(t)
	js := "fetch('https://api.xycovo.com/v1');\n" +
		"var cdn='https://cdn.thirdparty.cn/x';\n" +
		"var intra='http://10.0.0.5:8080/metrics';\n" +
		"var intra2='http://172.16.5.9/x';\n" +
		"var pub='http://8.8.4.4/x';\n" +
		"var ver='1.2.3.4';\n" +
		"var rela='//static.xycovo.com/a.js';\n"
	py := parityJSON(t, js, "domains", "xycovo.com")
	goD := jsintel.ExtractDomains(js, "xycovo.com")
	if !reflect.DeepEqual(py, ToMap(t, goD)) {
		t.Fatalf("extract_domains:\n  py=%v\n  go=%+v", py, goD)
	}
}

func TestParityJSIntelScripts(t *testing.T) {
	RequiresPython(t)
	cases := []struct{ html, page string }{
		{mockweb.JSSitePage, "https://example.com/dir/page"},
		{`<html><head>` +
			`<script src="https://cdn.a.com/x.js"></script>` +
			`<script src="//b.com/y.js"></script>` +
			`<script src="/js/app.js?v=2"></script>` +
			`<script src="data:text/javascript,var x=1"></script>` +
			`<script src="JavaScript:void(0)"></script>` +
			`</head><body><script>var x="/api/keep";</script>` +
			`<script src="/img/empty.gif"></script>` +
			`<script>if (a < b) { var y = "/api/two"; }</script>` +
			`</body></html>`, "https://example.com/dir/page"},
	}
	for i, tc := range cases {
		py := parityJSON(t, tc.html, "scripts", tc.page)
		ext, inline := jsintel.ExtractScripts(tc.html, tc.page)
		inlinePairs := [][]string{}
		for _, in := range inline {
			inlinePairs = append(inlinePairs, []string{in.Label, in.Text})
		}
		goOut := map[string]any{"ext": ext, "inline": inlinePairs}
		if !reflect.DeepEqual(py, toAny(t, goOut)) {
			t.Fatalf("extract_scripts case %d:\n  py=%v\n  go=%v", i, py, goOut)
		}
	}
}

// ── 全流程 parity：mockweb 三场景 ──

const pyJSIntelRun = `
import contextlib, io, json, sys
sys.path.insert(0, 'src')
from modules.jsintel import run_jsintel
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    run_jsintel(sys.argv[1], sys.argv[2])
with open(sys.argv[2] + '/jsintel.json', encoding='utf-8') as f:
    print(json.dumps(json.load(f), ensure_ascii=False))
`

// pyRunJSIntel 跑 Python 全流程，返回落盘 JSON 的解析结果与 txt 文本。
func pyRunJSIntel(t *testing.T, url, outDir string) (any, string) {
	t.Helper()
	raw := RunPy(t, pyJSIntelRun, url, outDir)
	var v any
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &v); err != nil {
		t.Fatalf("python run_jsintel 输出不是 JSON: %v\n输出:\n%s", err, raw)
	}
	txt, err := os.ReadFile(filepath.Join(outDir, "jsintel.txt"))
	if err != nil {
		t.Fatalf("python jsintel.txt: %v", err)
	}
	return v, string(txt)
}

// compareJSIntelRun 两引擎同站跑同一入口，比对 JSON 结构与 txt 文本。
func compareJSIntelRun(t *testing.T, url string) (any, string, string) {
	t.Helper()
	pyDir := t.TempDir()
	pyJSON, pyTxt := pyRunJSIntel(t, url, pyDir)
	goDir := t.TempDir()
	if _, err := jsintel.RunJSIntel(url, goDir, jsintel.DefaultWorkers,
		jsintel.DefaultMaxFiles, jsintel.DefaultTimeout); err != nil {
		t.Fatalf("Go RunJSIntel(%s): %v", url, err)
	}
	raw, err := os.ReadFile(filepath.Join(goDir, "jsintel.json"))
	if err != nil {
		t.Fatalf("Go jsintel.json: %v", err)
	}
	var goJSON any
	if err := json.Unmarshal(raw, &goJSON); err != nil {
		t.Fatalf("Go jsintel.json 非法 JSON: %v\n%s", err, raw)
	}
	if !reflect.DeepEqual(pyJSON, goJSON) {
		pb, _ := json.MarshalIndent(pyJSON, "", "  ")
		gb, _ := json.MarshalIndent(goJSON, "", "  ")
		t.Fatalf("[%s] jsintel.json 结构不一致:\n--- python ---\n%s\n--- go ---\n%s", url, pb, gb)
	}
	goTxtBytes, err := os.ReadFile(filepath.Join(goDir, "jsintel.txt"))
	if err != nil {
		t.Fatalf("Go jsintel.txt: %v", err)
	}
	goTxt := string(goTxtBytes)
	if StripCR(pyTxt) != StripCR(goTxt) {
		t.Fatalf("[%s] jsintel.txt 文本不一致:\n--- python ---\n%s\n--- go ---\n%s", url, pyTxt, goTxt)
	}
	return pyJSON, string(raw), goTxt
}

func TestParityJSIntelFullChain(t *testing.T) {
	RequiresPython(t)
	srv := mockweb.New()
	defer srv.Close()
	for _, sc := range []string{"jssite", "waf", "soft404"} {
		url := srv.URL + "/" + sc
		pyJSON, goRaw, goTxt := compareJSIntelRun(t, url)
		if sc != "jssite" {
			continue
		}
		// jssite 隐私纪律：两侧落盘文件都不得含全量值。
		for _, secret := range []string{mockweb.FakePw, mockweb.FakeToken, mockweb.FakeAppID} {
			if strings.Contains(goRaw, secret) {
				t.Errorf("Go jsintel.json 泄露全量值: %s", secret)
			}
			if strings.Contains(goTxt, secret) {
				t.Errorf("Go jsintel.txt 泄露全量值: %s", secret)
			}
			pb, _ := json.Marshal(pyJSON)
			if strings.Contains(string(pb), secret) {
				t.Errorf("Python jsintel.json 泄露全量值: %s", secret)
			}
		}
		if !strings.Contains(goRaw, mockweb.FakePw[:4]+"****") {
			t.Error("Go 输出应含打码值")
		}
	}
}

// ── 全流程 parity：陷阱站（协议相对/静态资源/二进制/空文件/内联序号） ──

func TestParityJSIntelTrickySite(t *testing.T) {
	RequiresPython(t)
	inlineOne := "var cfg={token:'" + mockweb.FakeToken + "'};fetch('/api/tricky/one');"
	inlineTwo := "var cfg2={password:'" + mockweb.FakePw + "', appId:'" + mockweb.FakeAppID + "'};axios.get('/api/tricky/two');"
	page := "<!doctype html><html><body>" +
		"<script src=\"/a.js\"></script>" +
		"<script src=\"data:text/javascript,var x=1\"></script>" +
		"<script>" + inlineOne + "</script>" +
		"<script src=\"/logo.png\"></script>" +
		"<script src=\"/bin.js\"></script>" +
		"<script>" + inlineTwo + "</script>" +
		"<script src=\"/empty.js\"></script>" +
		"</body></html>"
	sk := "AKIA" + "FAKE" + "KEY" + "0001"
	appJS := "fetch('/api/js/one');\n" +
		"axios({url:'/v2/tricky'});\n" +
		"var s='/assets/x.css';\n" +
		"var key={secret_key:'" + sk + "'};\n" +
		"var host='https://api.tricky-sub.example-cdn.com/v1/x';\n" +
		"var intra='http://172.16.5.9:9000/metrics';\n" +
		"var pub='http://8.8.4.4/x';\n" +
		"var ver='1.2.3.4';\n" +
		"var tpl='/api/${" + "id}/x';\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/a.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(appJS))
	})
	mux.HandleFunc("/bin.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05})
	})
	mux.HandleFunc("/empty.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pyJSON, goRaw, goTxt := compareJSIntelRun(t, srv.URL+"/")
	// 内容锚点：避免两侧同时"优雅失败"却结构相等的假绿。
	m := pyJSON.(map[string]any)
	scripts := m["scripts"].(map[string]any)
	if scripts["external"].(float64) != 3 || scripts["inline"].(float64) != 2 {
		t.Fatalf("陷阱站脚本清点不符: %v", scripts)
	}
	eps := fmt.Sprint(m["endpoints"])
	for _, need := range []string{"/api/tricky/one", "/api/tricky/two", "/api/js/one", "/v2/tricky"} {
		if !strings.Contains(eps, need) {
			t.Errorf("端点线索缺少 %s: %s", need, eps)
		}
	}
	if strings.Contains(eps, "/assets/x.css") {
		t.Errorf("静态资源混入端点线索: %s", eps)
	}
	if !strings.Contains(goRaw, mockweb.FakePw[:4]+"****") {
		t.Error("Go jsintel.json 应含打码后的 password")
	}
	for _, secret := range []string{mockweb.FakePw, mockweb.FakeToken, mockweb.FakeAppID, sk} {
		if strings.Contains(goRaw, secret) || strings.Contains(goTxt, secret) {
			t.Errorf("落盘文件泄露全量值: %s", secret)
		}
	}
}
