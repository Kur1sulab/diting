package cli

// intel_ip_artifacts_test.go — intel 的 IP 目标分支必须与域名分支同一产物契约：
// out/<ip>/ 下落 assets.json / assets.txt / intel.md。
//
// 回归背景：此前 IP 分支只把反查结果打到 stdout，out/ 是空目录，末尾却报
// 「[+] 采集完成：N 条记录 -> out」；下游 report.Collect 读 assets.txt
// （report/report.go）会静默丢掉整段情报。这里用 httptest 顶掉 reverse 双源
// 的真实端点（intel 包级变量），离线钉住：
//  1. 正常命中 → 三件产物齐全、旧契约行正确、report.Collect 读得到；
//  2. 双源全挂 → 仍落盘（与域名分支「源全失败也写产物」语义对齐），不 panic。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kur1sulab/yata/engine-go/intel"
	"github.com/Kur1sulab/yata/engine-go/report"
)

// chdirTemp 把 cwd 切到临时目录（MakeOutdir 相对 cwd 建 out/），结束还原。
func chdirTemp(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return tmp
}

// stubReverse 顶掉 hackertarget-reverse / rapiddns-sameip 两个真实端点。
func stubReverse(t *testing.T, ht, rd http.HandlerFunc) {
	t.Helper()
	htSrv := httptest.NewServer(ht)
	rdSrv := httptest.NewServer(rd)
	t.Cleanup(htSrv.Close)
	t.Cleanup(rdSrv.Close)
	oldHT, oldRD := intel.ReverseHackerTargetBase, intel.ReverseRapidDNSBase
	intel.ReverseHackerTargetBase = htSrv.URL
	intel.ReverseRapidDNSBase = rdSrv.URL
	t.Cleanup(func() {
		intel.ReverseHackerTargetBase = oldHT
		intel.ReverseRapidDNSBase = oldRD
	})
}

func TestIntelIPTargetWritesArtifacts(t *testing.T) {
	tmp := chdirTemp(t)
	stubReverse(t,
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("a.example.com\nb.example.com\n"))
		},
		func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<table><tr><th scope="row">1</th>` +
				`<td>c.example.com</td><td><a href="#">192.0.2.10</a></td><td>2026-11-01</td></tr></table>`))
		})
	if code := Run([]string{"intel", "-d", "192.0.2.10"}); code != 0 {
		t.Fatalf("intel -d <IP> 退出码 = %d，期望 0", code)
	}
	out := filepath.Join(tmp, "out", "192.0.2.10")
	for _, f := range []string{"assets.json", "assets.txt", "intel.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("IP 目标缺产物 %s: %v", f, err)
		}
	}
	// assets.txt 旧契约行（host|ip|port|protocol，反查记录无端口/协议）
	b, err := os.ReadFile(filepath.Join(out, "assets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "a.example.com|192.0.2.10||") {
		t.Fatalf("assets.txt 缺 hackertarget 记录行: %q", string(b))
	}
	if !strings.Contains(string(b), "c.example.com|192.0.2.10||") {
		t.Fatalf("assets.txt 缺 rapiddns 记录行: %q", string(b))
	}
	// assets.json：结构化 + 溯源 + 计时 + Files 回填
	jb, err := os.ReadFile(filepath.Join(out, "assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Target    string `json:"target"`
		StartedAt string `json:"started_at"`
		ElapsedMS int64  `json:"elapsed_ms"`
		Records   []struct {
			Host   string `json:"host"`
			IP     string `json:"ip"`
			Source string `json:"source"`
		} `json:"records"`
		Sources []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
			Count  int    `json:"count"`
		} `json:"sources"`
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal(jb, &rep); err != nil {
		t.Fatalf("assets.json 解析失败: %v", err)
	}
	if rep.Target != "192.0.2.10" || len(rep.Records) != 3 {
		t.Fatalf("target/records 不对: %+v", rep)
	}
	if rep.StartedAt == "" || rep.ElapsedMS < 0 {
		t.Fatalf("IP 分支应填 started_at/elapsed_ms: %+v", rep)
	}
	srcOK := map[string]bool{}
	for _, s := range rep.Sources {
		if s.Status == "ok" {
			srcOK[s.Name] = true
		}
	}
	if !srcOK["hackertarget-reverse"] || !srcOK["rapiddns-sameip"] {
		t.Fatalf("双源状态应 ok: %+v", rep.Sources)
	}
	if len(rep.Files) != 3 {
		t.Fatalf("files 应回填 3 件: %v", rep.Files)
	}
	for _, r := range rep.Records {
		if r.Source == "" || r.IP != "192.0.2.10" {
			t.Fatalf("记录缺溯源/IP: %+v", r)
		}
	}
	// 下游契约：report.Collect 必须能从 assets.txt 读到情报行
	bundle := report.Collect(out, "192.0.2.10")
	assets, _ := bundle["assets"].([]string)
	if len(assets) != 3 {
		t.Fatalf("report.Collect assets = %v，期望 3 行", bundle["assets"])
	}
}

func TestIntelIPTargetAllSourcesErrorStillWrites(t *testing.T) {
	tmp := chdirTemp(t)
	stubReverse(t,
		func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) })
	if code := Run([]string{"intel", "-d", "192.0.2.11"}); code != 0 {
		t.Fatalf("源全挂不应让命令失败（与域名分支一致），退出码 = %d", code)
	}
	out := filepath.Join(tmp, "out", "192.0.2.11")
	for _, f := range []string{"assets.json", "assets.txt", "intel.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("源全挂仍应落产物 %s: %v", f, err)
		}
	}
	jb, err := os.ReadFile(filepath.Join(out, "assets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Records []any `json:"records"`
		Sources []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(jb, &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Records) != 0 {
		t.Fatalf("源全挂 records 应为空: %+v", rep.Records)
	}
	if len(rep.Sources) != 2 {
		t.Fatalf("应保留两条源状态: %+v", rep.Sources)
	}
	for _, s := range rep.Sources {
		if s.Status != "error" || s.Message == "" {
			t.Fatalf("源状态应 error 且带原因: %+v", s)
		}
	}
	// intel.md 里逐源错误可见（排障第一现场）
	md, err := os.ReadFile(filepath.Join(out, "intel.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "error") {
		t.Fatalf("intel.md 应含逐源错误状态: %q", string(md))
	}
}
