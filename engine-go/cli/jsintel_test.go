package cli

// jsintel_test.go —— jsintel 子命令接线验收（engine-go/jsintel → CLI）：
// 参数校验 exit 2 / mock 靶站 exit 0 / out/<target>/jsintel.json 落盘结构。
// 靶站走 Go httptest（mockweb），零外网。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Kur1sulab/yata/engine-go/mockweb"
)

func TestJSIntelCLIWiring(t *testing.T) {
	resetProgress(t)
	srv := mockweb.New()
	defer srv.Close()
	dir := t.TempDir()
	t.Chdir(dir)

	url := srv.URL + "/jssite"
	if code := Run([]string{"jsintel", "-u", url, "--workers", "2", "--max-files", "5"}); code != 0 {
		t.Fatalf("jsintel exit=%d，期望 0", code)
	}
	outDir := filepath.Join("out", OutdirName(url))
	raw, err := os.ReadFile(filepath.Join(outDir, "jsintel.json"))
	if err != nil {
		t.Fatalf("jsintel.json 缺失: %v", err)
	}
	var res struct {
		Base      string   `json:"base"`
		Endpoints []string `json:"endpoints"`
		Scripts   struct {
			External int `json:"external"`
			Inline   int `json:"inline"`
		} `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("jsintel.json 解析失败: %v\n%s", err, raw)
	}
	if res.Base != url {
		t.Fatalf("base = %q, want %q", res.Base, url)
	}
	want := map[string]bool{"/api/v1/users": true, "/api/v2/login": true,
		"/v3/pay": true, "/weather/beijing": true}
	for _, e := range res.Endpoints {
		delete(want, e)
	}
	if len(want) != 0 {
		t.Fatalf("端点线索缺失: %v（实得 %v）", want, res.Endpoints)
	}
	if res.Scripts.External != 1 || res.Scripts.Inline != 1 {
		t.Fatalf("scripts 计数异常: %+v", res.Scripts)
	}
	if _, err := os.Stat(filepath.Join(outDir, "jsintel.txt")); err != nil {
		t.Fatalf("jsintel.txt 缺失: %v", err)
	}
}

func TestJSIntelCLIArgErrors(t *testing.T) {
	resetProgress(t)
	if code := Run([]string{"jsintel"}); code != 2 {
		t.Fatalf("缺少 -u 应 exit 2，得 %d", code)
	}
	if code := Run([]string{"jsintel", "-u", "http://127.0.0.1/x", "--workers", "abc"}); code != 2 {
		t.Fatalf("非法 --workers 应 exit 2，得 %d", code)
	}
}
