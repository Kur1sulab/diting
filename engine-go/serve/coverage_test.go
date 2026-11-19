package serve

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// covWrite 夹具落盘小工具。
func covWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// 空根目录（out/ 不存在）= 空态而非错误：7 列横轴仍在，0 行。
func TestCoverageAtEmptyRoot(t *testing.T) {
	v := coverageAt(filepath.Join(t.TempDir(), "nonexistent"), nil)
	if len(v.Checks) != 7 {
		t.Fatalf("checks = %d, want 7", len(v.Checks))
	}
	if len(v.Targets) != 0 || v.Summary.Cells != 0 {
		t.Fatalf("empty root should yield 0 targets: %+v", v.Summary)
	}
}

// 三态判定 + 基线 k/8 + 坏 JSON 不崩溃 + 测试夹具目录被跳过 + 汇总计数。
func TestCoverageAtThreeStates(t *testing.T) {
	root := t.TempDir()

	// example.com：子域命中 2 / 端口命中 2（扫 100）/ 路径已跑无命中 /
	// 指纹、API、JS 未跑 / 基线 2/8 且 1 处 warn。
	d := filepath.Join(root, "example.com")
	covWrite(t, d, "subdomains.txt", "a.example.com\nb.example.com\n\n")
	covWrite(t, d, "ports.json", `{"scanned":100,"open":[{"port":80},{"port":443}]}`)
	covWrite(t, d, "paths.json", `{"alive":[]}`)
	covWrite(t, d, "secheaders.json", `{"check":"secheaders","risks":[{"level":"warn","title":"HSTS 缺失"}]}`)
	covWrite(t, d, "webfiles.json", `{"check":"webfiles","risks":[{"level":"ok","title":"无"}]}`)

	// broken.test：ports.json 损坏 → 已跑但计数不可信（empty），其余未跑。
	b := filepath.Join(root, "broken.test")
	covWrite(t, b, "ports.json", `{invalid json`)

	// 测试夹具目录必须被跳过。
	covWrite(t, filepath.Join(root, "_unittest"), "ports.json", `{"open":[{}]}`)
	// patchdiff 是工具固定产物目录（补丁差异），不是资产目标，同样必须跳过。
	covWrite(t, filepath.Join(root, "patchdiff"), "patchdiff.json", `{"diffs":[]}`)

	v := coverageAt(root, nil)
	if len(v.Targets) != 2 {
		t.Fatalf("targets = %d, want 2 (_unittest/patchdiff skipped)", len(v.Targets))
	}
	byName := map[string]CoverageTarget{}
	for _, row := range v.Targets {
		byName[row.Target] = row
	}

	ex := byName["example.com"]
	if ex.Kind != "domain" {
		t.Fatalf("example.com kind = %q", ex.Kind)
	}
	want := map[string]struct {
		state string
		n     int
		text  string
	}{
		"subs":     {"hits", 2, "2"},
		"ports":    {"hits", 2, "2"},
		"finger":   {"missing", 0, "未跑"},
		"paths":    {"empty", 0, "0"},
		"api":      {"missing", 0, "未跑"},
		"jsintel":  {"missing", 0, "未跑"},
		"baseline": {"hits", 1, "2/8"},
	}
	for key, w := range want {
		c := ex.Cells[key]
		if c.State != w.state || c.N != w.n || c.Text != w.text {
			t.Errorf("example.com/%s = %+v, want state=%s n=%d text=%s", key, c, w.state, w.n, w.text)
		}
	}
	if ex.Missing != 3 {
		t.Errorf("example.com missing = %d, want 3", ex.Missing)
	}
	if !ex.Cells["baseline"].Partial {
		t.Errorf("baseline 2/8 should be flagged partial")
	}

	br := byName["broken.test"]
	if br.Cells["ports"].State != "empty" {
		t.Errorf("broken ports state = %q, want empty (ran but unparseable)", br.Cells["ports"].State)
	}
	if br.Missing != 6 {
		t.Errorf("broken.test missing = %d, want 6", br.Missing)
	}

	// 汇总：2 目标 × 7 列 = 14 格；missing 3+6=9，empty 1+1=2，hits 3。
	s := v.Summary
	if s.Targets != 2 || s.Cells != 14 || s.Missing != 9 || s.Empty != 2 || s.Hits != 3 {
		t.Fatalf("summary = %+v, want {2 14 9 2 3}", s)
	}
}

// IP:port 目标目录判 ip；在跑任务行置顶并带上 job 关联。
func TestCoverageJobLinkAndSort(t *testing.T) {
	root := t.TempDir()
	covWrite(t, filepath.Join(root, "example.com"), "subdomains.txt", "a.example.com\n")
	covWrite(t, filepath.Join(root, "127.0.0.1_18080"), "ports.json", `{"scanned":1,"open":[]}`)

	jobs := []*JobView{{ID: "j9", Target: "127.0.0.1:18080", Status: JobRunning}}
	v := coverageAt(root, jobs)
	if len(v.Targets) != 2 {
		t.Fatalf("targets = %d", len(v.Targets))
	}
	first := v.Targets[0]
	if first.Target != "127.0.0.1_18080" || first.JobID != "j9" || first.JobStatus != JobRunning {
		t.Fatalf("running job row should sort first with link: %+v", first)
	}
	if first.Kind != "ip" {
		t.Fatalf("kind = %q, want ip", first.Kind)
	}
	if first.Cells["ports"].State != "empty" {
		t.Fatalf("ports with open=[] should be empty: %+v", first.Cells["ports"])
	}
}

// HTTP 层：GET /api/coverage 200 + JSON 形状（7 列、summary 与行数自洽）。
func TestCoverageHandler(t *testing.T) {
	s := newTestServer(t)
	mux := buildMux(s)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/coverage", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var v CoverageView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(v.Checks) != 7 {
		t.Fatalf("checks = %d, want 7", len(v.Checks))
	}
	if v.Summary.Cells != 7*len(v.Targets) {
		t.Fatalf("summary.cells = %d, targets = %d", v.Summary.Cells, len(v.Targets))
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
}
