package intel

// writeoutputs_test.go — WriteOutputs 导出后的独立契约测试。
// IP 反查分支（cli.runIntel）构造的 Report 不带 Files map，
// WriteOutputs 必须自行初始化而不是 panic（nil map 赋值）。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteOutputsNilFilesMap(t *testing.T) {
	out := t.TempDir()
	rep := &Report{
		Target: "192.0.2.10",
		Records: []Record{
			{Source: "hackertarget-reverse", Host: "a.example.com", IP: "192.0.2.10"},
		},
		Sources: []SourceStat{
			{Name: "hackertarget-reverse", Kind: "reverse", Count: 1, Status: "ok"},
		},
	}
	if err := WriteOutputs(out, rep); err != nil {
		t.Fatalf("WriteOutputs 失败: %v", err)
	}
	if len(rep.Files) != 3 {
		t.Fatalf("Files 应回填 3 件产物，实得 %v", rep.Files)
	}
	for _, f := range []string{"assets.json", "assets.txt", "intel.md"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Fatalf("缺产物 %s: %v", f, err)
		}
	}
	b, err := os.ReadFile(filepath.Join(out, "assets.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "a.example.com|192.0.2.10||") {
		t.Fatalf("assets.txt 旧契约行缺失: %q", string(b))
	}
}

// 空 out 不写盘、不报错（与 Run 的 out=="" 语义一致）。
func TestWriteOutputsEmptyOutNoop(t *testing.T) {
	rep := &Report{Target: "192.0.2.10"}
	if err := WriteOutputs("", rep); err != nil {
		t.Fatalf("空 out 应为 no-op: %v", err)
	}
	if len(rep.Files) != 0 {
		t.Fatalf("空 out 不应产文件: %v", rep.Files)
	}
}
