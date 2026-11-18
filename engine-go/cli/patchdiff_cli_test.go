package cli

// patchdiff_cli_test.go —— patchdiff 子命令门面验收：
//   - 参数与 sweep.py:208-213 对齐（-r/--repo 必填、--commit/--range/--limit/--emit-rule）；
//   - 产物落 out/patchdiff（对齐 sweep.py:268 make_outdir("patchdiff")）；
//   - 退出码契约：缺参/参数类型错 → 2（argparse 口径）、非 git 仓库 → 1（Go 侧 fail 口径）；
//   - -h → 0（与其它子命令同款）。
//
// 测试目标红线：git fixture 建在 t.TempDir()，零外网、零真实仓库。

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pdCLIFixture 建一个最小 git 仓库（init → fix），返回目录。
func pdCLIFixture(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 不在 PATH，跳过 patchdiff CLI 测试")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_CONFIG_SYSTEM="+os.DevNull,
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q")
	write("def q(uid):\n    return \"SELECT * FROM u WHERE id=\" + uid\n")
	git("add", "-A")
	git("commit", "-q", "-m", "init")
	write("def q(uid):\n    uid = int(uid)\n    return cursor.execute(\"SELECT * FROM u WHERE id=?)\n")
	git("add", "-A")
	git("commit", "-q", "-m", "fix: sql injection")
	return dir
}

func TestPatchdiffCLIEndToEnd(t *testing.T) {
	repo := pdCLIFixture(t)
	work := t.TempDir()
	t.Chdir(work)

	if code := Run([]string{"patchdiff", "-r", repo, "--limit", "5", "--emit-rule", "variants.yaml"}); code != 0 {
		t.Fatalf("exit %d，want 0", code)
	}
	jsonPath := filepath.Join(work, "out", "patchdiff", "patchdiff.json")
	if _, err := os.Stat(jsonPath); err != nil {
		t.Fatalf("产物未落 out/patchdiff: %v", err)
	}
	rule := filepath.Join(work, "out", "patchdiff", "variants.yaml")
	b, err := os.ReadFile(rule)
	if err != nil {
		t.Fatalf("规则未落 out/patchdiff: %v", err)
	}
	if !strings.Contains(string(b), "patchdiff.variant-hunt") || !strings.Contains(string(b), "SELECT") {
		t.Errorf("规则内容异常:\n%s", b)
	}
	j, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"commits"`) || !strings.Contains(string(j), "SQL 拼接") {
		t.Errorf("JSON 内容异常:\n%s", j)
	}
}

// TestPatchdiffCLIRepoAlias --repo 是 -r 的别名（argparse 同款）。
func TestPatchdiffCLIRepoAlias(t *testing.T) {
	repo := pdCLIFixture(t)
	work := t.TempDir()
	t.Chdir(work)
	if code := Run([]string{"patchdiff", "--repo", repo, "--commit", "HEAD"}); code != 0 {
		t.Fatalf("exit %d，want 0", code)
	}
	if _, err := os.Stat(filepath.Join(work, "out", "patchdiff", "patchdiff.json")); err != nil {
		t.Fatalf("产物缺失: %v", err)
	}
}

func TestPatchdiffCLIMissingRepo(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := Run([]string{"patchdiff"}); code != 2 {
		t.Fatalf("缺 -r 应 exit 2，得 %d", code)
	}
}

func TestPatchdiffCLIBadLimit(t *testing.T) {
	repo := pdCLIFixture(t)
	t.Chdir(t.TempDir())
	if code := Run([]string{"patchdiff", "-r", repo, "--limit", "abc"}); code != 2 {
		t.Fatalf("--limit 非整数应 exit 2，得 %d", code)
	}
}

func TestPatchdiffCLINotGitRepo(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(t.TempDir())
	if code := Run([]string{"patchdiff", "-r", dir}); code != 1 {
		t.Fatalf("非 git 仓库应 exit 1（Go 侧 fail 口径），得 %d", code)
	}
	// 目录仍按 Python 语义先建出来（sweep.py:268 在 run_patchdiff 之前 make_outdir）
	if _, err := os.Stat(filepath.Join("out", "patchdiff")); err != nil {
		t.Errorf("输出目录应先创建: %v", err)
	}
}

func TestPatchdiffCLIHelp(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := Run([]string{"patchdiff", "-h"}); code != 0 {
		t.Fatalf("-h 应 exit 0，得 %d", code)
	}
}
