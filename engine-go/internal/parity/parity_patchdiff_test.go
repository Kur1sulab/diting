package parity

// parity_patchdiff_test.go —— patchdiff（补丁差分→变种狩猎）Python↔Go 对照。
//
// 三条独立断言：
//   ① 分类器逐行对照：同一批 added/removed 行喂两引擎，fix/vuln 标签与顺序必须全等
//      （含 \b 的 Unicode 词边界、上下文判定、去重保序、样本截断）；
//   ② semgrep 规则逐字节对照：转义/过滤/120 字符截断/去重/12 条上限；
//   ③ 仓库级全流程对照：同一本地 fixture 仓库（真 git 子进程，零外网）跑两引擎，
//      commits/hunks 结构、规则文件、终端摘要（输出目录归一后）全等。
//
// 门禁：git 不在 PATH 或 python/python3 都不在 PATH → Skip（纯 Go 测试不受影响）；
// CI=true 同 RequiresPython 口径跳过（parity=本地黄金对照门禁）。
// 解释器解析用自己的 python→python3 回退（与 portscan 3 项同口径）：本机 Homebrew
// 只装 python3，若沿用 Shared RequiresPython 的「只认 python」会把 patchdiff 4 项
// 静默 Skip 掉，等于没做 parity。

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Kur1sulab/sweep/engine-go/patchdiff"
)

// ── 本地 fixture 仓库（与 patchdiff 包内测试同构，刻意重复：跨包不共享 test helper）──

type pdRepo struct{ dir string }

func newPdRepo(t *testing.T) *pdRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 不在 PATH，跳过 patchdiff parity")
	}
	r := &pdRepo{dir: t.TempDir()}
	r.git(t, "init", "-q")
	return r
}

func (r *pdRepo) git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_SYSTEM="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_TERMINAL_PROMPT=0",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v 失败: %v\n%s", args, err, out)
	}
	return string(out)
}

func (r *pdRepo) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (r *pdRepo) commit(t *testing.T, msg string) string {
	t.Helper()
	r.git(t, "add", "-A")
	r.git(t, "commit", "-q", "--allow-empty", "-m", msg)
	return strings.TrimSpace(r.git(t, "rev-parse", "HEAD"))
}

// buildPatchdiffFixture 造一个覆盖解析/分类边角的仓库：
// SQL 拼接、PHP 文件包含、Java/Node 输入源、CJK 词边界、注释行、空提交、二进制、重命名。
func buildPatchdiffFixture(t *testing.T) *pdRepo {
	t.Helper()
	r := newPdRepo(t)
	r.write(t, "app.py", "def q(uid):\n    return \"SELECT * FROM u WHERE id=\" + uid\n")
	r.write(t, "www/index.php", "<?php\ninclude($_GET['page']);\n")
	r.write(t, "src/Main.java", "String id = req.getParameter(\"id\");\n")
	r.write(t, "web/app.js", "const id = req.query.id;\n")
	r.write(t, "sql/init.sql", "-- legacy note\nSELECT 1;\n")
	r.write(t, "cjk.txt", "请int(uid)\n删除select记录 + x\n（select 1） + x\n")
	r.commit(t, "init")

	r.write(t, "app.py", "def q(uid):\n    uid = int(uid)\n    stmt = conn.prepare(\"SELECT * FROM u WHERE id=?\")\n    return stmt.execute((uid,))\n")
	r.commit(t, "fix: sql injection in q()")

	r.write(t, "www/index.php", "<?php\necho htmlspecialchars($_GET['page'], ENT_QUOTES);\n")
	r.commit(t, "security: escape output")

	r.write(t, "sql/init.sql", "-- legacy note\nSELECT 1;\n")
	r.write(t, "cjk.txt", "int(uid)\n删除select记录 + x\n")
	r.commit(t, "fix: cjk 词边界与注释行")

	r.write(t, "docs/readme.md", "# 说明\n")
	r.commit(t, "chore: docs only") // 不含关键词：自动扫描不该收，--range 该收

	r.write(t, "bin/blob.bin", "\x00\x01\x02BINARY\xff")
	r.commit(t, "fix: add binary asset")

	r.git(t, "mv", "docs/readme.md", "docs/guide.md")
	r.commit(t, "fix: rename readme")

	r.commit(t, "fix: 空提交") // --allow-empty：meta 有、hunk 0
	return r
}

// ── python 探针 ──

func pdRequiresPython(t *testing.T) string {
	t.Helper()
	if os.Getenv("CI") == "true" {
		t.Skip("CI 环境：parity=本地黄金对照门禁（见 PARITY.md），跳过")
	}
	for _, name := range []string{"python", "python3"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("python/python3 不在 PATH，跳过 patchdiff parity")
	return ""
}

// pdRunPy 在仓库根跑 python -c <code> [args...]（stdin 可选），返回合并输出。
// 与 parity.RunPy 同环境（PYTHONUTF8=1 / PYTHONPATH=src / cwd=仓库根），
// 差别只在解释器由 pdRequiresPython 解析。
func pdRunPy(t *testing.T, stdin, code string, args ...string) string {
	t.Helper()
	bin := pdRequiresPython(t)
	cmd := exec.Command(bin, append([]string{"-c", code}, args...)...)
	cmd.Dir = RepoRoot()
	cmd.Env = append(os.Environ(),
		"PYTHONUTF8=1",
		"PYTHONPATH="+filepath.Join(RepoRoot(), "src"),
	)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python 执行失败: %v\n输出:\n%s", err, out)
	}
	return string(out)
}

// pdGoJSON 把 Go 值走一遍 JSON 编解码，得到与 python 侧同构的 any 树。
func pdGoJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Go 侧 JSON 编码失败: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Go 侧 JSON 解码失败: %v", err)
	}
	return out
}

// ── ① 分类器逐行对照 ──

const pyClassify = `
import json, sys
sys.path.insert(0, 'src')
from modules.patchdiff import _classify
print(json.dumps(_classify(json.load(sys.stdin)), ensure_ascii=False))
`

func TestParityPatchdiffClassify(t *testing.T) {
	fixLines := []string{
		`htmlspecialchars($x, ENT_QUOTES)`, `HTMLSPECIALCHARS($x)`,
		`addslashes($s)`, `mysqli_real_escape_string($c, $s)`, `escapeString($s)`,
		`$db->prepare("SELECT 1")`, `stmt.bindParam(1, v)`, `PreparedStatement ps = null`,
		`intval($x)`, `(int)$x`, `int($x)`, `parseInt(s)`, `Integer.parseInt(s)`,
		`is_numeric($x)`, `ctype_digit($x)`, `n, _ := strconv.Atoi(s)`,
		`basename($p)`, `realpath($p)`, `filepath.Clean(p)`, `path.normalize(p)`,
		`is_uploaded_file($f)`, `getimagesize($f)`, `whitelist`, `allowlist`,
		`csrf_token()`, `SameSite=Lax`,
		`is_admin($u)`, `hasRole('x')`, `checkPermission()`, `@PreAuthorize("x")`,
		`preg_quote($s)`, `re.escape(s)`, `Pattern.quote(s)`,
		`yaml.safe_load(s)`, `SafeLoader`, `allow_list`,
		`urlparse(u)`, `allowed_hosts`, `validate_url(u)`, `is_private(ip)`,
		`escapeshellarg($a)`, `escapeshellcmd($a)`, `shlex.quote(s)`,
		// \b 的 Unicode 边界
		`请int(uid)`, `xint(uid)`, `（int(uid)`, `int(uid)请`, `  int (uid)`,
		// 上下文判定
		`cursor.execute("... id=?)`, `cursor.execute("... id=?, x)`, `execute("plain")`,
		`x = 1`, ``, `   `,
	}
	vulnLines := []string{
		`echo $_GET['x'];`, `$_REQUEST['y']`,
		`req.getParameter("id")`, `@RequestParam String id`,
		`x = request.form['a']`, `y = request.args.get('b')`,
		`const id = req.query.id;`, `req.body`,
		`os.system(cmd)`, `Runtime.getRuntime().exec(cmd)`, `child_process.exec(c)`,
		`pickle.load(f)`, `yaml.load(s)`, `unserialize($s)`, `readObject(in)`,
		`q = "select * from t where id=" + uid`, `q = "id=" + $x`, `q = "id=" . $_GET['id']`,
		`include($_GET['f']);`, `require($f);`,
		`删除select记录 + x`, `（select 1） + x`, `select1 + x`, `de-select + x`,
		`x = 1`, ``,
	}

	files := []patchdiff.File{}
	for i, ln := range fixLines {
		files = append(files, patchdiff.File{File: fmt.Sprintf("fix%02d.txt", i),
			Hunks: []patchdiff.Hunk{{Header: "@@ added", Removed: []string{}, Added: []string{ln}}}})
	}
	for i, ln := range vulnLines {
		files = append(files, patchdiff.File{File: fmt.Sprintf("vuln%02d.txt", i),
			Hunks: []patchdiff.Hunk{{Header: "@@ removed", Removed: []string{ln}, Added: []string{}}}})
	}
	// 混排 hunk：样本截断 + 去重保序 + 两类信号同块
	files = append(files, patchdiff.File{File: "mixed.diff", Hunks: []patchdiff.Hunk{{
		Header:  "@@ -1,20 +1,20 @@",
		Removed: []string{`echo $_GET['a'];`, `os.system(c)`, `echo $_GET['a'];`, `"x" + $y`, `a`, `b`, `c`, `d`, `e`, `f`, `g`, `h`, `i`, `j`},
		Added:   []string{`int($x)`, `htmlspecialchars($x)`, `csrf_token()`, `int($x)`, `a`, `b`, `c`, `d`, `e`, `f`, `g`, `h`, `i`, `j`},
	}}})

	stdin, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	pyOut := pdRunPy(t, string(stdin), pyClassify)
	var py any
	if err := json.Unmarshal([]byte(pyOut), &py); err != nil {
		t.Fatalf("python 输出不是 JSON: %v\n%s", err, pyOut)
	}

	if rows, ok := py.([]any); !ok || len(rows) < 50 {
		t.Fatalf("对照语料该产出 ≥50 行（防空跑），实得 %d", len(py.([]any)))
	}
	got := pdGoJSON(t, patchdiff.Classify(files))
	stripSha(t, got)
	if !reflect.DeepEqual(py, got) {
		pyText, _ := json.MarshalIndent(py, "", " ")
		goText, _ := json.MarshalIndent(got, "", " ")
		t.Fatalf("分类结果不一致\npython(%d):\n%s\ngo(%d):\n%s", len(py.([]any)), pyText, len(got.([]any)), goText)
	}
}

// stripSha 去掉 Go 行里多出的 sha 键（Python 的 _classify 不产出该键，run 阶段才补）。
func stripSha(t *testing.T, v any) {
	t.Helper()
	rows, ok := v.([]any)
	if !ok {
		t.Fatalf("行集合类型异常: %T", v)
	}
	for _, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("行类型异常: %T", r)
		}
		if s, ok := m["sha"]; ok && s == "" {
			delete(m, "sha")
		}
	}
}

// ── ② semgrep 规则逐字节对照 ──

const pyEmitRule = `
import json, sys
sys.path.insert(0, 'src')
from modules.patchdiff import emit_rule
rows = json.load(sys.stdin)
print(emit_rule(rows, sys.argv[1]))
`

func TestParityPatchdiffEmitRule(t *testing.T) {
	rows := []map[string]any{
		{"removed": []string{`    return "SELECT * FROM u WHERE id=" + uid`, `    return "SELECT * FROM u WHERE id=" + uid`}},
		{"removed": []string{"x=1", "// comment", "# hash", "* star", ""}},
		{"removed": []string{strings.Repeat("漏", 130)}},
		{"removed": []string{`include($_GET['page']);`, `eval($code);`}},
		{"removed": []string{"a1", "b2", "c3", "d4", "e5", "f6", "g7", "h8", "i9", "j0", "k1", "l2", "m3", "n4"}},
	}
	stdin, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}

	pyPath := filepath.Join(t.TempDir(), "py.yaml")
	pdRunPy(t, string(stdin), pyEmitRule, pyPath)

	goRows := make([]patchdiff.Row, len(rows))
	for i, r := range rows {
		goRows[i] = patchdiff.Row{Removed: r["removed"].([]string)}
	}
	goPath := filepath.Join(t.TempDir(), "go.yaml")
	if _, err := patchdiff.EmitRule(goRows, goPath); err != nil {
		t.Fatal(err)
	}
	pyText, err := os.ReadFile(pyPath)
	if err != nil {
		t.Fatalf("python 规则文件未生成: %v", err)
	}
	goText, err := os.ReadFile(goPath)
	if err != nil {
		t.Fatalf("go 规则文件未生成: %v", err)
	}
	if string(pyText) != string(goText) {
		t.Fatalf("规则文本不一致\npython:\n%q\ngo:\n%q", pyText, goText)
	}
	if strings.Contains(string(goText), "TODO_PATTERN") || !strings.Contains(string(goText), "\\+") {
		t.Fatalf("规则应含转义后的真实样本（防空跑）:\n%s", goText)
	}
}

// ── ③ 仓库级全流程对照 ──

const pyRunPatchdiff = `
import sys
sys.path.insert(0, 'src')
from modules.patchdiff import run_patchdiff
run_patchdiff(sys.argv[1], None, None, 20, 'variants.yaml', outdir=sys.argv[2])
`

func TestParityPatchdiffRun(t *testing.T) {
	pdRequiresPython(t)
	repo := buildPatchdiffFixture(t)

	pyOut := t.TempDir()
	pyText := pdRunPy(t, "", pyRunPatchdiff, repo.dir, pyOut)

	goOut := t.TempDir()
	var buf strings.Builder
	res, err := patchdiff.Run(patchdiff.Options{
		Repo: repo.dir, Limit: 20, Emit: "variants.yaml", Outdir: goOut,
		Logf: func(f string, a ...any) { fmt.Fprintf(&buf, f, a...) },
	})
	if err != nil {
		t.Fatalf("Go Run: %v", err)
	}

	// 3.1 产物 JSON 结构全等
	pyDoc := readJSONFile(t, filepath.Join(pyOut, "patchdiff.json"))
	goDoc := pdGoJSON(t, struct {
		Commits []patchdiff.Commit `json:"commits"`
		Hunks   []patchdiff.Row    `json:"hunks"`
	}{res.Commits, res.Hunks})
	if !reflect.DeepEqual(pyDoc, goDoc) {
		pyText, _ := json.MarshalIndent(pyDoc, "", " ")
		goText2, _ := json.MarshalIndent(goDoc, "", " ")
		t.Fatalf("产物结构不一致\npython:\n%s\ngo:\n%s", pyText, goText2)
	}
	if len(res.Commits) == 0 || len(res.Hunks) == 0 {
		t.Fatalf("fixture 该命中安全相关 hunk，实得 commits=%d hunks=%d", len(res.Commits), len(res.Hunks))
	}

	// 3.2 规则文件逐字节全等
	pyRule, err := os.ReadFile(filepath.Join(pyOut, "variants.yaml"))
	if err != nil {
		t.Fatalf("python 规则未生成: %v", err)
	}
	goRule, err := os.ReadFile(filepath.Join(goOut, "variants.yaml"))
	if err != nil {
		t.Fatalf("go 规则未生成: %v", err)
	}
	if string(pyRule) != string(goRule) {
		t.Fatalf("规则文本不一致\npython:\n%s\ngo:\n%s", pyRule, goRule)
	}

	// 3.3 终端摘要全等（输出目录各自归一）
	norm := func(s, outdir string) string {
		s = strings.ReplaceAll(s, outdir, "<OUT>")
		return StripCR(s)
	}
	pySum, goSum := norm(pyText, pyOut), norm(buf.String(), goOut)
	if pySum != goSum {
		t.Fatalf("摘要输出不一致\npython:\n%s\ngo:\n%s", pySum, goSum)
	}
}

// readJSONFile 读 JSON 文件成 any 树。
func readJSONFile(t *testing.T, path string) any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s: %v", path, err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("解析 %s: %v\n%s", path, err, b)
	}
	return v
}

// ── ④ 提交挑选（--grep 关键词 / --range / --commit / --limit）──

const pyCommits = `
import json, sys
sys.path.insert(0, 'src')
from modules.patchdiff import _commits
repo, commit, rng, limit = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
print(json.dumps(_commits(repo, commit or None, rng or None, limit)))
`

func TestParityPatchdiffCommits(t *testing.T) {
	pdRequiresPython(t)
	repo := buildPatchdiffFixture(t)
	head := strings.TrimSpace(repo.git(t, "rev-parse", "HEAD"))

	cases := []struct {
		name        string
		commit, rng string
		limit       int
	}{
		{"auto-grep", "", "", 20},
		{"auto-grep-limit2", "", "", 2},
		{"range", "", "HEAD~4..HEAD", 20},
		{"commit", head, "", 20},
	}
	for _, c := range cases {
		pyOut := pdRunPy(t, "", pyCommits, repo.dir, c.commit, c.rng, fmt.Sprint(c.limit))
		var want []string
		if err := json.Unmarshal([]byte(pyOut), &want); err != nil {
			t.Fatalf("[%s] python 输出不是数组: %v\n%s", c.name, err, pyOut)
		}
		got, err := patchdiff.Commits(t.Context(), repo.dir, c.commit, c.rng, c.limit)
		if err != nil {
			t.Fatalf("[%s] Go Commits: %v", c.name, err)
		}
		if !reflect.DeepEqual(pyListOrEmpty(want), pyListOrEmpty(got)) {
			t.Errorf("[%s] 提交列表不一致\npython: %v\ngo:     %v", c.name, pyListOrEmpty(want), pyListOrEmpty(got))
		}
	}
}

func pyListOrEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
