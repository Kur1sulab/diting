package patchdiff

// patchdiff_test.go —— 移植验收（对齐 tests/test_patchdiff.py 三项 + Go 侧加固）：
//   ① diff 解析：多文件/多 hunk、b/ 取名、`---`/`+++` 跳过（Python 现状照搬）；
//   ② 信号分类：12 条修复信号 + 8 条漏洞痕迹逐条命中、上下文判定、去重保序、样本截断；
//   ③ semgrep 规则：转义/过滤/120 字符截断/去重/12 条上限/空表兜底；
//   ④ 仓库级主流程：真 git 子进程跑本地 fixture 仓库（零外网、零真实目标）；
//   ⑤ 词边界：Python 的 \b 是 Unicode 语义（Go 原生是 ASCII），中文相邻不得多命中。
//
// 测试目标红线：全部 t.TempDir() 本地建仓，不碰任何既有仓库与外部主机。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// ── 本地 git fixture ──

type fixtureRepo struct{ dir string }

func newFixtureRepo(t *testing.T) *fixtureRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git 不在 PATH，跳过 fixture 仓库测试")
	}
	r := &fixtureRepo{dir: t.TempDir()}
	r.git(t, "init", "-q")
	return r
}

// git 跑一条 git 命令；隔离全局/系统配置（用户 commit.gpgsign 等不该影响测试）。
func (r *fixtureRepo) git(t *testing.T, args ...string) string {
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

func (r *fixtureRepo) write(t *testing.T, name, content string) {
	t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// commit 提交当前工作区，返回完整 sha（--allow-empty 兼容空提交场景）。
func (r *fixtureRepo) commit(t *testing.T, msg string) string {
	t.Helper()
	r.git(t, "add", "-A")
	r.git(t, "commit", "-q", "--allow-empty", "-m", msg)
	return strings.TrimSpace(r.git(t, "rev-parse", "HEAD"))
}

// ── ① diff 解析 ──

func TestParseHunks(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@ def q(uid):
-old = "SELECT * FROM u WHERE id=" + uid
+uid = int(uid)
+---- 这行以 + 开头，是内容不是文件头
diff --git a/dir a/file with space.php b/dir a/file with space.php
index 3333333..4444444 100644
--- a/dir a/file with space.php	
+++ b/dir a/file with space.php	
@@ -10 +10,2 @@
-echo $_GET['x'];
+echo htmlspecialchars($_GET['x']);
`
	files := ParseHunks(diff)
	if len(files) != 2 {
		t.Fatalf("文件数 %d，want 2: %+v", len(files), files)
	}
	if files[0].File != "app.py" {
		t.Errorf("文件名 %q，want app.py（b/ 之后取名）", files[0].File)
	}
	// 带空格的路径：`\sb/(.+)$` 贪婪取到行尾，两侧一致。
	if files[1].File != "dir a/file with space.php" {
		t.Errorf("文件名 %q，want %q", files[1].File, "dir a/file with space.php")
	}
	if len(files[0].Hunks) != 1 {
		t.Fatalf("hunk 数 %d，want 1", len(files[0].Hunks))
	}
	h := files[0].Hunks[0]
	if h.Header != "@@ -1,2 +1,3 @@ def q(uid):" {
		t.Errorf("header = %q", h.Header)
	}
	if len(h.Removed) != 1 || h.Removed[0] != `old = "SELECT * FROM u WHERE id=" + uid` {
		t.Errorf("removed = %#v", h.Removed)
	}
	if len(h.Added) != 2 || h.Added[0] != "uid = int(uid)" ||
		h.Added[1] != "---- 这行以 + 开头，是内容不是文件头" {
		t.Errorf("added = %#v", h.Added)
	}
}

// TestParseHunksQuirks 把 Python 侧两处现状钉死（照搬而非修好）：
//   - 内容行以 `-- ` 开头 → diff 呈现为 `--- ...` → 被当文件头跳过（丢一行）；
//   - `diff --cc` 不在 `diff --git` 分支，其 @@@ 因 cur 空被忽略（合并提交 0 hunk）。
func TestParseHunksQuirks(t *testing.T) {
	diff := `@@ -1 +1 @@
先行 @@ 没有所属文件，忽略
diff --cc merge.py
@@@ -1,2 -1,2 +1,3 @@@
--- sqlcomment 行被跳过
+++ 新增行保留
diff --git a/x.txt b/x.txt
@@ -1 +1 @@
--- 这行内容以两个减号开头（被跳过）
-普通删除行
+普通新增行
`
	files := ParseHunks(diff)
	if len(files) != 1 {
		t.Fatalf("文件数 %d，want 1（diff --cc 不建文件、其 @@@ 被忽略）: %+v", len(files), files)
	}
	h := files[0].Hunks[0]
	if len(h.Removed) != 1 || h.Removed[0] != "普通删除行" {
		t.Errorf("`--- ` 内容行应被跳过，removed = %#v", h.Removed)
	}
	if len(h.Added) != 1 || h.Added[0] != "普通新增行" {
		t.Errorf("added = %#v", h.Added)
	}
}

func TestParseHunksCRLF(t *testing.T) {
	// 对齐 Python text=True 的 universal newlines：行尾 \r 不进内容。
	files := ParseHunks("diff --git a/a b/a\r\n@@ -1 +1 @@\r\n-x\r\n+y\r\n")
	if len(files) != 1 || len(files[0].Hunks) != 1 {
		t.Fatalf("解析结果 %+v", files)
	}
	if got := files[0].Hunks[0].Removed[0]; got != "x" {
		t.Errorf("removed 行残留 \\r: %q", got)
	}
	if got := files[0].Hunks[0].Added[0]; got != "y" {
		t.Errorf("added 行残留 \\r: %q", got)
	}
}

// ── ② 信号分类 ──

func classifyOne(added, removed []string) Row {
	rows := Classify([]File{{File: "x", Hunks: []Hunk{{Header: "@@", Removed: removed, Added: added}}}})
	if len(rows) == 0 {
		return Row{}
	}
	return rows[0]
}

func TestClassifyFixSignals(t *testing.T) {
	cases := []struct{ line, want string }{
		{`htmlspecialchars($x, ENT_QUOTES)`, "XSS 转义"},
		{`mysqli_real_escape_string($c, $x)`, "SQL 转义"},
		{`$stmt = $db->prepare("SELECT 1")`, "参数化查询"},
		{"\tuid = int(uid)\n", "整数化"},
		{`if (is_numeric($id)) {`, "整数化"},
		{`n, _ := strconv.Atoi(raw)`, "整数化"},
		{`p = os.path.basename(p)`, "路径规范化"},
		{`if ext in whitelist:`, "上传白名单"},
		{`csrf_token(request)`, "CSRF/令牌"},
		{`if (!checkPermission(u)) {`, "鉴权"},
		{`re.escape(name)`, "正则转义"},
		{`data = yaml.safe_load(text)`, "序列化加固"},
		{`u = urlparse(raw)`, "SSRF 防护"},
		{`cmd = escapeshellarg(x)`, "命令转义"},
		{`HTMLSPECIALCHARS($x)`, "XSS 转义"},     // re.I：大小写不敏感
		{`allowed_hosts.append(h)`, "SSRF 防护"}, // allow_?list / allowed_hosts 两族都要认
	}
	for _, c := range cases {
		got := classifyOne([]string{c.line}, nil).Fix
		if !hasLabel(got, c.want) {
			t.Errorf("added %q → fix=%v，want 含 %q", c.line, got, c.want)
		}
	}
}

func TestClassifyVulnSignals(t *testing.T) {
	cases := []struct{ line, want string }{
		{`echo $_GET['x'];`, "PHP 输入源"},
		{`String id = req.getParameter("id");`, "Java 输入源"},
		{`x = request.form['a']`, "Python 输入源"},
		{`const id = req.query.id;`, "Node 输入源"},
		{`os.system(cmd)`, "命令/代码执行"},
		{`data = pickle.load(f)`, "反序列化"},
		{`q = "select * from t where id=" + uid`, "SQL 拼接"},
		{`include($_GET['f']);`, "文件包含"},
		{`q = "id=" + $x`, "SQL 拼接"}, // \+\s*\$ 分支
	}
	for _, c := range cases {
		got := classifyOne(nil, []string{c.line}).Vuln
		if !hasLabel(got, c.want) {
			t.Errorf("removed %q → vuln=%v，want 含 %q", c.line, got, c.want)
		}
	}
}

// TestClassifyWordBoundaryPythonSemantics 钉住 \b 的 Unicode 语义（见 pyMatcher）。
func TestClassifyWordBoundaryPythonSemantics(t *testing.T) {
	intCases := []struct {
		line string
		want bool
	}{
		{"int(uid)", true},
		{"  int (uid)", true},
		{"int(uid)请", true},    // 右边界对中文成立
		{"（int(uid)", true},    // 全角括号是非词字符 → 有边界
		{"请int(uid)", false},   // 中文是词字符 → Python 侧无边界
		{"xint(uid)", false},   // 前接 ASCII 词字符 → 无边界
		{"printf(uid)", false}, // int 后面不是 \s*(，本就不该命中
	}
	for _, c := range intCases {
		got := hasLabel(classifyOne([]string{c.line}, nil).Fix, "整数化")
		if got != c.want {
			t.Errorf("%q → 整数化=%v，want %v", c.line, got, c.want)
		}
	}
	sqlCases := []struct {
		line string
		want bool
	}{
		{`"select * from t" + uid`, true},
		{`（select 1） + x`, true},
		{`de-select + x`, true},
		{`删除select记录 + x`, false}, // 中文紧贴 → Python 无边界
		{`select1 + x`, false},    // 尾边界不成立
	}
	for _, c := range sqlCases {
		got := hasLabel(classifyOne(nil, []string{c.line}).Vuln, "SQL 拼接")
		if got != c.want {
			t.Errorf("%q → SQL 拼接=%v，want %v", c.line, got, c.want)
		}
	}
}

// TestSignalPatternsBoundaryForms 守卫：pyMatcher 只支持「顶层分支首/尾」的 \b。
// 将来若有人往信号表里塞分支中段 \b（如 `foo\bbar`），此处先红，逼他扩展实现。
func TestSignalPatternsBoundaryForms(t *testing.T) {
	for _, d := range append(append([]signalDef{}, fixSignalDefs...), vulnSignalDefs...) {
		for _, br := range splitTopLevelAlt(d.pat) {
			s := strings.TrimPrefix(br, `\b`)
			s = strings.TrimSuffix(s, `\b`)
			if strings.Contains(s, `\b`) {
				t.Errorf("信号 %q（%s）分支 %q 含中段 \\b：pyMatcher 不支持，需扩展实现", d.label, d.pat, br)
			}
		}
	}
	// 拆分支本身也要对：括号内/转义后的 | 不算顶层
	if got := splitTopLevelAlt(`a|(b|c)|d\|e|[|]`); len(got) != 4 {
		t.Errorf("顶层分支拆分错误: %#v", got)
	}
}

func TestClassifyContextualParamQuery(t *testing.T) {
	cases := []struct {
		line string
		want bool
	}{
		{`cursor.execute("SELECT * FROM u WHERE id=?)`, true},           // `\?\s*[,)]` 命中 `?)`
		{`cursor.execute("SELECT * FROM u WHERE id=?, uid)`, true},      // 命中 `?,`
		{`cursor.execute("SELECT * FROM u WHERE id=?", (uid,))`, false}, // ? 后是引号：Python 同样不命中
		{`cursor.execute("SELECT * FROM u WHERE id=%s")`, false},
		{`cursor.execute(f"SELECT * FROM u WHERE id={uid}")`, false},
	}
	for _, c := range cases {
		got := hasLabel(classifyOne([]string{c.line}, nil).Fix, "参数化查询")
		if got != c.want {
			t.Errorf("%q → 参数化查询=%v，want %v", c.line, got, c.want)
		}
	}
}

func TestClassifyDedupOrderAndCap(t *testing.T) {
	row := classifyOne([]string{`htmlspecialchars($a)`, `csrf_token()`, `htmlspecialchars($b)`}, nil)
	if strings.Join(row.Fix, ",") != "XSS 转义,CSRF/令牌" {
		t.Errorf("去重保序失败: %v", row.Fix)
	}
	if len(row.Added) != 3 {
		t.Errorf("added 样本 %d 条，want 3", len(row.Added))
	}

	added := make([]string, 12)
	removed := make([]string, 12)
	for i := range added {
		added[i] = "int(x)"
		removed[i] = `echo $_GET['a'];`
	}
	row = classifyOne(added, removed)
	if len(row.Added) != 10 || len(row.Removed) != 10 {
		t.Errorf("样本应各截 10 行: added=%d removed=%d", len(row.Added), len(row.Removed))
	}
}

func TestClassifyNoSignalNoRow(t *testing.T) {
	rows := Classify([]File{{File: "a", Hunks: []Hunk{{Header: "@@", Removed: []string{"x = 1"}, Added: []string{"y = 2"}}}}})
	if len(rows) != 0 {
		t.Fatalf("无关 hunk 不该出行: %+v", rows)
	}
}

// ── ③ semgrep 规则 ──

func TestEmitRuleExactFormat(t *testing.T) {
	dir := t.TempDir()
	path, err := EmitRule([]Row{{Removed: []string{
		`    return "SELECT * FROM u WHERE id=" + uid`,
		`    return "SELECT * FROM u WHERE id=" + uid`, // 重复项只留一份
		"x=1",        // <6 字符丢弃
		"// comment", // 注释行丢弃
		"# hash",
		"* star",
	}}}, filepath.Join(dir, "v.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "v.yaml") {
		t.Errorf("返回值应是写入路径: %q", path)
	}
	want := `rules:
- id: patchdiff.variant-hunt
  languages: [generic]
  severity: WARNING
  message: 该写法在修复补丁中被移除，疑似同类漏洞变种，需人工确认可达性
  metadata:
    confidence: LOW
    source: patchdiff
  patterns:
    - pattern-regex: (return \"SELECT \* FROM u WHERE id=\" \+ uid)
`
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("规则文本不一致\n got: %q\nwant: %q", string(got), want)
	}
}

func TestEmitRuleEmptyFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.yaml")
	if _, err := EmitRule([]Row{{Removed: []string{"", "a", "//x"}}}, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "pattern-regex: (TODO_PATTERN)") {
		t.Errorf("空表应落 TODO_PATTERN:\n%s", b)
	}
}

func TestEmitRuleCapAndRuneTruncate(t *testing.T) {
	rows := []Row{}
	for i := 0; i < 20; i++ {
		rows = append(rows, Row{Removed: []string{strings.Repeat(string(rune('a'+i)), 10)}})
	}
	// 第 21 条：宽字符长行，验证 120 是「字符」不是「字节」
	rows = append(rows, Row{Removed: []string{strings.Repeat("漏", 130)}})

	path := filepath.Join(t.TempDir(), "r.yaml")
	if _, err := EmitRule(rows, path); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	line := ""
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.Contains(ln, "pattern-regex: (") {
			line = strings.TrimSuffix(strings.TrimPrefix(ln, "    - pattern-regex: ("), ")")
		}
	}
	parts := strings.Split(line, "|")
	if len(parts) != 12 {
		t.Fatalf("规则条数 %d，want 12: %v", len(parts), parts)
	}
	for _, p := range parts {
		if utf8.RuneCountInString(p) != 10 {
			t.Errorf("截断/去重异常: %q", p)
		}
	}

	// 单条超长行：120 字符截断（130 个「漏」→ 120 个）
	path2 := filepath.Join(t.TempDir(), "long.yaml")
	if _, err := EmitRule([]Row{{Removed: []string{strings.Repeat("漏", 130)}}}, path2); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(path2)
	if !strings.Contains(string(b2), strings.Repeat("漏", 120)+")") {
		t.Errorf("应按 120 字符截断")
	}
	if strings.Contains(string(b2), strings.Repeat("漏", 121)) {
		t.Errorf("截断多了：出现 121 个字符")
	}
}

// ── ④ 仓库级主流程 ──

func TestRunEndToEnd(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "app.py", "def q(uid):\n    return \"SELECT * FROM u WHERE id=\" + uid\n")
	first := repo.commit(t, "init")
	repo.write(t, "app.py", "def q(uid):\n    uid = int(uid)\n    stmt = conn.prepare(\"SELECT * FROM u WHERE id=?\")\n    return stmt.execute((uid,))\n")
	second := repo.commit(t, "fix: sql injection in q()")

	out := t.TempDir()
	res, err := Run(Options{Repo: repo.dir, Limit: 5, Outdir: out, Emit: "variants.yaml", Quiet: true})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK {
		t.Fatal("res.OK 应为 true")
	}
	if len(res.Commits) != 1 || res.Commits[0].Sha != second[:10] {
		t.Fatalf("应只命中 fix 提交: %+v", res.Commits)
	}
	if res.Commits[0].Subject != "fix: sql injection in q()" || res.Commits[0].Hunks != 1 {
		t.Errorf("元信息不对: %+v", res.Commits[0])
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`).MatchString(res.Commits[0].Date) {
		t.Errorf("日期应为 --date=short: %q", res.Commits[0].Date)
	}
	if _, err := os.Stat(filepath.Join(repo.dir, ".git", "HEAD")); err != nil {
		t.Fatal(err)
	}
	if len(res.Hunks) != 1 {
		t.Fatalf("hunk 数 %d，want 1: %+v", len(res.Hunks), res.Hunks)
	}
	h := res.Hunks[0]
	if h.File != "app.py" || h.Sha != second[:10] {
		t.Errorf("行归属不对: %+v", h)
	}
	if !hasLabel(h.Fix, "整数化") || !hasLabel(h.Fix, "参数化查询") {
		t.Errorf("修复信号缺失: %v", h.Fix)
	}
	if !hasLabel(h.Vuln, "SQL 拼接") {
		t.Errorf("漏洞痕迹缺失: %v", h.Vuln)
	}
	if h.Removed[0] != `    return "SELECT * FROM u WHERE id=" + uid` {
		t.Errorf("removed 样本 = %q", h.Removed[0])
	}
	if res.JSON != filepath.Join(out, "patchdiff.json") {
		t.Errorf("JSON 路径 %q", res.JSON)
	}
	if res.Rule != filepath.Join(out, "variants.yaml") {
		t.Errorf("规则路径 %q（相对名应落在 outdir）", res.Rule)
	}
	if b, err := os.ReadFile(res.Rule); err != nil || !strings.Contains(string(b), "patchdiff.variant-hunt") {
		t.Errorf("规则文件内容异常: %v %s", err, b)
	}

	var d doc
	b, err := os.ReadFile(res.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("产物不是 JSON: %v\n%s", err, b)
	}
	if len(d.Commits) != 1 || len(d.Hunks) != 1 {
		t.Errorf("产物包络: commits=%d hunks=%d", len(d.Commits), len(d.Hunks))
	}
	_ = first
}

func TestRunAbsoluteEmitPath(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	repo.commit(t, "init")
	repo.write(t, "a.py", "x = int(1)\n")
	repo.commit(t, "fix: cast")

	rule := filepath.Join(t.TempDir(), "abs.yaml")
	res, err := Run(Options{Repo: repo.dir, Outdir: t.TempDir(), Emit: rule, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rule != rule {
		t.Errorf("绝对路径应原样使用: %q", res.Rule)
	}
	if _, err := os.Stat(rule); err != nil {
		t.Errorf("规则未写到绝对路径: %v", err)
	}
}

func TestRunNotGitRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := Run(Options{Repo: dir, Outdir: t.TempDir(), Quiet: true})
	if !errors.Is(err, ErrNotGitRepo) {
		t.Fatalf("want ErrNotGitRepo，得到 %v", err)
	}
	var ng *NotGitRepoError
	if !errors.As(err, &ng) || !filepath.IsAbs(ng.Repo) {
		t.Fatalf("错误应带绝对路径: %#v", ng)
	}
	if !strings.HasPrefix(err.Error(), "不是 git 仓库: ") {
		t.Errorf("文案应对齐 Python: %q", err.Error())
	}
}

// TestRunGitFileRejected .git 是文件（worktree/submodule 指针）→ 同罪拒绝，
// 与 Python os.path.isdir 判据一致。
func TestRunGitFileRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".git"), []byte("gitdir: /elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Run(Options{Repo: dir, Outdir: t.TempDir(), Quiet: true})
	if !errors.Is(err, ErrNotGitRepo) {
		t.Fatalf("want ErrNotGitRepo，得到 %v", err)
	}
}

func TestRunUnknownCommitSkipped(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	repo.commit(t, "init")

	out := t.TempDir()
	res, err := Run(Options{Repo: repo.dir, Commit: "0000000000000000000000000000000000000000",
		Outdir: out, Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commits) != 0 || len(res.Hunks) != 0 {
		t.Fatalf("不存在的提交应被跳过: %+v", res)
	}
	b, _ := os.ReadFile(res.JSON)
	if !strings.Contains(string(b), `"commits": []`) || !strings.Contains(string(b), `"hunks": []`) {
		t.Errorf("空结果应落 []（不是 null）:\n%s", b)
	}
}

func TestRunEmptyCommitHasMeta(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	repo.commit(t, "init")
	empty := repo.commit(t, "fix: 只有说明没有改动")

	res, err := Run(Options{Repo: repo.dir, Outdir: t.TempDir(), Quiet: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Commits) != 1 || res.Commits[0].Sha != empty[:10] || res.Commits[0].Hunks != 0 {
		t.Fatalf("空提交应留在 meta、hunk 记 0: %+v", res.Commits)
	}
	if len(res.Hunks) != 0 {
		t.Errorf("空提交不该有 hunk")
	}
}

func TestRunCommitRangeAndLimit(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	first := repo.commit(t, "init")
	repo.write(t, "a.py", "x = int(1)\n")
	repo.commit(t, "fix: one")
	repo.write(t, "a.py", "x = int(int(1))\n")
	third := repo.commit(t, "fix: two")

	res, err := Run(Options{Repo: repo.dir, Commit: third, Outdir: t.TempDir(), Quiet: true})
	if err != nil || len(res.Commits) != 1 || res.Commits[0].Sha != third[:10] {
		t.Fatalf("--commit 应只回该提交: %+v %v", res.Commits, err)
	}

	res, err = Run(Options{Repo: repo.dir, Range: first + ".." + third, Outdir: t.TempDir(), Quiet: true})
	if err != nil || len(res.Commits) != 2 {
		t.Fatalf("--range 应回区间内 2 个提交: %+v %v", res.Commits, err)
	}

	res, err = Run(Options{Repo: repo.dir, Limit: 1, Outdir: t.TempDir(), Quiet: true})
	if err != nil || len(res.Commits) != 1 || res.Commits[0].Sha != third[:10] {
		t.Fatalf("--limit 1 应只回最新一个: %+v %v", res.Commits, err)
	}
}

// TestCommitsDefaultLimit limit<=0 采用 argparse 默认 20（Options 零值可用）。
func TestCommitsDefaultLimit(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "0\n")
	repo.commit(t, "init")
	for i := 0; i < 24; i++ {
		repo.write(t, "a.py", strings.Repeat("x", i+1)+"\n")
		repo.commit(t, "fix: bump "+strings.Repeat("x", i+1))
	}
	shas, err := Commits(context.Background(), repo.dir, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(shas) != DefaultLimit {
		t.Fatalf("默认上限 %d，得到 %d", DefaultLimit, len(shas))
	}
	// 显式上限照传：3 → 3
	shas, err = Commits(context.Background(), repo.dir, "", "", 3)
	if err != nil || len(shas) != 3 {
		t.Fatalf("limit 3 → %d %v", len(shas), err)
	}
}

func TestRunQuietSuppressesSummary(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	repo.commit(t, "init")
	repo.write(t, "a.py", "x = int(1)\n")
	repo.commit(t, "fix: cast")

	called := false
	_, err := Run(Options{Repo: repo.dir, Outdir: t.TempDir(), Quiet: true,
		Logf: func(string, ...any) { called = true }})
	if err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("Quiet 模式下不该打摘要")
	}
}

func TestRunSummaryFormat(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", `q = "SELECT * FROM u WHERE id=" + uid`+"\n")
	repo.commit(t, "init")
	repo.write(t, "a.py", "uid = int(uid)\nstmt = conn.prepare(\"SELECT * FROM u WHERE id=?\")\n")
	repo.commit(t, "fix: 修补 SQL 注入并加参数化查询")

	var lines []string
	_, err := Run(Options{Repo: repo.dir, Outdir: t.TempDir(),
		Logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(lines, "")
	if !strings.Contains(joined, "[patchdiff] 仓库 ") || !strings.Contains(joined, "｜提交 1 个｜安全相关 hunk 1 个") {
		t.Errorf("摘要头不对:\n%s", joined)
	}
	if !strings.Contains(joined, "→ 1 hunk") {
		t.Errorf("缺提交行:\n%s", joined)
	}
	if !strings.Contains(joined, "修复信号: 整数化, 参数化查询｜漏洞痕迹: SQL 拼接") {
		t.Errorf("信号行不对:\n%s", joined)
	}
	if !strings.Contains(joined, "[patchdiff] 结果: ") || !strings.Contains(joined, "patchdiff.json") {
		t.Errorf("缺结果行:\n%s", joined)
	}
	if strings.Contains(joined, "｜规则: ") {
		t.Errorf("未 --emit-rule 不该打规则段:\n%s", joined)
	}
}

func TestTopRowsStable(t *testing.T) {
	rows := []Row{
		{File: "a", Fix: []string{"x"}},
		{File: "b", Vuln: []string{"y", "z"}},
		{File: "c", Fix: []string{"x"}, Vuln: []string{"y"}},
		{File: "d"},
		{File: "e", Fix: []string{"x"}, Vuln: []string{"y"}},
		{File: "f"},
	}
	got := topRows(rows, 5)
	if len(got) != 5 {
		t.Fatalf("want 5，得到 %d", len(got))
	}
	// 权重：c/e=3、a=2、b=2、d/f=0；同分保序 → c,e,a,b,d
	want := []string{"c", "e", "a", "b", "d"}
	for i, w := range want {
		if got[i].File != w {
			t.Fatalf("第 %d 位 %s，want %s（%v）", i, got[i].File, w, filesOf(got))
		}
	}
}

func filesOf(rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.File
	}
	return out
}

func TestMarshalDocIndent1(t *testing.T) {
	got := string(marshalDoc(doc{
		Commits: []Commit{{Sha: "abc", Date: "2026-01-02", Subject: "fix: x", Hunks: 2}},
		Hunks:   []Row{{File: "a.py", Header: "@@ -1 +1 @@", Fix: []string{}, Vuln: []string{"SQL 拼接"}, Removed: []string{"x"}, Added: []string{}, Sha: "abc"}},
	}))
	want := `{
 "commits": [
  {
   "sha": "abc",
   "date": "2026-01-02",
   "subject": "fix: x",
   "hunks": 2
  }
 ],
 "hunks": [
  {
   "file": "a.py",
   "header": "@@ -1 +1 @@",
   "fix": [],
   "vuln": [
    "SQL 拼接"
   ],
   "removed": [
    "x"
   ],
   "added": [],
   "sha": "abc"
  }
 ]
}`
	if got != want {
		t.Errorf("indent=1 文本不一致\n got: %q\nwant: %q", got, want)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("json.dump 不带末尾换行")
	}
	if got := string(marshalDoc(doc{Commits: []Commit{}, Hunks: []Row{}})); got != "{\n \"commits\": [],\n \"hunks\": []\n}" {
		t.Errorf("空包络: %q", got)
	}
}

func TestRunContextCanceled(t *testing.T) {
	repo := newFixtureRepo(t)
	repo.write(t, "a.py", "x = 1\n")
	repo.commit(t, "init")
	repo.write(t, "a.py", "x = int(1)\n")
	repo.commit(t, "fix: cast")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := t.TempDir()
	if _, err := RunContext(ctx, Options{Repo: repo.dir, Outdir: out, Quiet: true}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled，得到 %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "patchdiff.json")); !os.IsNotExist(err) {
		t.Errorf("取消后不该落盘: %v", err)
	}
}
