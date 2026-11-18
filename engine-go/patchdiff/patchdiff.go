// Package patchdiff：补丁差分 → 变种狩猎，移植 src/modules/patchdiff.py。
//
// 思路（patchdiff.py:3-8）：厂商修洞时改的那几行就是漏洞的「指纹」——
// 被删掉的行 ≈ 漏洞写法，新增的行 ≈ 补上的检查。把「被删写法」压成
// semgrep 规则骨架，就能拿它扫兄弟项目/二开版本，从 n-day 推出变种 0day。
//
// 移植口径（与 Python 版的每一处对齐都有对应注释）：
//   - git 一律走子进程、命令与参数逐字一致（不引 git 库）——两版看同一份仓库
//     历史，才有 parity 可比；
//   - 正则语义对齐 Python re.search(pat, line, re.I)：Python 的 \b 按 Unicode
//     词字符集判定，Go 原生 \b 只认 ASCII，中文紧贴关键字时会多命中；故带 \b
//     的信号走 pyMatcher（见下）；
//   - 产物 JSON 对齐 json.dump(..., ensure_ascii=False, indent=1)：缩进 1 空格、
//     不转义 <>&、无末尾换行、键序按 Python dict 插入序（结构体字段序即键序）；
//   - 失败口径：Python 版以 {'ok': False, 'error': ...} 返回、由调用方决定
//     退出码；Go 版返回 error（ErrNotGitRepo 等），CLI 据此 fail 事件 + exit 1。
package patchdiff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DefaultLimit 自动挑提交时的默认上限（patchdiff.py:57 / yata.py:212：-n 20）。
const DefaultLimit = 20

// gitTimeout 单条 git 命令上限，对齐 patchdiff.py:45 的 timeout=120。
const gitTimeout = 120 * time.Second

// ErrNotGitRepo 仓库路径不是 git 仓库（.git 必须是目录）——哨兵供 errors.Is 判定。
// Python 侧同一判据是 os.path.isdir(os.path.join(repo, '.git'))（patchdiff.py:143），
// 因此 worktree/submodule 的 .git 指针文件同样被拒（行为对齐，非疏漏）。
var ErrNotGitRepo = errors.New("不是 git 仓库")

// NotGitRepoError 带上被检查的绝对路径，错误文案与 Python 逐字一致：
// '不是 git 仓库: ' + abspath。
type NotGitRepoError struct{ Repo string }

func (e *NotGitRepoError) Error() string { return "不是 git 仓库: " + e.Repo }

// Is 让 errors.Is(err, ErrNotGitRepo) 成立（对上层只暴露哨兵语义）。
func (e *NotGitRepoError) Is(target error) bool { return target == ErrNotGitRepo }

// ── 信号表（patchdiff.py:17-41 逐条逐字）──

type signalDef struct{ label, pat string }

// fixSignalDefs 「修复信号」：出现在 added 行 → 这一 hunk 很可能在补洞。
var fixSignalDefs = []signalDef{
	{`XSS 转义`, `htmlspecialchars|htmlentities|esc_html|escape_html`},
	{`SQL 转义`, `addslashes|mysqli_real_escape_string|pg_escape|escapeString`},
	{`参数化查询`, `prepare\s*\(|bindParam|bindValue|PreparedStatement`},
	{`整数化`, `intval|\(int\)|\bint\s*\(|parseInt|Integer\.parseInt|is_numeric|cctype_digit|strconv\.Atoi`},
	{`路径规范化`, `basename|realpath|filepath\.Clean|path\.normalize`},
	{`上传白名单`, `is_uploaded_file|getimagesize|whitelist|allowlist`},
	{`CSRF/令牌`, `csrf|nonce|samesite`},
	{`鉴权`, `is_admin|hasRole|checkPermission|@PreAuthorize|authorize`},
	{`正则转义`, `preg_quote|re\.escape|Pattern\.quote`},
	{`序列化加固`, `safe_load|SafeLoader|allow_?list`},
	{`SSRF 防护`, `urlparse|allowed_hosts|validate_url|is_private`},
	{`命令转义`, `escapeshellarg|escapeshellcmd|shlex\.quote`},
}

// vulnSignalDefs 「漏洞写法痕迹」：出现在 removed 行。
var vulnSignalDefs = []signalDef{
	{`PHP 输入源`, `\$_GET|\$_POST|\$_REQUEST|\$_COOKIE`},
	{`Java 输入源`, `getParameter|getHeader|@RequestParam`},
	{`Python 输入源`, `request\.(args|form|GET|POST)`},
	{`Node 输入源`, `req\.(query|body|params)`},
	{`命令/代码执行`, `eval\s*\(|exec\s*\(|system\s*\(|Runtime\.getRuntime\(\)\.exec|child_process`},
	{`反序列化`, `unserialize|readObject|ObjectInputStream|pickle\.load|yaml\.load\s*\(`},
	{`SQL 拼接`, `\+\s*\$|\.\s*\$_(GET|POST|REQUEST)`},
	{`文件包含`, `include\s*\(|require\s*\(`},
}

type signal struct {
	label string
	m     pyMatcher
}

var (
	fixSignals  = compileSignals(fixSignalDefs)
	vulnSignals = compileSignals(vulnSignalDefs)

	// 上下文判定用的三条（patchdiff.py:92-93、100-101）。
	reExecute     = compilePyMatcher(`execute\s*\(`)
	rePlaceholder = compilePyMatcher(`\?\s*[,)]`)
	reSQLVerb     = compilePyMatcher(`\b(select|insert|update|delete)\b`)

	// diff --git 行取 b/ 之后的名字（patchdiff.py:70：re.search(r'\sb/(.+)$')）。
	reFileFromB = regexp.MustCompile(`\sb/(.+)$`)
)

func compileSignals(defs []signalDef) []signal {
	out := make([]signal, 0, len(defs))
	for _, d := range defs {
		out = append(out, signal{label: d.label, m: compilePyMatcher(d.pat)})
	}
	return out
}

// pyMatcher 复刻 Python re.search(pat, s, re.I) 的布尔语义。
//
// 差异点只有一个但会改结论：Python 的 \b 是 Unicode 词边界（\w = 字母/数字/
// 下划线），Go regexp 的 \b 只认 ASCII。信号表里 `intval|...|\bint\s*\(` 这类
// 模式若直接交给 RE2，`请int(x)`（中文紧贴关键字）在 Go 侧会命中、Python 侧不命中。
//
// 做法：先按顶层 `|` 拆成分支（`\b` 可能藏在某个分支开头，如「整数化」那条），
// 再把每个分支首/尾的 \b 摘掉，用 rune 判定回查边界。分支中段的 \b（如
// `foo\bbar`）RE2 无法表达零宽断言 → 不支持；当前信号表没有，
// TestSignalPatternsBoundaryForms 守卫（将来新增会先红）。
type pyMatcher struct {
	branches []pyBranch
}

// pyBranch 一条顶层分支：去掉首尾 \b 后的正则 + 边界要求。
type pyBranch struct {
	re     *regexp.Regexp
	leftB  bool // 分支以 \b 开头：匹配起点须是 Python 词边界
	rightB bool // 分支以 \b 结尾：匹配终点须是 Python 词边界
}

func compilePyMatcher(pat string) pyMatcher {
	m := pyMatcher{}
	for _, br := range splitTopLevelAlt(pat) {
		b := pyBranch{}
		s := br
		if strings.HasPrefix(s, `\b`) {
			b.leftB = true
			s = s[len(`\b`):]
		}
		if strings.HasSuffix(s, `\b`) {
			b.rightB = true
			s = s[:len(s)-len(`\b`)]
		}
		if strings.Contains(s, `\b`) {
			// 分支中段 \b：降级为无边界（守卫测试保证走不到）。
			s = strings.ReplaceAll(s, `\b`, "")
		}
		b.re = regexp.MustCompile("(?i)" + s)
		m.branches = append(m.branches, b)
	}
	return m
}

// MatchString 等价 Python re.search(pat, line, re.I) 的真假值。
func (m pyMatcher) MatchString(line string) bool {
	for _, b := range m.branches {
		if b.match(line) {
			return true
		}
	}
	return false
}

func (b pyBranch) match(line string) bool {
	if !b.leftB && !b.rightB {
		return b.re.MatchString(line)
	}
	// 带边界：逐个候选位置回查（RE2 不支持零宽断言，只能匹配后再验）。
	for off := 0; off <= len(line); {
		loc := b.re.FindStringIndex(line[off:])
		if loc == nil {
			return false
		}
		start, end := off+loc[0], off+loc[1]
		if (!b.leftB || pyBoundaryAt(line, start)) && (!b.rightB || pyBoundaryAt(line, end)) {
			return true
		}
		next := start + 1 // 下一候选：本轮起点之后（RE2 不重叠匹配，故手工推进）
		if next <= off {
			next = off + 1
		}
		off = next
	}
	return false
}

// splitTopLevelAlt 按顶层 `|` 切分支：括号内、字符类内、转义后的 `|` 不算。
func splitTopLevelAlt(pat string) []string {
	out := []string{}
	depth, start := 0, 0
	inClass := false
	for i := 0; i < len(pat); i++ {
		c := pat[i]
		if c == '\\' { // 转义：连同下一个字符一起跳过
			i++
			continue
		}
		if inClass {
			if c == ']' {
				inClass = false
			}
			continue
		}
		switch c {
		case '[':
			inClass = true
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case '|':
			if depth == 0 {
				out = append(out, pat[start:i])
				start = i + 1
			}
		}
	}
	return append(out, pat[start:])
}

// pyBoundaryAt 等价 Python 的 \b 判定：位置 pos 两侧「恰有一侧是词字符」。
// 越界一侧按非词字符算（与 Python 一致：串首 \b 仅当首字符是词字符才成立）。
func pyBoundaryAt(s string, pos int) bool {
	before, after := false, false
	if pos > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:pos])
		before = isPyWordRune(r)
	}
	if pos < len(s) {
		r, _ := utf8.DecodeRuneInString(s[pos:])
		after = isPyWordRune(r)
	}
	return before != after
}

// isPyWordRune Python 的 \w：字母 ∪ 数字 ∪ 下划线（CPython：ISALNUM || '_'）。
func isPyWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// ── 数据结构（字段序 = Python dict 键序，JSON 逐字节对齐用）──

// Hunk 单个 @@ 块。Removed/Added 只存行内容（去掉行首 -/+），顺序保持。
type Hunk struct {
	Header  string   `json:"header"`
	Removed []string `json:"removed"`
	Added   []string `json:"added"`
}

// File 单个 diff --git 文件段。
type File struct {
	File  string `json:"file"`
	Hunks []Hunk `json:"hunks"`
}

// Commit 提交元信息（sha 截前 10 位，日期 --date=short）。
type Commit struct {
	Sha     string `json:"sha"`
	Date    string `json:"date"`
	Subject string `json:"subject"`
	Hunks   int    `json:"hunks"`
}

// Row 一个被判定为安全相关的 hunk。
// 键序 file/header/fix/vuln/removed/added/sha 与 patchdiff.py:105-107 + 172 一致。
type Row struct {
	File    string   `json:"file"`
	Header  string   `json:"header"`
	Fix     []string `json:"fix"`
	Vuln    []string `json:"vuln"`
	Removed []string `json:"removed"`
	Added   []string `json:"added"`
	Sha     string   `json:"sha"`
}

// doc 落盘包络 {'commits': meta, 'hunks': rows}（patchdiff.py:177-178）。
type doc struct {
	Commits []Commit `json:"commits"`
	Hunks   []Row    `json:"hunks"`
}

// Options Run 的入参。零值可用：Repo 必填，Limit<=0 取 DefaultLimit。
type Options struct {
	Repo   string // 本地 git 仓库路径（内部转绝对路径）
	Commit string // 只看某个提交（优先于 Range，patchdiff.py:52-53）
	Range  string // 提交区间，如 v1.2..v1.3
	Limit  int    // 自动挑提交的上限；<=0 → DefaultLimit（Python argparse 默认 20）
	Emit   string // semgrep 规则文件名；相对路径落在 Outdir 内，绝对路径原样
	Outdir string // 产物目录，缺省 <cwd>/patchdiff-out
	Quiet  bool   // 不打摘要（对齐 run_patchdiff(quiet=True)）
	Logf   func(format string, a ...any)
}

// Result 成功态（Python 版 dict 的 Go 化身；Rule 为空表示未生成规则）。
type Result struct {
	OK      bool
	Commits []Commit
	Hunks   []Row
	JSON    string
	Rule    string
}

// ── git 子进程 ──

// runGit 跑一条 git 命令，返回 stdout 与退出码。
// 退出码非 0 不算 Go 侧错误（Python _sh 同样只回 rc，由调用点决定怎么处理）；
// error 只在「起不来/超时」时返回，对齐 subprocess.TimeoutExpired 会向上抛。
func runGit(ctx context.Context, repo string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, gitTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repo
	cmd.Env = gitEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", -1, fmt.Errorf("git %s: 超过 %s 未返回: %w",
			strings.Join(args, " "), gitTimeout, ctx.Err())
	}
	if err == nil {
		return stdout.String(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.String(), exitErr.ExitCode(), nil
	}
	return stdout.String(), -1, fmt.Errorf("git %s: %w（stderr: %s）",
		strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
}

// gitEnv 继承环境但剔掉 PYTHONPATH（patchdiff.py:45 env.pop('PYTHONPATH')：
// git 钩子里跑的 python 不该被本仓库 src/ 污染）。
func gitEnv() []string {
	env := os.Environ()
	out := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, "PYTHONPATH=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// Commits 挑要分析的提交（patchdiff.py:51-63）：
//   - commit 非空 → 只回该 sha（不校验存在性）；
//   - range 非空 → git log --pretty=%H <range>（注意 Python 侧 range 分支丢掉了
//     -n limit，这里同样不设上限，行为对齐）；
//   - 否则按 --grep 关键词挑：fix/security/cve/vuln/bypass，-i、OR 语义、-n limit。
func Commits(ctx context.Context, repo, commit, rng string, limit int) ([]string, error) {
	if commit != "" {
		return []string{commit}, nil
	}
	if limit <= 0 {
		limit = DefaultLimit
	}
	n := fmt.Sprint(limit)
	var args []string
	if rng != "" {
		args = []string{"log", "--pretty=%H", rng}
	} else {
		// git --grep 默认 BRE，「fix|security」不是「或」，必须拆成多个 --grep
		//（patchdiff.py:57-59 注释里「踩过的坑」）。
		args = []string{"log", "--pretty=%H", "-i",
			"--grep=fix", "--grep=security", "--grep=cve", "--grep=vuln", "--grep=bypass",
			"-n", n}
	}
	out, code, err := runGit(ctx, repo, args...)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return []string{}, nil // 对齐 _commits: rc != 0 → []
	}
	shas := []string{}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			shas = append(shas, s)
		}
	}
	return shas, nil
}

// ── diff 解析与分类 ──

// ParseHunks 解析 git show 的输出（patchdiff.py:66-82）。
// 保守照搬两处 Python 侧现状（不是笔误，是契约）：
//   - 内容行以 '--' 开头时，diff 里呈现为 '--- x'，会被 `not startswith('---')`
//     跳过——真被删的行就丢一行；
//   - 'diff --git' 之前出现的 @@（如合并提交的 diff --cc）因 cur 为空被忽略。
func ParseHunks(diffText string) []File {
	files := []File{}
	cur, hunk := -1, -1
	for _, line := range splitLines(diffText) {
		switch {
		case strings.HasPrefix(line, "diff --git"):
			name := line
			if m := reFileFromB.FindStringSubmatch(line); m != nil {
				name = m[1]
			}
			files = append(files, File{File: name, Hunks: []Hunk{}})
			cur, hunk = len(files)-1, -1
		case strings.HasPrefix(line, "@@"):
			if cur < 0 {
				continue
			}
			files[cur].Hunks = append(files[cur].Hunks, Hunk{Header: line, Removed: []string{}, Added: []string{}})
			hunk = len(files[cur].Hunks) - 1
		case hunk >= 0:
			h := &files[cur].Hunks[hunk]
			switch {
			case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
				h.Removed = append(h.Removed, line[1:])
			case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
				h.Added = append(h.Added, line[1:])
			}
		}
	}
	return files
}

// Classify 逐个 hunk 打信号标签（patchdiff.py:85-110）。
// 只在 fix 或 vuln 非空时出行；样本各截前 10 行。
func Classify(files []File) []Row {
	rows := []Row{}
	for _, f := range files {
		for _, h := range f.Hunks {
			fix := []string{}
			for _, a := range h.Added {
				for _, sig := range fixSignals {
					if sig.m.MatchString(a) && !hasLabel(fix, sig.label) {
						fix = append(fix, sig.label)
					}
				}
				// 上下文判定：execute(...) 里出现占位符 → 参数化查询
				if reExecute.MatchString(a) && rePlaceholder.MatchString(a) && !hasLabel(fix, "参数化查询") {
					fix = append(fix, "参数化查询")
				}
			}
			vuln := []string{}
			for _, r := range h.Removed {
				for _, sig := range vulnSignals {
					if sig.m.MatchString(r) && !hasLabel(vuln, sig.label) {
						vuln = append(vuln, sig.label)
					}
				}
				// 上下文判定：SQL 语句里出现字符串拼接 → 典型注入写法
				if reSQLVerb.MatchString(r) && strings.Contains(r, "+") && !hasLabel(vuln, "SQL 拼接") {
					vuln = append(vuln, "SQL 拼接")
				}
			}
			if len(fix) == 0 && len(vuln) == 0 {
				continue
			}
			rows = append(rows, Row{
				File: f.File, Header: h.Header,
				Fix: fix, Vuln: vuln,
				Removed: firstN(h.Removed, 10), Added: firstN(h.Added, 10),
			})
		}
	}
	return rows
}

// ── semgrep 规则骨架 ──

// reRuleEscape 对齐 emit_rule 里的 re.sub(r'([\\"\[\]\(\)\{\}\.\*\+\?\|\^\$])', r'\\\1', s)。
var reRuleEscape = regexp.MustCompile(`[\\"\[\]\(\)\{\}\.\*\+\?\|\^\$]`)

const ruleTemplate = `rules:
- id: patchdiff.variant-hunt
  languages: [generic]
  severity: WARNING
  message: 该写法在修复补丁中被移除，疑似同类漏洞变种，需人工确认可达性
  metadata:
    confidence: LOW
    source: patchdiff
  patterns:
    - pattern-regex: (%s)
`

// EmitRule 把「被删的危险写法」压成 semgrep 规则骨架（patchdiff.py:113-137），返回写入路径。
// 过滤/改写顺序逐条对齐：strip → 短行(<6 字符)与注释行(// # *)丢弃 → 正则元字符转义
// → 截前 120 字符 → 去重保序 → 取前 12 条 → '|' 连接。一条不剩时落 TODO_PATTERN。
func EmitRule(rows []Row, path string) (string, error) {
	pats := []string{}
	seen := map[string]bool{}
	for _, r := range rows {
		for _, line := range r.Removed {
			s := strings.TrimSpace(line)
			if utf8.RuneCountInString(s) < 6 || strings.HasPrefix(s, "//") ||
				strings.HasPrefix(s, "#") || strings.HasPrefix(s, "*") {
				continue
			}
			esc := reRuleEscape.ReplaceAllStringFunc(s, func(m string) string { return `\` + m })
			esc = truncRunes(esc, 120)
			if seen[esc] {
				continue
			}
			seen[esc] = true
			pats = append(pats, esc)
			if len(pats) == 12 {
				break
			}
		}
		if len(pats) == 12 {
			break
		}
	}
	body := fmt.Sprintf(ruleTemplate, joinOr(pats, "|", "TODO_PATTERN"))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// ── 主流程 ──

// Run 是 RunContext 的无取消版（包内零长任务，与九模块入口签名习惯一致）。
func Run(opts Options) (*Result, error) { return RunContext(context.Background(), opts) }

// RunContext 主流程，对齐 run_patchdiff（patchdiff.py:140-186）。
// 取消语义：ctx 取消即收敛返回 ctx.Err()、不落盘（Python 版无此能力）。
func RunContext(ctx context.Context, opts Options) (*Result, error) {
	repo, err := filepath.Abs(opts.Repo)
	if err != nil {
		return nil, err
	}
	// .git 必须是目录：worktree/submodule 的指针文件与「压根不是仓库」同罪。
	if fi, statErr := os.Stat(filepath.Join(repo, ".git")); statErr != nil || !fi.IsDir() {
		return nil, &NotGitRepoError{Repo: repo}
	}

	shas, err := Commits(ctx, repo, opts.Commit, opts.Range, opts.Limit)
	if err != nil {
		return nil, err
	}

	commits := []Commit{}
	rows := []Row{}
	for _, sha := range shas {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, code, gerr := runGit(ctx, repo, "show", "--unified=3", "--format=%H%n%ad%n%s", "--date=short", sha)
		if gerr != nil {
			return nil, gerr
		}
		if code != 0 || strings.TrimSpace(out) == "" {
			continue
		}
		head := splitLines(out)
		sha10 := truncRunes(sha, 10)
		meta := Commit{Sha: sha10}
		if len(head) > 1 {
			meta.Date = head[1]
		}
		if len(head) > 2 {
			meta.Subject = head[2]
		}
		commitRows := Classify(ParseHunks(out))
		meta.Hunks = len(commitRows)
		commits = append(commits, meta)
		for _, r := range commitRows {
			r.Sha = sha10
			rows = append(rows, r)
		}
	}

	outdir := opts.Outdir
	if outdir == "" {
		wd, werr := os.Getwd()
		if werr != nil {
			return nil, werr
		}
		outdir = filepath.Join(wd, "patchdiff-out")
	}
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return nil, err
	}
	jsonPath := filepath.Join(outdir, "patchdiff.json")
	if err := os.WriteFile(jsonPath, marshalDoc(doc{Commits: commits, Hunks: rows}), 0o644); err != nil {
		return nil, err
	}

	rule := ""
	if strings.TrimSpace(opts.Emit) != "" {
		p := opts.Emit
		if !filepath.IsAbs(p) {
			p = filepath.Join(outdir, p)
		}
		if rule, err = EmitRule(rows, p); err != nil {
			return nil, err
		}
	}

	if !opts.Quiet {
		logf := opts.Logf
		if logf == nil {
			logf = func(format string, a ...any) { fmt.Printf(format, a...) }
		}
		logf("[patchdiff] 仓库 %s｜提交 %d 个｜安全相关 hunk %d 个\n", repo, len(commits), len(rows))
		for _, m := range commits {
			logf("  %s %s %s → %d hunk\n", m.Sha, m.Date, truncRunes(m.Subject, 60), m.Hunks)
		}
		for _, r := range topRows(rows, 5) {
			logf("  · %s %s\n", r.Sha, r.File)
			logf("    修复信号: %s｜漏洞痕迹: %s\n", joinOr(r.Fix, ", ", "—"), joinOr(r.Vuln, ", ", "—"))
		}
		if rule != "" {
			logf("[patchdiff] 结果: %s｜规则: %s\n", jsonPath, rule)
		} else {
			logf("[patchdiff] 结果: %s\n", jsonPath)
		}
	}

	return &Result{OK: true, Commits: commits, Hunks: rows, JSON: jsonPath, Rule: rule}, nil
}

// topRows 按「修复信号×2 + 漏洞痕迹」降序取前 n（patchdiff.py:183：
// sorted(..., key=lambda r: -(len(fix)*2 + len(vuln)))[:5]）。同分保原始顺序
// （Python sorted 稳定 → Go 必须 SliceStable，否则同分行的先后会随机漂）。
func topRows(rows []Row, n int) []Row {
	idx := make([]int, len(rows))
	for i := range rows {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		wa := len(rows[idx[a]].Fix)*2 + len(rows[idx[a]].Vuln)
		wb := len(rows[idx[b]].Fix)*2 + len(rows[idx[b]].Vuln)
		return wa > wb
	})
	out := []Row{}
	for _, i := range idx {
		if len(out) == n {
			break
		}
		out = append(out, rows[i])
	}
	return out
}

// marshalDoc 产出 indent=1 的 JSON 文本（json.dump(indent=1) 对齐）：
// 关 HTML 转义、去 Encoder 自带末尾换行。
func marshalDoc(d doc) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(d); err != nil {
		return []byte("{}")
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// ── 小工具 ──

// splitLines 按 \n 切行并去掉行尾 \r——对齐 Python text=True 的 universal newlines
// （CRLF 仓库的 diff 在 Python 侧被折成 LF，Go 侧不能把 \r 留在行内容里）。
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		lines[i] = strings.TrimSuffix(ln, "\r")
	}
	return lines
}

// truncRunes 截前 n 个字符（Python 切片按码点，不是字节；中文不能按字节切）。
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// firstN 取前 n 项；空输入回非 nil 空切片（JSON 要 [] 不能是 null）。
func firstN(xs []string, n int) []string {
	if len(xs) == 0 {
		return []string{}
	}
	if len(xs) > n {
		xs = xs[:n]
	}
	out := make([]string, len(xs))
	copy(out, xs)
	return out
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

func joinOr(xs []string, sep, empty string) string {
	if len(xs) == 0 {
		return empty
	}
	return strings.Join(xs, sep)
}
