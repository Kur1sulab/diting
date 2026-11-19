// Package jsintel：JS 情报提取（前端接口挖掘），移植 src/modules/jsintel.py。
//
// 流程：抓目标页 → 收集 <script src> 外链 + 内联 JS → 低并发下载外链
// （≤6 并发 / 单文件 ≤2MB / 10s 超时 / 只 GET / 普通浏览器 UA）→ 三类线索：
//
//	a) API 端点/路径：fetch/axios/$.ajax 调用 + 字符串字面量中的路径；
//	   去重 + 规范化 + 滤静态资源；EndpointsFull（绝对 URL）可直接喂给
//	   api / paths 模块复核；
//	b) 敏感线索（只标位置，不判定漏洞）：key/secret/token/password/appid/
//	   authorization/ak/sk 命中的 文件+行号+片段（前 40 字符）；
//	   疑似值只留前 4 位其余打码——片段里的值同样打码，保证输出文件本身
//	   不泄露敏感值；
//	c) 域名线索：JS 中绝对 URL 的域名 / 内网 IP / 子域名（相对目标归类，去重）。
//
// 纪律：线索 ≠ 漏洞，所有命中必须人工复核；本模块只发 GET，不发任何写请求。
package jsintel

import (
	"context"
	"fmt"
	"net/netip"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kur1sulab/diting/engine-go/jsonx"
	"github.com/Kur1sulab/diting/engine-go/netutil"
)

// 常量逐项对照 jsintel.py:31-34。
const (
	MaxFileBytes    = 2_000_000        // 单个 JS 文件下载上限 ~2MB
	DefaultWorkers  = 6                // 低并发（对目标友好，WAF 也友好）
	DefaultTimeout  = 10 * time.Second // 单文件下载超时
	DefaultMaxFiles = 60               // 最多下载的外链 JS 数（防失控）
	maxEndpoints    = 800              // extract_endpoints 输出上限
	sensitiveCap    = 200              // extract_sensitive 默认上限
)

// 静态资源后缀：出现在端点线索里的一律丢弃（jsintel.py:37-41）。
var staticExts = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp3", ".mp4",
	".webm", ".webp", ".wav", ".pdf", ".zip", ".gz", ".wasm", ".cur",
}

// 正则逐条对照 jsintel.py:43-60。Go RE2 不支持 lookaround，但本组正则未使用；
// 字符类里的反引号用 \x60 表达（Go 字符串不能直接包含 raw string 反引号边界）。
var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)
	// <script ...> 内联体（re.S 语义 → (?s)）。
	scriptInlineRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	// fetch(...) / axios.xxx(...) / axios(...) / $.get|post|ajax|getJSON(...)
	callURLRe = regexp.MustCompile(`(?i)(?:fetch\s*\(|axios(?:\s*\.\s*\w+\s*\(|\s*\()|\$\s*\.\s*(?:get|post|ajax|getJSON)\s*\()\s*["'\x60]([^"'\x60\s]{2,200}?)["'\x60]`)
	urlKeyRe  = regexp.MustCompile(`(?i)url\s*[:=]\s*["'\x60](/[^"'\x60\s]{2,160})["'\x60]`)
	// 字符串字面量里的路径（以 / 开头）。
	literalPathRe = regexp.MustCompile(`["'\x60](/[A-Za-z0-9_][A-Za-z0-9_\-./~]{1,150})["'\x60]`)
	// 绝对 URL 的 host（http(s):// 或协议相对 //）。
	absHostRe = regexp.MustCompile(`(?:https?:)?//([A-Za-z0-9][A-Za-z0-9._-]*)(?::\d{2,5})?(?:[/"'\x60\s<>\\\)\]},;]|$)`)
	ipv4Re    = regexp.MustCompile(`(\d{1,3}(?:\.\d{1,3}){3})`)
	// 敏感键（长形式在前，避免 alternation 短路）；值打码后入库。
	// 首尾的 \b 由 findSecretMatches 按 Python Unicode 词边界回查（RE2 的 \b
	// 只认 ASCII，CJK 紧贴 key 时会多命中）。
	secretReNoB  = regexp.MustCompile(`(?i)(access[_-]?key|api[_-]?key|apikey|app[_-]?key|app[_-]?secret|appid|app_id|secret[_-]?key|authorization|passwd|password|secret|token|ak|sk)["'\x60]?\s*[:=]\s*["'\x60]?([^"'\x60\s;,&<>]{4,120})`)
	alnumRe      = regexp.MustCompile(`[A-Za-z0-9]`)
	digitsDotsRe = regexp.MustCompile(`^[\d.]+$`)
)

// 纯占位符/枚举短串，不是密钥（jsintel.py:61-62）。
var secretValueBlocklist = map[string]bool{
	"undefined": true, "null": true, "true": true, "false": true, "none": true,
	"password": true, "token": true, "secret": true, "xxxx": true,
}

// InlineScript 内联脚本（label 形如 inline#2，序号按 HTML 中所有 script 标签计）。
type InlineScript struct {
	Label string
	Text  string
}

// ScriptStats 对齐 Python result["scripts"] 的四个计数键。
type ScriptStats struct {
	External   int `json:"external"`
	Inline     int `json:"inline"`
	Downloaded int `json:"downloaded"`
	Failed     int `json:"failed"`
}

// Sensitive 单条敏感线索（JSON 键序对齐 jsintel.py:114-116）。
type Sensitive struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Key     string `json:"key"`
	Value   string `json:"value"`
	Snippet string `json:"snippet"`
}

// Domains 域名线索（相对目标归类；内网 IP 单列）。
type Domains struct {
	Subdomains  []string `json:"subdomains"`
	Thirdparty  []string `json:"thirdparty"`
	InternalIPs []string `json:"internal_ips"`
}

// Result 对齐 run_jsintel 返回 dict（键序与 Python dict 插入序一致）。
type Result struct {
	Base          string      `json:"base"`
	PageStatus    *int        `json:"page_status"`
	Error         string      `json:"error"`
	Scripts       ScriptStats `json:"scripts"`
	Endpoints     []string    `json:"endpoints"`
	EndpointsFull []string    `json:"endpoints_full"`
	Sensitive     []Sensitive `json:"sensitive"`
	Domains       Domains     `json:"domains"`
}

// DownloadRow 外链 JS 下载结果（仅内部使用，不落盘）。
type DownloadRow struct {
	URL    string
	Status int
	OK     bool
	Error  string
	Text   string
}

// MaskValue 疑似值打码：只留前 4 位，其余换成 ****（≤4 位全打码），
// 对齐 jsintel.py:65-68（按字符计长）。
func MaskValue(v string) string {
	v = strings.TrimSpace(v)
	r := []rune(v)
	if len(r) > 4 {
		return string(r[:4]) + "****"
	}
	return "****"
}

// printableRatio 前 4KB 的可打印比例（识别二进制 / WAF 挑战页），
// 对齐 jsintel.py:71-77：Python str.isprintable 的语义边界 = Go unicode.IsPrint
// （两者都只把 ASCII 空格算作 Printable 的 Zs 字符），另放行 \t\r\n。
func printableRatio(s string) float64 {
	if s == "" {
		return 1.0
	}
	r := []rune(s)
	if len(r) > 4000 {
		r = r[:4000]
	}
	ok := 0
	for _, c := range r {
		if unicode.IsPrint(c) || c == '\t' || c == '\r' || c == '\n' {
			ok++
		}
	}
	return float64(ok) / float64(len(r))
}

// isStaticPath 路径是否以静态资源后缀结尾（大小写不敏感）。
func isStaticPath(p string) bool {
	lp := strings.ToLower(p)
	for _, ext := range staticExts {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return false
}

// resolveURL 等价 Python urljoin(page_url, src) 的常用语义。
func resolveURL(pageURL, ref string) string {
	b, berr := neturl.Parse(pageURL)
	r, rerr := neturl.Parse(ref)
	if berr != nil || rerr != nil {
		return ref
	}
	if b.Scheme != "" {
		b.Scheme = strings.ToLower(b.Scheme)
	}
	out := b.ResolveReference(r)
	if out.Scheme != "" {
		out.Scheme = strings.ToLower(out.Scheme)
	}
	return out.String()
}

// urlPath 等价 Python urlsplit(u).path（保留百分号编码，不做解码）。
func urlPath(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	return u.EscapedPath()
}

// ExtractScripts HTML → (外链 JS 绝对 URL 列表, 内联代码)，对齐 jsintel.py:80-99。
func ExtractScripts(html, pageURL string) ([]string, []InlineScript) {
	ext := []string{}
	seen := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		src := strings.TrimSpace(m[1])
		if src == "" {
			continue
		}
		low := strings.ToLower(src)
		if strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "javascript:") {
			continue
		}
		u := resolveURL(pageURL, src)
		p := strings.ToLower(urlPath(u))
		if isStaticPath(p) && !strings.HasSuffix(p, ".js") {
			continue // 浏览器虽会请求，但对情报无价值，省掉
		}
		if !seen[u] {
			seen[u] = true
			ext = append(ext, u)
		}
	}
	inline := []InlineScript{}
	for i, m := range scriptInlineRe.FindAllStringSubmatchIndex(html, -1) {
		body := ""
		if m[3] > m[2] {
			body = html[m[2]:m[3]]
		}
		body = strings.TrimSpace(body)
		if len([]rune(body)) >= 8 { // 过滤 <script src> 的空体
			inline = append(inline, InlineScript{
				Label: fmt.Sprintf("inline#%d", i+1), Text: body})
		}
	}
	return ext, inline
}

// NormalizeEndpoint 端点线索规范化：去 query/fragment、绝对 URL 只留 path、
// 补前导斜杠、滤静态资源；不合格返回空串，对齐 jsintel.py:102-125。
// 这里是把"假线索"挡在输出之外的第一道闸。
func NormalizeEndpoint(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, "\"'")
	if s == "" || strings.ContainsAny(s, "{}") { // 模板占位符 / 动态拼接，不可复跑
		return ""
	}
	if strings.Contains(s, "://") { // 绝对 URL：host 记入域名线索，这里只留 path
		u, err := neturl.Parse(s)
		if err != nil {
			return ""
		}
		s = u.EscapedPath()
		if s == "" || s == "/" {
			return ""
		}
	}
	if !strings.HasPrefix(s, "/") {
		s = "/" + s
	}
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 2 && strings.HasSuffix(s, "/") {
		s = strings.TrimRight(s, "/")
	}
	if len(s) < 2 || !alnumRe.MatchString(s) {
		return ""
	}
	if isStaticPath(s) { // 静态资源不是攻击面入口
		return ""
	}
	return s
}

// ExtractEndpoints JS 源码 → 排序去重后的端点路径列表，对齐 jsintel.py:128-136。
func ExtractEndpoints(text string) []string {
	set := map[string]bool{}
	// callURLRe：Python 的 \bfetch / \baxios 只对这两个前缀生效（$ 分支无 \b）。
	callLocs := scanSubmatchIndex(callURLRe, text, func(s string, loc []int) bool {
		low := strings.ToLower(s[loc[0]:])
		if strings.HasPrefix(low, "fetch") || strings.HasPrefix(low, "axios") {
			return pyBoundaryAt(s, loc[0])
		}
		return true
	})
	urlLocs := scanSubmatchIndex(urlKeyRe, text, func(s string, loc []int) bool {
		return pyBoundaryAt(s, loc[0])
	})
	for _, loc := range callLocs {
		if e := NormalizeEndpoint(text[loc[2]:loc[3]]); e != "" {
			set[e] = true
		}
	}
	for _, loc := range urlLocs {
		if e := NormalizeEndpoint(text[loc[2]:loc[3]]); e != "" {
			set[e] = true
		}
	}
	for _, m := range literalPathRe.FindAllStringSubmatch(text, -1) {
		if e := NormalizeEndpoint(m[1]); e != "" {
			set[e] = true
		}
	}
	out := make([]string, 0, len(set))
	for e := range set {
		out = append(out, e)
	}
	sort.Strings(out)
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	return out
}

// pyWordRune 等价 Python re 的 \w 单词字符（Unicode 字母/数字/下划线）。
// Go regexp 的 \b 只按 ASCII 判定，CJK 紧贴 key 时会多命中——此处手工回查
// Python 的 Unicode 词边界（与 patchdiff 的 pyBoundaryAt 同口径）。
func pyWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsNumber(r)
}

// pyBoundaryAt 报告 pos 处（rune 边界）是否构成 Python 语义的 \b。
func pyBoundaryAt(s string, pos int) bool {
	if pos < 0 || pos > len(s) {
		return false
	}
	leftWord := false
	if pos > 0 {
		r, _ := utf8.DecodeLastRuneInString(s[:pos])
		leftWord = pyWordRune(r)
	}
	rightWord := false
	if pos < len(s) {
		r, _ := utf8.DecodeRuneInString(s[pos:])
		rightWord = pyWordRune(r)
	}
	return leftWord != rightWord
}

// findSecretMatches 在 text 上枚举敏感键匹配，并按 Python 的 Unicode 词边界
// 过滤 key 首尾。RE2 不支持零宽断言，故先去掉 \b 再做边界回查；候选被边界
// 否决时从 key 起点后一个 rune 继续找（对齐 Python 引擎的回溯扫描），命中
// 后从整个匹配末尾继续（对齐 re.finditer 的非重叠推进）。
func findSecretMatches(text string) [][]int {
	return scanSubmatchIndex(secretReNoB, text, func(s string, loc []int) bool {
		return pyBoundaryAt(s, loc[2]) && pyBoundaryAt(s, loc[3])
	})
}

// scanSubmatchIndex 枚举正则匹配并按 accept 过滤；RE2 不支持零宽断言，边界
// 类条件只能在命中后回查。候选被否决时从匹配起点后一个 rune 继续扫描（对齐
// Python 引擎逐位置回溯），命中后从整个匹配末尾继续（对齐 re.finditer 的
// 非重叠推进）。返回的下标均相对原串。
func scanSubmatchIndex(rx *regexp.Regexp, text string, accept func(string, []int) bool) [][]int {
	out := [][]int{}
	off := 0
	for off <= len(text) {
		loc := rx.FindStringSubmatchIndex(text[off:])
		if loc == nil {
			break
		}
		for i := range loc {
			if loc[i] >= 0 {
				loc[i] += off
			}
		}
		if accept(text, loc) {
			out = append(out, loc)
			off = loc[1]
			continue
		}
		_, size := utf8.DecodeRuneInString(text[loc[0]:])
		if size < 1 {
			size = 1
		}
		off = loc[0] + size
	}
	return out
}

// maskedLine 整行先做全量打码再截 40 字符——同一行里相邻敏感键的值也要打掉
// （审计发现，jsintel.py:141-150）。缓存按行号复用。
func maskedLine(lines []string, li int, cache map[int]string) string {
	if v, ok := cache[li]; ok {
		return v
	}
	ln := ""
	if li >= 0 && li < len(lines) {
		ln = lines[li]
	}
	// 匹配在原行上做；替换在逐步打码的行上做（等价 Python finditer(ln) 后
	// 循环 ln.replace(...) 的语义：迭代器绑定原行，替换结果层层累积）。
	matches := findSecretMatches(ln)
	vals := make([]string, 0, len(matches))
	for _, m := range matches {
		vals = append(vals, ln[m[4]:m[5]]) // 先按原行取全量值，再逐轮替换
	}
	for _, val := range vals {
		ln = strings.ReplaceAll(ln, val, MaskValue(val))
	}
	cache[li] = ln
	return ln
}

// pySplitLines 复刻 Python str.splitlines 的分行集合（\n / \r / \r\n / \v /
// \f / \x1c-\x1e / \x85 / \u2028 / \u2029）。Python 侧行号来自「仅按 \n 的
// 前缀表」而片段取 splitlines 结果——lone \r / 换页符会造成行号与片段错位的
// 固有 quirk，这里逐字复刻以保 parity（jsintel.py:143-144）。
func pySplitLines(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\r':
			out = append(out, s[start:i])
			i++
			if i < len(s) && s[i] == '\n' {
				i++
			}
			start = i
		case '\n', '\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029':
			out = append(out, s[start:i])
			i += size
			start = i
		default:
			i += size
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// ExtractSensitive 敏感线索：只标位置（文件+行号+片段前 40 字符），值打码
// （片段内同步打码），对齐 jsintel.py:139-162。cap<=0 时对齐 Python 的
// 「先 append 再判 len>=cap」：首条即停（默认调用传 sensitiveCap）。
func ExtractSensitive(text, source string, cap int) []Sensitive {
	rows := []Sensitive{}
	seen := map[string]bool{}
	starts := []int{0}
	for i, r := range text {
		if r == '\n' {
			starts = append(starts, i+1)
		}
	}
	lines := pySplitLines(text)
	lineCache := map[int]string{}
	for _, m := range findSecretMatches(text) {
		key := strings.ToLower(text[m[2]:m[3]])
		val := text[m[4]:m[5]]
		lv := strings.ToLower(val)
		if secretValueBlocklist[lv] || strings.HasPrefix(lv, "${") {
			continue
		}
		if allDigits(val) && utf8.RuneCountInString(val) < 8 { // 纯数字短串基本是枚举/计数，不是密钥
			continue
		}
		li := sort.Search(len(starts), func(i int) bool { return starts[i] > m[0] }) - 1
		if li < 0 {
			li = 0
		}
		snippet := strings.TrimSpace(maskedLine(lines, li, lineCache))
		if sr := []rune(snippet); len(sr) > 40 {
			snippet = string(sr[:40])
		}
		dedup := source + "\x00" + strconv.Itoa(li+1) + "\x00" + key
		if seen[dedup] {
			continue
		}
		seen[dedup] = true
		rows = append(rows, Sensitive{
			File: source, Line: li + 1, Key: key,
			Value: MaskValue(val), Snippet: snippet,
		})
		if len(rows) >= cap {
			break
		}
	}
	return rows
}

// allDigits 等价 Python str.isdigit 的数字判定（含非 ASCII 数字，与 Python
// unicode 语义一致）。
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// ExtractDomains JS 源码 → 域名线索（相对目标域名归类；内网 IP 单列；
// 公网 IP 不收，防版本号误报），对齐 jsintel.py:165-183。
func ExtractDomains(text, targetHost string) Domains {
	hosts := map[string]bool{}
	ips := map[string]bool{}
	for _, m := range absHostRe.FindAllStringSubmatch(text, -1) {
		h := strings.ToLower(m[1])
		if strings.Contains(h, ".") && !digitsDotsRe.MatchString(h) {
			hosts[h] = true
		}
	}
	for _, loc := range scanSubmatchIndex(ipv4Re, text, func(s string, loc []int) bool {
		return pyBoundaryAt(s, loc[2]) && pyBoundaryAt(s, loc[3])
	}) {
		raw := text[loc[2]:loc[3]]
		a, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		if netutil.IsBlockedIP(a) {
			ips[raw] = true
		}
	}
	t := strings.Trim(strings.ToLower(targetHost), ".")
	sub := []string{}
	for h := range hosts {
		if t != "" && (h == t || strings.HasSuffix(h, "."+t)) {
			sub = append(sub, h)
		}
	}
	sort.Strings(sub)
	inSub := map[string]bool{}
	for _, h := range sub {
		inSub[h] = true
	}
	third := []string{}
	for h := range hosts {
		if !inSub[h] {
			third = append(third, h)
		}
	}
	sort.Strings(third)
	ipList := make([]string, 0, len(ips))
	for ip := range ips {
		ipList = append(ipList, ip)
	}
	sort.Strings(ipList)
	return Domains{Subdomains: sub, Thirdparty: third, InternalIPs: ipList}
}

// DownloadScripts 低并发下载外链 JS（≤6 并发 / 只 GET / 单文件 ≤2MB），
// 返回与输入同序的结果列表，对齐 jsintel.py:186-208。
func DownloadScripts(ctx context.Context, urls []string, workers int, timeout time.Duration, maxFiles int) []DownloadRow {
	if maxFiles < 0 {
		maxFiles = 0
	}
	if len(urls) > maxFiles {
		urls = urls[:maxFiles]
	}
	if len(urls) == 0 {
		return []DownloadRow{}
	}
	if workers < 1 {
		workers = 1
	}
	if workers > DefaultWorkers {
		workers = DefaultWorkers
	}
	if ctx == nil {
		ctx = context.Background()
	}
	results := make([]DownloadRow, len(urls))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := netutil.Fetch(u, netutil.FetchOpt{
				Timeout: timeout, MaxBytes: MaxFileBytes, Follow: true,
				HopCheck: netutil.HopPolicy(u), Ctx: ctx,
			})
			row := DownloadRow{URL: u, Status: r.Status, OK: r.OK, Error: r.Err}
			if r.OK {
				row.Text = r.Body
			}
			if row.Text != "" && printableRatio(row.Text) < 0.5 {
				row.Text = ""
				row.Error = "非文本内容（疑似二进制/WAF 挑战页），跳过解析"
			}
			results[i] = row // 各 goroutine 只写自己的槽位（并发安全）
		}(i, u)
	}
	wg.Wait()
	return results
}

// pyStatus 对齐 Python print(None) / f-string 对 None 的渲染。
func pyStatus(p *int) string {
	if p == nil {
		return "None"
	}
	return strconv.Itoa(*p)
}

// RenderTxt 对齐 jsintel.py:211-239 的文本清单格式（逐行一致）。
func RenderTxt(r Result) string {
	var b strings.Builder
	a := func(s string) { b.WriteString(s); b.WriteString("\n") }
	a(fmt.Sprintf("# JS 情报清单 — %s", r.Base))
	a(fmt.Sprintf("- 页面状态: %s", pyStatus(r.PageStatus)))
	a(fmt.Sprintf("- 外链 JS: %d（下载成功 %d / 失败 %d），内联 %d 段",
		r.Scripts.External, r.Scripts.Downloaded, r.Scripts.Failed, r.Scripts.Inline))
	a("- 声明: 线索≠漏洞，需人工复核；疑似值已打码（只留前 4 位）\n")

	a(fmt.Sprintf("## API 端点线索（%d 条）", len(r.Endpoints)))
	a("以下绝对 URL 已规范化去重，可直接喂给 api / paths 模块复核：")
	for _, u := range r.EndpointsFull {
		a("  " + u)
	}
	a("")

	a(fmt.Sprintf("## 敏感线索（%d 处，仅位置提示，值为打码）", len(r.Sensitive)))
	for _, s := range r.Sensitive {
		a(fmt.Sprintf("- [%s:%d] %s = %s  |  `%s`", s.File, s.Line, s.Key, s.Value, s.Snippet))
	}
	if len(r.Sensitive) == 0 {
		a("- （未命中）")
	}
	a("")

	a("## 域名线索")
	a("- 子域/同域: " + joinOrDash(r.Domains.Subdomains))
	a("- 第三方域: " + joinOrDash(r.Domains.Thirdparty))
	a("- 内网 IP: " + joinOrDash(r.Domains.InternalIPs))
	return b.String()
}

func joinOrDash(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return strings.Join(v, ", ")
}

// emptyResult 对齐 run_jsintel 初始化 dict：所有列表均为 []（不是 null）。
func emptyResult(base string) Result {
	return Result{
		Base:          base,
		PageStatus:    nil,
		Error:         "",
		Scripts:       ScriptStats{},
		Endpoints:     []string{},
		EndpointsFull: []string{},
		Sensitive:     []Sensitive{},
		Domains: Domains{
			Subdomains: []string{}, Thirdparty: []string{}, InternalIPs: []string{},
		},
	}
}

// RunJSIntel JS 情报提取主流程，对齐 jsintel.py:242-300。
func RunJSIntel(url, out string, workers, maxFiles int, timeout time.Duration) (Result, error) {
	return RunJSIntelContext(context.Background(), url, out, workers, maxFiles, timeout)
}

// RunJSIntelContext 是 RunJSIntel 的取消变体：页面抓取与全部外链下载均过
// FetchOpt.Ctx 咽喉；取消立即收敛返回 ctx.Err() 且不落盘。
func RunJSIntelContext(ctx context.Context, url, out string, workers, maxFiles int, timeout time.Duration) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result := emptyResult(url)
	if err := ctx.Err(); err != nil {
		return result, err
	}
	fmt.Printf("[*] JS 情报提取: %s（外链并发 ≤%d，单文件 ≤%dMB，只 GET）\n",
		url, DefaultWorkers, MaxFileBytes/1_000_000)

	checked := ""
	if u, err := netutil.CheckHTTPURL(url, true); err != nil {
		// 授权测试允许内网目标；非法入口按 Python「fetch 返回 error 字段」的
		// 非异常路径降级为空结果（不落盘异常栈）。
		fmt.Printf("[!] 非法探测目标: %v\n", err)
		result.Error = err.Error()
	} else {
		checked = u
	}
	var page netutil.Result
	if checked != "" {
		pageTimeout := timeout
		if pageTimeout < 12*time.Second {
			pageTimeout = 12 * time.Second // Python: timeout=max(12, timeout)
		}
		page = netutil.Fetch(checked, netutil.FetchOpt{
			Timeout: pageTimeout, Follow: true,
			HopCheck: netutil.HopPolicy(checked), Ctx: ctx,
		})
	}
	if page.OK {
		st := page.Status
		result.PageStatus = &st
	}
	// 只有 200（含跳转后的最终页）才值得挖 JS；403/404/WAF 拦截页 → 优雅降级输出空结果。
	if !page.OK || page.Status != 200 || page.Body == "" {
		if result.Error == "" {
			result.Error = page.Err
		}
		if result.Error == "" {
			if page.Status != 0 {
				result.Error = fmt.Sprintf("HTTP %d", page.Status)
			} else {
				result.Error = "响应无内容"
			}
		}
		fmt.Printf("[!] 页面抓取失败（status=%s %s），输出空结果（WAF/不可达属正常，优雅降级）\n",
			pyStatus(result.PageStatus), page.Err)
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if err := save(out, result); err != nil {
			return result, err
		}
		return result, nil
	}

	final := page.FinalURL
	parts, perr := neturl.Parse(final)
	netloc := ""
	scheme := "http"
	if perr == nil {
		netloc = parts.Host
		if parts.User != nil {
			netloc = parts.User.String() + "@" + netloc
		}
		netloc = strings.ToLower(netloc)
		if parts.Scheme == "https" {
			scheme = "https"
		}
	}
	host := strings.Split(netloc, ":")[0] // 对齐 Python netloc.split(":")[0]
	ext, inline := ExtractScripts(page.Body, final)
	fmt.Printf("[*] 页面 status=%d，外链 JS %d 个，内联 %d 段\n", page.Status, len(ext), len(inline))

	type source struct{ label, text string }
	sources := make([]source, 0, len(inline)+len(ext))
	for _, in := range inline {
		sources = append(sources, source{in.Label, in.Text})
	}
	dl := DownloadScripts(ctx, ext, workers, timeout, maxFiles)
	okRows := make([]DownloadRow, 0, len(dl))
	failed := 0
	for _, d := range dl {
		if d.OK && d.Text != "" {
			okRows = append(okRows, d)
		} else {
			failed++
		}
	}
	if failed > 0 {
		fmt.Printf("[!] %d 个外链 JS 未取得内容（4xx/超时/二进制，已跳过并记录）\n", failed)
	}
	for _, d := range okRows {
		label := urlPath(d.URL)
		if label == "" {
			label = d.URL
		}
		sources = append(sources, source{label, d.Text})
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}

	endpointSet := map[string]bool{}
	sensitive := []Sensitive{}
	seen := map[string]bool{}
	texts := make([]string, 0, len(sources))
	for _, s := range sources {
		for _, e := range ExtractEndpoints(s.text) {
			endpointSet[e] = true
		}
		for _, f := range ExtractSensitive(s.text, s.label, sensitiveCap) {
			dedup := f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.Key
			if !seen[dedup] {
				seen[dedup] = true
				sensitive = append(sensitive, f)
			}
		}
		texts = append(texts, s.text)
	}
	endpoints := make([]string, 0, len(endpointSet))
	for e := range endpointSet {
		endpoints = append(endpoints, e)
	}
	sort.Strings(endpoints)

	result.Scripts = ScriptStats{
		External: len(ext), Inline: len(inline),
		Downloaded: len(okRows), Failed: failed,
	}
	result.Endpoints = endpoints
	result.EndpointsFull = []string{}
	if netloc != "" {
		for _, e := range endpoints {
			result.EndpointsFull = append(result.EndpointsFull, scheme+"://"+netloc+e)
		}
	}
	result.Sensitive = sensitive
	result.Domains = ExtractDomains(strings.Join(texts, "\n"), host)

	if err := save(out, result); err != nil {
		return result, err
	}
	d := result.Domains
	fmt.Printf("[+] 端点线索 %d 条 / 敏感线索 %d 条 / 子域 %d · 第三方域 %d · 内网 IP %d\n",
		len(endpoints), len(sensitive), len(d.Subdomains), len(d.Thirdparty), len(d.InternalIPs))
	for i, e := range endpoints {
		if i >= 10 {
			break
		}
		fmt.Printf("      [端点] %s\n", e)
	}
	for i, s := range sensitive {
		if i >= 8 {
			break
		}
		fmt.Printf("      [敏感] %s:%d  %s=%s（已打码）\n", s.File, s.Line, s.Key, s.Value)
	}
	return result, nil
}

// save 落盘统一走 netutil.SafeWrite（目录白名单清洗 + 纯文件名 + 越界校验），
// 对齐 jsintel.py:303-308。JSON 用 jsonx.Pretty（indent 2 / 不转义 HTML）。
func save(out string, r Result) error {
	p, err := netutil.SafeWrite(out, "jsintel.json", jsonx.Pretty(r))
	if err != nil {
		fmt.Printf("[!] jsintel.json 写盘失败: %v\n", err)
		return err
	}
	if _, err := netutil.SafeWrite(out, "jsintel.txt", RenderTxt(r)); err != nil {
		fmt.Printf("[!] jsintel.txt 写盘失败: %v\n", err)
		return err
	}
	fmt.Printf("[+] JS 情报完成 -> %s\n", p)
	return nil
}
