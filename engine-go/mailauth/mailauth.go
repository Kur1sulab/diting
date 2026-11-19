// Package mailauth：邮件认证体检（DMARC / SPF include 链与 lookup 计数 /
// DKIM 常见选择器 / BIMI），全部结论由公开 DNS TXT 记录推导。
//
// 纪律：
//   - 只读。查询面只有 DNS TXT（收发都不碰 SMTP 25/587，不发 HTTP——
//     BIMI 的 l=/a= 只读取不抓取，避免把「体检」变成对目标的实际请求）；
//   - 零凭据、零第三方依赖（只 stdlib，go.mod 不新增 require）；
//   - 单条结论三段式：现状 / 风险 / 建议，并按严重度分级
//     （none → p=none → p=quarantine → p=reject）。
//
// 注入面：TXTLookup 抽象 DNS 查询（*net.Resolver 天然满足），测试注入假
// resolver，与 typosquat.lookupAPI 同一套模式——不在测试里打真 DNS。
package mailauth

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// ── 严重度（DMARC 策略梯度，也是整份报告的定级主轴）──
const (
	SevNone       = "none"   // 无记录
	SevPolicyNone = "p=none" // 只监控不处置
	SevQuarantine = "p=quarantine"
	SevReject     = "p=reject"
)

// ── 单条体检项等级 ──
const (
	LevelFail = "fail" // 必须改：记录缺失/语法错误/SPF permerror
	LevelWarn = "warn" // 建议改：策略偏软、可被绕
	LevelOK   = "ok"   // 合规
	LevelInfo = "info" // 可选增强，不影响投递
)

// SPF 展开节点状态。
const (
	StOK         = "ok"
	StNoSPF      = "no-spf"      // 该域无 v=spf1 记录
	StNXDomain   = "nxdomain"    // 目标域不存在
	StError      = "error"       // DNS 查询失败（超时/SERVFAIL）
	StInvalid    = "invalid"     // 记录存在但语法不可解析
	StMultiple   = "multiple"    // 同一域返回多条 v=spf1（permerror）
	StLoop       = "loop"        // include 回环
	StDepthLimit = "depth-limit" // 超过展开深度上限
	StBudget     = "budget"      // 超过节点总数上限
)

// DefaultSelectors DKIM 常见选择器探测表（覆盖面优先，顺序即输出顺序）。
//
// 选取依据：default/s1/k1 是国内自建邮局与网易/腾讯企业邮的常见命名，
// google 是 Google Workspace，selector1/selector2 是 Exchange Online /
// Microsoft 365，mail 是 cPanel/Plesk 默认。少一个选择器就少一次「其实配了
// 但没探到」的误判，所以这里宁可多探几个。
var DefaultSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "s1", "mail",
}

// TXTLookup 抽象 DNS TXT 查询面（*net.Resolver 天然满足；测试注入假实现）。
type TXTLookup interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Options 体检参数。
type Options struct {
	Domain     string
	Timeout    time.Duration // 单次 TXT 查询超时，默认 5s
	Resolver   TXTLookup     // nil = net.DefaultResolver
	Selectors  []string      // DKIM 选择器，空 = DefaultSelectors
	MaxDepth   int           // SPF include 链展开深度上限，默认 5
	MaxLookups int           // RFC 7208 §4.6.4 lookup 上限，默认 10
	MaxNodes   int           // SPF 展开节点总数上限（防爆炸式扇出），默认 200
	Budget     time.Duration // 整份体检的总时间预算，默认 60s（0 或负数 = 不限）
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if len(o.Selectors) == 0 {
		o.Selectors = append([]string(nil), DefaultSelectors...)
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = 5
	}
	if o.MaxLookups <= 0 {
		o.MaxLookups = 10
	}
	if o.MaxNodes <= 0 {
		o.MaxNodes = 200
	}
	if o.Budget == 0 {
		o.Budget = 60 * time.Second
	}
	return o
}

// Finding 单条体检项：现状 / 风险 / 建议 三段式。
type Finding struct {
	Section string `json:"section"` // dmarc / spf / dkim / bimi
	Key     string `json:"key"`
	Label   string `json:"label"`
	Level   string `json:"level"`
	Status  string `json:"status"` // 现状
	Risk    string `json:"risk"`   // 风险
	Advice  string `json:"advice"` // 建议
}

// DMARCResult _dmarc.<domain> 解析结果。
type DMARCResult struct {
	Name          string   `json:"name"`
	Found         bool     `json:"found"`
	Records       []string `json:"records,omitempty"`
	Multiple      bool     `json:"multiple"`
	Raw           string   `json:"raw,omitempty"`
	Version       string   `json:"version,omitempty"`
	Policy        string   `json:"policy,omitempty"`           // p=
	SubdomainPol  string   `json:"subdomain_policy,omitempty"` // sp=
	Pct           int      `json:"pct"`                        // pct=，缺省 100
	PctInvalid    bool     `json:"pct_invalid,omitempty"`
	RUA           []string `json:"rua,omitempty"`
	RUF           []string `json:"ruf,omitempty"`
	ADKIM         string   `json:"adkim,omitempty"`
	ASPF          string   `json:"aspf,omitempty"`
	FO            string   `json:"fo,omitempty"`
	Invalid       bool     `json:"invalid,omitempty"`
	InvalidReason string   `json:"invalid_reason,omitempty"`
	Severity      string   `json:"severity"` // none / p=none / p=quarantine / p=reject
	Error         string   `json:"error,omitempty"`
}

// SPFMechanism 单条 SPF 机制。
type SPFMechanism struct {
	Raw       string `json:"raw"`
	Qualifier string `json:"qualifier,omitempty"` // + - ~ ?
	Name      string `json:"name"`                // include/a/mx/ptr/exists/ip4/ip6/all/redirect/exp
	Value     string `json:"value,omitempty"`
	Lookup    bool   `json:"lookup"` // 计入 RFC 7208 的 10 次上限
}

// SPFNode SPF include 链展开树节点。
type SPFNode struct {
	Domain     string         `json:"domain"`
	Depth      int            `json:"depth"`
	Status     string         `json:"status"`
	Record     string         `json:"record,omitempty"`
	Records    []string       `json:"records,omitempty"`
	Multiple   bool           `json:"multiple,omitempty"`
	Mechanisms []SPFMechanism `json:"mechanisms,omitempty"`
	Lookups    int            `json:"lookups"` // 本记录自身的 lookup 数
	Total      int            `json:"total"`   // 含子链累计
	Error      string         `json:"error,omitempty"`
	Children   []SPFNode      `json:"children,omitempty"`
}

// SPFChainRow include 链的扁平展示行（渲染用，深度缩进）。
type SPFChainRow struct {
	Domain  string `json:"domain"`
	Depth   int    `json:"depth"`
	Via     string `json:"via"` // 根 / include: / redirect=
	Lookups int    `json:"lookups"`
	Total   int    `json:"total"`
	Status  string `json:"status"`
	Record  string `json:"record,omitempty"`
	Error   string `json:"error,omitempty"`
}

// SPFResult SPF 体检聚合结果。
type SPFResult struct {
	Found        bool          `json:"found"`
	Records      []string      `json:"records,omitempty"`
	Record       string        `json:"record,omitempty"`
	Multiple     bool          `json:"multiple"`
	All          string        `json:"all,omitempty"` // -all / ~all / ?all / +all
	Lookups      int           `json:"lookups"`
	Limit        int           `json:"limit"`
	ExceedsLimit bool          `json:"exceeds_limit"`
	Depth        int           `json:"depth"`
	Loop         bool          `json:"loop"`
	Status       string        `json:"status"`
	Root         *SPFNode      `json:"root,omitempty"`
	Chain        []SPFChainRow `json:"chain,omitempty"`
	Error        string        `json:"error,omitempty"`
}

// DKIMResult 单个选择器的 DKIM 探测结果。Record 为脱敏摘要——公钥材料
// 一律不回显，只报存在性与模长。
type DKIMResult struct {
	Selector  string `json:"selector"`
	Name      string `json:"name"`
	Found     bool   `json:"found"`
	Record    string `json:"record,omitempty"`
	KeyType   string `json:"key_type,omitempty"`
	KeyBits   int    `json:"key_bits,omitempty"`
	Estimated bool   `json:"estimated,omitempty"`
	Revoked   bool   `json:"revoked,omitempty"`
	Note      string `json:"note,omitempty"`
}

// BIMIResult default._bimi.<domain> 解析结果。l=/a= 只读取不抓取。
type BIMIResult struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Record  string `json:"record,omitempty"`
	Version string `json:"version,omitempty"`
	Logo    string `json:"logo,omitempty"`
	VMC     string `json:"vmc,omitempty"`
	Invalid bool   `json:"invalid,omitempty"`
}

// Report 体检报告。
type Report struct {
	Domain      string       `json:"domain"`
	GeneratedAt string       `json:"generated_at"`
	Grade       string       `json:"grade"`
	Score       int          `json:"score"`
	Severity    string       `json:"severity"`
	Summary     string       `json:"summary"`
	Incomplete  bool         `json:"incomplete,omitempty"` // 有查询失败项，结论不完整
	Failed      []string     `json:"failed,omitempty"`     // 哪几项没查到
	Queries     int          `json:"queries"`
	ElapsedMS   int64        `json:"elapsed_ms"`
	DMARC       DMARCResult  `json:"dmarc"`
	SPF         SPFResult    `json:"spf"`
	DKIM        []DKIMResult `json:"dkim"`
	BIMI        BIMIResult   `json:"bimi"`
	Findings    []Finding    `json:"findings"`
}

// runner 查询计数器 + 单次超时包装 + 总预算。
type runner struct {
	lookup   TXTLookup
	timeout  time.Duration
	deadline time.Time // 零值 = 不设总预算
	queries  int
}

// txt 查一次 TXT。非 NXDOMAIN 类失败最多试 3 次——体检是纯 DNS 工具，本地
// resolver（MagicDNS / 企业 DNS / 代理）偶发超时很常见，一次超时就把一个有
// SPF 的 include 目标记成「查询失败」，或在 DMARC 上把「没查到」写成「没配」，
// 都会直接变成错误的安全结论。NXDOMAIN 不重试（重试不会变成有记录），
// 父 ctx 取消后也不再打。
//
// 总预算（Options.Budget）兜底：resolver 整体不可用时不再逐个熬满超时，
// 剩下的项直接标「预算耗尽」，体检按时收尾。
func (r *runner) txt(ctx context.Context, name string) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < txtAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		if !r.deadline.IsZero() && time.Now().After(r.deadline) {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, errBudget
		}
		r.queries++
		cctx, cancel := context.WithTimeout(ctx, r.timeout)
		recs, err := r.lookup.LookupTXT(cctx, name)
		cancel()
		if err == nil {
			return recs, nil
		}
		lastErr = err
		if isNXDomain(err) {
			break
		}
	}
	return nil, lastErr
}

// txtAttempts 单次逻辑查询的最大尝试次数（含首次）。
const txtAttempts = 3

// errBudget 本次体检的总预算已耗尽，该项未查询。
var errBudget = errors.New("超出体检总预算（--budget），本次未查询")

// Run 执行一次体检。返回 error 仅限输入不可用（域名为空），
// 单条 DNS 失败一律降级为「未发现」并记 Error，不中断整份报告。
func Run(ctx context.Context, o Options) (*Report, error) {
	o = o.withDefaults()
	domain := normalizeDomain(o.Domain)
	if domain == "" {
		return nil, errors.New("mailauth: 域名为空")
	}
	start := time.Now()
	r := &runner{lookup: o.Resolver, timeout: o.Timeout}
	if o.Budget > 0 {
		r.deadline = start.Add(o.Budget)
	}

	rep := &Report{
		Domain:      domain,
		GeneratedAt: start.Format("2006-01-02T15:04:05Z07:00"),
	}
	rep.DMARC = probeDMARC(ctx, r, domain)
	rep.SPF = probeSPF(ctx, r, domain, o)
	rep.DKIM = probeDKIM(ctx, r, domain, o.Selectors)
	rep.BIMI = probeBIMI(ctx, r, domain)
	rep.Queries = r.queries

	// 「没查到」与「没配」必须分开记账：前者是本次网络问题，后者才是安全结论。
	// 有失败项时整份报告标 Incomplete，避免把一次 DNS 抖动读成评级。
	if rep.DMARC.Error != "" {
		rep.Failed = append(rep.Failed, "DMARC")
	}
	if rep.SPF.Status == StError {
		rep.Failed = append(rep.Failed, "SPF")
	}
	for _, d := range rep.DKIM {
		if strings.HasPrefix(d.Note, "DNS 查询失败") {
			rep.Failed = append(rep.Failed, "DKIM/"+d.Selector)
		}
	}
	rep.Incomplete = len(rep.Failed) > 0

	rep.Findings = buildFindings(rep)
	rep.Score, rep.Grade, rep.Severity = grade(rep)
	rep.Summary = summarize(rep)
	rep.ElapsedMS = time.Since(start).Milliseconds()
	return rep, nil
}

// normalizeDomain 小写、去尾点、去协议/路径残留（容忍 `https://a.com/x` 这种
// 粘贴错误，但只取 host 段，不做任何猜测）。
func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	if i := strings.Index(d, "://"); i >= 0 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.TrimSuffix(strings.ToLower(d), ".")
	return d
}

// isNXDomain 区分「域不存在」与「查询失败」——两者对体检结论的意义不同：
// 前者说明 include 目标已废弃，后者只是这次没查到。
func isNXDomain(err error) bool {
	var d *net.DNSError
	if errors.As(err, &d) {
		return d.IsNotFound
	}
	return false
}

// txtOf 取某名字的 TXT 记录。空结果与 NXDOMAIN 都回空切片，但 NXDOMAIN
// 用 errNXDomain 单独标记——SPF 链里「include 目标不存在」和「目标存在但
// 没发 SPF」是两种问题，处置建议不同（前者删 include，后者核对服务商文档）。
func (r *runner) txtOf(ctx context.Context, name string) ([]string, error) {
	recs, err := r.txt(ctx, name)
	if err != nil {
		if isNXDomain(err) {
			return nil, errNXDomain
		}
		return nil, err
	}
	out := make([]string, 0, len(recs))
	for _, rec := range recs {
		if s := strings.TrimSpace(rec); s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

// errNXDomain 「名字不存在」哨兵（区别于查询失败）。
var errNXDomain = errors.New("nxdomain")

// parseTags 解析 RFC 6376/7489 同款 `k=v; k=v` 语法（DMARC 与 DKIM 共用）。
func parseTags(rec string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		out[k] = strings.TrimSpace(v)
	}
	return out
}

func fmtList(v []string) string {
	if len(v) == 0 {
		return "（无）"
	}
	return strings.Join(v, "、")
}
