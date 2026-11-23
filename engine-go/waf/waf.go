// Package waf —— 离线 WAF / bot 挑战指纹（调研总纲 §3 P1）。
//
// 要解决的问题：现有扫描链只判「通/不通/状态码」，把 WAF 的 403/412/挑战页
// 当成「目标不存在」。这是漏扫里最贵的一类系统性错误——目标明明活着，只是
// 被拦在前门，报告上却写「未发现资产」。本包把「前面有没有 WAF、什么牌子、
// 有没有 bot 挑战」变成资产的一个属性，供空境 Kara 选路（绕、降速、换指纹、
// 还是直接标注为需人工）。
//
// 三条设计红线：
//  1. 不发请求。输入是一份**已经抓到的**响应快照（状态码/头/Cookie/正文），
//     输出是判定结果。纯函数 ⇒ 可单测、可离线回放、可在取证包里复现结论。
//  2. 证据先于结论。每条结论都必须带 evidence；凑不出证据就不许报 vendor，
//     最多报 unknown。宁可漏，不许编。
//  3. 置信度要诚实。单个弱特征 = low；多特征互证 = high；拿不准就降级。
//     low/medium 的语义是「设备/品牌大概率对，但 WAF 模块是否真的开启未确认」，
//     消费方不要把 medium 当成「确定有 WAF 拦截」。
package waf

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ── 对外 JSON 契约（Kara 直接按字面匹配这些值）─────────────────────

// 置信度枚举。
const (
	ConfHigh   = "high"   // 多特征互证，可直接据此选路
	ConfMedium = "medium" // 单一强特征或双弱特征互证：品牌可信，拦截能力待确认
	ConfLow    = "low"    // 单一弱特征：仅供参考，不要据此做强决策
)

// 挑战类型枚举。
const (
	ChalNone    = "none"         // 无挑战（可能是纯规则拦截/直通）
	ChalJS      = "js_challenge" // JS 挑战：需执行 JS 拿 cookie 再复用
	ChalCaptcha = "captcha"      // 验证码类挑战：脚本化难度最高
)

// VendorUnknown 表示「有拦截迹象但认不出牌子」——诚实兜底，不许拿它当默认值。
const VendorUnknown = "unknown"

// maxEvidence 单条属性最多保留的证据条数（够复盘即可，避免 JSON 膨胀）。
const maxEvidence = 8

// Attribute 是挂到资产上的 WAF/bot 属性，也是给 Kara 的稳定契约：
//
//	{"vendor":"cloudflare","confidence":"high","challenge":"js_challenge",
//	 "evidence":["header:server=cloudflare","cookie:__cf_bm"]}
//
// 四个字段恒在，不做 omitempty——下游按固定 schema 解析，缺字段比空值更难查。
type Attribute struct {
	Vendor     string   `json:"vendor"`
	Confidence string   `json:"confidence"`
	Challenge  string   `json:"challenge"`
	Evidence   []string `json:"evidence"`
}

// Present 报告这份属性是否真的判出了东西（Vendor 为空 = 没有任何拦截证据）。
func (a Attribute) Present() bool { return a.Vendor != "" }

// MarshalJSON 保证 evidence 恒为数组：nil 会被编码成 null，下游 range 会炸。
// 这是给 Kara 的契约的一部分——四键类型稳定，不许出现 null。
func (a Attribute) MarshalJSON() ([]byte, error) {
	type plain struct {
		Vendor     string   `json:"vendor"`
		Confidence string   `json:"confidence"`
		Challenge  string   `json:"challenge"`
		Evidence   []string `json:"evidence"`
	}
	ev := a.Evidence
	if ev == nil {
		ev = []string{}
	}
	return json.Marshal(plain{a.Vendor, a.Confidence, a.Challenge, ev})
}

// String 供 CLI 单行展示：cloudflare/high/js_challenge。
func (a Attribute) String() string {
	if !a.Present() {
		return "-"
	}
	return a.Vendor + "/" + a.Confidence + "/" + a.Challenge
}

// Response 是一次已抓取响应的快照——本包唯一的输入，绝不自己发请求。
//
// 字段刻意保持「原始形态」：Headers 键大小写不敏感（本包内部统一小写），
// Cookies 是逐条 Set-Cookie 原始行（"name=value; Path=/; HttpOnly"）或裸名，
// Body 是正文片段（netutil 默认截 200KB，足够覆盖挑战页与品牌文案）。
type Response struct {
	Status  int
	Headers map[string]string
	Cookies []string
	Body    string
	URL     string // 可选：最终 URL，用于 /TSPD/ 这类路径级特征
}

// DetectFromResult 是给调用方省事的适配器：netutil.Fetch 的结果直接喂进来。
func DetectFromResult(status int, headers map[string]string, cookies []string, body, finalURL string) *Attribute {
	return Detect(Response{Status: status, Headers: headers, Cookies: cookies, Body: body, URL: finalURL})
}

// ── 内部快照：把原始响应规整成可反复匹配的形态 ────────────────────

type snapshot struct {
	status    int
	headers   map[string]string // 全小写键
	cookies   []string          // cookie 名（保留原始大小写，匹配时再小写）
	bodyLow   string            // 全小写正文（子串/正则统一在低态上匹配）
	targetLow string            // 全小写 URL
	// pageLike 表示「这看起来是一个正常应用页面」：200/201 且正文够长。
	// 正常页面提到某 WAF 的名字（技术博客、产品对比页）是内容而非证据，
	// 因此除少数「本就在正常页面里注入」的厂商外，正文特征一律不参与判定。
	// 挑战页/拦截页的特征是：要么非 2xx，要么很短（纯 JS）。
	pageLike bool
}

// pageLikeBodyBytes 正文超过这个长度且状态 2xx，就按「正常页面」看待。
// 挑战页（cf "Just a moment"、jsl_clearance、雷池验证页）通常在 1-5KB。
const pageLikeBodyBytes = 8192

func newSnapshot(r Response) *snapshot {
	s := &snapshot{
		status:    r.Status,
		headers:   make(map[string]string, len(r.Headers)),
		bodyLow:   strings.ToLower(r.Body),
		targetLow: strings.ToLower(r.URL),
	}
	s.pageLike = (r.Status == 200 || r.Status == 201) && len(r.Body) > pageLikeBodyBytes
	for k, v := range r.Headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" {
			continue
		}
		// 同键多值（如多条 set-cookie）在 map[string]string 里只能留一条：
		// 这里用 ", " 拼接保住信息，WAF 指纹要的是「有没有」，不是精确取值。
		if old, ok := s.headers[lk]; ok && old != "" {
			s.headers[lk] = old + ", " + v
		} else {
			s.headers[lk] = v
		}
	}
	for _, c := range r.Cookies {
		if n := cookieName(c); n != "" {
			s.cookies = append(s.cookies, n)
		}
	}
	// 调用方没给 Cookie 明细时退回 headers 里的 set-cookie 单条（有损，但比没有强）。
	if len(s.cookies) == 0 {
		if sc, ok := s.headers["set-cookie"]; ok && sc != "" {
			// 只按首个 "name=value;" 段取一个名字：逗号分隔的 set-cookie 与
			// Expires 里的逗号无法可靠切分，宁可少认一个也不制造假证据。
			first := sc
			if i := strings.IndexByte(first, ';'); i > 0 {
				first = first[:i]
			}
			if n := cookieName(first); n != "" {
				s.cookies = append(s.cookies, n)
			}
		}
	}
	return s
}

// cookieAttrNames 是 Set-Cookie 的属性名，不是 Cookie 名。
// 不排除它们的话，"Path=/; HttpOnly" 这类片段会被当成一个叫 Path 的 Cookie，
// 进而在证据里留下假条目。
var cookieAttrNames = map[string]bool{
	"path": true, "domain": true, "expires": true, "max-age": true,
	"secure": true, "httponly": true, "samesite": true, "priority": true,
	"version": true, "comment": true, "partitioned": true,
}

// cookieName 抽出 cookie 名（保留原始大小写，便于证据里显示真名）：取第一个 '=' 之前的部分；
// 无 '=' 视为裸名。匹配阶段再做小写比较。
func cookieName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if i := strings.IndexByte(raw, '='); i > 0 {
		name := strings.TrimSpace(raw[:i])
		if cookieAttrNames[strings.ToLower(name)] {
			return ""
		}
		return name
	}
	// 没有 '=' 时，只接受「像名字」的串，避免把 "Path=/; HttpOnly" 片段当名字。
	if strings.ContainsAny(raw, " ;/") {
		return ""
	}
	if cookieAttrNames[strings.ToLower(raw)] {
		return ""
	}
	return raw
}

// clip 按字符截断证据里嵌入的观测值，避免把整段 body/超长头塞进 JSON。
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// ── 匹配引擎 ──────────────────────────────────────────────────

type matchKind int

const (
	matchHeaderValue   matchKind = iota // 头存在且值含 Sub（大小写不敏感）
	matchHeaderPresent                  // 头存在且非空
	matchCookiePrefix                   // 存在以 Name 为前缀的 cookie
	matchBody                           // 正文含子串（大小写不敏感）
	matchBodyRe                         // 正文匹配正则（规则在低态正文上跑）
	matchStatus                         // 状态码相等
	matchURL                            // 最终 URL 含子串（路径级特征，如 /TSPD/）
)

// Signal 是一条可独立举证的指纹特征。
//
// Strong 的语义是「这个特征只可能来自该厂商」——headers 牌子名、独家 cookie、
// 品牌文案。弱特征是「共享的、可能是别的东西」——通用 403、LB 持久化 cookie、
// 通用 JS 挑战。置信度完全由强弱计数决定，不靠人肉拍脑袋。
type Signal struct {
	Kind      matchKind
	Name      string // 头名（小写）/ cookie 名前缀 / 正文子串 / URL 子串
	Sub       string // matchHeaderValue 时：头值需包含的子串
	Status    int    // matchStatus 时：期望状态码
	Re        string // matchBodyRe 时：正则（对全小写正文匹配）
	Strong    bool
	Evidence  string // 证据模板，可含一个 %s（由实际观测值填充）
	Challenge string // 该特征顺带指示的挑战类型，空 = 不指示
}

// match 在快照上求值一条特征，返回是否命中 + 用于写证据的观测值。
func (s *snapshot) match(sig Signal) (bool, string) {
	switch sig.Kind {
	case matchHeaderValue:
		v, ok := s.headers[sig.Name]
		if !ok || strings.TrimSpace(v) == "" {
			return false, ""
		}
		if strings.Contains(strings.ToLower(v), strings.ToLower(sig.Sub)) {
			return true, clip(v, 48)
		}
		return false, ""
	case matchHeaderPresent:
		v, ok := s.headers[sig.Name]
		if ok && strings.TrimSpace(v) != "" {
			return true, clip(v, 48)
		}
		return false, ""
	case matchCookiePrefix:
		// 长前缀优先：__cf_bm 不能被 __cf 之类短前缀抢走（规则表按长度自证，
		// 这里只做精确前缀匹配，命中即返回实际 cookie 名作为证据）。
		for _, c := range s.cookies {
			if strings.HasPrefix(strings.ToLower(c), sig.Name) {
				return true, c
			}
		}
		return false, ""
	case matchBody:
		if sig.Name != "" && strings.Contains(s.bodyLow, strings.ToLower(sig.Name)) {
			return true, sig.Name
		}
		return false, ""
	case matchBodyRe:
		if sig.Re == "" {
			return false, ""
		}
		if m := regexpCache(sig.Re).FindString(s.bodyLow); m != "" {
			return true, clip(m, 40)
		}
		return false, ""
	case matchStatus:
		if sig.Status != 0 && s.status == sig.Status {
			return true, fmt.Sprintf("%d", s.status)
		}
		return false, ""
	case matchURL:
		if sig.Name != "" && strings.Contains(s.targetLow, strings.ToLower(sig.Name)) {
			return true, sig.Name
		}
		return false, ""
	}
	return false, ""
}

// isBodySignal 标记「靠正文内容取证」的特征类型——它们受 pageLike 门槛约束。
func isBodySignal(k matchKind) bool { return k == matchBody || k == matchBodyRe }

// renderEvidence 把模板和观测值拼成一条人可读、机可核的证据。
func renderEvidence(tpl, observed string) string {
	if tpl == "" {
		return ""
	}
	if strings.Contains(tpl, "%s") {
		return fmt.Sprintf(tpl, observed)
	}
	return tpl
}

// ── 置信度与仲裁 ────────────────────────────────────────────────

// confidenceOf 是整套判定唯一的置信度来源——它是纯函数，规则表不许自带 confidence。
//
//	strong≥2            → high    （两个互不相关的强特征，几乎不可能是巧合）
//	strong==1 && weak≥2 → high    （一强两弱互证：强特征定品牌，弱特征补场景）
//	strong==1           → medium  （单一强特征：品牌可信，场景未确认）
//	weak≥2              → medium  （多弱特征互证：没有独家特征，但不像是巧合）
//	weak==1             → low     （单一弱特征：只能作为线索）
//	0                   → ""      （无特征，不产生结论）
func confidenceOf(strong, weak int) string {
	switch {
	case strong >= 2:
		return ConfHigh
	case strong == 1 && weak >= 2:
		return ConfHigh
	case strong == 1:
		return ConfMedium
	case weak >= 2:
		return ConfMedium
	case weak == 1:
		return ConfLow
	}
	return ""
}

func confRank(c string) int {
	switch c {
	case ConfHigh:
		return 3
	case ConfMedium:
		return 2
	case ConfLow:
		return 1
	}
	return 0
}

// challengeRank 用于合并多个挑战指示：captcha 比 js_challenge 更具体，优先报。
func challengeRank(c string) int {
	switch c {
	case ChalCaptcha:
		return 3
	case ChalJS:
		return 2
	case ChalNone:
		return 1
	}
	return 0
}

func strongerChallenge(a, b string) string {
	if challengeRank(b) > challengeRank(a) {
		return b
	}
	if a == "" {
		return ChalNone
	}
	return a
}

// candidate 是一个厂商的初步判定结果（未定稿）。
type candidate struct {
	vendor    string
	strong    int
	weak      int
	conf      string
	evidence  []string
	challenge string
	order     int // 规则表顺序 = 同等强度时的优先级
}

// better 判断 a 是否应压过 b：先比置信度，再比证据强度，最后比规则表顺序。
func (a candidate) better(b candidate) bool {
	if ra, rb := confRank(a.conf), confRank(b.conf); ra != rb {
		return ra > rb
	}
	if sa, sb := a.strong*3+a.weak, b.strong*3+b.weak; sa != sb {
		return sa > sb
	}
	return a.order < b.order
}

// Detect 是唯一入口：输入响应快照，输出 WAF 属性；无任何拦截证据时返回 nil。
//
// 返回 nil 而不是 {vendor:"unknown"} 是刻意的：unknown 只用于「确实有拦截
// 迹象但认不出牌子」，把「什么都没有」也塞成 unknown 会让下游无法区分
// 「干净的源站」和「认不出的 WAF」，等于把噪声当信号。
func Detect(r Response) *Attribute {
	s := newSnapshot(r)

	// ① 厂商规则：逐个厂商收集命中特征，算置信度，凑不出证据的淘汰。
	var cands []candidate
	for i, rule := range vendorRules {
		c := candidate{vendor: rule.Vendor, order: i, challenge: ChalNone}
		for _, sig := range rule.Signals {
			// 正常应用页面的正文不算证据（见 snapshot.pageLike 注释）。
			// BodyAnyStatus 的厂商如瑞数/极验/顶象例外——它们的特征本来就注入在正常页面里。
			if s.pageLike && !rule.BodyAnyStatus && isBodySignal(sig.Kind) {
				continue
			}
			ok, obs := s.match(sig)
			if !ok {
				continue
			}
			if sig.Strong {
				c.strong++
			} else {
				c.weak++
			}
			// 同一厂商内部也可能重复举证（如 cf-chl 与 challenge-platform），
			// 统一走 appendUnique，条数在出口 capEvidence 处收敛。
			c.evidence = appendUnique(c.evidence, renderEvidence(sig.Evidence, obs))
			c.challenge = strongerChallenge(c.challenge, sig.Challenge)
		}
		c.conf = confidenceOf(c.strong, c.weak)
		// 红线：说不出证据就不许报厂商。conf 为空或证据为空一律淘汰。
		// MinStrong 挡住「单一通用弱特征就定品牌」（如任何 202 都想认成瑞数）。
		if c.conf == "" || len(c.evidence) == 0 || c.strong < rule.MinStrong {
			continue
		}
		cands = append(cands, c)
	}

	// ② 通用挑战特征独立检测：即使厂商认不出，也要回答「有没有 bot 挑战」。
	genChal, genEv := detectGenericChallenge(s)

	// ③ 仲裁：置信度高者胜；同分按证据强度、规则表顺序。
	var best *candidate
	for i := range cands {
		if best == nil || cands[i].better(*best) {
			best = &cands[i]
		}
	}
	if best != nil {
		ev := append([]string{}, best.evidence...)
		ev = appendUnique(ev, genEv...)
		chal := strongerChallenge(best.challenge, genChal)
		if chal == "" {
			chal = ChalNone
		}
		return &Attribute{
			Vendor:     best.vendor,
			Confidence: best.conf,
			Challenge:  chal,
			Evidence:   capEvidence(ev),
		}
	}

	// ④ 兜底：认不出厂商，但有拦截/挑战迹象 → vendor=unknown，置信度封顶 low。
	//    这里绝不猜品牌：猜错品牌比报 unknown 更贵（Kara 会按错误品牌选错绕法）。
	blockEv := s.blockPageEvidence()
	ev := append([]string{}, genEv...)
	ev = appendUnique(ev, blockEv...)
	if len(ev) == 0 {
		return nil
	}
	chal := genChal
	if chal == "" {
		chal = ChalNone
	}
	return &Attribute{
		Vendor:     VendorUnknown,
		Confidence: ConfLow,
		Challenge:  chal,
		Evidence:   capEvidence(ev),
	}
}

// ── 证据收集小工具 ─────────────────────────────────────────────

// evidenceSubsumed 判断 candidate 是否已被 dst 里的某条证据覆盖。
// 证据串形如 "body:<观测值>"，比对必须先剥掉取证位点前缀：
// "body:/cdn-cgi/challenge-platform/" 并不「包含」"body:cdn-cgi/challenge-platform"
// （前缀后面立刻是斜杠），直接 strings.Contains 会漏判，证据就重复了。
func evidenceSubsumed(dst []string, candidate string) bool {
	cp, cbody := splitEvidence(candidate)
	for _, d := range dst {
		if d == candidate {
			return true
		}
		dp, dbody := splitEvidence(d)
		if cp != "" && cp == dp && cbody != "" && strings.Contains(dbody, cbody) {
			return true
		}
		if strings.Contains(d, candidate) {
			return true
		}
	}
	return false
}

// splitEvidence 拆出 "位点:负载"（位点如 header/cookie/body/status/url）。
// 没有冒号时位点为空、负载为整串。
func splitEvidence(s string) (kind, payload string) {
	if i := strings.IndexByte(s, ':'); i > 0 {
		return s[:i], s[i+1:]
	}
	return "", s
}

func appendUnique(dst []string, extra ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, d := range dst {
		seen[d] = true
	}
	for _, e := range extra {
		if e == "" || seen[e] {
			continue
		}
		// 被已有证据包含的条目直接丢弃：同一条特征常被厂商规则与通用挑战
		// 各记一次（如 /cdn-cgi/challenge-platform/ 与 cdn-cgi/challenge-platform），
		// 重复会稀释证据密度，也让报告显得啰嗦。
		if evidenceSubsumed(dst, e) {
			continue
		}
		seen[e] = true
		dst = append(dst, e)
	}
	return dst
}

func capEvidence(ev []string) []string {
	if len(ev) > maxEvidence {
		ev = ev[:maxEvidence]
	}
	if ev == nil {
		ev = []string{}
	}
	return ev
}
