package waf

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// 本文件是**指纹库**：只放特征，不放判断逻辑。改这里等于改题库，
// 每条特征都必须能回答「为什么它只可能来自这家」。写不出这句就别加。
//
// 强弱划分口径：
//   - Strong：厂商独家的头名/头值、独家 Cookie、品牌文案、独家拦截页。
//   - !Strong：共享特征——通用 403、LB 持久化 Cookie、通用 JS 挑战、
//     云厂商通用请求 ID。它们只能补场景，不能单独定品牌（否则全是误报）。

// vendorRule 一个厂商的全部特征。Vendor 值必须落在对外契约的枚举里。
// BodyAnyStatus=true 表示该厂商的正文特征可以出现在「正常的大页面」里
// （瑞数把 $_ts 注入每个页面；极验/顶象是页面内验证码组件），
// 这类厂商不受 pageLike 门槛约束，其余一律受约束。
type vendorRule struct {
	Vendor        string
	BodyAnyStatus bool
	// MinStrong 该厂商至少要命中几条强特征才算数（0 = 弱特征也能定品牌）。
	// 用于挡住「只有一个通用弱特征」就报品牌的场景：202 是瑞数的典型状态码，
	// 但任何 REST API 的 202 Accepted 都会命中，必须要求强特征兜底。
	MinStrong int
	Signals   []Signal
}

// regexpCache 编译缓存：正文正则只编一次，避免每资产重复 Compile。
var (
	reMu    sync.Mutex
	reCache = map[string]*regexp.Regexp{}
)

func regexpCache(expr string) *regexp.Regexp {
	reMu.Lock()
	defer reMu.Unlock()
	if re, ok := reCache[expr]; ok {
		return re
	}
	re := regexp.MustCompile(expr)
	reCache[expr] = re
	return re
}

// vendorRules 是判定顺序，也是「同等强度时的优先级」。
// 边缘/CDN 型 WAF 排在前面：它们通常真的在最外层，能解释更多现象。
var vendorRules = []vendorRule{
	// ── Cloudflare ──────────────────────────────────────────────
	// 特征来源：CF 对外的 cf-ray / cf-cache-status / cf-mitigated 头，
	// Bot Management 的 __cf_bm、挑战通过后的 cf_clearance，
	// 挑战页的 "Just a moment..." 与 /cdn-cgi/challenge-platform/ 脚本。
	{Vendor: "cloudflare", Signals: []Signal{
		{Kind: matchHeaderValue, Name: "server", Sub: "cloudflare", Strong: true, Evidence: "header:server=%s"},
		{Kind: matchHeaderPresent, Name: "cf-ray", Strong: true, Evidence: "header:cf-ray=%s"},
		{Kind: matchHeaderValue, Name: "cf-mitigated", Sub: "challenge", Strong: true,
			Evidence: "header:cf-mitigated=%s", Challenge: ChalJS},
		{Kind: matchHeaderPresent, Name: "cf-cache-status", Strong: false, Evidence: "header:cf-cache-status=%s"},
		{Kind: matchCookiePrefix, Name: "__cf_bm", Strong: true, Evidence: "cookie:%s"},
		{Kind: matchCookiePrefix, Name: "cf_clearance", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchCookiePrefix, Name: "__cfduid", Strong: false, Evidence: "cookie:%s"},
		{Kind: matchBody, Name: "Attention Required! | Cloudflare", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "Just a moment...", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "Checking your browser before accessing", Strong: true,
			Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "_cf_chl_opt", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "/cdn-cgi/challenge-platform/", Strong: true,
			Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "cf-chl", Strong: false, Evidence: "body:%s", Challenge: ChalJS},
	}},

	// ── Akamai ──────────────────────────────────────────────────
	// AkamaiGHost 是边缘节点 Server 头；x-akamai-* 是边缘注入；
	// errors.edgesuite.net 是 Akamai 拦截页的报错域。
	// Bot Manager：_abck / bm_sz / ak_bmsc 三件套，其中 bm_sz 是 JS 传感器。
	{Vendor: "akamai", Signals: []Signal{
		{Kind: matchHeaderValue, Name: "server", Sub: "akamaighost", Strong: true, Evidence: "header:server=%s"},
		{Kind: matchHeaderPresent, Name: "x-akamai-transformed", Strong: true, Evidence: "header:x-akamai-transformed=%s"},
		{Kind: matchHeaderPresent, Name: "akamai-grn", Strong: true, Evidence: "header:akamai-grn=%s"},
		{Kind: matchHeaderPresent, Name: "x-akamai-request-id", Strong: true, Evidence: "header:x-akamai-request-id=%s"},
		{Kind: matchCookiePrefix, Name: "_abck", Strong: true, Evidence: "cookie:%s"},
		{Kind: matchCookiePrefix, Name: "bm_sz", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchCookiePrefix, Name: "ak_bmsc", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "errors.edgesuite.net", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "Reference #", Strong: false, Evidence: "body:%s（Akamai 报错单号）"},
	}},

	// ── Imperva / Incapsula ─────────────────────────────────────
	// x-iinfo 是 Incapsula 独有的信息头；visid_incap_/incap_ses_ 是其会话
	// Cookie（后缀是站点数字 ID，故按前缀匹配）。
	{Vendor: "imperva", Signals: []Signal{
		{Kind: matchHeaderPresent, Name: "x-iinfo", Strong: true, Evidence: "header:x-iinfo=%s"},
		{Kind: matchHeaderValue, Name: "x-cdn", Sub: "incapsula", Strong: true, Evidence: "header:x-cdn=%s"},
		{Kind: matchCookiePrefix, Name: "visid_incap_", Strong: true, Evidence: "cookie:%s"},
		{Kind: matchCookiePrefix, Name: "incap_ses_", Strong: true, Evidence: "cookie:%s"},
		{Kind: matchCookiePrefix, Name: "nlbi_", Strong: false, Evidence: "cookie:%s"},
		{Kind: matchBody, Name: "Incapsula incident ID", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "_Incapsula_Resource", Strong: true, Evidence: "body:%s"},
	}},

	// ── F5 BIG-IP (ASM / AdvWAF / TSPD) ────────────────────────
	// x-wa-info 是 ASM 的 support ID JSON；"Your support ID is:" 是 ASM 拦截页
	// 原文；/TSPD/ 与 TSPD_101 是 BIG-IP 反自动化（bot defense）的脚本与 Cookie。
	// BIGipServer* 只是负载均衡持久化 Cookie —— 弱特征，单独出现不许定品牌。
	{Vendor: "f5", Signals: []Signal{
		{Kind: matchHeaderPresent, Name: "x-wa-info", Strong: true, Evidence: "header:x-wa-info=%s"},
		{Kind: matchHeaderValue, Name: "server", Sub: "big-ip", Strong: false, Evidence: "header:server=%s"},
		{Kind: matchCookiePrefix, Name: "bigipserver", Strong: false, Evidence: "cookie:%s"},
		{Kind: matchCookiePrefix, Name: "tspd_101", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "The requested URL was rejected", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "Your support ID is:", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "/TSPD/", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchURL, Name: "/TSPD/", Strong: true, Evidence: "url:%s", Challenge: ChalJS},
	}},

	// ── 阿里云盾 / 阿里云 WAF ───────────────────────────────────
	// acw_sc__v2 是阿里反爬 JS 挑战写入的 Cookie（acw_tc 只是 CDN 流量标记，
	// 普通阿里云 CDN 站点也有 ⇒ 弱特征）；"请开启JavaScript并刷新该页" 是
	// 阿里盾挑战页原文；yunjiasu-nginx 是阿里云加速的 Server 头。
	{Vendor: "aliyun", Signals: []Signal{
		{Kind: matchCookiePrefix, Name: "acw_sc__v2", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchCookiePrefix, Name: "acw_sc_v2", Strong: true, Evidence: "cookie:%s", Challenge: ChalJS},
		{Kind: matchCookiePrefix, Name: "acw_tc", Strong: false, Evidence: "cookie:%s"},
		{Kind: matchBody, Name: "acw_sc__v2", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "请开启JavaScript并刷新该页", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "errors.aliyun.com", Strong: true, Evidence: "body:%s"},
		{Kind: matchHeaderValue, Name: "server", Sub: "yunjiasu-nginx", Strong: true, Evidence: "header:server=%s"},
	}},

	// ── 腾讯云 WAF ──────────────────────────────────────────────
	// 腾讯云 WAF 的拦截图带品牌文案（中文/英文两版），这是最可靠的判据；
	// x-nws-log-uuid 是腾讯云 NWS/安全加速注入的请求号，属弱特征。
	{Vendor: "tencent", Signals: []Signal{
		{Kind: matchBody, Name: "腾讯云Web应用防火墙", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "腾讯云 Web 应用防火墙", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "waf.tencentcloud.com", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "Tencent Cloud Web Application Firewall", Strong: true, Evidence: "body:%s"},
		{Kind: matchHeaderPresent, Name: "x-nws-log-uuid", Strong: false, Evidence: "header:x-nws-log-uuid=%s"},
	}},

	// ── 长亭雷池 SafeLine ───────────────────────────────────────
	// 雷池是 nginx/Lua 反代，Server 头通常仍伪装成 nginx，判据主要是品牌文案
	// 与挑战页路径。中文"雷池"与外文 SafeLine 任一出现即认。
	{Vendor: "chaitin-safeline", Signals: []Signal{
		{Kind: matchHeaderValue, Name: "server", Sub: "safeline", Strong: true, Evidence: "header:server=%s"},
		{Kind: matchBody, Name: "SafeLine", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "雷池", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "长亭", Strong: false, Evidence: "body:%s"},
		{Kind: matchBody, Name: "/challenge/verify", Strong: false, Evidence: "body:%s", Challenge: ChalJS},
	}},

	// ── 安全狗 SafeDog ──────────────────────────────────────────
	{Vendor: "safedog", Signals: []Signal{
		{Kind: matchHeaderValue, Name: "server", Sub: "safedog", Strong: true, Evidence: "header:server=%s"},
		{Kind: matchBody, Name: "safedog.cn", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "安全狗", Strong: true, Evidence: "body:%s"},
		{Kind: matchCookiePrefix, Name: "safedog", Strong: false, Evidence: "cookie:%s"},
	}},

	// ── 360 网站卫士（原加速乐 Jiasule）────────────────────────
	// __jsl_clearance / __jsluid 是加速乐系 JS 挑战的招牌 Cookie，360 收购后
	// 归入网站卫士 —— 证据串里保留"（jiasule/360 系）"避免过度断言。
	{Vendor: "360", Signals: []Signal{
		{Kind: matchCookiePrefix, Name: "__jsl_clearance", Strong: true,
			Evidence: "cookie:%s（jiasule/360 系 JS 挑战）", Challenge: ChalJS},
		{Kind: matchCookiePrefix, Name: "__jsluid", Strong: true, Evidence: "cookie:%s"},
		{Kind: matchBody, Name: "__jsl_clearance", Strong: true, Evidence: "body:%s", Challenge: ChalJS},
		{Kind: matchBody, Name: "360wzb", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "wangzhan.360.cn", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "360网站卫士", Strong: true, Evidence: "body:%s"},
	}},

	// ── AWS WAF（CloudFront / ALB 前置）─────────────────────────
	// AWS WAF 自身不注入专属响应头，默认就是干巴巴的 403，因此只能靠
	// CloudFront/ALB 的边缘特征间接定位，置信度天然偏低，这是诚实的结果。
	{Vendor: "aws", Signals: []Signal{
		{Kind: matchHeaderValue, Name: "server", Sub: "cloudfront", Strong: false, Evidence: "header:server=%s"},
		{Kind: matchHeaderPresent, Name: "x-amz-cf-id", Strong: false, Evidence: "header:x-amz-cf-id=%s"},
		{Kind: matchHeaderPresent, Name: "x-amzn-requestid", Strong: false, Evidence: "header:x-amzn-requestid=%s"},
		{Kind: matchHeaderValue, Name: "server", Sub: "awselb", Strong: false, Evidence: "header:server=%s"},
		// 注意：下面这条刻意是弱特征。CloudFront 的这句报错也可能来自
		// 地理限制、源站 5xx、不存在的 S3 key，不等于 WAF 开了。AWS 因此
		// 天然只能到 medium——这是诚实，不是缺陷。
		{Kind: matchBody, Name: "The request could not be satisfied", Strong: false,
			Evidence: "body:%s（CloudFront 边缘错误页）"},
		{Kind: matchBody, Name: "Request blocked", Strong: false, Evidence: "body:%s"},
	}},

	// ── ModSecurity (CRS) ───────────────────────────────────────
	{Vendor: "modsecurity", Signals: []Signal{
		{Kind: matchHeaderPresent, Name: "x-mod-security", Strong: true, Evidence: "header:x-mod-security=%s"},
		{Kind: matchBody, Name: "ModSecurity", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "ModSecurity Action", Strong: true, Evidence: "body:%s"},
		{Kind: matchBody, Name: "This error was generated by Mod_Security", Strong: true, Evidence: "body:%s"},
	}},

	// ── 瑞数信息 RiverSecurity（重点：bot 挑战，不是传统规则 WAF）──
	// 判据一：Cookie 前缀 FSSBBIl1UgzbN7N —— 瑞数为每个站点生成的一组
	// 随机化 Cookie，全部带这个固定前缀，业界公认的强特征。
	// 判据二：注入脚本里的 $_ts 配置对象（动态混淆引擎的运行时）。
	// 判据三：202 + JS 重载是瑞数的典型手法，但它与通用挑战难区分 ⇒ 弱。
	{Vendor: "river-security", BodyAnyStatus: true, MinStrong: 1, Signals: []Signal{
		// 前缀用全小写书写：匹配前 cookie 名统一转小写，这里保持低态即可，
		// 也避免高熵字符串被外挂的密钥扫描误判。真实前缀是 FSSBBIl1UgzbN7N（此处按小写书写，匹配前统一转小写）。
		{Kind: matchCookiePrefix, Name: "fssbbil1ugzbn7n", Strong: true,
			Evidence: "cookie:%s（瑞数 FSSBBIl1UgzbN7N 前缀）"},
		// 正则要求 $_ts 以「代码形态」出现（后接 = 或 .），而不是散文里提到：
		// 技术博客写「$_ts 是瑞数特征」不该被算成证据，真页面一定是在赋值/取值。
		{Kind: matchBodyRe, Name: `\$_ts`, Re: `\$_ts\s*[=.]`, Strong: true,
			Evidence: "body:%s（瑞数 $_ts 运行时）", Challenge: ChalJS},
		{Kind: matchStatus, Status: 202, Strong: false, Evidence: "status:202（JS 重载挑战常见码）",
			Challenge: ChalJS},
	}},

	// ── 顶象 Dingxiang（验证码类）───────────────────────────────
	{Vendor: "dinjie", BodyAnyStatus: true, Signals: []Signal{
		{Kind: matchBody, Name: "dingxiang-inc.com", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
		{Kind: matchBody, Name: "dx-captcha", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
		{Kind: matchBody, Name: "dingxiangcaptcha", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
	}},

	// ── 极验 Geetest（验证码类）────────────────────────────────
	// 注意：这是「站点用了验证码」的直接证据，不代表前面有反代型 WAF；
	// challenge=captcha 才是给 Kara 的关键信号（脚本化必须先破验证码）。
	{Vendor: "geetest", BodyAnyStatus: true, Signals: []Signal{
		{Kind: matchBody, Name: "static.geetest.com", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
		{Kind: matchBody, Name: "initgeetest", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
		{Kind: matchBody, Name: "geetest.com", Strong: true, Evidence: "body:%s", Challenge: ChalCaptcha},
		{Kind: matchBody, Name: "gt.js", Strong: false, Evidence: "body:%s", Challenge: ChalCaptcha},
	}},
}

// challengeSignals 是「通用 JS 挑战特征」——不归属任何厂商，但必须能被识别：
// 它们决定 challenge 字段，也决定「这不是目标不存在，而是被挑战了」。
var challengeSignals = []Signal{
	{Kind: matchCookiePrefix, Name: "__jsl_clearance", Evidence: "cookie:%s", Challenge: ChalJS},
	{Kind: matchCookiePrefix, Name: "acw_sc__v2", Evidence: "cookie:%s", Challenge: ChalJS},
	{Kind: matchCookiePrefix, Name: "cf_clearance", Evidence: "cookie:%s", Challenge: ChalJS},
	{Kind: matchCookiePrefix, Name: "tspd_101", Evidence: "cookie:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "acw_sc__v2", Evidence: "body:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "__jsl_clearance", Evidence: "body:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "cf-chl", Evidence: "body:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "/tspd/", Evidence: "body:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "cdn-cgi/challenge-platform", Evidence: "body:%s", Challenge: ChalJS},
	{Kind: matchURL, Name: "/tspd/", Evidence: "url:%s", Challenge: ChalJS},
	{Kind: matchBody, Name: "turnstile", Evidence: "body:%s", Challenge: ChalCaptcha},
}

// blockStatuses 是「可能意味着被拦」的状态码集合。仅凭状态码不下结论，
// 必须叠加 blockPhrases 里的拦截页文案——否则每个 nginx 的 403 都会被
// 误判成 WAF（这正是本次要修的病的反面）。
var blockStatuses = map[int]bool{403: true, 406: true, 412: true, 429: true, 501: true, 503: true}

// blockPhrases 是通用拦截页文案。刻意排除裸 "Forbidden"/"Access Denied" 之外的
// 弱词：nginx 默认 403 页只有 "403 Forbidden"，若不设门槛会全量误报。
var blockPhrases = []struct{ Token, Evidence string }{
	{"access denied", "body:Access Denied"},
	{"request rejected", "body:Request Rejected"},
	{"request blocked", "body:Request blocked"},
	{"the requested url was rejected", "body:F5 拦截页文案"},
	{"访问被拒绝", "body:访问被拒绝"},
	{"非法请求", "body:非法请求"},
	{"请求被拦截", "body:请求被拦截"},
	{"安全拦截", "body:安全拦截"},
	{"您的请求", "body:您的请求（中文拦截页常见开头）"},
}

// detectGenericChallenge 独立于厂商识别，回答「有没有 bot 挑战」。
// 返回 (挑战类型, 证据)。空字符串表示没有挑战迹象（由调用方归一成 none）。
func detectGenericChallenge(s *snapshot) (string, []string) {
	chal := ""
	var ev []string
	for _, sig := range challengeSignals {
		if s.pageLike && isBodySignal(sig.Kind) { // 正常页面里的正文不算
			continue
		}
		ok, obs := s.match(sig)
		if !ok {
			continue
		}
		chal = strongerChallenge(chal, sig.Challenge)
		if e := renderEvidence(sig.Evidence, obs); e != "" {
			ev = appendUnique(ev, e)
		}
	}
	// 412 + 正文含 <script> 是「JS 挑战」的组合特征：单看 412 可能是
	// 请求头被篡改，单看 <script> 是任何网页；两者同时出现才是挑战页指纹。
	if s.status == 412 && strings.Contains(s.bodyLow, "<script") {
		chal = strongerChallenge(chal, ChalJS)
		ev = appendUnique(ev, "status:412 + body:<script>（JS 挑战页）")
	}
	return chal, ev
}

// blockPageEvidence 只认「拦状态码 + 拦截页文案」同时成立的情况。
// 返回的证据不含厂商信息，故调用方只能把它用在 unknown 兜底里。
func (s *snapshot) blockPageEvidence() []string {
	if !blockStatuses[s.status] {
		return nil
	}
	var ev []string
	for _, bp := range blockPhrases {
		if strings.Contains(s.bodyLow, bp.Token) {
			ev = appendUnique(ev, fmt.Sprintf("status:%d + %s", s.status, bp.Evidence))
		}
	}
	return ev
}
