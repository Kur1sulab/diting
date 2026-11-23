package waf

import (
	"encoding/json"
	"strings"
	"testing"
)

// ── 置信度阶梯：这套规则是全部判定的地基，必须逐档钉死 ──────────────

func TestConfidenceLadder(t *testing.T) {
	cases := []struct {
		strong, weak int
		want         string
		why          string
	}{
		{0, 0, "", "无特征不许产生结论"},
		{0, 1, ConfLow, "单一弱特征只能是线索"},
		{0, 2, ConfMedium, "双弱特征互证 → medium"},
		{0, 5, ConfMedium, "弱特征再多也不许升到 high"},
		{1, 0, ConfMedium, "单一强特征：品牌可信、场景未确认"},
		{1, 1, ConfMedium, "一强一弱：仍然是 medium"},
		{1, 2, ConfHigh, "一强两弱互证 → high"},
		{2, 0, ConfHigh, "两个独立强特征 → high"},
		{3, 4, ConfHigh, "强特征叠加不降级"},
	}
	for _, c := range cases {
		if got := confidenceOf(c.strong, c.weak); got != c.want {
			t.Fatalf("confidenceOf(%d,%d) = %q, want %q（%s）",
				c.strong, c.weak, got, c.want, c.why)
		}
	}
}

// ── 规则表自检：防止加规则时手滑写出「无法举证」或「枚举外」的厂商 ──

// allowedVendors 是对外契约里允许出现的全部 vendor 值（Kara 按这份清单分支）。
var allowedVendors = map[string]bool{
	"cloudflare": true, "akamai": true, "f5": true, "imperva": true,
	"aliyun": true, "tencent": true, "chaitin-safeline": true, "safedog": true,
	"360": true, "aws": true, "modsecurity": true, "river-security": true,
	"dinjie": true, "geetest": true, "unknown": true,
}

func TestRuleTableSanity(t *testing.T) {
	seen := map[string]bool{}
	for _, rule := range vendorRules {
		if !allowedVendors[rule.Vendor] {
			t.Errorf("厂商 %q 不在对外枚举里（Kara 会读不到）", rule.Vendor)
		}
		if seen[rule.Vendor] {
			t.Errorf("厂商 %q 重复定义，仲裁会失序", rule.Vendor)
		}
		seen[rule.Vendor] = true
		if len(rule.Signals) == 0 {
			t.Errorf("厂商 %q 没有任何特征", rule.Vendor)
		}
		strong := 0
		for i, sig := range rule.Signals {
			// 红线 1：每条特征都必须能写出证据，否则等于不可复核。
			if strings.TrimSpace(sig.Evidence) == "" {
				t.Errorf("%s 第 %d 条特征缺 evidence 模板", rule.Vendor, i)
			}
			// 红线 2：证据必须指明取证位点，读报告的人才知道去哪儿复核。
			if !strings.Contains(sig.Evidence, ":") {
				t.Errorf("%s 第 %d 条证据 %q 未标注取证位点（header:/cookie:/body:/status:/url:）",
					rule.Vendor, i, sig.Evidence)
			}
			if sig.Strong {
				strong++
			}
			// 红线 3：需要名字的匹配类型必须给名字，否则永远不命中。
			switch sig.Kind {
			case matchHeaderValue, matchHeaderPresent, matchCookiePrefix,
				matchBody, matchBodyRe, matchURL:
				if sig.Name == "" {
					t.Errorf("%s 第 %d 条特征 Kind=%d 缺 Name", rule.Vendor, i, sig.Kind)
				}
			case matchStatus:
				if sig.Status == 0 {
					t.Errorf("%s 第 %d 条 status 特征缺 Status", rule.Vendor, i)
				}
			}
			// Cookie 名前缀必须是小写：匹配时会统一转小写比较。
			if sig.Kind == matchCookiePrefix && sig.Name != strings.ToLower(sig.Name) {
				t.Errorf("%s 第 %d 条 cookie 前缀 %q 必须小写", rule.Vendor, i, sig.Name)
			}
		}
		// 红线 4：一个厂商若全是弱特征，永远到不了 high —— 这是设计允许的，
		// 但必须至少有一个强特征才能进 high 档，这里只做提示性校验。
		if strong == 0 {
			t.Logf("提示：厂商 %q 只用弱特征，置信度上限 medium（如为刻意设计请忽略）", rule.Vendor)
		}
	}
}

// ── 证据与枚举的不变量 ─────────────────────────────────────────

func TestAttributeInvariants(t *testing.T) {
	cases := loadFixtures(t)
	for _, c := range cases {
		got := Detect(c.toResponse())
		if got == nil {
			continue
		}
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if !allowedVendors[got.Vendor] {
				t.Fatalf("vendor %q 不在枚举内", got.Vendor)
			}
			if got.Confidence != ConfHigh && got.Confidence != ConfMedium && got.Confidence != ConfLow {
				t.Fatalf("confidence %q 非法", got.Confidence)
			}
			if got.Challenge != ChalNone && got.Challenge != ChalJS && got.Challenge != ChalCaptcha {
				t.Fatalf("challenge %q 非法", got.Challenge)
			}
			if len(got.Evidence) == 0 {
				t.Fatal("没有任何证据却给出了结论 —— 违反红线 2")
			}
			if len(got.Evidence) > maxEvidence {
				t.Fatalf("证据条数 %d 超过上限 %d", len(got.Evidence), maxEvidence)
			}
		})
	}
}

// ── 兜底：认不出品牌但确实有拦截迹象 ────────────────────────────

func TestUnknownFallbackBlockPage(t *testing.T) {
	// 典型自研/私有 WAF 拦截图：403 + 中文拦截文案，没有任何品牌特征。
	got := Detect(Response{
		Status:  403,
		Headers: map[string]string{"server": "nginx"},
		Body:    "<html><body><h1>非法请求</h1><p>请联系管理员</p></body></html>",
	})
	if got == nil {
		t.Fatal("有拦截迹象时应给出 unknown 兜底，不能当成目标不存在")
	}
	if got.Vendor != VendorUnknown {
		t.Fatalf("vendor = %q, want unknown（猜品牌比报 unknown 更贵）", got.Vendor)
	}
	if got.Confidence != ConfLow {
		t.Fatalf("兜底置信度必须封顶 low，实际 %q", got.Confidence)
	}
	if got.Challenge != ChalNone {
		t.Fatalf("challenge = %q, want none", got.Challenge)
	}
	if len(got.Evidence) == 0 || !strings.Contains(strings.Join(got.Evidence, " "), "status:403") {
		t.Fatalf("证据应含状态码锚点: %v", got.Evidence)
	}
}

func TestUnknownFallbackJSChallenge(t *testing.T) {
	// 412 + JS：认不出厂商，但「这是 JS 挑战页」这个结论必须给出来。
	got := Detect(Response{
		Status: 412,
		Body:   "<html><body><script>document.cookie='x=1';location.reload()</script></body></html>",
	})
	if got == nil {
		t.Fatal("412 + JS 必须判为挑战页，不能当成目标不存在")
	}
	if got.Vendor != VendorUnknown || got.Challenge != ChalJS {
		t.Fatalf("got %s, want unknown/*/js_challenge", got.String())
	}
}

// ── 误报红线：干净响应必须返回 nil ─────────────────────────────

func TestCleanResponsesReturnNil(t *testing.T) {
	cases := []struct {
		name string
		resp Response
	}{
		{"空响应", Response{}},
		{"200 空正文", Response{Status: 200}},
		{"普通 nginx 200", Response{
			Status:  200,
			Headers: map[string]string{"server": "nginx", "x-powered-by": "PHP/8.1"},
			Body:    "<html><body>hello</body></html>",
		}},
		{"nginx 403 默认页", Response{
			Status:  403,
			Headers: map[string]string{"server": "nginx/1.24.0"},
			Body:    "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center></body></html>",
		}},
		{"500 错误页", Response{
			Status:  500,
			Headers: map[string]string{"server": "Apache"},
			Body:    "<h1>Internal Server Error</h1>",
		}},
	}
	for _, c := range cases {
		if got := Detect(c.resp); got != nil {
			t.Fatalf("%s：应返回 nil，实际 %s（%v）", c.name, got.String(), got.Evidence)
		}
	}
}

// TestF5LBCookieOnlyIsLow BIGipServer 是弱特征：会给出 f5/low —— 这是有意的，
// 「F5 设备在链路上」本身就是有价值的路由信息，但绝不能升到 medium 以上。
func TestF5LBCookieOnlyIsLow(t *testing.T) {
	got := Detect(Response{
		Status:  200,
		Headers: map[string]string{"server": "nginx"},
		Cookies: []string{"BIGipServerpool=1.2.3.4"},
		Body:    "ok",
	})
	if got == nil || got.Vendor != "f5" || got.Confidence != ConfLow {
		t.Fatalf("BIGipServer 单独出现应为 f5/low，实际 %v", got)
	}
}

// ── 解析健壮性：Cookie / 头名 / 大小写 ─────────────────────────

func TestCookieParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"__cf_bm=abc; Path=/; HttpOnly", "__cf_bm"},
		{"  FSSBBIl1UgzbN7N80T=4g2h  ", "FSSBBIl1UgzbN7N80T"},
		{"solo_name", "solo_name"},
		{"Path=/; HttpOnly", ""}, // 碎片不能当成 cookie 名
		{"", ""},
	}
	for _, c := range cases {
		if got := cookieName(c.raw); got != c.want {
			t.Fatalf("cookieName(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestHeaderKeysAreCaseInsensitive(t *testing.T) {
	// 真实抓包时头名大小写五花八门，判定必须与大小写无关。
	got := Detect(Response{
		Status:  200,
		Headers: map[string]string{"Server": "CloudFlare", "CF-RAY": "8f2a-LAX"},
		Body:    "ok",
	})
	if got == nil || got.Vendor != "cloudflare" || got.Confidence != ConfHigh {
		t.Fatalf("大小写不同的头应照常识别，实际 %v", got)
	}
}

func TestHeaderValueSubMatch(t *testing.T) {
	// Server 值常带版本号/后缀（cloudflare-nginx、safedog/4.0），按子串识别。
	got := Detect(Response{
		Status:  403,
		Headers: map[string]string{"server": "cloudflare-nginx"},
		Body:    "",
	})
	if got == nil || got.Vendor != "cloudflare" {
		t.Fatalf("server 子串应命中 cloudflare，实际 %v", got)
	}
}

// ── 挑战类型合并：captcha 比 js_challenge 更具体 ─────────────────

func TestCaptchaBeatsJSChallenge(t *testing.T) {
	if got := strongerChallenge(ChalJS, ChalCaptcha); got != ChalCaptcha {
		t.Fatalf("captcha 应压过 js_challenge，实际 %q", got)
	}
	if got := strongerChallenge(ChalCaptcha, ChalJS); got != ChalCaptcha {
		t.Fatalf("已有 captcha 时不应被 js_challenge 覆盖，实际 %q", got)
	}
	if got := strongerChallenge("", ChalNone); got != ChalNone {
		t.Fatalf("空挑战应收敛成 none，实际 %q", got)
	}
}

// ── 正常大页面不许凭正文判 WAF ──────────────────────────────────

func TestPageLikeGateSuppressesBodySignals(t *testing.T) {
	// 8KB 以上的 200 页面 = 正常应用页。正文里出现 WAF 品牌词是内容，不是证据。
	body := strings.Repeat("本文介绍 Cloudflare、ModSecurity、雷池 SafeLine 的差异。", 300)
	if len(body) <= pageLikeBodyBytes {
		t.Fatalf("测试正文不够长（%d），造不出 pageLike 场景", len(body))
	}
	got := Detect(Response{
		Status:  200,
		Headers: map[string]string{"server": "nginx"},
		Body:    body,
	})
	if got != nil {
		t.Fatalf("正常大页面提到品牌词不应判 WAF，实际 %s（%v）", got.String(), got.Evidence)
	}
}

func TestPageLikeDoesNotBlockHeaderSignals(t *testing.T) {
	// 门槛只约束正文；头/Cookie 是响应元数据，任何页面都算数。
	body := strings.Repeat("filler ", 2000)
	got := Detect(Response{
		Status:  200,
		Headers: map[string]string{"server": "cloudflare", "cf-ray": "abc-LAX"},
		Body:    body,
	})
	if got == nil || got.Vendor != "cloudflare" {
		t.Fatalf("大页面的头部特征仍应生效，实际 %v", got)
	}
}

// ── 仲裁：多厂商同时命中时取证据更强的一个 ─────────────────────

func TestArbitrationPrefersStronger(t *testing.T) {
	// 同时出现 Cloudflare 强特征与 F5 的单个弱 Cookie：CF 必须胜出。
	got := Detect(Response{
		Status:  403,
		Headers: map[string]string{"server": "cloudflare", "cf-ray": "abc-LAX", "cf-mitigated": "challenge"},
		Cookies: []string{"BIGipServerpool=1.2.3.4"},
		Body:    "blocked",
	})
	if got == nil || got.Vendor != "cloudflare" || got.Confidence != ConfHigh {
		t.Fatalf("应仲裁出 cloudflare/high，实际 %v", got)
	}
}

// ── JSON 契约：Kara 按固定四键解析 ─────────────────────────────

func TestAttributeJSONShape(t *testing.T) {
	a := Attribute{Vendor: "cloudflare", Confidence: ConfHigh, Challenge: ChalJS,
		Evidence: []string{"header:cf-ray=abc"}}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"vendor":"cloudflare","confidence":"high","challenge":"js_challenge","evidence":["header:cf-ray=abc"]}`
	if string(b) != want {
		t.Fatalf("JSON 契约漂移：\n got %s\nwant %s", b, want)
	}
	// 证据为空时必须是 [] 而不是 null：下游 range 时才不会炸。
	b2, _ := json.Marshal(Attribute{Vendor: VendorUnknown, Confidence: ConfLow, Challenge: ChalNone})
	if !strings.Contains(string(b2), `"evidence":[]`) {
		t.Fatalf("空证据应序列化为 []: %s", b2)
	}
}

func TestAttributePresentAndString(t *testing.T) {
	if (Attribute{}).Present() {
		t.Fatal("零值不应 Present")
	}
	if (Attribute{}).String() != "-" {
		t.Fatal("零值展示应为 -")
	}
	a := Attribute{Vendor: "f5", Confidence: ConfHigh, Challenge: ChalNone}
	if !a.Present() || a.String() != "f5/high/none" {
		t.Fatalf("String() = %q", a.String())
	}
}

func TestDetectFromResultAdapter(t *testing.T) {
	// netutil.Fetch 的结果直接喂进来的路径，必须与 Detect 等价。
	got := DetectFromResult(200,
		map[string]string{"Server": "AkamaiGHost", "X-Akamai-Request-Id": "abc"},
		[]string{"_abck=1; Path=/"},
		"ok", "https://example.com/")
	if got == nil || got.Vendor != "akamai" {
		t.Fatalf("适配器应等价于 Detect，实际 %v", got)
	}
}

// ── /TSPD/ 路径级特征：拦截跳转后的 URL 本身就是证据 ─────────────

func TestTSPDPathSignal(t *testing.T) {
	got := Detect(Response{
		Status:  200,
		Headers: map[string]string{"server": "nginx"},
		Body:    "ok",
		URL:     "https://example.com/TSPD/10201/scripts/0.js",
	})
	if got == nil || got.Vendor != "f5" || got.Challenge != ChalJS {
		t.Fatalf("/TSPD/ 路径应判 f5/js_challenge，实际 %v", got)
	}
}
