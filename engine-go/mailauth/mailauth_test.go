package mailauth

// mailauth_test.go —— 纯注入式测试：假 Resolver 承担全部 DNS，不打真网络。
// 覆盖 DMARC 策略梯度、SPF include 链展开/lookup 计数/回环/超限/多条、
// DKIM 模长与密钥不回显、BIMI、三段式契约与渲染。

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTXT 假 resolver：记录被查过的名字，便于断言查询面与查询次数。
type fakeTXT struct {
	mu    sync.Mutex
	recs  map[string][]string
	errs  map[string]error
	names []string
}

func newFake() *fakeTXT {
	return &fakeTXT{recs: map[string][]string{}, errs: map[string]error{}}
}

func (f *fakeTXT) set(name string, recs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recs[name] = recs
}

func (f *fakeTXT) fail(name string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[name] = err
}

func (f *fakeTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	f.names = append(f.names, name)
	recs, hasRec := f.recs[name]
	err, hasErr := f.errs[name]
	f.mu.Unlock()
	if hasErr {
		return nil, err
	}
	if hasRec {
		return recs, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeTXT) queried() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.names...)
}

func run(t *testing.T, f *fakeTXT, domain string) *Report {
	t.Helper()
	rep, err := Run(context.Background(), Options{Domain: domain, Resolver: f, Timeout: time.Second})
	if err != nil {
		t.Fatalf("Run(%s) 失败: %v", domain, err)
	}
	return rep
}

// ───────────────────────── DMARC ─────────────────────────

func TestDMARCParseAndSeverity(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com",
		"v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:agg@example.com,mailto:agg2@example.com; adkim=s; aspf=r; fo=1")

	rep := run(t, f, "example.com")
	d := rep.DMARC

	if !d.Found || d.Policy != "reject" || d.SubdomainPol != "quarantine" {
		t.Fatalf("DMARC 解析错误: %+v", d)
	}
	if d.Pct != 50 {
		t.Errorf("pct 应为 50，得 %d", d.Pct)
	}
	if len(d.RUA) != 2 || d.RUA[0] != "mailto:agg@example.com" {
		t.Errorf("rua 解析错误: %v", d.RUA)
	}
	if d.ADKIM != "s" || d.ASPF != "r" || d.FO != "1" {
		t.Errorf("对齐标签解析错误: adkim=%q aspf=%q fo=%q", d.ADKIM, d.ASPF, d.FO)
	}
	if d.Severity != SevReject {
		t.Errorf("严重度应为 %s，得 %s", SevReject, d.Severity)
	}
	if d.Invalid {
		t.Errorf("不应判无效: %s", d.InvalidReason)
	}
	// pct<100 必须单独出一条警告项
	if !hasFinding(rep, "dmarc-pct") {
		t.Error("pct=50 应产生 dmarc-pct 警告项")
	}
}

func TestDMARCMissingIsTopSeverity(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com") // 显式空 → 无 TXT
	rep := run(t, f, "example.com")

	if rep.DMARC.Found {
		t.Fatal("不应判为已发布")
	}
	if rep.DMARC.Severity != SevNone {
		t.Errorf("严重度应为 %s，得 %s", SevNone, rep.DMARC.Severity)
	}
	fd, ok := find(rep, "dmarc")
	if !ok {
		t.Fatal("缺 DMARC 体检项")
	}
	if fd.Level != LevelFail {
		t.Errorf("缺 DMARC 应为 %s，得 %s", LevelFail, fd.Level)
	}
	if rep.Grade == "A" || rep.Grade == "B" {
		t.Errorf("缺 DMARC 不该拿 %s", rep.Grade)
	}
}

func TestDMARCInvalidPolicy(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com", "v=DMARC1; p=blocks") // 非标准策略值
	rep := run(t, f, "example.com")
	if !rep.DMARC.Invalid {
		t.Fatal("p=blocks 应判无效")
	}
	if rep.DMARC.Severity != SevNone {
		t.Errorf("无效记录按无记录计，得 %s", rep.DMARC.Severity)
	}
}

func TestDMARCMultipleRecords(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com", "v=DMARC1; p=reject", "v=DMARC1; p=none")
	rep := run(t, f, "example.com")
	if !rep.DMARC.Multiple {
		t.Fatal("两条 DMARC 记录应标记 Multiple")
	}
	if !hasFinding(rep, "dmarc-multiple") {
		t.Error("多条记录应产生 fail 项")
	}
}

// ───────────────────────── SPF ─────────────────────────

func TestSPFIncludeChainLookupCount(t *testing.T) {
	f := newFake()
	f.set("example.com", "v=spf1 include:_spf.a.example.net include:_spf.b.example.net -all")
	f.set("_spf.a.example.net", "v=spf1 include:_spf.c.example.net ip4:192.0.2.0/24 -all")
	f.set("_spf.c.example.net", "v=spf1 ip4:198.51.100.1 -all")
	f.set("_spf.b.example.net", "v=spf1 ip4:203.0.113.5 -all")

	rep := run(t, f, "example.com")
	s := rep.SPF

	// 期望：根自身 2 次（两条 include）+ a 自身 1 次（include c）= 3
	if s.Lookups != 3 {
		t.Fatalf("lookup 计数应为 3，得 %d（链: %+v）", s.Lookups, s.Chain)
	}
	if s.ExceedsLimit {
		t.Error("3 次不该判超限")
	}
	if s.All != "-all" {
		t.Errorf("all 应为 -all，得 %q", s.All)
	}
	if len(s.Chain) != 4 {
		t.Fatalf("链应展开 4 个节点（根+a+c+b），得 %d: %+v", len(s.Chain), s.Chain)
	}
	// 行序必须是先序：根 → a → c → b
	wantOrder := []string{"example.com", "_spf.a.example.net", "_spf.c.example.net", "_spf.b.example.net"}
	for i, w := range wantOrder {
		if s.Chain[i].Domain != w {
			t.Errorf("链序错误 [%d]: 应为 %s，得 %s", i, w, s.Chain[i].Domain)
		}
	}
	if s.Chain[0].Lookups != 2 || s.Chain[1].Lookups != 1 || s.Chain[2].Lookups != 0 {
		t.Errorf("各节点自身 lookup 数错误: %+v", s.Chain)
	}
	// 根节点 total 必须等于全局计数
	if s.Chain[0].Total != 3 {
		t.Errorf("根累计应为 3，得 %d", s.Chain[0].Total)
	}
	if s.Depth != 2 {
		t.Errorf("最大深度应为 2，得 %d", s.Depth)
	}
}

func TestSPFExceedsRFC7208Limit(t *testing.T) {
	f := newFake()
	// 11 条 include → 11 次 lookup，越过 RFC 7208 的 10 次上限
	var b strings.Builder
	b.WriteString("v=spf1")
	for i := 0; i < 11; i++ {
		b.WriteString(" include:spf")
		b.WriteByte(byte('a' + i))
		b.WriteString(".example.net")
	}
	b.WriteString(" -all")
	f.set("example.com", b.String())

	rep := run(t, f, "example.com")
	s := rep.SPF
	if s.Lookups != 11 {
		t.Fatalf("应为 11 次 lookup，得 %d", s.Lookups)
	}
	if !s.ExceedsLimit {
		t.Fatal("应判超限")
	}
	fd, ok := find(rep, "spf-lookups")
	if !ok || fd.Level != LevelFail {
		t.Fatalf("超限必须出 fail 项，得 %+v", fd)
	}
}

func TestSPFIncludeLoopTerminates(t *testing.T) {
	f := newFake()
	f.set("example.com", "v=spf1 include:loop1.example.net -all")
	f.set("loop1.example.net", "v=spf1 include:loop2.example.net -all")
	f.set("loop2.example.net", "v=spf1 include:loop1.example.net -all") // 回到 loop1

	done := make(chan *Report, 1)
	go func() { done <- run(t, f, "example.com") }()
	select {
	case rep := <-done:
		if !rep.SPF.Loop {
			t.Fatalf("应检出回环，链: %+v", rep.SPF.Chain)
		}
		// 回环节点不再展开：root(1) + loop1(1) + loop2(1) = 3
		if rep.SPF.Lookups != 3 {
			t.Errorf("回环下 lookup 应停在 3，得 %d", rep.SPF.Lookups)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("include 回环未收敛（疑似死循环）")
	}
}

func TestSPFMultipleRecordsIsPermerror(t *testing.T) {
	f := newFake()
	f.set("example.com", "v=spf1 ip4:192.0.2.1 -all", "v=spf1 include:other.example.net ~all")
	rep := run(t, f, "example.com")
	if !rep.SPF.Multiple || rep.SPF.Status != StMultiple {
		t.Fatalf("应判多条 permerror，得 %+v", rep.SPF)
	}
	fd, ok := find(rep, "spf-multiple")
	if !ok || fd.Level != LevelFail {
		t.Fatalf("多条 SPF 必须出 fail 项: %+v", fd)
	}
}

func TestSPFAllQualifiers(t *testing.T) {
	cases := []struct {
		rec  string
		all  string
		want string
	}{
		{"v=spf1 ip4:192.0.2.1 -all", "-all", LevelOK},
		{"v=spf1 ip4:192.0.2.1 ~all", "~all", LevelOK},
		{"v=spf1 ip4:192.0.2.1 ?all", "?all", LevelWarn},
		{"v=spf1 +all", "+all", LevelFail},
		{"v=spf1 ip4:192.0.2.1", "", LevelWarn},
	}
	for _, c := range cases {
		f := newFake()
		f.set("example.com", c.rec)
		f.set("_dmarc.example.com", "v=DMARC1; p=reject")
		rep := run(t, f, "example.com")
		if rep.SPF.All != c.all {
			t.Errorf("%q: all 应为 %q，得 %q", c.rec, c.all, rep.SPF.All)
		}
		fd, ok := find(rep, "spf-all")
		if !ok {
			t.Errorf("%q: 缺 spf-all 体检项", c.rec)
			continue
		}
		if fd.Level != c.want {
			t.Errorf("%q: 等级应为 %s，得 %s", c.rec, c.want, fd.Level)
		}
	}
}

func TestSPFDeadIncludeReported(t *testing.T) {
	f := newFake()
	f.set("example.com", "v=spf1 include:gone.example.net -all")
	// gone.example.net 不在 fake 表里 → NXDOMAIN
	rep := run(t, f, "example.com")
	if !hasFinding(rep, "spf-chain-nx") {
		t.Fatalf("失效 include 应被点名，链: %+v", rep.SPF.Chain)
	}
}

// ───────────────────────── DKIM ─────────────────────────

// dkimRecord 造一条真实结构的 DKIM TXT（公钥为真 SPKI DER）。
func dkimRecord(t *testing.T, bits int) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("编码公钥失败: %v", err)
	}
	p := base64.StdEncoding.EncodeToString(der)
	return "v=DKIM1; k=rsa; p=" + p, p
}

func TestDKIMKeyBitsAndRedaction(t *testing.T) {
	rec, raw := dkimRecord(t, 2048)
	f := newFake()
	f.set("default._domainkey.example.com", rec)

	rep := run(t, f, "example.com")
	var got *DKIMResult
	for i := range rep.DKIM {
		if rep.DKIM[i].Selector == "default" {
			got = &rep.DKIM[i]
		}
	}
	if got == nil || !got.Found {
		t.Fatal("default 选择器应被发现")
	}
	if got.KeyBits != 2048 {
		t.Errorf("模长应为 2048，得 %d", got.KeyBits)
	}
	if got.Estimated {
		t.Error("标准 SPKI 不该走估算分支")
	}
	if got.KeyType != "rsa" {
		t.Errorf("k 应为 rsa，得 %q", got.KeyType)
	}
	// 硬约束：公钥材料一律不回显
	if strings.Contains(got.Record, raw) || strings.Contains(got.Record, raw[:40]) {
		t.Errorf("记录摘要泄露了公钥材料: %s", got.Record)
	}
	if !strings.Contains(got.Record, "2048-bit") {
		t.Errorf("摘要应标注模长: %s", got.Record)
	}
	if !hasFinding(rep, "dkim") {
		t.Error("发现 DKIM 应产生 dkim 体检项")
	}
}

func TestDKIMRevokedSelector(t *testing.T) {
	f := newFake()
	f.set("s1._domainkey.example.com", "v=DKIM1; k=rsa; p=")
	rep := run(t, f, "example.com")
	for _, d := range rep.DKIM {
		if d.Selector != "s1" {
			continue
		}
		if !d.Revoked {
			t.Fatalf("p= 为空应判吊销: %+v", d)
		}
		if d.KeyBits != 0 {
			t.Errorf("吊销记录不该给模长，得 %d", d.KeyBits)
		}
		return
	}
	t.Fatal("未找到 s1 探测结果")
}

func TestDKIMWeakKeyWarns(t *testing.T) {
	rec, _ := dkimRecord(t, 1024)
	f := newFake()
	f.set("k1._domainkey.example.com", rec)
	rep := run(t, f, "example.com")
	for _, d := range rep.DKIM {
		if d.Selector == "k1" && d.KeyBits != 1024 {
			t.Errorf("k1 模长应为 1024，得 %d", d.KeyBits)
		}
	}
	if !hasFinding(rep, "dkim-weak-k1") {
		t.Error("1024 位应产生弱密钥警告项")
	}
}

func TestDKIMCustomSelectors(t *testing.T) {
	f := newFake()
	f.set("weird._domainkey.example.com", "v=DKIM1; k=rsa; p=")
	rep, err := Run(context.Background(), Options{
		Domain: "example.com", Resolver: f, Selectors: []string{"weird"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.DKIM) != 1 || rep.DKIM[0].Selector != "weird" {
		t.Fatalf("自定义选择器未生效: %+v", rep.DKIM)
	}
}

// ───────────────────────── BIMI ─────────────────────────

func TestBIMIFound(t *testing.T) {
	f := newFake()
	f.set("default._bimi.example.com", "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
	rep := run(t, f, "example.com")
	if !rep.BIMI.Found {
		t.Fatal("BIMI 应被发现")
	}
	if rep.BIMI.Logo != "https://example.com/logo.svg" {
		t.Errorf("Logo 解析错误: %q", rep.BIMI.Logo)
	}
	if !hasFinding(rep, "bimi") {
		t.Error("BIMI 应产生体检项")
	}
	// 只读纪律：l=/a= 只记录不抓取——查询面必须全是 DNS TXT 名字，
	// 出现 http 前缀的查询就说明有人把 URL 当成 DNS 名去查了。
	for _, n := range f.queried() {
		if strings.Contains(n, "http") || strings.Contains(n, "/") {
			t.Errorf("查询面出现非 DNS 名字: %q", n)
		}
	}
}

func TestBIMIInvalid(t *testing.T) {
	f := newFake()
	f.set("default._bimi.example.com", "v=BIMI1; l=; a=")
	rep := run(t, f, "example.com")
	if !rep.BIMI.Found || !rep.BIMI.Invalid {
		t.Fatalf("空 l=/a= 应判 invalid: %+v", rep.BIMI)
	}
}

// ───────────────────────── 契约 / 评分 / 渲染 ─────────────────────────

func TestFindingsContract(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com", "v=DMARC1; p=none")
	f.set("example.com", "v=spf1 include:_spf.a.example.net ~all")
	f.set("_spf.a.example.net", "v=spf1 ip4:192.0.2.0/24 -all")
	rep := run(t, f, "example.com")

	if len(rep.Findings) == 0 {
		t.Fatal("应产出体检项")
	}
	valid := map[string]bool{LevelFail: true, LevelWarn: true, LevelOK: true, LevelInfo: true}
	for _, fd := range rep.Findings {
		if fd.Section == "" || fd.Label == "" {
			t.Errorf("体检项缺章节/名称: %+v", fd)
		}
		if strings.TrimSpace(fd.Status) == "" {
			t.Errorf("%s 缺「现状」", fd.Key)
		}
		if strings.TrimSpace(fd.Risk) == "" {
			t.Errorf("%s 缺「风险」", fd.Key)
		}
		if strings.TrimSpace(fd.Advice) == "" {
			t.Errorf("%s 缺「建议」", fd.Key)
		}
		if !valid[fd.Level] {
			t.Errorf("%s 等级非法: %q", fd.Key, fd.Level)
		}
	}
}

func TestGradeLadder(t *testing.T) {
	rejectRec, _ := dkimRecord(t, 2048)

	cases := []struct {
		name    string
		recs    map[string][]string
		wantG   string
		wantSev string
	}{
		{
			name: "全绿",
			recs: map[string][]string{
				"_dmarc.example.com":             {"v=DMARC1; p=reject; rua=mailto:a@example.com"},
				"example.com":                    {"v=spf1 ip4:192.0.2.1 -all"},
				"default._domainkey.example.com": {rejectRec},
				"default._bimi.example.com":      {"v=BIMI1; l=https://example.com/l.svg"},
			},
			wantG: "A", wantSev: SevReject,
		},
		{
			name: "p=none 无 DKIM",
			recs: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=none"},
				"example.com":        {"v=spf1 ip4:192.0.2.1 -all"},
			},
			wantG: "D", wantSev: SevPolicyNone,
		},
		{
			name:  "全无",
			recs:  map[string][]string{},
			wantG: "F", wantSev: SevNone,
		},
		{
			name: "p=quarantine",
			recs: map[string][]string{
				"_dmarc.example.com": {"v=DMARC1; p=quarantine"},
				"example.com":        {"v=spf1 ip4:192.0.2.1 ~all"},
			},
			wantG: "B", wantSev: SevQuarantine,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			for k, v := range c.recs {
				f.set(k, v...)
			}
			rep := run(t, f, "example.com")
			if rep.Grade != c.wantG {
				t.Errorf("评级应为 %s，得 %s（分数 %d，摘要 %s）", c.wantG, rep.Grade, rep.Score, rep.Summary)
			}
			if rep.Severity != c.wantSev {
				t.Errorf("严重度应为 %s，得 %s", c.wantSev, rep.Severity)
			}
			if rep.Score < 0 || rep.Score > 100 {
				t.Errorf("分数越界: %d", rep.Score)
			}
			if rep.Summary == "" {
				t.Error("摘要为空")
			}
		})
	}
}

func TestRenderTextSections(t *testing.T) {
	rec, _ := dkimRecord(t, 2048)
	f := newFake()
	f.set("_dmarc.example.com", "v=DMARC1; p=none; rua=mailto:agg@example.com")
	f.set("example.com", "v=spf1 include:_spf.a.example.net -all")
	f.set("_spf.a.example.net", "v=spf1 ip4:192.0.2.0/24 -all")
	f.set("default._domainkey.example.com", rec)
	rep := run(t, f, "example.com")

	txt := RenderText(rep)
	for _, want := range []string{
		"邮件认证体检", "example.com", "DMARC", "SPF", "DKIM", "BIMI",
		"include 链", "lookup", "现状：", "风险：", "建议：", "综合评级",
	} {
		if !strings.Contains(txt, want) {
			t.Errorf("报告缺 %q\n%s", want, txt)
		}
	}
	if strings.Contains(txt, rec[strings.Index(rec, "p=")+2:][:40]) {
		t.Error("渲染结果泄露公钥材料")
	}
}

func TestQueryNamesAreDNSStyle(t *testing.T) {
	f := newFake()
	f.set("_dmarc.example.com", "v=DMARC1; p=reject")
	f.set("example.com", "v=spf1 -all")
	run(t, f, "example.com")

	names := f.queried()
	if len(names) == 0 {
		t.Fatal("没有发生任何查询")
	}
	for _, n := range names {
		if strings.ContainsAny(n, " /:") {
			t.Errorf("非法 DNS 查询名: %q", n)
		}
	}
	// 根域 SPF 只查一次（DMARC/SPF/根各一次 + 7 个选择器 + BIMI = 10）
	want := 1 + 1 + len(DefaultSelectors) + 1
	if len(names) != want {
		t.Errorf("查询次数应为 %d，得 %d: %v", want, len(names), names)
	}
	count := 0
	for _, n := range names {
		if n == "example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("根域应只查 1 次，实际 %d 次", count)
	}
}

func TestDNSFailureDegrades(t *testing.T) {
	f := newFake()
	f.fail("_dmarc.example.com", errors.New("server misbehaving"))
	rep := run(t, f, "example.com")
	if rep.DMARC.Found {
		t.Fatal("查询失败不该判为已发布")
	}
	if rep.DMARC.Error == "" {
		t.Error("应记录 DNS 错误")
	}
	// 「没查到」不能写成「没配」——后者是安全结论，前者只是这次网络不好
	fd, ok := find(rep, "dmarc")
	if !ok {
		t.Fatal("缺 DMARC 体检项")
	}
	if !strings.Contains(fd.Status, "查询失败") {
		t.Errorf("查询失败应如实写明，得 %q", fd.Status)
	}
	if fd.Level == LevelFail {
		t.Errorf("查询失败不应判 fail（那是断言的语气），得 %s", fd.Level)
	}
}

func TestSPFQueryFailureIsNotMissing(t *testing.T) {
	f := newFake()
	f.fail("example.com", errors.New("i/o timeout"))
	rep := run(t, f, "example.com")
	if rep.SPF.Found {
		t.Fatal("查询失败不该判为有 SPF")
	}
	if rep.SPF.Status != StError {
		t.Fatalf("状态应为 %s，得 %s", StError, rep.SPF.Status)
	}
	fd, ok := find(rep, "spf")
	if !ok {
		t.Fatal("缺 SPF 体检项")
	}
	if strings.Contains(fd.Status, "未发布") {
		t.Errorf("查询失败不该写成「未发布」: %q", fd.Status)
	}
	if !strings.Contains(rep.Summary, "查询失败") {
		t.Errorf("摘要应写明查询失败: %q", rep.Summary)
	}
	if !rep.Incomplete || len(rep.Failed) == 0 {
		t.Errorf("有失败项应标 Incomplete 并列出失败项: %+v", rep.Failed)
	}
	// 一次失败要重试（DNS 抖动常见），故查询次数为 txtAttempts
	if n := countQuery(f, "example.com"); n != txtAttempts {
		t.Errorf("失败应重试到 %d 次，得 %d", txtAttempts, n)
	}
}

// slowTXT 永远超时的 resolver（每次查询耗时 delay），用于验证总预算兜底。
type slowTXT struct {
	delay time.Duration
	n     int
}

func (s *slowTXT) LookupTXT(ctx context.Context, name string) ([]string, error) {
	s.n++
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
}

func TestBudgetBoundsRuntime(t *testing.T) {
	slow := &slowTXT{delay: 20 * time.Millisecond}
	start := time.Now()
	rep, err := Run(context.Background(), Options{
		Domain:   "example.com",
		Resolver: slow,
		Timeout:  10 * time.Millisecond,
		Budget:   60 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	// 无预算兜底时 7 个选择器 + 3 次尝试 ≈ 1s 以上；有预算必须早收。
	if elapsed > 1500*time.Millisecond {
		t.Errorf("总预算未生效，耗时 %v", elapsed)
	}
	if !rep.Incomplete {
		t.Error("全部查询失败应标 Incomplete")
	}
	if len(rep.Failed) != 1+1+len(DefaultSelectors) {
		t.Errorf("失败项应覆盖 DMARC/SPF/各选择器，得 %v", rep.Failed)
	}
	// 前两项可能各自熬满 3 次超时，后面的选择器应直接命中预算闸
	hasBudget := strings.Contains(rep.SPF.Error+rep.DMARC.Error, "预算")
	for _, d := range rep.DKIM {
		if strings.Contains(d.Note, "预算") {
			hasBudget = true
		}
	}
	if !hasBudget {
		t.Errorf("预算耗尽应在错误里写明: spf=%q dmarc=%q dkim=%+v", rep.SPF.Error, rep.DMARC.Error, rep.DKIM)
	}
}

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"Example.COM.":            "example.com",
		" https://example.com/x ": "example.com",
		"http://example.com?a=1":  "example.com",
		"example.com":             "example.com",
	}
	for in, want := range cases {
		if got := normalizeDomain(in); got != want {
			t.Errorf("normalizeDomain(%q) = %q，应为 %q", in, got, want)
		}
	}
	if _, err := Run(context.Background(), Options{Domain: "   "}); err == nil {
		t.Error("空域名应返回 error")
	}
}

// ───────────────────────── 助手 ─────────────────────────

func find(rep *Report, key string) (Finding, bool) {
	for _, f := range rep.Findings {
		if f.Key == key {
			return f, true
		}
	}
	return Finding{}, false
}

func hasFinding(rep *Report, key string) bool {
	_, ok := find(rep, key)
	return ok
}

func countQuery(f *fakeTXT, name string) int {
	n := 0
	for _, q := range f.queried() {
		if q == name {
			n++
		}
	}
	return n
}
