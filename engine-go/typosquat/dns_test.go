package typosquat

// dns_test.go —— 限速器、判活语义（NXDOMAIN/超时/失败区分）、缓存、
// 指定 resolver（本地 UDP DNS stub 实测 Go 解析器路径）。

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLimiterQPS(t *testing.T) {
	lim := newLimiter(100) // 10ms 间隔
	ctx := context.Background()
	start := time.Now()
	for i := 0; i < 6; i++ {
		if err := lim.wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	if elapsed < 45*time.Millisecond { // 5 个间隔 × 10ms
		t.Fatalf("限速未生效: 6 次仅 %v", elapsed)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("限速过慢: %v", elapsed)
	}
	// ctx 取消立即返回
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	lim2 := newLimiter(0.001)
	_ = lim2.wait(ctx) // 占掉首槽
	if err := lim2.wait(cctx); err == nil {
		t.Fatal("取消的 ctx 应返回错误")
	}
}

// fakeDNS 测试用假 resolver（计数并发安全）。
type fakeDNS struct {
	mu        sync.Mutex
	hosts     map[string][]string
	mx        map[string][]*net.MX
	ns        map[string][]*net.NS
	errs      map[string]error
	hostCalls int
	mxCalls   int
	nsCalls   int
}

func (f *fakeDNS) LookupHost(_ context.Context, h string) ([]string, error) {
	f.mu.Lock()
	f.hostCalls++
	f.mu.Unlock()
	if e, ok := f.errs[h]; ok {
		return nil, e
	}
	if ips, ok := f.hosts[h]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

func (f *fakeDNS) LookupMX(_ context.Context, h string) ([]*net.MX, error) {
	f.mu.Lock()
	f.mxCalls++
	f.mu.Unlock()
	if mx, ok := f.mx[h]; ok {
		return mx, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

func (f *fakeDNS) LookupNS(_ context.Context, h string) ([]*net.NS, error) {
	f.mu.Lock()
	f.nsCalls++
	f.mu.Unlock()
	if ns, ok := f.ns[h]; ok {
		return ns, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{
		hosts: map[string][]string{"ok.test": {"1.2.3.4"}},
		mx:    map[string][]*net.MX{"ok.test": {{Host: "mail.ok.test.", Pref: 10}}},
		ns:    map[string][]*net.NS{"nx.test": {{Host: "ns1.park.test."}}},
		errs: map[string]error{
			"slow.test": &net.DNSError{Err: "i/o timeout", Name: "slow.test", IsTimeout: true},
		},
	}
}

func TestCheckDNSSemantics(t *testing.T) {
	f := newFakeDNS()
	// empty.test：LookupHost 返回 (nil, nil) → "empty answer"，不计命中
	f.errs["empty.test"] = nil
	delete(f.hosts, "empty.test")
	cands := []Candidate{
		{Domain: "ok.test"}, {Domain: "nx.test"}, {Domain: "slow.test"}, {Domain: "empty.test"},
	}
	o := DNSOptions{QPS: 1000, Workers: 4, Timeout: time.Second, CheckMX: true, CheckNS: true, lookup: f}
	results, stats := CheckDNS(context.Background(), cands, o)

	byDomain := map[string]DNSResult{}
	for _, r := range results {
		byDomain[r.Domain] = r
	}
	ok := byDomain["ok.test"]
	if !ok.Resolved || !ok.HasMX || len(ok.MX) != 1 || ok.IPs[0] != "1.2.3.4" {
		t.Fatalf("ok.test 应解析+MX: %+v", ok)
	}
	nx := byDomain["nx.test"]
	if !nx.NXDomain || nx.Resolved || len(nx.NS) != 1 {
		t.Fatalf("nx.test 应 NXDOMAIN+NS: %+v", nx)
	}
	slow := byDomain["slow.test"]
	if slow.Resolved || slow.NXDomain || slow.Err != "timeout" {
		t.Fatalf("超时不计命中且应标记 timeout: %+v", slow)
	}
	empty := byDomain["empty.test"]
	if empty.Resolved || empty.NXDomain || empty.Err == "" {
		t.Fatalf("空应答应计失败: %+v", empty)
	}
	if stats.Resolved != 1 || stats.NXDomain != 1 || stats.Errors != 2 {
		t.Fatalf("统计错误: %+v", stats)
	}
	if stats.Queries != 6 { // host×4 + mx×1 + ns×1
		t.Fatalf("查询数应 6, got %d", stats.Queries)
	}
	if f.mxCalls != 1 {
		t.Fatalf("MX 只应对已解析域查 1 次, got %d", f.mxCalls)
	}
}

func TestCheckDNSNullMX(t *testing.T) {
	f := newFakeDNS()
	f.hosts["nullmx.test"] = []string{"5.6.7.8"}
	f.mx["nullmx.test"] = []*net.MX{{Host: ".", Pref: 0}} // RFC 7505 null MX
	f.hosts["mixedmx.test"] = []string{"5.6.7.9"}
	f.mx["mixedmx.test"] = []*net.MX{{Host: ".", Pref: 0}, {Host: "real.mixedmx.test.", Pref: 10}}
	o := DNSOptions{QPS: 1000, Workers: 2, CheckMX: true, lookup: f}
	results, _ := CheckDNS(context.Background(), []Candidate{{Domain: "nullmx.test"}, {Domain: "mixedmx.test"}}, o)
	byDomain := map[string]DNSResult{}
	for _, r := range results {
		byDomain[r.Domain] = r
	}
	if n := byDomain["nullmx.test"]; !n.Resolved || n.HasMX || len(n.MX) != 0 {
		t.Fatalf("null MX 不应计 HasMX: %+v", n)
	}
	if m := byDomain["mixedmx.test"]; !m.HasMX || len(m.MX) != 1 || m.MX[0] != "real.mixedmx.test." {
		t.Fatalf("混合 MX 应只留真实主机: %+v", m)
	}
}

func TestCheckDNSCache(t *testing.T) {
	dir := t.TempDir()
	f := newFakeDNS()
	cands := []Candidate{{Domain: "ok.test"}, {Domain: "nx.test"}, {Domain: "slow.test"}}
	o := DNSOptions{QPS: 1000, Workers: 2, CheckMX: true, CacheDir: dir, lookup: f}
	_, s1 := CheckDNS(context.Background(), cands, o)
	if s1.CachedHits != 0 {
		t.Fatalf("首轮不应有缓存命中: %+v", s1)
	}
	f2 := newFakeDNS()
	o.lookup = f2
	results, s2 := CheckDNS(context.Background(), cands, o)
	if s2.CachedHits != 2 { // ok + nx 命中；slow（错误）不缓存
		t.Fatalf("次轮应缓存命中 2: %+v", s2)
	}
	if s2.Queries != 1 { // 只重查 slow 的 host
		t.Fatalf("次轮应只查 1 次, got %d", s2.Queries)
	}
	for _, r := range results {
		if r.Domain == "ok.test" && !r.Cached {
			t.Fatal("ok.test 应标记 Cached")
		}
	}
}

func TestCheckDNSEmptyAndCancel(t *testing.T) {
	r, s := CheckDNS(context.Background(), nil, DNSOptions{})
	if len(r) != 0 || s.Candidates != 0 {
		t.Fatal("空输入应零开销")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFakeDNS()
	_, s2 := CheckDNS(ctx, []Candidate{{Domain: "ok.test"}}, DNSOptions{lookup: f, QPS: 1000})
	if s2.Resolved != 0 {
		t.Fatal("取消的 ctx 不应产生命中")
	}
}

// ---- 本地 UDP DNS stub：验证「指定 resolver」的真实网络路径 ----

func encodeDNSName(name string) []byte {
	var b []byte
	for _, lab := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b = append(b, byte(len(lab)))
		b = append(b, lab...)
	}
	return append(b, 0)
}

func buildDNSAnswer(qtype uint16, rdata []byte) []byte {
	a := []byte{0xC0, 0x0C} // 名字指针 → question
	a = append(a, byte(qtype>>8), byte(qtype))
	a = append(a, 0, 1)       // class IN
	a = append(a, 0, 0, 0, 60) // TTL
	a = append(a, byte(len(rdata)>>8), byte(len(rdata)))
	return append(a, rdata...)
}

// buildDNSResponse 手工构造 DNS 应答（A/MX/NS/NXDOMAIN；slow 域丢包模拟超时）。
func buildDNSResponse(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	pos := 12
	var labels []string
	for pos < len(q) {
		l := int(q[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 != 0 || pos+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[pos+1:pos+1+l]))
		pos += 1 + l
	}
	if pos+4 > len(q) {
		return nil
	}
	qtype := uint16(q[pos])<<8 | uint16(q[pos+1])
	name := strings.Join(labels, ".")
	if strings.Contains(name, "slow") {
		return nil // 丢包 → 客户端超时
	}
	nx := strings.Contains(name, "nx")
	flags := uint16(0x8180)
	if nx {
		flags = 0x8183
	}
	var answer []byte
	ancount := uint16(0)
	if !nx {
		switch qtype {
		case 1: // A
			ancount = 1
			answer = buildDNSAnswer(1, []byte{1, 2, 3, 4})
		case 15: // MX
			ancount = 1
			rdata := append([]byte{0, 10}, encodeDNSName("mail."+name)...)
			answer = buildDNSAnswer(15, rdata)
		case 2: // NS
			ancount = 1
			answer = buildDNSAnswer(2, encodeDNSName("ns1."+name))
		}
	}
	resp := make([]byte, 12)
	copy(resp[0:2], q[0:2])
	resp[2], resp[3] = byte(flags>>8), byte(flags)
	resp[5] = 1 // QDCOUNT
	resp[6], resp[7] = byte(ancount>>8), byte(ancount)
	resp = append(resp, q[12:pos+4]...)
	resp = append(resp, answer...)
	return resp
}

func startUDPStub(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := buildDNSResponse(buf[:n]); resp != nil {
				_, _ = pc.WriteTo(resp, raddr)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func TestCheckDNSCustomResolverUDP(t *testing.T) {
	addr := startUDPStub(t)
	cands := []Candidate{{Domain: "ok.test"}, {Domain: "nx.test"}, {Domain: "slow.test"}}
	o := DNSOptions{
		QPS: 1000, Workers: 3, Timeout: 800 * time.Millisecond,
		Resolver: addr, CheckMX: true,
	}
	results, stats := CheckDNS(context.Background(), cands, o)
	byDomain := map[string]DNSResult{}
	for _, r := range results {
		byDomain[r.Domain] = r
	}
	ok := byDomain["ok.test"]
	if !ok.Resolved || len(ok.IPs) == 0 || ok.IPs[0] != "1.2.3.4" {
		t.Fatalf("指定 resolver 应解析 ok.test → 1.2.3.4: %+v", ok)
	}
	if !ok.HasMX || len(ok.MX) == 0 || strings.TrimSuffix(ok.MX[0], ".") != "mail.ok.test" {
		t.Fatalf("MX 应经指定 resolver 查到: %+v", ok)
	}
	if nx := byDomain["nx.test"]; !nx.NXDomain {
		t.Fatalf("nx.test 应 NXDOMAIN: %+v", nx)
	}
	if slow := byDomain["slow.test"]; slow.Resolved || slow.NXDomain || slow.Err == "" {
		t.Fatalf("slow.test 应超时失败: %+v", slow)
	}
	if stats.Queries == 0 {
		t.Fatal("应产生真实查询")
	}
}

func TestNewResolverAddrNormalize(t *testing.T) {
	r := newResolver(DNSOptions{Resolver: "223.5.5.5", Timeout: time.Second})
	if r == net.DefaultResolver {
		t.Fatal("指定 resolver 不应回落系统")
	}
	if newResolver(DNSOptions{}) != net.DefaultResolver {
		t.Fatal("空 resolver 应用系统默认")
	}
}