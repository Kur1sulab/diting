package typosquat

// dns.go —— 批量 DNS 判活：并发 worker + 全局令牌限速（可配 QPS），
// 支持指定 resolver；NXDOMAIN 与超时/失败严格区分，超时/失败不计入命中。
// 本地 JSON 缓存（TTL）避免跨轮重复查询。只用标准库。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// lookupAPI 抽象 DNS 查询面（*net.Resolver 天然满足；测试注入假实现）。
type lookupAPI interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
}

// DNSResult 单个候选的判活结果。
type DNSResult struct {
	Domain    string    `json:"domain"`
	Resolved  bool      `json:"resolved"`            // A/AAAA 解析成功
	IPs       []string  `json:"ips,omitempty"`       // 解析到的地址
	MX        []string  `json:"mx,omitempty"`        // MX 交换主机（可截收邮件的信号）
	HasMX     bool      `json:"has_mx"`              //
	NS        []string  `json:"ns,omitempty"`        // CheckNS 时的 NS 记录
	NXDomain  bool      `json:"nx_domain"`           // 明确不存在（可判未注册）
	Err       string    `json:"err,omitempty"`       // 超时/其它失败（不计入命中）
	Cached    bool      `json:"cached,omitempty"`    // 来自本地缓存
	CheckedAt time.Time `json:"checked_at"`          //
}

// DNSStats 一轮判活的真实配额消耗统计。
type DNSStats struct {
	Candidates int           `json:"candidates"`  // 进入判活的候选数
	Queries    int           `json:"queries"`     // 实际发出的 DNS 查询数（含 MX/NS）
	Resolved   int           `json:"resolved"`    // 解析成功
	NXDomain   int           `json:"nx_domain"`   // 明确不存在
	Errors     int           `json:"errors"`      // 超时/失败（不计入命中）
	CachedHits int           `json:"cached_hits"` // 本地缓存命中（零查询）
	Elapsed    time.Duration `json:"elapsed_ns"`
}

// limiter 全局速率限制器：按固定间隔发放时间槽（等价令牌桶，QPS 可配）。
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(qps float64) *limiter {
	if qps <= 0 {
		qps = 20
	}
	return &limiter{interval: time.Duration(float64(time.Second) / qps)}
}

// wait 阻塞到下一个时间槽；ctx 取消立即返回。
func (l *limiter) wait(ctx context.Context) error {
	l.mu.Lock()
	now := time.Now()
	if l.next.Before(now) {
		l.next = now
	}
	slot := l.next
	l.next = slot.Add(l.interval)
	l.mu.Unlock()
	d := time.Until(slot)
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// newResolver 构造 resolver：指定地址时强制 Go 解析器走该 UDP DNS 服务器。
func newResolver(o DNSOptions) *net.Resolver {
	addr := strings.TrimSpace(o.Resolver)
	if addr == "" {
		return net.DefaultResolver
	}
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: o.Timeout}
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// dnsCacheEntry 本地缓存条目（带过期时间）。
type dnsCacheEntry struct {
	Result    DNSResult `json:"result"`
	ExpiresAt time.Time `json:"expires_at"`
}

func dnsCachePath(dir string, o DNSOptions) string {
	name := fmt.Sprintf("dns-cache-%t-%t.json", o.CheckMX, o.CheckNS)
	return filepath.Join(dir, name)
}

func loadDNSCache(path string) map[string]dnsCacheEntry {
	m := map[string]dnsCacheEntry{}
	if path == "" {
		return m
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return m
	}
	_ = json.Unmarshal(b, &m)
	return m
}

func saveDNSCache(path string, m map[string]dnsCacheEntry) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

// CheckDNS 并发限速判活。返回结果与输入候选一一对应（同序）。
// 语义：LookupHost 成功 → Resolved；NXDOMAIN → NXDomain（未注册）；
// 超时/其它错误 → Err（不计入命中，下轮可重试）。MX 只对已解析域查（省配额）。
func CheckDNS(ctx context.Context, cands []Candidate, o DNSOptions) ([]DNSResult, DNSStats) {
	o = o.withDefaults()
	start := time.Now()
	stats := DNSStats{Candidates: len(cands)}
	results := make([]DNSResult, len(cands))
	if len(cands) == 0 {
		stats.Elapsed = time.Since(start)
		return results, stats
	}

	var api lookupAPI = o.lookup
	if api == nil {
		api = newResolver(o)
	}
	lim := newLimiter(o.QPS)

	cachePath := ""
	if o.CacheDir != "" {
		cachePath = dnsCachePath(o.CacheDir, o)
	}
	cache := loadDNSCache(cachePath)
	var cacheMu sync.Mutex
	var queries int64

	// query 包装：每次真实查询先过限速器并计数。
	query := func(fn func(context.Context) error) error {
		if err := lim.wait(ctx); err != nil {
			return err
		}
		atomic.AddInt64(&queries, 1)
		qctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		return fn(qctx)
	}

	checkOne := func(c Candidate) DNSResult {
		r := DNSResult{Domain: c.Domain, CheckedAt: time.Now()}
		cacheMu.Lock()
		ce, ok := cache[c.Domain]
		cacheMu.Unlock()
		if ok && time.Now().Before(ce.ExpiresAt) && ce.Result.Err == "" {
			r = ce.Result
			r.Cached = true
			return r
		}

		var ips []string
		err := query(func(qctx context.Context) error {
			var e error
			ips, e = api.LookupHost(qctx, c.Domain)
			return e
		})
		switch {
		case err == nil && len(ips) > 0:
			r.Resolved = true
			r.IPs = ips
		case err != nil:
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				r.NXDomain = true
				if o.CheckNS {
					var nss []*net.NS
					e2 := query(func(qctx context.Context) error {
						var e error
						nss, e = api.LookupNS(qctx, c.Domain)
						return e
					})
					if e2 == nil {
						for _, ns := range nss {
							r.NS = append(r.NS, ns.Host)
						}
					}
				}
			} else if ctx.Err() != nil {
				r.Err = "cancelled"
			} else {
				var de2 *net.DNSError
				if errors.As(err, &de2) && de2.IsTimeout {
					r.Err = "timeout"
				} else {
					r.Err = err.Error()
				}
			}
		default:
			r.Err = "empty answer"
		}

		if r.Resolved && o.CheckMX {
			var mxs []*net.MX
			e := query(func(qctx context.Context) error {
				var e error
				mxs, e = api.LookupMX(qctx, c.Domain)
				return e
			})
			if e == nil {
				for _, mx := range mxs {
					if strings.TrimSuffix(mx.Host, ".") == "" {
						continue // null MX（RFC 7505）：声明不收邮件，不算截收能力
					}
					r.MX = append(r.MX, mx.Host)
				}
				r.HasMX = len(r.MX) > 0
			}
			// MX 查询失败不影响 A 记录命中判定，只记录。
			if e != nil && ctx.Err() == nil {
				r.Err = "mx: " + e.Error()
			}
		}

		if r.Err == "" {
			cacheMu.Lock()
			cache[c.Domain] = dnsCacheEntry{Result: r, ExpiresAt: time.Now().Add(o.CacheTTL)}
			cacheMu.Unlock()
		}
		return r
	}

	var wg sync.WaitGroup
	ch := make(chan int)
	for w := 0; w < o.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range ch {
				results[i] = checkOne(cands[i])
			}
		}()
	}
	for i := range cands {
		select {
		case ch <- i:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()

	for _, r := range results {
		switch {
		case r.Cached:
			stats.CachedHits++
		case r.Resolved:
			stats.Resolved++
		case r.NXDomain:
			stats.NXDomain++
		case r.Err != "":
			stats.Errors++
		}
	}
	stats.Queries = int(atomic.LoadInt64(&queries))
	stats.Elapsed = time.Since(start)
	_ = saveDNSCache(cachePath, cache)
	return results, stats
}