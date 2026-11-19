package typosquat

// rdap.go —— RDAP（RFC 9082/9083）域名注册信息查询：
// IANA bootstrap（TLD→端点）+ GET {base}domain/{domain}，归一化出
// 注册日期/注册商/到期日。本地 JSON 缓存（域名 7 天、bootstrap 30 天）
// + 429/5xx 指数退避（尊重 Retry-After）+ 全局 QPS 限速（默认 1）。
// 只对「已注册 + 高分」子集调用，不做批量抓取。只用标准库。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RDAPInfo 归一化后的注册信息（缺失留零值，Error 记录失败原因）。
type RDAPInfo struct {
	Domain       string    `json:"domain"`
	Provider     string    `json:"provider,omitempty"`
	Registrar    string    `json:"registrar,omitempty"`
	Registrant   string    `json:"registrant,omitempty"`
	RegisteredAt time.Time `json:"registered_at,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
	Status       []string  `json:"status,omitempty"`
	Nameservers  []string  `json:"nameservers,omitempty"`
	NotFound     bool      `json:"not_found,omitempty"` // 404：RDAP 明确无此域
	Error        string    `json:"error,omitempty"`
	Cached       bool      `json:"cached,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// RDAPClient 带缓存与退避的 RDAP 客户端。并发安全。
type RDAPClient struct {
	Opts RDAPOptions
	HTTP *http.Client // 可注入（测试打 httptest）；nil 用默认

	lim       *limiter
	mu        sync.Mutex
	bootstrap map[string]string // tld → base url
	bootAt    time.Time
	cache     map[string]rdapCacheEntry
	cachePath string
	bootPath  string
	cacheOnce sync.Once
}

type rdapCacheEntry struct {
	Info      RDAPInfo  `json:"info"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewRDAPClient 构造客户端并加载本地缓存。
func NewRDAPClient(o RDAPOptions) *RDAPClient {
	o = o.withDefaults()
	c := &RDAPClient{Opts: o, lim: newLimiter(o.QPS), cache: map[string]rdapCacheEntry{}}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: o.Timeout}
	}
	if o.CacheDir != "" {
		c.cachePath = filepath.Join(o.CacheDir, "rdap-cache.json")
		c.bootPath = filepath.Join(o.CacheDir, "rdap-bootstrap.json")
	}
	return c
}

func (c *RDAPClient) loadCaches() {
	c.cacheOnce.Do(func() {
		if c.cachePath != "" {
			if b, err := os.ReadFile(c.cachePath); err == nil {
				_ = json.Unmarshal(b, &c.cache)
			}
		}
		if c.bootPath != "" {
			var disk struct {
				Services  map[string]string `json:"services"`
				FetchedAt time.Time         `json:"fetched_at"`
			}
			if b, err := os.ReadFile(c.bootPath); err == nil && json.Unmarshal(b, &disk) == nil {
				if time.Since(disk.FetchedAt) < 30*24*time.Hour && len(disk.Services) > 0 {
					c.bootstrap = disk.Services
					c.bootAt = disk.FetchedAt
				}
			}
		}
	})
}

func (c *RDAPClient) saveCaches() {
	if c.cachePath != "" {
		if b, err := json.MarshalIndent(c.cache, "", "  "); err == nil {
			_ = os.MkdirAll(filepath.Dir(c.cachePath), 0o755)
			_ = atomicWrite(c.cachePath, b)
		}
	}
	if c.bootPath != "" && len(c.bootstrap) > 0 {
		disk := struct {
			Services  map[string]string `json:"services"`
			FetchedAt time.Time         `json:"fetched_at"`
		}{c.bootstrap, c.bootAt}
		if b, err := json.MarshalIndent(disk, "", "  "); err == nil {
			_ = os.MkdirAll(filepath.Dir(c.bootPath), 0o755)
			_ = atomicWrite(c.bootPath, b)
		}
	}
}

// get 带退避的 GET：429/5xx 重试（Retry-After 优先，否则指数退避）。
func (c *RDAPClient) get(ctx context.Context, u string) (int, []byte, error) {
	var lastErr error
	for attempt := 0; attempt <= c.Opts.MaxRetries; attempt++ {
		if err := c.lim.wait(ctx); err != nil {
			return 0, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return 0, nil, ctx.Err()
			}
		} else {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return resp.StatusCode, body, nil
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
				return resp.StatusCode, body, lastErr // 404 等不重试
			}
			// 退避：Retry-After（秒）优先，否则 BaseBackoff × 2^attempt，封顶 30s。
			backoff := c.Opts.BaseBackoff * time.Duration(1<<attempt)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, e := strconv.Atoi(strings.TrimSpace(ra)); e == nil && secs >= 0 {
					backoff = time.Duration(secs) * time.Second
				}
			}
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			if attempt < c.Opts.MaxRetries {
				t := time.NewTimer(backoff)
				select {
				case <-ctx.Done():
					t.Stop()
					return 0, nil, ctx.Err()
				case <-t.C:
				}
			}
			continue
		}
		// 网络错误：同样退避后重试
		if attempt < c.Opts.MaxRetries {
			backoff := c.Opts.BaseBackoff * time.Duration(1<<attempt)
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			t := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				t.Stop()
				return 0, nil, ctx.Err()
			case <-t.C:
			}
		}
	}
	return 0, nil, lastErr
}

// loadBootstrap 取 TLD→RDAP 端点表（内存→磁盘→网络，30 天有效）。
func (c *RDAPClient) loadBootstrap(ctx context.Context) (map[string]string, error) {
	c.loadCaches()
	c.mu.Lock()
	if len(c.bootstrap) > 0 && time.Since(c.bootAt) < 30*24*time.Hour {
		m := c.bootstrap
		c.mu.Unlock()
		return m, nil
	}
	c.mu.Unlock()

	_, body, err := c.get(ctx, c.Opts.BootstrapURL)
	if err != nil {
		return nil, fmt.Errorf("RDAP bootstrap 获取失败: %w", err)
	}
	var data struct {
		Services [][][]string `json:"services"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("RDAP bootstrap 非 JSON: %w", err)
	}
	m := map[string]string{}
	for _, svc := range data.Services {
		if len(svc) < 2 || len(svc[1]) == 0 {
			continue
		}
		for _, tld := range svc[0] {
			m[strings.ToLower(tld)] = svc[1][0]
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("RDAP bootstrap 表为空")
	}
	c.mu.Lock()
	c.bootstrap = m
	c.bootAt = time.Now()
	c.mu.Unlock()
	c.saveCaches()
	return m, nil
}

// Lookup 查询域名注册信息（缓存命中零网络）。
func (c *RDAPClient) Lookup(ctx context.Context, domain string) RDAPInfo {
	domain = strings.ToLower(strings.TrimSpace(domain))
	info := RDAPInfo{Domain: domain, FetchedAt: time.Now()}
	c.loadCaches()

	c.mu.Lock()
	ce, ok := c.cache[domain]
	c.mu.Unlock()
	if ok && time.Now().Before(ce.ExpiresAt) && ce.Info.Error == "" {
		ce.Info.Cached = true
		return ce.Info
	}

	boot, err := c.loadBootstrap(ctx)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	tld := domain
	if i := strings.LastIndex(domain, "."); i >= 0 {
		tld = domain[i+1:]
	}
	base, ok := boot[strings.ToLower(tld)]
	if !ok {
		info.Error = "RDAP 无该 TLD 端点: " + tld
		return info
	}
	info.Provider = base
	u := strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(domain)
	code, body, err := c.get(ctx, u)
	if err != nil {
		if code == http.StatusNotFound {
			info.NotFound = true
		}
		info.Error = err.Error()
		return info
	}
	parsed, perr := parseRDAP(body)
	if perr != nil {
		info.Error = perr.Error()
		return info
	}
	parsed.Domain = domain
	parsed.Provider = base
	parsed.FetchedAt = time.Now()

	c.mu.Lock()
	c.cache[domain] = rdapCacheEntry{Info: *parsed, ExpiresAt: time.Now().Add(c.Opts.CacheTTL)}
	c.mu.Unlock()
	c.saveCaches()
	return *parsed
}

// parseRDAP 解析 RFC 9083 响应：events / entities(vcard fn) / status / nameservers。
func parseRDAP(body []byte) (*RDAPInfo, error) {
	var data struct {
		LDHName     string   `json:"ldhName"`
		Status      []string `json:"status"`
		Events      []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles      []string `json:"roles"`
			VcardArray []any    `json:"vcardArray"`
		} `json:"entities"`
		Nameservers []struct {
			LDHName string `json:"ldhName"`
		} `json:"nameservers"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("RDAP 响应非 JSON: %w", err)
	}
	info := &RDAPInfo{Status: data.Status}
	for _, ev := range data.Events {
		t, err := time.Parse(time.RFC3339, ev.EventDate)
		if err != nil {
			continue
		}
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			info.RegisteredAt = t
		case "expiration":
			info.ExpiresAt = t
		case "last changed", "last update of rdap database":
			info.UpdatedAt = t
		}
	}
	for _, ns := range data.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, ent := range data.Entities {
		fn := vcardFN(ent.VcardArray)
		if fn == "" {
			continue
		}
		for _, role := range ent.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				if info.Registrar == "" {
					info.Registrar = fn
				}
			case "registrant":
				if info.Registrant == "" {
					info.Registrant = fn
				}
			}
		}
	}
	return info, nil
}

// vcardFN 从 jCard ["vcard", [["fn",{},"text","Name"],...]] 取 fn。
func vcardFN(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		arr, ok := p.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		name, _ := arr[0].(string)
		if strings.EqualFold(name, "fn") {
			if s, ok := arr[3].(string); ok {
				return s
			}
		}
	}
	return ""
}