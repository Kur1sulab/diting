package typosquat

// ledger.go —— 增量台账（JSON）+ 白名单 + 增量 diff。
// 台账记录每个候选的来源 fuzzer、判活状态、RDAP 富化、评分与时间戳；
// 下一轮只对「新增 / 来源变化 /（可选）过期未注册」项重查，其余跳过。
// 白名单排除品牌方防御性注册与无关同名词，在 DNS 之前过滤以省配额。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LedgerVersion 台账格式版本。
const LedgerVersion = 1

// Entry 台账条目。
type Entry struct {
	Domain      string    `json:"domain"`
	Fuzzers     []string  `json:"fuzzers"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	LastChecked time.Time `json:"last_checked"`
	Resolved    bool      `json:"resolved"`
	NXDomain    bool      `json:"nx_domain"`
	IPs         []string  `json:"ips,omitempty"`
	MX          []string  `json:"mx,omitempty"`
	HasMX       bool      `json:"has_mx"`
	RDAP        *RDAPInfo `json:"rdap,omitempty"`
	Ownership   Ownership `json:"ownership"`
	Score       int       `json:"score"`
	Level       string    `json:"level"`
	Whitelisted bool      `json:"whitelisted,omitempty"`
}

// Ledger 一个品牌一份台账。
type Ledger struct {
	Version   int               `json:"version"`
	Brand     string            `json:"brand"`
	UpdatedAt time.Time         `json:"updated_at"`
	Entries   map[string]*Entry `json:"entries"`
}

// NewLedger 空台账。
func NewLedger(brand string) *Ledger {
	return &Ledger{Version: LedgerVersion, Brand: brand, Entries: map[string]*Entry{}}
}

// LoadLedger 读台账；文件不存在返回空台账（首轮）。
func LoadLedger(path, brand string) (*Ledger, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NewLedger(brand), nil
	}
	if err != nil {
		return nil, err
	}
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	if l.Entries == nil {
		l.Entries = map[string]*Entry{}
	}
	if l.Version == 0 {
		l.Version = LedgerVersion
	}
	return &l, nil
}

// Save 原子写台账（temp + rename）。
func (l *Ledger) Save(path string) error {
	l.UpdatedAt = time.Now()
	l.Version = LedgerVersion
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(path, b)
}

// atomicWrite 同目录临时文件 + rename，避免半截 JSON。
func atomicWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// sameStringSet 集合相等（忽略顺序）。
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}

// Diff 增量 diff：返回需要重查的候选（新增 / fuzzer 来源变化 /
// recheckTTL>0 时超过 TTL 仍未注册的监控项），以及跳过数。
// recheckTTL=0 表示严格「只查新增/变化」。
func Diff(led *Ledger, cands []Candidate, recheckTTL time.Duration, now time.Time) (toQuery []Candidate, skipped int) {
	if now.IsZero() {
		now = time.Now()
	}
	for _, c := range cands {
		e, ok := led.Entries[c.Domain]
		if !ok {
			toQuery = append(toQuery, c) // 新增
			continue
		}
		if !sameStringSet(e.Fuzzers, c.Fuzzers) {
			toQuery = append(toQuery, c) // 来源变化
			continue
		}
		// 判活失败（超时/连不上）不是结论：Resolved=false 且 NXDomain=false
		// 意味着上一轮根本没拿到答案。这类条目必须下一轮无条件重查——
		// 否则一次 DNS 抖动就能把该域永久钉成「未知」，而台账此后
		// 一直显示「未变化」，漏报就此固化（实测：弱网下 145 个候选里
		// 110 个超时，若不重查等于白跑一轮）。
		if !e.Resolved && !e.NXDomain && !e.LastChecked.IsZero() {
			toQuery = append(toQuery, c)
			continue
		}
		if recheckTTL > 0 && !e.Resolved && now.Sub(e.LastChecked) > recheckTTL {
			toQuery = append(toQuery, c) // 未注册≠安全：到期重查是否被抢注
			continue
		}
		skipped++
	}
	return toQuery, skipped
}

// Whitelist 白名单规则（全部大小写不敏感）：
//   - Domains：精确域；写 "example.com" 同时覆盖其全部子域（防御性注册）
//   - Subdomains：写 "*.example.com" 只覆盖子域、不含裸域
//   - Keywords：域名含该子串即排除（无关同名词，如品牌 "apple" 与 "appletree"）
type Whitelist struct {
	Domains    []string `json:"domains,omitempty"`
	Subdomains []string `json:"subdomains,omitempty"`
	Keywords   []string `json:"keywords,omitempty"`
}

// Match 判断域名是否命中白名单，返回命中的规则描述。
func (w Whitelist) Match(domain string) (bool, string) {
	d := strings.ToLower(strings.TrimSpace(domain))
	for _, rule := range w.Domains {
		r := strings.ToLower(strings.TrimSpace(rule))
		r = strings.TrimPrefix(r, "*.")
		if r == "" {
			continue
		}
		if d == r || strings.HasSuffix(d, "."+r) {
			return true, "domain:" + rule
		}
	}
	for _, rule := range w.Subdomains {
		r := strings.ToLower(strings.TrimSpace(rule))
		r = strings.TrimPrefix(r, "*.")
		if r == "" {
			continue
		}
		if strings.HasSuffix(d, "."+r) {
			return true, "subdomain:" + rule
		}
	}
	for _, kw := range w.Keywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k != "" && strings.Contains(d, k) {
			return true, "keyword:" + kw
		}
	}
	return false, ""
}

// FilterWhitelist 在候选阶段过滤白名单（省 DNS 配额）。
func FilterWhitelist(cands []Candidate, w Whitelist) (kept, excluded []Candidate) {
	for _, c := range cands {
		if ok, _ := w.Match(c.Domain); ok {
			excluded = append(excluded, c)
		} else {
			kept = append(kept, c)
		}
	}
	return kept, excluded
}

// SortedEntries 台账条目按分数降序（同分按域名），报告/导出用。
func (l *Ledger) SortedEntries() []*Entry {
	out := make([]*Entry, 0, len(l.Entries))
	for _, e := range l.Entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}