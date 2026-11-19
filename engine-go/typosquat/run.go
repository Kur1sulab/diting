package typosquat

// run.go —— 编排：一轮「DNS-only」汇洞监控管线（不接 CLI 主流程，供调用方/测试用）。
//
//	生成候选 → 白名单过滤 → 增量 diff → 限速 DNS 判活 → 评分 → 更新台账
//
// RDAP 富化是独立可选步骤（EnrichRDAP），只对已注册且分数达标的子集跑，
// 默认不在 DNS-only 轮里触发（配额保守）。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RunOptions 一轮监控的配置。
type RunOptions struct {
	Brand      string          // 品牌种子（域名或裸词，可中文）
	StateDir   string          // 台账/缓存目录（必填）
	Whitelist  Whitelist       // 白名单
	Generate   GenerateOptions // 候选生成
	DNS        DNSOptions      // 判活
	RecheckTTL time.Duration   // >0 时对超过 TTL 仍未注册的项重查（监控抢注）
}

// RunReport 一轮监控的真实数字（可直接 JSON 导出）。
type RunReport struct {
	Brand       string        `json:"brand"`
	Generated   int           `json:"generated"`    // 生成候选总数
	Whitelisted int           `json:"whitelisted"`  // 白名单排除数
	ToQuery     int           `json:"to_query"`     // 本轮实际判活数（增量）
	Skipped     int           `json:"skipped"`      // 台账未变化跳过数
	Stats       DNSStats      `json:"dns_stats"`    // DNS 配额消耗
	Elapsed     time.Duration `json:"elapsed_ns"`   // 全轮耗时
	LedgerPath  string        `json:"ledger_path"`  //
	Top         []*Entry      `json:"top"`          // 分数最高的前 N 条
	NewDomains  []string      `json:"new_domains"`  // 本轮新增域
	Resolved    []string      `json:"resolved"`     // 本轮解析成功域
	StartedAt   time.Time     `json:"started_at"`   //
}

// RunDNS 跑一轮 DNS-only 监控并落台账。
func RunDNS(ctx context.Context, o RunOptions) (*RunReport, error) {
	start := time.Now()
	if o.StateDir == "" {
		o.StateDir = "."
	}
	if err := os.MkdirAll(o.StateDir, 0o755); err != nil {
		return nil, err
	}
	ledgerPath := filepath.Join(o.StateDir, "ledger.json")
	led, err := LoadLedger(ledgerPath, o.Brand)
	if err != nil {
		return nil, err
	}

	cands := Generate(o.Brand, o.Generate)
	kept, excluded := FilterWhitelist(cands, o.Whitelist)
	for _, c := range excluded {
		led.Entries[c.Domain] = &Entry{
			Domain: c.Domain, Fuzzers: c.Fuzzers, Whitelisted: true,
			FirstSeen: time.Now(), LastSeen: time.Now(), Ownership: OwnershipBrand,
			Score: 0, Level: "low",
		}
	}

	toQuery, skipped := Diff(led, kept, o.RecheckTTL, time.Now())
	newDomains := make([]string, 0, len(toQuery))
	for _, c := range toQuery {
		if _, ok := led.Entries[c.Domain]; !ok {
			newDomains = append(newDomains, c.Domain)
		}
	}

	o.DNS.CacheDir = o.StateDir
	results, stats := CheckDNS(ctx, toQuery, o.DNS)

	now := time.Now()
	var resolved []string
	for i, r := range results {
		c := toQuery[i]
		e, ok := led.Entries[c.Domain]
		if !ok {
			e = &Entry{Domain: c.Domain, FirstSeen: now, Ownership: OwnershipUnknown}
			led.Entries[c.Domain] = e
		}
		e.Fuzzers = c.Fuzzers
		e.LastSeen = now
		e.LastChecked = r.CheckedAt
		e.Resolved = r.Resolved
		e.NXDomain = r.NXDomain
		e.IPs = r.IPs
		e.MX = r.MX
		e.HasMX = r.HasMX
		if r.Resolved {
			resolved = append(resolved, r.Domain)
		}
		// 评分：域龄用台账已有 RDAP（若有），否则未知；归属沿用已有判定。
		in := ScoreInput{HasMX: e.HasMX, Ownership: e.Ownership, Fuzzers: e.Fuzzers, Now: now}
		if e.RDAP != nil {
			in.RegisteredAt = e.RDAP.RegisteredAt
		}
		sc := Score(in)
		e.Score = sc.Score
		e.Level = sc.Level
	}

	if err := led.Save(ledgerPath); err != nil {
		return nil, err
	}

	rep := &RunReport{
		Brand: o.Brand, Generated: len(cands), Whitelisted: len(excluded),
		ToQuery: len(toQuery), Skipped: skipped, Stats: stats,
		Elapsed: time.Since(start), LedgerPath: ledgerPath,
		NewDomains: newDomains, Resolved: resolved, StartedAt: start,
	}
	sorted := led.SortedEntries()
	for _, e := range sorted {
		if e.Whitelisted {
			continue
		}
		rep.Top = append(rep.Top, e)
		if len(rep.Top) >= 10 {
			break
		}
	}
	// 报告落盘（审计/导出）。
	if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = atomicWrite(filepath.Join(o.StateDir, "last-report.json"), b)
	}
	return rep, nil
}

// EnrichRDAP 可选富化：只对「已注册 + 分数 ≥ minScore」的条目查 RDAP，
// 最多 limit 条（0=不限），全程限速。查完重算分数并保存台账。
// 归属判定保守：RDAP 注册商/注册人信息只作展示，不自动改 Ownership
//（品牌方归属应由白名单/人工确认，避免误判）。
func EnrichRDAP(ctx context.Context, led *Ledger, client *RDAPClient, minScore, limit int, ledgerPath string) (enriched int, err error) {
	for _, e := range led.SortedEntries() {
		if !e.Resolved || e.Whitelisted || e.Score < minScore {
			continue
		}
		if e.RDAP != nil && !e.RDAP.RegisteredAt.IsZero() {
			continue // 已有注册日期，跳过
		}
		if limit > 0 && enriched >= limit {
			break
		}
		info := client.Lookup(ctx, e.Domain)
		e.RDAP = &info
		in := ScoreInput{
			RegisteredAt: info.RegisteredAt, HasMX: e.HasMX,
			Ownership: e.Ownership, Fuzzers: e.Fuzzers,
		}
		sc := Score(in)
		e.Score = sc.Score
		e.Level = sc.Level
		enriched++
	}
	if ledgerPath != "" {
		if err := led.Save(ledgerPath); err != nil {
			return enriched, err
		}
	}
	return enriched, nil
}