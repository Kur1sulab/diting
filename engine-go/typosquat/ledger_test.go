package typosquat

// ledger_test.go —— 增量 diff（只返回新增/变化）、白名单排除、台账原子读写。

import (
	"path/filepath"
	"testing"
	"time"
)

func mkLedger(entries map[string][]string) *Ledger {
	l := NewLedger("example.com")
	now := time.Now()
	for d, fz := range entries {
		l.Entries[d] = &Entry{Domain: d, Fuzzers: fz, FirstSeen: now, LastSeen: now, LastChecked: now, Resolved: true}
	}
	return l
}

func TestDiffOnlyNewAndChanged(t *testing.T) {
	led := mkLedger(map[string][]string{
		"a.com": {FuzzReplacement},
		"b.com": {FuzzOmission},
	})
	cands := []Candidate{
		{Domain: "b.com", Fuzzers: []string{FuzzOmission}},                    // 未变化 → 跳过
		{Domain: "c.com", Fuzzers: []string{FuzzInsertion}},                   // 新增 → 重查
		{Domain: "a.com", Fuzzers: []string{FuzzInsertion, FuzzReplacement}},  // 来源变化 → 重查
	}
	toQuery, skipped := Diff(led, cands, 0, time.Now())
	if skipped != 1 {
		t.Fatalf("应跳过 1 项, got %d", skipped)
	}
	got := map[string]bool{}
	for _, c := range toQuery {
		got[c.Domain] = true
	}
	if len(toQuery) != 2 || !got["c.com"] || !got["a.com"] {
		t.Fatalf("diff 应只返回新增 c.com 与变化 a.com, got %v", got)
	}
	// 来源集合相同但顺序不同 → 不算变化
	led2 := mkLedger(map[string][]string{"x.com": {FuzzOmission, FuzzReplacement}})
	tq, sk := Diff(led2, []Candidate{{Domain: "x.com", Fuzzers: []string{FuzzReplacement, FuzzOmission}}}, 0, time.Now())
	if len(tq) != 0 || sk != 1 {
		t.Fatal("集合相等（乱序）不应触发重查")
	}
}

func TestDiffRecheckTTL(t *testing.T) {
	led := NewLedger("example.com")
	old := time.Now().AddDate(0, 0, -10)
	led.Entries["nx.com"] = &Entry{Domain: "nx.com", Fuzzers: []string{FuzzOmission}, LastChecked: old, Resolved: false}
	cands := []Candidate{{Domain: "nx.com", Fuzzers: []string{FuzzOmission}}}
	// TTL=0：严格只查新增/变化 → 跳过
	if tq, _ := Diff(led, cands, 0, time.Now()); len(tq) != 0 {
		t.Fatal("TTL=0 时未注册旧项不应重查")
	}
	// TTL=7d：超过 10 天未注册 → 重查（监控是否被抢注）
	if tq, _ := Diff(led, cands, 7*24*time.Hour, time.Now()); len(tq) != 1 {
		t.Fatal("超过 recheckTTL 的未注册项应重查")
	}
	// 已注册项不受 TTL 影响
	led.Entries["nx.com"].Resolved = true
	if tq, _ := Diff(led, cands, 7*24*time.Hour, time.Now()); len(tq) != 0 {
		t.Fatal("已注册项不应因 TTL 重查")
	}
}

func TestWhitelistMatch(t *testing.T) {
	w := Whitelist{
		Domains:    []string{"example.com", "brand.cn"},
		Subdomains: []string{"*.defensive.example.org"},
		Keywords:   []string{"appletree"},
	}
	yes := []string{"example.com", "sub.example.com", "a.b.example.com", "brand.cn", "x.defensive.example.org", "myappletree.com"}
	for _, d := range yes {
		if ok, _ := w.Match(d); !ok {
			t.Fatalf("白名单应命中 %s", d)
		}
	}
	no := []string{"badexample.com", "example.com.evil.net", "defensive.example.org", "example.org", "apple.com"}
	for _, d := range no {
		if ok, rule := w.Match(d); ok {
			t.Fatalf("白名单不应命中 %s (rule=%s)", d, rule)
		}
	}
	// 大小写不敏感
	if ok, _ := w.Match("EXAMPLE.COM"); !ok {
		t.Fatal("白名单应大小写不敏感")
	}
}

func TestFilterWhitelistSavesQuota(t *testing.T) {
	cands := Generate("example.com", GenerateOptions{})
	w := Whitelist{Domains: []string{"example.net", "example.org"}, Keywords: []string{"examplevip"}}
	kept, excluded := FilterWhitelist(cands, w)
	if len(kept)+len(excluded) != len(cands) {
		t.Fatal("过滤不应丢候选")
	}
	if len(excluded) < 3 {
		t.Fatalf("应至少排除 3 项, got %d", len(excluded))
	}
	for _, c := range kept {
		if ok, _ := w.Match(c.Domain); ok {
			t.Fatalf("kept 中混入白名单域 %s", c.Domain)
		}
	}
}

func TestLedgerRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.json")
	led := mkLedger(map[string][]string{"a.com": {FuzzReplacement}})
	led.Entries["a.com"].Score = 68
	led.Entries["a.com"].Level = "high"
	led.Entries["a.com"].HasMX = true
	if err := led.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadLedger(path, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	e := got.Entries["a.com"]
	if e == nil || e.Score != 68 || e.Level != "high" || !e.HasMX || len(e.Fuzzers) != 1 {
		t.Fatalf("台账往返丢失字段: %+v", e)
	}
	if got.Version != LedgerVersion {
		t.Fatalf("版本应 %d, got %d", LedgerVersion, got.Version)
	}
	// 不存在的文件 → 空台账（首轮）
	empty, err := LoadLedger(filepath.Join(dir, "none.json"), "b")
	if err != nil || len(empty.Entries) != 0 {
		t.Fatalf("缺失文件应返回空台账: %v %d", err, len(empty.Entries))
	}
}

func TestSortedEntries(t *testing.T) {
	led := mkLedger(map[string][]string{"a.com": {FuzzOmission}, "b.com": {FuzzOmission}, "c.com": {FuzzOmission}})
	led.Entries["a.com"].Score = 10
	led.Entries["b.com"].Score = 90
	led.Entries["c.com"].Score = 50
	sorted := led.SortedEntries()
	if sorted[0].Domain != "b.com" || sorted[1].Domain != "c.com" || sorted[2].Domain != "a.com" {
		t.Fatal("应按分数降序")
	}
}