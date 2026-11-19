package typosquat

// run_test.go —— 离线全管线：生成 → 白名单 → diff → 判活 → 评分 → 台账，
// 以及第二轮增量（ToQuery=0）。全部走假 resolver，零外网。

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pipelineFake() *fakeDNS {
	f := newFakeDNS()
	f.hosts["examp1e.com"] = []string{"93.184.216.34"}
	f.mx["examp1e.com"] = []*net.MX{{Host: "mxa.examp1e.com.", Pref: 10}}
	return f
}

func TestRunDNSPipelineOffline(t *testing.T) {
	dir := t.TempDir()
	o := RunOptions{
		Brand:    "example.com",
		StateDir: dir,
		DNS:      DNSOptions{QPS: 1000, Workers: 8, CheckMX: true, lookup: pipelineFake()},
	}
	rep, err := RunDNS(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Generated < 100 {
		t.Fatalf("候选量异常: %d", rep.Generated)
	}
	if rep.ToQuery != rep.Generated-rep.Whitelisted {
		t.Fatalf("首轮应全量判活: toQuery=%d generated=%d wl=%d", rep.ToQuery, rep.Generated, rep.Whitelisted)
	}
	if rep.Stats.Resolved != 1 {
		t.Fatalf("应只有 examp1e.com 解析成功: %+v", rep.Stats)
	}
	if len(rep.Resolved) != 1 || rep.Resolved[0] != "examp1e.com" {
		t.Fatalf("解析清单错误: %v", rep.Resolved)
	}
	if rep.Top[0].Domain != "examp1e.com" {
		t.Fatalf("最高分应 examp1e.com: %+v", rep.Top[0])
	}
	// DNS-only：未知域龄15 + MX30 + 未知归属18 + 相似5 = 68 high
	if rep.Top[0].Score != 68 || rep.Top[0].Level != "high" || !rep.Top[0].HasMX {
		t.Fatalf("评分错误: %+v", rep.Top[0])
	}
	// 台账与报告落盘
	if _, err := os.Stat(filepath.Join(dir, "ledger.json")); err != nil {
		t.Fatal("台账未落盘")
	}
	if _, err := os.Stat(filepath.Join(dir, "last-report.json")); err != nil {
		t.Fatal("报告未落盘")
	}
	led, err := LoadLedger(filepath.Join(dir, "ledger.json"), "example.com")
	if err != nil || len(led.Entries) != rep.Generated {
		t.Fatalf("台账条目数应等于候选数: %d vs %d (%v)", len(led.Entries), rep.Generated, err)
	}

	// 第二轮：增量 diff → 零重查、零 DNS 查询
	o.DNS.lookup = pipelineFake()
	rep2, err := RunDNS(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.ToQuery != 0 {
		t.Fatalf("第二轮应零重查, got %d", rep2.ToQuery)
	}
	if rep2.Skipped != rep.Generated-rep.Whitelisted {
		t.Fatalf("第二轮应全部跳过: %d", rep2.Skipped)
	}
	if rep2.Stats.Queries != 0 {
		t.Fatalf("第二轮应零 DNS 查询, got %d", rep2.Stats.Queries)
	}
	if rep2.Top[0].Domain != "examp1e.com" || rep2.Top[0].Score != 68 {
		t.Fatal("第二轮台账评分应保持")
	}
}

func TestRunDNSWhitelistExcludes(t *testing.T) {
	dir := t.TempDir()
	o := RunOptions{
		Brand:     "example.com",
		StateDir:  dir,
		Whitelist: Whitelist{Domains: []string{"examp1e.com"}, Keywords: []string{"examplevip"}},
		DNS:       DNSOptions{QPS: 1000, Workers: 8, CheckMX: true, lookup: pipelineFake()},
	}
	rep, err := RunDNS(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Whitelisted < 2 {
		t.Fatalf("白名单应排除 ≥2 项, got %d", rep.Whitelisted)
	}
	for _, e := range rep.Top {
		if e.Domain == "examp1e.com" {
			t.Fatal("白名单域不应进 Top")
		}
	}
	led, _ := LoadLedger(filepath.Join(dir, "ledger.json"), "example.com")
	e := led.Entries["examp1e.com"]
	if e == nil || !e.Whitelisted || e.Ownership != OwnershipBrand {
		t.Fatalf("白名单域应标记 brand/whitelisted: %+v", e)
	}
	// 白名单域不消耗 DNS 查询：examp1e.com 未被判活
	if rep.Stats.Resolved != 0 {
		t.Fatalf("白名单域不应被判活: %+v", rep.Stats)
	}
}

func TestRunDNSRecheckTTL(t *testing.T) {
	dir := t.TempDir()
	f := pipelineFake()
	o := RunOptions{
		Brand: "example.com", StateDir: dir,
		DNS: DNSOptions{QPS: 1000, Workers: 8, lookup: f},
	}
	if _, err := RunDNS(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	// 把台账里所有未注册项的 LastChecked 拨回 10 天前
	led, _ := LoadLedger(filepath.Join(dir, "ledger.json"), "example.com")
	old := time.Now().AddDate(0, 0, -10)
	nxCount := 0
	for _, e := range led.Entries {
		if !e.Resolved && !e.Whitelisted {
			e.LastChecked = old
			nxCount++
		}
	}
	if err := led.Save(filepath.Join(dir, "ledger.json")); err != nil {
		t.Fatal(err)
	}
	o.RecheckTTL = 7 * 24 * time.Hour
	o.DNS.lookup = pipelineFake()
	rep, err := RunDNS(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ToQuery != nxCount {
		t.Fatalf("TTL 重查应命中全部未注册项 %d, got %d", nxCount, rep.ToQuery)
	}
	if len(rep.NewDomains) != 0 {
		t.Fatal("TTL 重查项不是新增域")
	}
}