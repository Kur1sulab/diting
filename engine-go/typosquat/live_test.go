package typosquat

// live_test.go —— 真实验证（env 门控，默认 Skip，离线 `go test` 不受影响）：
//
//	DITING_TYPOSQUAT_LIVE=1 go test ./typosquat/ -run TestLiveExampleDNS -v
//
// 只跑 example.com 一个品牌、一轮 DNS 判活（不做 RDAP 批量），
// QPS=20 保守限速，配额上限断言 600 次查询。第二轮验证增量 diff=0。
// 状态目录可用 DITING_TYPOSQUAT_STATE 指定（默认临时目录）。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveExampleDNS(t *testing.T) {
	if os.Getenv("DITING_TYPOSQUAT_LIVE") != "1" {
		t.Skip("真实跑需 DITING_TYPOSQUAT_LIVE=1（默认跳过，保持离线测试零外网）")
	}
	state := os.Getenv("DITING_TYPOSQUAT_STATE")
	if state == "" {
		state = t.TempDir()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	o := RunOptions{
		Brand:    "example.com",
		StateDir: state,
		DNS: DNSOptions{
			QPS: 20, Workers: 16, Timeout: 3 * time.Second, CheckMX: true,
		},
	}
	rep, err := RunDNS(ctx, o)
	if err != nil {
		t.Fatalf("真实跑失败: %v", err)
	}

	t.Logf("===== 真实跑 example.com（DNS-only，一轮）=====")
	t.Logf("生成候选=%d 白名单排除=%d 本轮判活=%d 台账跳过=%d",
		rep.Generated, rep.Whitelisted, rep.ToQuery, rep.Skipped)
	t.Logf("DNS查询总量=%d 解析成功=%d NXDOMAIN=%d 超时/失败=%d 缓存命中=%d",
		rep.Stats.Queries, rep.Stats.Resolved, rep.Stats.NXDomain, rep.Stats.Errors, rep.Stats.CachedHits)
	t.Logf("DNS层耗时=%v 全轮耗时=%v", rep.Stats.Elapsed.Round(time.Millisecond), rep.Elapsed.Round(time.Millisecond))
	t.Logf("解析成功域: %v", rep.Resolved)
	t.Logf("----- 前 5 高分候选 -----")
	for i, e := range rep.Top {
		if i >= 5 {
			break
		}
		t.Logf("#%d %s score=%d level=%s(%s) mx=%v fuzzers=%v",
			i+1, e.Domain, e.Score, e.Level, LevelZh(e.Level), e.MX, e.Fuzzers)
	}

	if rep.Generated < 100 {
		t.Fatalf("候选量异常偏少: %d", rep.Generated)
	}
	if rep.Stats.Queries > 600 {
		t.Fatalf("DNS 配额失控: %d > 600", rep.Stats.Queries)
	}
	if rep.Stats.Resolved+rep.Stats.CachedHits == 0 {
		t.Fatal("example.com 仿冒排列应有已注册域（实测基线 86/1976），解析/缓存命中为 0 异常")
	}

	// 第一轮报告单独存档（第二轮会覆盖 last-report.json）
	if b, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(state, "live-round1.json"), b, 0o644)
	}

	// 第二轮：增量 diff 应零重查、零查询
	rep2, err := RunDNS(ctx, o)
	if err != nil {
		t.Fatalf("第二轮失败: %v", err)
	}
	t.Logf("===== 第二轮（增量验证）=====")
	t.Logf("判活=%d 跳过=%d DNS查询=%d 耗时=%v", rep2.ToQuery, rep2.Skipped, rep2.Stats.Queries, rep2.Elapsed.Round(time.Millisecond))
	if rep2.ToQuery != 0 || rep2.Stats.Queries != 0 {
		t.Fatalf("增量 diff 失效: toQuery=%d queries=%d", rep2.ToQuery, rep2.Stats.Queries)
	}
	t.Logf("台账: %s", rep.LedgerPath)
}