package cli

// typosquat_cmd.go —— 域名汇洞（品牌仿冒域监控）子命令门面。
//
// 引擎在 typosquat 包（Generate / CheckDNS / Score / Ledger / RDAP），本文件
// 只做三件事：参数解析、台账目录约定、终端输出格式。不重复实现任何判定逻辑，
// 否则 CLI 与测试会跑出两套阈值。
//
// 一轮的语义（typosquat.RunDNS）：生成候选 → 白名单过滤 → 增量 diff →
// 限速 DNS 判活 → 评分 → 落台账。第二轮同命令只查新增/变化项，配额可控。

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Kur1sulab/diting/engine-go/typosquat"
)

// typosquatStateRoot 台账根目录：$DITING_HOME/typosquat，默认 ~/.diting/typosquat。
// 与 keys.env 同住 ~/.diting，用户只需要记一个目录。
func typosquatStateRoot() string {
	if v := strings.TrimSpace(os.Getenv("DITING_HOME")); v != "" {
		return filepath.Join(v, "typosquat")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".diting", "typosquat")
	}
	return filepath.Join(".diting", "typosquat")
}

// loadWhitelistFile 读白名单：JSON（typosquat.Whitelist 结构）或纯文本一行一条。
// 纯文本支持 # 注释与空行——手写白名单时比 JSON 好用得多。
func loadWhitelistFile(path string) (typosquat.Whitelist, error) {
	var w typosquat.Whitelist
	b, err := os.ReadFile(path)
	if err != nil {
		return w, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		if err := json.Unmarshal(b, &w); err != nil {
			return w, fmt.Errorf("白名单 JSON 解析失败: %w", err)
		}
		return w, nil
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		w.Domains = append(w.Domains, line)
	}
	return w, nil
}

// dispatchTyposquat 处理 typosquat 子命令。
func dispatchTyposquat(rest []string) int { return runTyposquat(rest) }

func runTyposquat(rest []string) int {
	fs := newFlagSet()
	domain := fs.String("d", "", "")
	domainAlias := fs.String("domain", "", "")
	brandFlag := fs.String("b", "", "")
	brandAlias := fs.String("brand", "", "")
	tlds := fs.String("tlds", "", "tld-swap 目标列表，逗号分隔")
	qps := fs.Float64("qps", 20, "每秒 DNS 查询上限（全部查询类型合计）")
	workers := fs.Int("workers", 16, "并发判活 worker 数")
	timeout := fs.Duration("timeout", 3*time.Second, "单次 DNS 查询超时")
	resolver := fs.String("resolver", "", "指定 resolver，如 223.5.5.5 或 8.8.8.8:53")
	checkMX := fs.Bool("mx", true, "对解析成功的域查 MX（判邮件截收能力）")
	checkNS := fs.Bool("ns", false, "对 NXDOMAIN 补查 NS（判已注册未解析）")
	state := fs.String("state", "", "台账目录（默认 ~/.diting/typosquat/<品牌>）")
	recheck := fs.Duration("recheck", 0, "对超过该时长仍未注册的项重查，如 168h")
	wlFile := fs.String("whitelist", "", "白名单文件（JSON 或一行一条，支持 # 注释）")
	enrich := fs.Bool("enrich", false, "对高分已注册域补 RDAP 富化（额外配额）")
	enrichLimit := fs.Int("enrich-limit", 50, "RDAP 富化最多查多少条（0=不限）")
	enrichMin := fs.Int("enrich-min-score", 40, "参与 RDAP 富化的最低分")
	noPinyin := fs.Bool("no-pinyin-fuzz", false, "不对拼音词干再跑核心 fuzzer（省配额）")
	asJSON := fs.Bool("json", false, "以 JSON 输出整轮报告")

	usage := "typosquat -d <domain|品牌> [--tlds com,cn] [--qps 20] [--workers 16] " +
		"[--state <dir>] [--whitelist <file>] [--recheck 168h] [--enrich] [--json]"
	if c := parseOrUsage(fs, rest, "typosquat", usage); c != -1 {
		return c
	}
	brand := pickAliasLastWins(rest, map[string]*string{
		"-d": domain, "--domain": domainAlias, "-b": brandFlag, "--brand": brandAlias,
	})
	if brand == "" {
		return missingArgs("typosquat", usage)
	}

	stateDir := *state
	if stateDir == "" {
		// 品牌可含中文/斜杠：目录名走与 out/ 同一套清洗，避免 A/b 这类品牌
		// 在 ~/.diting 下建出嵌套目录。
		stateDir = filepath.Join(typosquatStateRoot(), OutdirName(brand))
	}

	gen := typosquat.GenerateOptions{DisablePinyinFuzz: *noPinyin}
	if *tlds != "" {
		var list []string
		for _, t := range strings.Split(*tlds, ",") {
			if t = strings.TrimSpace(t); t != "" {
				list = append(list, t)
			}
		}
		if len(list) == 0 {
			fmt.Printf("[!] --tlds 解析后为空，请检查逗号分隔格式\n")
			return 1
		}
		gen.TLDs = list
	}

	var wl typosquat.Whitelist
	if *wlFile != "" {
		var err error
		if wl, err = loadWhitelistFile(*wlFile); err != nil {
			fmt.Printf("[!] 白名单读取失败: %v\n", err)
			return 1
		}
	}

	ctx := context.Background()
	rep, err := typosquat.RunDNS(ctx, typosquat.RunOptions{
		Brand:      brand,
		StateDir:   stateDir,
		Whitelist:  wl,
		Generate:   gen,
		RecheckTTL: *recheck,
		DNS: typosquat.DNSOptions{
			QPS: *qps, Workers: *workers, Timeout: *timeout,
			Resolver: *resolver, CheckMX: *checkMX, CheckNS: *checkNS,
		},
	})
	if err != nil {
		fmt.Printf("[!] 汇洞监控失败: %v\n", err)
		return 1
	}

	// RDAP 富化是独立可选步骤（额外外联配额），失败不影响本轮台账结果。
	if *enrich {
		led, lerr := typosquat.LoadLedger(rep.LedgerPath, brand)
		if lerr != nil {
			fmt.Printf("[!] 台账重载失败，跳过 RDAP 富化: %v\n", lerr)
		} else {
			client := typosquat.NewRDAPClient(typosquat.RDAPOptions{CacheDir: stateDir})
			n, nf, eerr := typosquat.EnrichRDAP(ctx, led, client, *enrichMin, *enrichLimit, rep.LedgerPath)
			noProxy := os.Getenv("HTTPS_PROXY") == "" && os.Getenv("https_proxy") == ""
			switch {
			case eerr != nil:
				fmt.Printf("[!] RDAP 富化中断（成功 %d / 失败 %d）: %v\n", n, nf, eerr)
			case nf > 0 && noProxy:
				// 实测：国内直连 rdap.verisign.com（.com/.net 的 RDAP）12s 超时，
				// 走代理 5s 返回。失败既不能落库也不能只打一个 0 条让用户猜。
				fmt.Printf("[!] RDAP 成功 %d 条 / 失败 %d 条——.com/.net 的 RDAP 端点在国内常超时，\n", n, nf)
				fmt.Printf("    设 HTTP(S)_PROXY 后重跑可补查（如 export HTTPS_PROXY=http://127.0.0.1:7897）\n")
			default:
				fmt.Printf("[*] RDAP 富化 %d 条（失败 %d）\n", n, nf)
			}
		}
	}

	if *asJSON {
		out, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fmt.Printf("[!] JSON 编码失败: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("[*] 汇洞监控：%s\n", rep.Brand)
	fmt.Printf("[*] 台账：%s\n", rep.LedgerPath)
	fmt.Printf("[*] 候选 %d / 白名单排除 %d / 本轮判活 %d / 台账未变跳过 %d\n",
		rep.Generated, rep.Whitelisted, rep.ToQuery, rep.Skipped)
	fmt.Printf("[*] DNS：解析 %d / NXDOMAIN %d / 失败 %d / 缓存命中 %d / 查询 %d / 耗时 %.1fs\n",
		rep.Stats.Resolved, rep.Stats.NXDomain, rep.Stats.Errors,
		rep.Stats.CachedHits, rep.Stats.Queries, rep.Elapsed.Seconds())
	if len(rep.NewDomains) > 0 {
		fmt.Printf("[+] 本轮新增 %d 个候选域\n", len(rep.NewDomains))
	}
	if len(rep.Resolved) > 0 {
		fmt.Printf("[+] 解析成功 %d 个（已被注册或本就存在，需人工判归属）\n", len(rep.Resolved))
	}

	if len(rep.Top) > 0 {
		fmt.Printf("\n[!] 高分候选（按风险分排序，最多 10 条）\n")
		fmt.Printf("    %-4s %-6s %-30s %-4s %-16s %s\n", "分", "等级", "域名", "MX", "来源", "首次发现")
		for _, e := range rep.Top {
			mx := "no"
			if e.HasMX {
				mx = "yes"
			}
			src := strings.Join(e.Fuzzers, ",")
			if len(src) > 15 {
				src = src[:15]
			}
			fmt.Printf("    %-4d %-6s %-30s %-4s %-16s %s\n",
				e.Score, e.Level, e.Domain, mx, src, e.FirstSeen.Format("2006-01-02"))
		}
	}

	if rep.Generated == 0 {
		fmt.Printf("\n[!] 没有生成任何候选：品牌词太短或全是非法标签。\n")
		return 1
	}
	fmt.Printf("\n[*] 未注册排列 ≠ 安全，台账会持续监控；合法相似域用 --whitelist 排除。\n")
	fmt.Printf("[*] 增量：下一轮同命令只查新增/变化项；--recheck 168h 可定期重查未注册项。\n")
	return 0
}
