package cli

// intel_cmds.go —— 多源情报子命令的接线层。
//
// 这一层只做三件事：参数解析、把参数翻译成 intel.Options、把结果打到 stdout。
// 具体每个源怎么查全部在 intel 包里（可单测、可被 serve/desktop 复用）。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Kur1sulab/diting/engine-go/asset"
	"github.com/Kur1sulab/diting/engine-go/icp"
	"github.com/Kur1sulab/diting/engine-go/intel"
	"github.com/Kur1sulab/diting/engine-go/netutil"
	"github.com/Kur1sulab/diting/engine-go/reverseip"
)

// splitList 拆 "a,b,c" 形式的源列表。
func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// dispatchIntel 处理 intel / providers / whois / ipinfo 四个子命令。
func dispatchIntel(cmd string, rest []string) int {
	switch cmd {
	case "providers":
		return runProviders(rest)
	case "intel":
		return runIntel(rest)
	case "whois":
		return runWhois(rest)
	case "ipinfo":
		return runIPInfo(rest)
	}
	fmt.Printf("[*] 未知子命令: %q\n", cmd)
	return 2
}

// runProviders `diting providers [--json]` —— 列数据源与凭据状态。
func runProviders(rest []string) int {
	fs := newFlagSet()
	asJSON := fs.Bool("json", false, "")
	if c := parseOrUsage(fs, rest, "providers", "providers [--json]"); c != -1 {
		return c
	}
	if *asJSON {
		type row struct {
			Name       string   `json:"name"`
			Kind       string   `json:"kind"`
			Env        []string `json:"env,omitempty"`
			Free       bool     `json:"free"`
			Configured bool     `json:"configured"`
			Doc        string   `json:"doc"`
		}
		var rows []row
		for _, p := range intel.AllProviders() {
			rows = append(rows, row{
				Name: p.Name, Kind: p.Kind, Env: p.Env, Free: p.Free,
				Configured: intel.Configured(p), Doc: p.Doc,
			})
		}
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Print(intel.StatusTable(intel.Options{}))
	fmt.Println("\n配置方式：环境变量，或 ~/.diting/keys.env（chmod 600）中的 KEY=VALUE")
	fmt.Println("免 key 源无需任何配置即可用：crtsh / certspotter / hackertarget / rapiddns / urlscan / subdomaincenter")
	return 0
}

// intelFlags 解析 asset/intel 共用的一批参数。
type intelFlags struct {
	sources string
	limit   int
	query   string
	target  string
}

func parseIntelFlags(rest []string, cmd, usage string) (*intelFlags, int) {
	fs := newFlagSet()
	f := &intelFlags{}
	fs.StringVar(&f.sources, "sources", "", "")
	fs.IntVar(&f.limit, "limit", 100, "")
	fs.StringVar(&f.query, "query", "", "")
	d := fs.String("d", "", "")
	dAlias := fs.String("domain", "", "")
	t := fs.String("t", "", "")
	if c := parseOrUsage(fs, rest, cmd, usage); c != -1 {
		return nil, c
	}
	f.target = pickNonEmpty3(pickAliasLastWins(rest, map[string]*string{"-d": d, "--domain": dAlias}),
		pickAliasLastWins(rest, map[string]*string{"-t": t}), "")
	return f, -1
}

// runIntel `diting intel -d <domain> [--sources a,b] [--limit N] [--query '…'] [--no-icp] [--no-whois]`
//
// 一次把「空间测绘 + 被动源 + 备案 + WHOIS + IP 归属」全跑一遍，落 assets.json /
// assets.txt / intel.md / icp_<domain>.json / whois_<domain>.json。
// IP 目标走反查双源（hackertarget-reverse + rapiddns-sameip），同样落
// assets.json / assets.txt / intel.md（无 icp/whois——备案/注册信息只对域名有意义）。
func runIntel(rest []string) int {
	fs := newFlagSet()
	sources := fs.String("sources", "", "")
	limit := fs.Int("limit", 100, "")
	rawQuery := fs.String("query", "", "")
	fieldsFlag := fs.String("fields", "", "")
	d := fs.String("d", "", "")
	dAlias := fs.String("domain", "", "")
	t := fs.String("t", "", "")
	noICP := fs.Bool("no-icp", false, "")
	noWhois := fs.Bool("no-whois", false, "")
	demoICP := fs.Bool("demo", false, "")
	usage := "intel -d <domain> [--sources fofa,quake,…] [--limit N] [--query '…'] [--fields a,b] [--no-icp] [--no-whois] [--demo]"
	if c := parseOrUsage(fs, rest, "intel", usage); c != -1 {
		return c
	}
	target := pickNonEmpty3(
		pickAliasLastWins(rest, map[string]*string{"-d": d, "--domain": dAlias}),
		pickAliasLastWins(rest, map[string]*string{"-t": t}), "")
	if target == "" {
		return missingArgs("intel", usage)
	}
	isIP := net.ParseIP(target) != nil
	if !isIP {
		if bad, why := invalidDomainShape(target); bad {
			fmt.Printf("[!] 非法域名（%s）: %q\n", why, target)
			return 2
		}
	}
	out, err := MakeOutdir(target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}
	ctx := context.Background()
	opt := intel.Options{
		Sources:  splitList(*sources),
		Limit:    *limit,
		RawQuery: *rawQuery,
		Fields:   splitList(*fieldsFlag),
		Ctx:      ctx,
	}
	var rep *intel.Report
	if isIP {
		// IP：不做子域/证书类被动源（它们按域名索引），改走反查 + 归属。
		// 产物契约与域名分支一致：此前只打印不落盘，out/ 空目录却报
		// 「采集完成 -> out」，下游 report.Collect 读 assets.txt 静默丢情报。
		start := time.Now()
		recs, stats := intel.ReverseIP(ctx, target, opt)
		fmt.Print(intel.FormatReverse(target, recs, stats))
		rep = &intel.Report{
			Target:    target,
			StartedAt: start.Format("2006-01-02T15:04:05Z07:00"),
			ElapsedMS: time.Since(start).Milliseconds(),
			Records:   recs,
			Sources:   stats,
		}
		if err := intel.WriteOutputs(out, rep); err != nil {
			fmt.Printf("[!] 采集写盘失败: %v\n", err)
			return 1
		}
	} else {
		rep, err = intel.Run(target, out, opt)
		if err != nil {
			fmt.Printf("[!] 采集写盘失败: %v\n", err)
			return 1
		}
	}
	if !isIP && !*noICP {
		res := icp.RunICPChain(ctx, target, out, icp.ChainOptions{Demo: *demoICP})
		_ = res
	}
	if !isIP && !*noWhois {
		info := intel.Whois(ctx, target, opt)
		if b, err := json.MarshalIndent(info, "", "  "); err == nil {
			if p, e := safeWriteJSON(out, "whois_"+target+".json", b); e == nil {
				fmt.Printf("[*] RDAP/WHOIS -> %s\n", p)
			}
		}
		if info.Error != "" {
			fmt.Printf("[!] WHOIS 未取得（%s）\n", info.Error)
		} else {
			fmt.Printf("[+] WHOIS: 注册商=%s 注册=%s 到期=%s NS=%s\n",
				dashStr(info.Registrar), dashStr(info.RegisteredAt), dashStr(info.ExpiresAt),
				dashStr(strings.Join(info.Nameservers, ",")))
		}
	}
	fmt.Printf("[+] 采集完成：%d 条记录 -> %s\n", len(rep.Records), out)
	return 0
}

func dashStr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// runAsset `diting asset -d <domain> [--sources …] [--limit N] [--query …] [--legacy]`
//
// 默认走多源（intel）；--legacy 保留旧的两源（FOFA+Hunter）行为，便于与旧脚本对齐。
func runAssetMulti(rest []string) int {
	f, code := parseIntelFlags(rest, "asset", "asset -d <domain> [--sources a,b] [--limit N] [--query '…'] [--legacy]")
	if code != -1 {
		return code
	}
	legacy := false
	for _, a := range rest {
		if a == "--legacy" || a == "-legacy" {
			legacy = true
		}
	}
	if f.target == "" {
		return missingArgs("asset", "asset -d <domain>")
	}
	if bad, why := invalidDomainShape(f.target); bad {
		fmt.Printf("[!] 非法域名（%s）: %q\n", why, f.target)
		return 2
	}
	out, err := MakeOutdir(f.target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}
	if legacy {
		asset.RunAsset(f.target, out)
		return 0
	}
	opt := intel.Options{
		Sources:  splitList(f.sources),
		Limit:    f.limit,
		RawQuery: f.query,
		Ctx:      context.Background(),
	}
	rep, err := intel.Run(f.target, out, opt)
	if err != nil {
		fmt.Printf("[!] 资产测绘写盘失败: %v\n", err)
		return 1
	}
	fmt.Printf("[+] 资产测绘完成：%d 条（%d 个源）-> %s\n", len(rep.Records), len(rep.Sources), out)
	for _, st := range rep.Sources {
		if st.Status != "ok" || st.Count == 0 {
			fmt.Printf("    · %-16s %s %s\n", st.Name, st.Status, st.Message)
		}
	}
	return 0
}

// runICPChain `diting icp -d <domain> [-d2 …] [--demo]`
func runICPChain(rest []string) int {
	fs := newFlagSet()
	d := fs.String("d", "", "")
	dAlias := fs.String("domain", "", "")
	demo := fs.Bool("demo", false, "")
	file := fs.String("file", "", "")
	usage := "icp -d <domain> [--file domains.txt] [--demo]"
	if c := parseOrUsage(fs, rest, "icp", usage); c != -1 {
		return c
	}
	targets := []string{}
	if t := pickAliasLastWins(rest, map[string]*string{"-d": d, "--domain": dAlias}); t != "" {
		targets = append(targets, t)
	}
	if *file != "" {
		b, err := os.ReadFile(*file)
		if err != nil {
			fmt.Printf("[!] 读取域名列表失败: %v\n", err)
			return 1
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			targets = append(targets, line)
		}
	}
	if len(targets) == 0 {
		return missingArgs("icp", usage)
	}
	code := 0
	for i, tgt := range targets {
		if bad, why := invalidDomainShape(tgt); bad {
			fmt.Printf("[!] 跳过非法域名（%s）: %q\n", why, tgt)
			code = 2
			continue
		}
		out, err := MakeOutdir(tgt)
		if err != nil {
			fmt.Printf("[!] 输出目录创建失败: %v\n", err)
			code = 1
			continue
		}
		if len(targets) > 1 {
			fmt.Printf("\n── [%d/%d] %s ──\n", i+1, len(targets), tgt)
		}
		icp.RunICPChain(context.Background(), tgt, out, icp.ChainOptions{Demo: *demo})
	}
	return code
}

// runReverseMulti `diting reverse -i <ip> [--legacy]`
func runReverseMulti(rest []string) int {
	fs := newFlagSet()
	ip := fs.String("i", "", "")
	ipAlias := fs.String("ip", "", "")
	if c := parseOrUsage(fs, rest, "reverse", "reverse -i <ip> [--legacy]"); c != -1 {
		return c
	}
	target := pickAliasLastWins(rest, map[string]*string{"-i": ip, "--ip": ipAlias})
	if target == "" {
		return missingArgs("reverse", "reverse -i <ip>")
	}
	if net.ParseIP(target) == nil {
		fmt.Printf("[!] 非法 IP: %q（reverse -i 需要合法 IPv4/IPv6 地址）\n", target)
		return 2
	}
	legacy := false
	for _, a := range rest {
		if a == "--legacy" || a == "-legacy" {
			legacy = true
		}
	}
	out, err := MakeOutdir(target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}
	if legacy {
		reverseip.RunReverse(target, out)
		return 0
	}
	ctx := context.Background()
	opt := intel.Options{Ctx: ctx, Limit: 500, Timeout: 25 * time.Second}
	recs, stats := intel.ReverseIP(ctx, target, opt)
	fmt.Print(intel.FormatReverse(target, recs, stats))
	if len(recs) > 0 {
		var sb strings.Builder
		for _, r := range recs {
			sb.WriteString(r.Host + "\n")
		}
		if p, err := safeWriteText(out, "reverse.txt", sb.String()); err == nil {
			fmt.Printf("    -> %s\n", p)
		}
	}
	return 0
}

// runWhois `diting whois -d <domain>`
func runWhois(rest []string) int {
	fs := newFlagSet()
	d := fs.String("d", "", "")
	dAlias := fs.String("domain", "", "")
	asJSON := fs.Bool("json", false, "")
	if c := parseOrUsage(fs, rest, "whois", "whois -d <domain> [--json]"); c != -1 {
		return c
	}
	target := pickAliasLastWins(rest, map[string]*string{"-d": d, "--domain": dAlias})
	if target == "" {
		return missingArgs("whois", "whois -d <domain>")
	}
	if bad, why := invalidDomainShape(target); bad {
		fmt.Printf("[!] 非法域名（%s）: %q\n", why, target)
		return 2
	}
	info := intel.Whois(context.Background(), target, intel.Options{})
	if *asJSON {
		b, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Printf("域名      %s\n", info.Domain)
	fmt.Printf("RDAP 端   %s\n", dashStr(info.Provider))
	if info.Error != "" {
		fmt.Printf("[!] %s\n", info.Error)
		return 1
	}
	fmt.Printf("注册商    %s\n", dashStr(info.Registrar))
	fmt.Printf("注册时间  %s\n", dashStr(info.RegisteredAt))
	fmt.Printf("到期时间  %s\n", dashStr(info.ExpiresAt))
	fmt.Printf("更新时间  %s\n", dashStr(info.UpdatedAt))
	fmt.Printf("注册人    %s\n", dashStr(info.Registrant))
	fmt.Printf("状态      %s\n", dashStr(strings.Join(info.Status, ", ")))
	fmt.Printf("NS        %s\n", dashStr(strings.Join(info.Nameservers, ", ")))
	return 0
}

// runIPInfo `diting ipinfo -i 1.1.1.1[,8.8.8.8] [--file ips.txt]`
func runIPInfo(rest []string) int {
	fs := newFlagSet()
	ips := fs.String("i", "", "")
	ipAlias := fs.String("ip", "", "")
	file := fs.String("file", "", "")
	if c := parseOrUsage(fs, rest, "ipinfo", "ipinfo -i <ip[,ip…]> [--file ips.txt]"); c != -1 {
		return c
	}
	raw := pickAliasLastWins(rest, map[string]*string{"-i": ips, "--ip": ipAlias})
	var list []string
	for _, s := range append(splitList(raw), readIPFile(*file)...) {
		if net.ParseIP(s) == nil {
			fmt.Printf("[!] 跳过非法 IP: %q\n", s)
			continue
		}
		list = append(list, s)
	}
	if len(list) == 0 {
		return missingArgs("ipinfo", "ipinfo -i <ip[,ip…]>")
	}
	res := intel.LookupBatchIP(context.Background(), list, intel.Options{})
	fmt.Println("IP\t归属\tISP\tASN\t反查")
	for _, i := range res {
		fmt.Println(intel.FormatIPInfo(i))
	}
	return 0
}

func readIPFile(path string) []string {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("[!] 读取 IP 列表失败: %v\n", err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// safeWriteText / safeWriteJSON 小包装：走 netutil 的白名单文件名 + 目录内校验。
func safeWriteText(out, name, content string) (string, error) {
	return netutil.SafeWrite(out, name, content)
}

func safeWriteJSON(out, name string, b []byte) (string, error) {
	return netutil.SafeWrite(out, name, string(b))
}
