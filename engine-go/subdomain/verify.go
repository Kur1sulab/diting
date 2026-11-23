package subdomain

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/diting/engine-go/netutil"
	"github.com/Kur1sulab/diting/engine-go/waf"
)

// DNSLookup 解析域名 → 去重排序的 IP 列表；失败返回空列表（对齐 subdomain.py:121-138）。
// 注意：排序用字符串字典序（Python sorted 对字符串序），不是 IP 数值序。
// 本机 Clash fake-ip 环境下假域名可能"解析成功"（198.18.0.0/15），测试锚点一律用
// 127.0.0.1 字面量，禁止依赖"假域名必须解析失败"。
func DNSLookup(host string, timeout time.Duration) []string {
	return dnsLookupCtx(context.Background(), host, timeout)
}

// dnsLookupCtx 是 DNSLookup 的取消变体（第一步「取消能力注入」①）：
// 解析 ctx 取调用方 ctx 的超时子级——父 ctx 取消即解析立即失败返回空。
// 旧签名委托本函数，存量测试零改动。
func dnsLookupCtx(ctx context.Context, host string, timeout time.Duration) []string {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var ips []string
	for _, a := range addrs {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		ips = append(ips, a)
	}
	sort.Strings(ips)
	return ips
}

// ProbeResult 轻量 HTTP 探测结果，JSON 键对齐 Python http_probe 返回 dict。
//
// WAF 是新增的资产属性（调研总纲 §3 P1）：把「被 WAF 拦住」和「目标不存在」
// 区分开。它是**附加字段**，Python 侧没有对应键，因此只在 Go 侧生效；
// 为兼容存量 parity 断言，该键只在「真的拿到了 HTTP 响应」时出现（见 MarshalJSON）。
type ProbeResult struct {
	Scheme   string         `json:"scheme"`
	Status   int            `json:"status"`
	Server   string         `json:"server"`
	Ctype    string         `json:"ctype"`
	Title    string         `json:"title"`
	FinalURL string         `json:"final_url"`
	WAF      *waf.Attribute `json:"waf"`
}

// MarshalJSON 固定输出 waf 键（无证据时为 null）。
// 下游（空境 Kara）需要区分三种情况：没探活 / 探活了没 WAF / 探活了有 WAF，
// 所以这个键不能 omitempty —— 缺键与 null 是两种语义。
func (p ProbeResult) MarshalJSON() ([]byte, error) {
	type plain struct {
		Scheme   string         `json:"scheme"`
		Status   int            `json:"status"`
		Server   string         `json:"server"`
		Ctype    string         `json:"ctype"`
		Title    string         `json:"title"`
		FinalURL string         `json:"final_url"`
		WAF      *waf.Attribute `json:"waf"`
	}
	return json.Marshal(plain{p.Scheme, p.Status, p.Server, p.Ctype, p.Title, p.FinalURL, p.WAF})
}

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]{0,80})`)

// HTTPProbe 对单个主机做一次轻量 HTTP 探测（先 https 后 http），
// 对齐 subdomain.py:141-158。port>0 时拼 :port 后缀；全失败返回零值。
func HTTPProbe(host string, timeout time.Duration, port int) ProbeResult {
	return httpProbeCtx(context.Background(), host, timeout, port)
}

// httpProbeCtx 是 HTTPProbe 的取消变体（第一步①）：https/http 两次尝试
// 均过 FetchOpt.Ctx 咽喉，且第二次尝试前设检查点——取消即不再发下一跳。
// 旧签名委托本函数，存量测试零改动。
func httpProbeCtx(ctx context.Context, host string, timeout time.Duration, port int) ProbeResult {
	suffix := ""
	if port > 0 {
		suffix = fmt.Sprintf(":%d", port)
	}
	// fix2 P1：探活跟随重定向同样逐跳校验（入口公网→私网落点阻断；
	// 入口私网=授权内网靶标→放行），https/http 两尝试共享同一入口策略
	hop := netutil.HopPolicy("https://" + host + suffix)
	for _, scheme := range []string{"https", "http"} {
		if ctx.Err() != nil { // 尝试间检查点（第一步①）
			return ProbeResult{}
		}
		r := netutil.Fetch(scheme+"://"+host+suffix, netutil.FetchOpt{Timeout: timeout, Follow: true, HopCheck: hop, Ctx: ctx})
		if r.OK && r.Status != 0 {
			title := ""
			if m := titleRe.FindStringSubmatch(r.Body); m != nil {
				title = strings.TrimSpace(m[1])
			}
			return ProbeResult{
				Scheme:   scheme,
				Status:   r.Status,
				Server:   r.Headers["server"],
				Ctype:    r.Ctype,
				Title:    title,
				FinalURL: r.FinalURL,
				// WAF/bot 指纹（§3 P1）：拿到的响应立刻过一遍离线判定库。
				// 关键点是 4xx/5xx 也要判——被 403 挡住不等于主机不存在，
				// 以前这一层把拦截页直接丢了，等于把「有 WAF」误报成「没有资产」。
				WAF: waf.DetectFromResult(r.Status, r.Headers, r.Cookies, r.Body, r.FinalURL),
			}
		}
	}
	return ProbeResult{}
}

// VerifyRow 单行验证结果，JSON 键对齐 Python：{host, ips, alive, http}。
// 空值形态也对齐 Python（fix1 审计 medium#3）：死亡行 ips 序列化为 []（非 null）、
// http 序列化为 {}（非六字段空对象）——与 Python "ips": dns or [] / http_map.get(h,{})
// 的落盘形态逐键一致，键序 host,ips,alive,http。
type VerifyRow struct {
	Host  string      `json:"host"`
	IPs   []string    `json:"ips"`
	Alive bool        `json:"alive"`
	HTTP  ProbeResult `json:"http"`
}

// MarshalJSON 落盘形态对齐：nil/空 ips → []；零值探活结果 → {}。
// Python http_probe 只在 status 为真时返回六键 dict，故以 Status!=0 区分
// 「探测成功（六键全出）」与「未探测/失败（空对象）」。
func (r VerifyRow) MarshalJSON() ([]byte, error) {
	ips := r.IPs
	if ips == nil {
		ips = []string{}
	}
	httpField := json.RawMessage("{}")
	if r.HTTP.Status != 0 {
		b, err := json.Marshal(r.HTTP)
		if err != nil {
			return nil, err
		}
		httpField = b
	}
	return json.Marshal(struct {
		Host  string          `json:"host"`
		IPs   []string        `json:"ips"`
		Alive bool            `json:"alive"`
		HTTP  json.RawMessage `json:"http"`
	}{r.Host, ips, r.Alive, httpField})
}

// VerifySubs 并发（低频）验证子域，对齐 subdomain.py:161-184：
// 先 DNS 全量解析；可解析者取前 httpCap 个做 HTTP 探活；rows 保持输入序。
func VerifySubs(subs []string, workers int, doHTTP bool, httpCap int) []VerifyRow {
	return verifySubsCtx(context.Background(), subs, workers, doHTTP, httpCap)
}

// verifySubsCtx 是 VerifySubs 的取消变体（第一步①连带件：verify worker 池
// 检查点）——发新 worker 前检查 ctx，取消即停止派发后续任务，已派发任务
// 经 dnsLookupCtx/httpProbeCtx 随 ctx 秒级收敛；rows 保持输入序。
// 旧签名委托本函数，存量测试零改动。
func verifySubsCtx(ctx context.Context, subs []string, workers int, doHTTP bool, httpCap int) []VerifyRow {
	if workers < 1 {
		workers = 1
	}
	if httpCap <= 0 {
		httpCap = 120
	}
	rows := make([]VerifyRow, 0, len(subs))
	if len(subs) == 0 {
		return rows
	}
	// DNS 全量（并发受 workers 限制，保持输入序）；派发前检查点，取消即停发
	dnsMap := make([][]string, len(subs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i, h := range subs {
		if ctx.Err() != nil { // 取消检查点（第一步①）
			break
		}
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			dnsMap[i] = dnsLookupCtx(ctx, h, 3*time.Second)
		}(i, h)
	}
	wg.Wait()
	if ctx.Err() != nil { // 取消：不再进入 HTTP 探活阶段
		return rows
	}
	var resolved []string
	var resolvedIdx []int
	for i, h := range subs {
		if len(dnsMap[i]) > 0 {
			resolved = append(resolved, h)
			resolvedIdx = append(resolvedIdx, i)
		}
	}
	// HTTP 探活：只做前 httpCap 个可解析主机。
	// httpMap 必须是按索引切片而非 map：各 goroutine 写互不重叠的下标（i），
	// 与上方 dnsMap 同构，无锁且数据竞争安全——此前用 map[int]ProbeResult
	// 被 goroutine 无锁并发写，运行时 fatal error: concurrent map writes
	// 整进程中止（fix1 审计 high#1，30 连跑 16 崩实锤）。
	httpMap := make([]ProbeResult, len(subs))
	if doHTTP && len(resolved) > 0 {
		targets := resolvedIdx
		if len(targets) > httpCap {
			fmt.Printf("[!] 可解析主机 %d 个，HTTP 探活只做前 %d 个（避免压力）\n", len(resolved), httpCap)
			targets = targets[:httpCap]
		}
		var wg2 sync.WaitGroup
		sem2 := make(chan struct{}, workers)
		for _, i := range targets {
			if ctx.Err() != nil { // 取消检查点（第一步①）：停发新探活任务
				break
			}
			wg2.Add(1)
			go func(i int, h string) {
				defer wg2.Done()
				sem2 <- struct{}{}
				defer func() { <-sem2 }()
				httpMap[i] = httpProbeCtx(ctx, h, 5*time.Second, 0)
			}(i, subs[i])
		}
		wg2.Wait()
	}
	for i, h := range subs {
		rows = append(rows, VerifyRow{
			Host:  h,
			IPs:   dnsMap[i],
			Alive: len(dnsMap[i]) > 0,
			HTTP:  httpMap[i],
		})
	}
	return rows
}

// RunVerify 读取 out/subdomains.txt 验证存活，写 subdomains_live.json（全量）+
// subdomains_live.txt（仅 live），打印摘要前 20 条，对齐 subdomain.py:187-211。
func RunVerify(out string, workers int, doHTTP bool) []VerifyRow {
	return RunVerifyContext(context.Background(), out, workers, doHTTP)
}

// RunVerifyContext 是 RunVerify 的取消变体（第一步「取消能力注入」①）：
// 入口与验证后各设检查点——取消即收敛返回 nil、不落盘任何产物。
// 旧签名委托本函数（Background 即原行为），cli.go 调用点零改动。
func RunVerifyContext(ctx context.Context, out string, workers int, doHTTP bool) []VerifyRow {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil
	}
	src := out + "/subdomains.txt"
	data, err := readFile(src)
	if err != nil {
		fmt.Printf("[!] 找不到 %s，请先跑子域枚举\n", src)
		return nil
	}
	var subs []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			subs = append(subs, l)
		}
	}
	fmt.Printf("[*] 存活验证：%d 个子域（DNS 解析 + HTTP 探活，并发 %d，低频克制）\n", len(subs), workers)
	rows := verifySubsCtx(ctx, subs, workers, doHTTP, 120)
	if err := ctx.Err(); err != nil { // 取消：不落盘（第一步①）
		fmt.Println("[!] 存活验证已取消，不写产物")
		return nil
	}
	var live []VerifyRow
	web := 0
	for _, r := range rows {
		if r.Alive {
			live = append(live, r)
			if r.HTTP.Status != 0 {
				web++
			}
		}
	}
	if _, err := netutil.SafeWrite(out, "subdomains_live.json", marshalPretty(rows)); err != nil {
		fmt.Printf("[!] subdomains_live.json 写盘失败: %v\n", err)
	}
	liveTxt := strings.Join(hosts(live), "\n")
	if len(live) > 0 {
		liveTxt += "\n"
	}
	if _, err := netutil.SafeWrite(out, "subdomains_live.txt", liveTxt); err != nil {
		fmt.Printf("[!] subdomains_live.txt 写盘失败: %v\n", err)
	}
	// WAF/bot 属性汇总（§3 P1）：单独落一份 waf.json 给空境 Kara 选路用。
	// 只在真做了 HTTP 探活时写——没探活却写一份空汇总，等于谎报「没有 WAF」。
	if doHTTP {
		writeWAFSummary(out, rows)
	}
	fmt.Printf("[+] 存活验证完成：可解析 %d 个（其中 %d 个有 HTTP 响应）-> subdomains_live.txt / .json\n", len(live), web)
	for i, r := range live {
		if i >= 20 {
			break
		}
		ipStr := strings.Join(firstN(r.IPs, 2), ",")
		info := "（无 HTTP 响应）"
		if r.HTTP.Status != 0 {
			t := []rune(r.HTTP.Title)
			if len(t) > 28 {
				t = t[:28]
			}
			info = fmt.Sprintf("%s://%d %s", r.HTTP.Scheme, r.HTTP.Status, string(t))
			if r.HTTP.WAF != nil {
				info += "  [WAF " + r.HTTP.WAF.String() + "]"
			}
		}
		fmt.Printf("      %-44s %-20s %s\n", r.Host, ipStr, info)
	}
	if len(live) > 20 {
		fmt.Printf("      ... 另 %d 个见 subdomains_live.json\n", len(live)-20)
	}
	if doHTTP {
		printWAFSummary(waf.BuildSummary(wafAssets(rows), nowStamp()).Stats, "waf.json")
	}
	return rows
}

// nowStamp 可注入时钟：产物时间戳格式与 report 一致（本地时区 ISO 秒级）。
var nowStamp = waf.Stamp

// wafAssets 把验证结果映射成 waf 汇总的资产视图（同一份数据，不重复判定）。
func wafAssets(rows []VerifyRow) []waf.Asset {
	assets := make([]waf.Asset, 0, len(rows))
	for _, r := range rows {
		assets = append(assets, waf.Asset{
			Host:     r.Host,
			IPs:      r.IPs,
			Scheme:   r.HTTP.Scheme,
			Status:   r.HTTP.Status,
			FinalURL: r.HTTP.FinalURL,
			WAF:      r.HTTP.WAF,
		})
	}
	return assets
}

// WAFSummary 返回这批验证结果的 WAF 汇总。导出给 serve 流水线复用同一口径，
// 避免控制台日志与 waf.json 两套算法。
func WAFSummary(rows []VerifyRow) waf.Summary {
	return waf.BuildSummary(wafAssets(rows), nowStamp())
}

// writeWAFSummary 落盘 waf.json。抽成独立函数是为了可离线单测产物形态，
// 不必真的跑一遍 DNS + 探活。
func writeWAFSummary(out string, rows []VerifyRow) {
	sum := WAFSummary(rows)
	if _, err := netutil.SafeWrite(out, "waf.json", marshalPretty(sum)); err != nil {
		fmt.Printf("[!] waf.json 写盘失败: %v\n", err)
	}
}

// printWAFSummary 打印 WAF/挑战分布。
//
// 这一行是本次改动的核心可见价值：以前报告只说「N 个有 HTTP 响应」，
// 现在能直接看出「其中几个其实是被 WAF 拦住的」。运营者据此判断
// 这批资产是需要绕行（Kara 选路）还是可以直接打。
func printWAFSummary(st waf.Stats, path string) {
	if st.HTTPResponded == 0 {
		fmt.Println("[*] WAF 指纹：无 HTTP 响应可判（不影响存活结论）")
		return
	}
	if st.WAFDetected == 0 {
		fmt.Printf("[+] WAF 指纹：%d 个响应均未见 WAF/挑战特征 -> %s\n", st.HTTPResponded, path)
		return
	}
	fmt.Printf("[!] WAF 指纹：%d/%d 个响应命中 WAF 或 bot 挑战（被拦 ≠ 不存在）-> %s\n",
		st.WAFDetected, st.HTTPResponded, path)
	for _, v := range sortedCountKeys(st.ByVendor) {
		fmt.Printf("      厂商 %-18s %d 个\n", v, st.ByVendor[v])
	}
	if len(st.ByConfidence) > 0 {
		parts := make([]string, 0, len(st.ByConfidence))
		for _, c := range sortedCountKeys(st.ByConfidence) {
			parts = append(parts, fmt.Sprintf("%s×%d", c, st.ByConfidence[c]))
		}
		fmt.Printf("      置信度 %s\n", strings.Join(parts, "  "))
	}
	for _, c := range sortedCountKeys(st.ByChallenge) {
		if c == waf.ChalNone {
			continue
		}
		fmt.Printf("      挑战 %-18s %d 个\n", c, st.ByChallenge[c])
	}
	if st.ByVendor[waf.VendorUnknown] > 0 {
		fmt.Printf("      提示：%d 个只判出「有拦截、认不出品牌」（unknown）——证据不足，未猜品牌\n",
			st.ByVendor[waf.VendorUnknown])
	}
}

// sortedCountKeys 固定键序，避免 map 遍历顺序让 CLI 输出抖动。
func sortedCountKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func hosts(rows []VerifyRow) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Host)
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// readFile 读取文件（统一入口便于将来审计）。
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
