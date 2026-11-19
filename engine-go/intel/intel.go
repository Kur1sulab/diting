// Package intel：多源资产情报总线。
//
// 设计目标：把「一个域名」丢进来，把外部可见面从尽量多的源捞出来，
// 归一成同一种记录（Record），去重后落盘成 assets.json / assets.txt / intel.md。
//
// 三条纪律（与产品铁律一致）：
//  1. 只读：所有 Provider 只做 GET/POST 查询，没有写原语、没有 exploit 链；
//  2. 凭据只走环境变量或 ~/.yata/keys.env，源码零字面量；未配置的源跳过不报错；
//  3. 免 key 源默认开启（crt.sh / certspotter / hackertarget / rapiddns /
//     urlscan / subdomain.center），有 key 的源自动增强，缺 key 不阻断。
//
// 支持的源（Kind=space 为空间测绘引擎，均需 key）：
//
//	fofa      FOFA_EMAIL(可选)+FOFA_KEY
//	hunter    奇安信 Hunter  HUNTER_KEY
//	quake     360 Quake      QUAKE_TOKEN
//	zoomeye    ZoomEye       ZOOMEYE_KEY
//	shodan     Shodan        SHODAN_KEY
//	censys     Censys v3     CENSYS_TOKEN（或 CENSYS_API_ID+CENSYS_API_SECRET）
//	netlas     Netlas        NETLAS_KEY
//	zerozone   0.zone        ZEROZONE_KEY
//
// Kind=passive 为免 key 被动源：crtsh / certspotter / hackertarget /
// rapiddns / urlscan / subdomaincenter。
//
// Kind=icp 为备案查询（见 icp 包，本包只在 intel 报告里聚合结果）。
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Kur1sulab/yata/engine-go/netutil"
)

// Record 是一条归一化后的资产记录。字段全部来自实测，不做推演填充。
type Record struct {
	Source   string `json:"source"`
	Host     string `json:"host,omitempty"`   // 主机名或 host:port
	Domain   string `json:"domain,omitempty"` // 归属域名
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // http/https/ssh/...
	Title    string `json:"title,omitempty"`
	Server   string `json:"server,omitempty"`
	Product  string `json:"product,omitempty"`
	Country  string `json:"country,omitempty"`
	ASN      string `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	ICP      string `json:"icp,omitempty"` // 备案号（FOFA 等源在 fields 里带 icp 时才有）
	Updated  string `json:"updated,omitempty"`
}

// pyStr 等价 Python f"{v}" 的字符串化：None→"None"（FOFA 行的历史语义）。
func pyStr(v any) string {
	if v == nil {
		return "None"
	}
	return fmt.Sprintf("%v", v)
}

// LegacyLine 旧格式行 "host|ip|port|protocol"——assets.txt 的历史契约
// （report 模块按行读取；两侧引擎同名产物必须同构）。
func (r Record) LegacyLine() string {
	port := ""
	if r.Port > 0 {
		port = fmt.Sprintf("%d", r.Port)
	}
	return strings.Join([]string{r.Host, r.IP, port, r.Protocol}, "|")
}

// Key 去重键：优先 host|ip|port|protocol，其次 domain|ip|port|protocol。
func (r Record) Key() string {
	return r.LegacyLine() + "|" + r.Domain
}

// Options 一次 intel 采集的参数。
type Options struct {
	Sources   []string          // 空 = 全部已配置的源 + 免 key 源
	Limit     int               // 单源条数上限（默认 100）
	RawQuery  string            // 自定义查询语法（仅 space 源生效；空 = domain="<d>"）
	Fields    []string          // 自定义返回字段（仅 FOFA 生效；空 = 默认七列）
	Endpoints map[string]string // 测试注入：源名 → URL 前缀
	Timeout   time.Duration     // 单请求超时（默认 25s）
	Ctx       context.Context
	Log       func(format string, a ...any) // 进度回调（nil = 打到 stdout）
	Workers   int                           // 并发源数（默认 6）
}

// Provider 一个数据源的描述与查询入口。
type Provider struct {
	Name  string
	Kind  string // space / passive
	Env   []string
	Free  bool
	Doc   string
	Query func(ctx context.Context, target string, o Options) ([]Record, error)
}

func logf(o Options, format string, a ...any) {
	if o.Log != nil {
		o.Log(format, a...)
		return
	}
	fmt.Printf(format, a...)
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 25 * time.Second
	}
	return o.Timeout
}

func (o Options) limit() int {
	if o.Limit <= 0 {
		return 100
	}
	if o.Limit > 1000 {
		return 1000
	}
	return o.Limit
}

func (o Options) endpoint(name, def string) string {
	if o.Endpoints != nil {
		if v, ok := o.Endpoints[name]; ok && v != "" {
			return v
		}
	}
	return def
}

// Report 一次采集的汇总。
type Report struct {
	Target    string            `json:"target"`
	StartedAt string            `json:"started_at"`
	ElapsedMS int64             `json:"elapsed_ms"`
	Sources   []SourceStat      `json:"sources"`
	Records   []Record          `json:"records"`
	Files     map[string]string `json:"files,omitempty"`
}

// SourceStat 单源执行结果（成功条数 / 跳过原因 / 错误）。
type SourceStat struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Status  string `json:"status"` // ok / skipped / error
	Count   int    `json:"count"`
	Message string `json:"message,omitempty"`
}

// Run 对 target（域名或 IP）跑一遍多源采集并落盘，返回汇总。
//
// 产物（写到 out 目录）：
//
//	assets.json   全量记录（结构化，含 source 字段可溯源）
//	assets.txt    兼容旧契约的 "host|ip|port|protocol" 行
//	intel.md      人读摘要（每源条数 + 前 N 条高价值资产）
func Run(target, out string, opt Options) (*Report, error) {
	ctx := opt.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	rep := &Report{
		Target:    target,
		StartedAt: start.Format("2006-01-02T15:04:05Z07:00"),
		Files:     map[string]string{},
	}
	provs := selectProviders(opt)
	if len(provs) == 0 {
		logf(opt, "[!] 没有任何可用数据源（既没配 key，也没开免 key 源）\n")
	}
	workers := opt.Workers
	if workers <= 0 {
		workers = 6
	}
	if workers > len(provs) {
		workers = len(provs)
	}
	if workers < 1 {
		workers = 1
	}

	type result struct {
		name string
		kind string
		recs []Record
		err  error
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	ch := make(chan result, len(provs))
	for _, p := range provs {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			logf(opt, "[*] %s 查询中…\n", p.Name)
			recs, err := safeQuery(ctx, p, target, opt)
			ch <- result{name: p.Name, kind: p.Kind, recs: recs, err: err}
		}(p)
	}
	wg.Wait()
	close(ch)

	order := map[string]int{}
	for i, p := range allProviders {
		order[p.Name] = i
	}
	var results []result
	for r := range ch {
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool { return order[results[i].name] < order[results[j].name] })

	seen := map[string]bool{}
	for _, r := range results {
		st := SourceStat{Name: r.name, Kind: r.kind}
		switch {
		case r.err != nil:
			st.Status = "error"
			st.Message = r.err.Error()
			logf(opt, "[!] %s 失败: %v\n", r.name, r.err)
		case len(r.recs) == 0:
			st.Status = "ok"
			logf(opt, "[*] %s 0 条\n", r.name)
		default:
			st.Status = "ok"
		}
		for _, rec := range r.recs {
			k := rec.Key()
			if seen[k] {
				continue
			}
			seen[k] = true
			rep.Records = append(rep.Records, rec)
			st.Count++
		}
		if st.Status == "ok" && st.Count > 0 {
			logf(opt, "[+] %s %d 条\n", r.name, st.Count)
		}
		rep.Sources = append(rep.Sources, st)
	}
	rep.ElapsedMS = time.Since(start).Milliseconds()

	if err := WriteOutputs(out, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func safeQuery(ctx context.Context, p Provider, target string, o Options) (recs []Record, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("解析异常: %v", r)
		}
	}()
	qctx, cancel := context.WithTimeout(ctx, o.timeout()*3)
	defer cancel()
	return p.Query(qctx, target, o)
}

// WriteOutputs 把一次采集结果落成标准产物集：assets.json（全量结构化）/
// assets.txt（host|ip|port|protocol 旧契约）/ intel.md（人读摘要），并回填
// rep.Files。域名分支（Run）与 IP 反查分支（cli.runIntel）共用同一写盘契约：
// intel 无论目标是域名还是 IP，out/ 里都必须有产物——report.Collect 依赖
// assets.txt（report.go），缺写会让下游报告静默丢掉情报段。
// rep.Files 为 nil 时自动初始化（IP 分支构造的 Report 不带 Files map）。
func WriteOutputs(out string, rep *Report) error {
	if out == "" {
		return nil
	}
	if rep.Files == nil {
		rep.Files = map[string]string{}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	// 产物清单先登记再序列化：assets.json 落盘时 files 段必须非空。
	// 旧实现在写盘后才回填内存 map，盘上 JSON 的 files 永远是 {}。
	// 路径是确定性的（out/固定文件名），写失败会整体返回 error，不留半成品清单。
	jp := filepath.Join(out, "assets.json")
	tp := filepath.Join(out, "assets.txt")
	mp := filepath.Join(out, "intel.md")
	rep.Files["assets.json"] = jp
	rep.Files["assets.txt"] = tp
	rep.Files["intel.md"] = mp

	js, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(jp, append(js, '\n'), 0o644); err != nil {
		return err
	}

	var sb strings.Builder
	for _, r := range rep.Records {
		sb.WriteString(r.LegacyLine() + "\n")
	}
	if err := os.WriteFile(tp, []byte(sb.String()), 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(mp, []byte(renderMarkdown(rep)), 0o644); err != nil {
		return err
	}
	return nil
}

func renderMarkdown(rep *Report) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# 资产情报汇总 · %s\n\n", rep.Target)
	fmt.Fprintf(&sb, "- 采集时间：%s（耗时 %d ms）\n", rep.StartedAt, rep.ElapsedMS)
	fmt.Fprintf(&sb, "- 记录总数：%d\n\n", len(rep.Records))
	sb.WriteString("## 数据源\n\n| 源 | 类型 | 状态 | 条数 | 备注 |\n|---|---|---|---|---|\n")
	for _, s := range rep.Sources {
		msg := s.Message
		if msg == "" {
			msg = "-"
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %d | %s |\n", s.Name, s.Kind, s.Status, s.Count, mdCell(msg))
	}
	sb.WriteString("\n## 资产（前 200 条）\n\n")
	sb.WriteString("| 源 | 主机 | IP | 端口 | 协议 | 标题 | 服务器 |\n|---|---|---|---|---|---|---|\n")
	n := 0
	for _, r := range rep.Records {
		if n >= 200 {
			break
		}
		n++
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s | %s |\n",
			r.Source, mdCell(r.Host), mdCell(r.IP), portStr(r.Port), mdCell(r.Protocol),
			mdCell(truncRunes(r.Title, 40)), mdCell(r.Server))
	}
	if len(rep.Records) > n {
		fmt.Fprintf(&sb, "\n> 另有 %d 条未在摘要中展开，见 assets.json\n", len(rep.Records)-n)
	}
	return sb.String()
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	if s == "" {
		return "-"
	}
	return s
}

func portStr(p int) string {
	if p <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", p)
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// fetchJSON 统一 JSON 拉取：返回 body 与 HTTP 状态。失败抛 error（含状态码）。
func fetchJSON(ctx context.Context, opt Options, url string, headers map[string]string, data []byte, method string) (string, int, error) {
	h := map[string]string{"Accept": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	res := netutil.Fetch(url, netutil.FetchOpt{
		Timeout:  opt.timeout(),
		Follow:   true,
		MaxBytes: 8 << 20,
		Method:   method,
		Data:     data,
		Headers:  h,
		Ctx:      ctx,
	})
	if !res.OK {
		return "", res.Status, fmt.Errorf("请求失败: %s", res.Err)
	}
	if res.Status != 200 {
		return res.Body, res.Status, fmt.Errorf("HTTP %d", res.Status)
	}
	return res.Body, res.Status, nil
}
