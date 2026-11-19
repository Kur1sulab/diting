package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ── 免 key 被动源：只读公开数据（证书透明日志、被动 DNS、公开扫描记录）──
//
// 全部无需凭据，默认参与采集；外层通过 Options.Sources 可单独关掉。
// 返回的都是「域名/主机名」级线索，不带端口协议时 Port=0（不臆造）。

// inScope 资产归属边界：name 必须是 target 的 apex 本身或真子域（以 "." 分隔）。
// 裸 HasSuffix(name, target) 会把 notexample.com 误收为 example.com 的子域——
// 多 SAN 证书（共享主机/CDN）的 name_value/dns_names 与被动 DNS 数据常带这类
// 形似 apex 的无关域，混入 assets.json/assets.txt 后下游 verify/portscan/report
// 会打到范围外资产。与 jsintel 的域归属判定（h == t || HasSuffix(h, "."+t)）同规则。
// 调用方保证 name 已 lower；target 在此归一。
func inScope(name, target string) bool {
	t := strings.ToLower(target)
	return name == t || strings.HasSuffix(name, "."+t)
}

// queryCrtSh 证书透明日志。crt.sh 响应慢（实测 15~25s），单请求超时放宽。
// GET https://crt.sh/?q=%25.<domain>&output=json
func queryCrtSh(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("crtsh", "https://crt.sh/")
	q := fmt.Sprintf("%%%%.%s", target) // %.<domain>
	pv := url.Values{}
	pv.Set("q", q)
	pv.Set("output", "json")
	slow := o
	slow.Timeout = 40 * time.Second // crt.sh 常年 15s+，单请求放宽
	body, _, err := fetchJSON(ctx, slow, strings.TrimRight(base, "/")+"/?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
		NotBefore  string `json:"not_before"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("响应非 JSON（crt.sh 偶发返回 HTML 限流页）")
	}
	set := map[string]string{}
	for _, r := range rows {
		for _, name := range strings.Split(r.NameValue, "\n") {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || !inScope(name, target) {
				continue
			}
			if _, ok := set[name]; !ok {
				set[name] = r.NotBefore
			}
		}
	}
	return hostRecords("crtsh", set), nil
}

// queryCertSpotter GET https://api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&expand=dns_names
func queryCertSpotter(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("certspotter", "https://api.certspotter.com/v1/issuances")
	pv := url.Values{}
	pv.Set("domain", target)
	pv.Set("include_subdomains", "true")
	pv.Set("expand", "dns_names")
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var rows []struct {
		DNSNames  []string `json:"dns_names"`
		NotBefore string   `json:"not_before"`
	}
	if err := json.Unmarshal([]byte(body), &rows); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	set := map[string]string{}
	for _, r := range rows {
		for _, n := range r.DNSNames {
			n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "*."))
			if n != "" && inScope(n, target) {
				if _, ok := set[n]; !ok {
					set[n] = r.NotBefore
				}
			}
		}
	}
	return hostRecords("certspotter", set), nil
}

// queryHackerTarget GET https://api.hackertarget.com/hostsearch/?q=…  →  CSV "host,ip"
func queryHackerTarget(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("hackertarget", "https://api.hackertarget.com/hostsearch/")
	pv := url.Values{}
	pv.Set("q", target)
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	b := strings.TrimSpace(body)
	if strings.HasPrefix(b, "error") || strings.Contains(b, "API count exceeded") {
		return nil, fmt.Errorf("%s", truncRunes(b, 80))
	}
	var out []Record
	for _, line := range strings.Split(b, "\n") {
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) < 2 {
			continue
		}
		h, ip := strings.ToLower(parts[0]), parts[1]
		if h == "" || !inScope(h, target) {
			continue
		}
		out = append(out, Record{Source: "hackertarget", Host: h, Domain: target, IP: ip})
	}
	return out, nil
}

// rapidRow 抓 <tr>…</tr>；rapidCell 抓每行里的 <td>…</td>（内容可能含 <a> 等标签）。
var (
	rapidRow  = regexp.MustCompile(`(?is)<tr[^>]*>(.*?)</tr>`)
	rapidCell = regexp.MustCompile(`(?is)<td[^>]*>(.*?)</td>`)
	rapidTag  = regexp.MustCompile(`(?s)<[^>]*>`)
)

// parseRapidDNS 解析 RapidDNS 表格：每行 [主机, 类型/IP, 日期]。
// 结构实测（2026-11）：<tr><th scope="row">1</th><td>host</td><td><a …>ip</a></td><td>date</td></tr>
// 行首是 <th> 序号，所以不能按「第一个 <td> 就是主机」之外的位置猜——统一收集 td 后取前三格。
func parseRapidDNS(body string) [][3]string {
	var out [][3]string
	for _, rm := range rapidRow.FindAllStringSubmatch(body, -1) {
		cells := rapidCell.FindAllStringSubmatch(rm[1], -1)
		if len(cells) < 2 {
			continue
		}
		var vals []string
		for _, c := range cells {
			v := strings.TrimSpace(rapidTag.ReplaceAllString(c[1], " "))
			v = strings.TrimSpace(strings.Join(strings.Fields(v), " "))
			vals = append(vals, v)
		}
		var row [3]string
		copy(row[:], vals)
		out = append(out, row)
	}
	return out
}

// queryRapidDNS GET https://rapiddns.io/subdomain/<d>?full=1  →  HTML 表格
func queryRapidDNS(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("rapiddns", "https://rapiddns.io/subdomain/")
	pv := url.Values{}
	pv.Set("full", "1")
	u := strings.TrimRight(base, "/") + "/" + url.PathEscape(target) + "?" + pv.Encode()
	body, _, err := fetchJSON(ctx, o, u, nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var out []Record
	seen := map[string]bool{}
	for _, row := range parseRapidDNS(body) {
		host := strings.ToLower(strings.TrimSpace(row[0]))
		if host == "" || !inScope(host, target) || seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, Record{Source: "rapiddns", Host: host, Domain: target, Updated: row[2]})
		if len(out) >= o.limit() {
			break
		}
	}
	return out, nil
}

// queryURLScan GET https://urlscan.io/api/v1/search/?q=page.domain:<d>&size=…
func queryURLScan(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("urlscan", "https://urlscan.io/api/v1/search/")
	pv := url.Values{}
	pv.Set("q", "page.domain:"+target)
	pv.Set("size", fmt.Sprintf("%d", o.limit()))
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
				IP     string `json:"ip"`
				Server string `json:"server"`
				Status string `json:"status"`
			} `json:"page"`
			Task struct {
				URL  string `json:"url"`
				Time string `json:"time"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	var out []Record
	for _, r := range data.Results {
		d := strings.ToLower(strings.TrimSpace(r.Page.Domain))
		if d == "" || !inScope(d, target) {
			continue
		}
		out = append(out, Record{
			Source: "urlscan", Host: d, Domain: target,
			IP: r.Page.IP, Server: r.Page.Server, Protocol: "https", Updated: r.Task.Time,
		})
	}
	return out, nil
}

// querySubdomainCenter GET https://api.subdomain.center/?domain=…  →  JSON 字符串数组
// 注意：该服务国内直连偶发空返回，走代理更稳（引擎遵循 HTTP(S)_PROXY）。
func querySubdomainCenter(ctx context.Context, target string, o Options) ([]Record, error) {
	base := o.endpoint("subdomaincenter", "https://api.subdomain.center/")
	pv := url.Values{}
	pv.Set("domain", target)
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	b := strings.TrimSpace(body)
	if b == "" {
		return nil, fmt.Errorf("空响应（多为出口被限，可挂代理重试）")
	}
	var names []string
	if err := json.Unmarshal([]byte(b), &names); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	seen := map[string]bool{}
	var out []Record
	for _, n := range names {
		n = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(n), "*."))
		if n == "" || seen[n] || !inScope(n, target) {
			continue
		}
		seen[n] = true
		out = append(out, Record{Source: "subdomaincenter", Host: n, Domain: target})
		if len(out) >= o.limit() {
			break
		}
	}
	return out, nil
}

// hostRecords 把 host→时间 映射拍平成记录（稳定排序，输出可复现）。
func hostRecords(source string, set map[string]string) []Record {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Record, 0, len(keys))
	for _, k := range keys {
		out = append(out, Record{Source: source, Host: k, Updated: set[k]})
	}
	return out
}
