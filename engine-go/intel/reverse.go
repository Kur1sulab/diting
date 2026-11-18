package intel

// reverse.go —— IP 反查域名（同 IP 邻里）。
//
// 两条免 key 通道：
//  1. hackertarget reverseiplookup（CSV，快，有日额度）；
//  2. rapiddns sameip（HTML 表格，慢一些但稳）。
//
// 只做只读查询；返回的是「该 IP 上解析过的域名」线索，是否为同一业务需人工判断。

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

var (
	ReverseHackerTargetBase = "https://api.hackertarget.com/reverseiplookup/"
	ReverseRapidDNSBase     = "https://rapiddns.io/sameip/"
)

// ReverseIP 反查 IP 上的域名，双源合并去重（保序：hackertarget → rapiddns）。
func ReverseIP(ctx context.Context, ip string, o Options) ([]Record, []SourceStat) {
	var recs []Record
	var stats []SourceStat
	seen := map[string]bool{}

	// 源 1：hackertarget
	func() {
		pv := url.Values{}
		pv.Set("q", ip)
		base := o.endpoint("hackertarget-reverse", ReverseHackerTargetBase)
		body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
		st := SourceStat{Name: "hackertarget-reverse", Kind: "reverse"}
		if err != nil {
			st.Status = "error"
			st.Message = err.Error()
			stats = append(stats, st)
			return
		}
		b := strings.TrimSpace(body)
		if strings.HasPrefix(b, "error") || strings.Contains(b, "API count exceeded") {
			st.Status = "error"
			st.Message = truncRunes(b, 80)
			stats = append(stats, st)
			return
		}
		for _, line := range strings.Split(b, "\n") {
			h := strings.ToLower(strings.TrimSpace(line))
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			recs = append(recs, Record{Source: "hackertarget-reverse", Host: h, IP: ip})
			st.Count++
		}
		st.Status = "ok"
		stats = append(stats, st)
	}()

	// 源 2：rapiddns sameip
	func() {
		base := o.endpoint("rapiddns-sameip", ReverseRapidDNSBase)
		u := strings.TrimRight(base, "/") + "/" + url.PathEscape(ip) + "?full=1"
		body, _, err := fetchJSON(ctx, o, u, nil, nil, "GET")
		st := SourceStat{Name: "rapiddns-sameip", Kind: "reverse"}
		if err != nil {
			st.Status = "error"
			st.Message = err.Error()
			stats = append(stats, st)
			return
		}
		for _, row := range parseRapidDNS(body) {
			h := strings.ToLower(strings.TrimSpace(row[0]))
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			recs = append(recs, Record{Source: "rapiddns-sameip", Host: h, IP: ip, Updated: row[2]})
			st.Count++
			if st.Count >= o.limit() {
				break
			}
		}
		st.Status = "ok"
		stats = append(stats, st)
	}()

	if len(recs) == 0 {
		return nil, stats
	}
	return recs, stats
}

// FormatReverse 人读摘要。
func FormatReverse(ip string, recs []Record, stats []SourceStat) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "IP 反查 %s：%d 个域名\n", ip, len(recs))
	for _, s := range stats {
		fmt.Fprintf(&sb, "  %-22s %s %d 条", s.Name, s.Status, s.Count)
		if s.Message != "" {
			fmt.Fprintf(&sb, "（%s）", s.Message)
		}
		sb.WriteString("\n")
	}
	for _, r := range recs {
		sb.WriteString("  " + r.Host + "\n")
	}
	return sb.String()
}
