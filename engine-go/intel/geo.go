package intel

// geo.go —— IP 归属情报：geo / ISP / ASN / 反向 DNS。
//
// 数据源：ip-api.com 免费档（无需 key，限速 45 次/分钟，HTTP only）。
// 纪律：免费档限速是按源 IP 计的，批量查询用 /batch 一次最多 100 个，
// 本包默认分片 100 并按 1.5s 间隔节流，避免把额度打满被临时封禁。

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// IPInfo 一个 IP 的归属情报（字段全部来自实测响应）。
type IPInfo struct {
	Query      string `json:"query"`
	Status     string `json:"status"`
	Country    string `json:"country,omitempty"`
	RegionName string `json:"region,omitempty"`
	City       string `json:"city,omitempty"`
	ISP        string `json:"isp,omitempty"`
	Org        string `json:"org,omitempty"`
	AS         string `json:"as,omitempty"`
	Reverse    string `json:"reverse,omitempty"`
	Error      string `json:"error,omitempty"`
}

// GeoBase 可注入（测试打 httptest stub）。
var (
	GeoBase     = "http://ip-api.com"
	geoThrottle = 1500 * time.Millisecond
)

// LookupIP 查单个 IP。
func LookupIP(ctx context.Context, ip string, o Options) IPInfo {
	res := LookupBatchIP(ctx, []string{ip}, o)
	if len(res) == 0 {
		return IPInfo{Query: ip, Status: "fail", Error: "无响应"}
	}
	return res[0]
}

// LookupBatchIP 批量查（自动分片 ≤100，片间节流）。
func LookupBatchIP(ctx context.Context, ips []string, o Options) []IPInfo {
	if len(ips) == 0 {
		return nil
	}
	if o.Timeout <= 0 {
		o.Timeout = 25 * time.Second
	}
	var out []IPInfo
	for start := 0; start < len(ips); start += 100 {
		end := start + 100
		if end > len(ips) {
			end = len(ips)
		}
		chunk := ips[start:end]
		items := make([]map[string]string, 0, len(chunk))
		for _, ip := range chunk {
			items = append(items, map[string]string{"query": ip})
		}
		payload, _ := json.Marshal(items)
		u := strings.TrimRight(GeoBase, "/") + "/batch?fields=status,message,country,regionName,city,isp,org,as,reverse,query"
		body, _, err := fetchJSON(ctx, o, u,
			map[string]string{"Content-Type": "application/json"}, payload, "POST")
		if err != nil {
			for _, ip := range chunk {
				out = append(out, IPInfo{Query: ip, Status: "fail", Error: err.Error()})
			}
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(body), &rows); err != nil {
			for _, ip := range chunk {
				out = append(out, IPInfo{Query: ip, Status: "fail", Error: "响应非 JSON"})
			}
			continue
		}
		for _, r := range rows {
			info := IPInfo{
				Query:      pickStr(r, "query"),
				Status:     pickStr(r, "status"),
				Country:    pickStr(r, "country"),
				RegionName: pickStr(r, "regionName"),
				City:       pickStr(r, "city"),
				ISP:        pickStr(r, "isp"),
				Org:        pickStr(r, "org"),
				AS:         pickStr(r, "as"),
				Reverse:    pickStr(r, "reverse"),
			}
			if info.Status == "fail" {
				info.Error = pickStr(r, "message")
			}
			out = append(out, info)
		}
		if end < len(ips) {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(geoThrottle):
			}
		}
	}
	return out
}

// ASNOf 从 "AS13335 Cloudflare, Inc." 里取 ASN 号。
func ASNOf(as string) string {
	as = strings.TrimSpace(as)
	if i := strings.IndexByte(as, ' '); i > 0 {
		return as[:i]
	}
	return as
}

// FormatIPInfo 人读单行。
func FormatIPInfo(i IPInfo) string {
	if i.Status != "success" {
		return fmt.Sprintf("%s\t查询失败\t%s", i.Query, i.Error)
	}
	loc := strings.Join(nonEmpty(i.Country, i.RegionName, i.City), "/")
	return fmt.Sprintf("%s\t%s\t%s\t%s\t%s", i.Query, loc, i.ISP, i.AS, i.Reverse)
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
