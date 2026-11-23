package waf

import (
	"sort"
	"time"
)

// 本文件负责「给下游的汇总视图」。单资产属性挂在 subdomains_live.json 的
// http.waf 里，但空境 Kara 选路时真正需要的是「这一批资产里哪些前面有 WAF、
// 分别是哪家」，逐条翻 subdomains_live.json 成本太高，因此单独产出一份
// waf.json。两份产物同源（都来自 Detect 的结果），不存在口径分叉。

// Asset 是汇总用的最小资产视图。
type Asset struct {
	Host     string     `json:"host"`
	IPs      []string   `json:"ips"`
	Scheme   string     `json:"scheme"`
	Status   int        `json:"status"`
	FinalURL string     `json:"final_url"`
	WAF      *Attribute `json:"waf"` // nil = 已探活但无 WAF 证据
}

// Stats 是汇总计数。by_* 三张表的键就是对外枚举值，Kara 可直方图式消费。
type Stats struct {
	Alive         int            `json:"alive"`          // 有 DNS 记录的资产数
	HTTPResponded int            `json:"http_responded"` // 拿到 HTTP 响应的资产数
	WAFDetected   int            `json:"waf_detected"`   // 判出 WAF/挑战的资产数（含 unknown）
	ByVendor      map[string]int `json:"by_vendor"`
	ByConfidence  map[string]int `json:"by_confidence"`
	ByChallenge   map[string]int `json:"by_challenge"`
}

// Summary 是 waf.json 的顶层结构。
type Summary struct {
	GeneratedAt string  `json:"generated_at"`
	Stats       Stats   `json:"stats"`
	Assets      []Asset `json:"assets"` // 只含判出 WAF 的资产，按 host 排序
}

// BuildSummary 从资产列表汇总出 waf.json 内容。
// generatedAt 由调用方给（保持与其它产物同一时间口径），本包不取系统时间。
func BuildSummary(assets []Asset, generatedAt string) Summary {
	st := Stats{
		ByVendor:     map[string]int{},
		ByConfidence: map[string]int{},
		ByChallenge:  map[string]int{},
	}
	hit := make([]Asset, 0, len(assets))
	for _, a := range assets {
		if a.IPs == nil {
			a.IPs = []string{}
		}
		st.Alive++
		if a.Status != 0 {
			st.HTTPResponded++
		}
		if a.WAF == nil || !a.WAF.Present() {
			continue
		}
		st.WAFDetected++
		st.ByVendor[a.WAF.Vendor]++
		st.ByConfidence[a.WAF.Confidence]++
		st.ByChallenge[a.WAF.Challenge]++
		hit = append(hit, a)
	}
	// 固定排序：产物要可 diff，不能随 goroutine 完成顺序抖动。
	sort.SliceStable(hit, func(i, j int) bool { return hit[i].Host < hit[j].Host })
	return Summary{GeneratedAt: generatedAt, Stats: st, Assets: hit}
}

// Stamp 返回与其它产物一致的时间戳格式（本地时区 ISO 秒级）。
// 统一放在本包，避免各消费方各写一套格式导致产物时间口径不一致。
func Stamp() string { return time.Now().Format("2006-01-02T15:04:05Z07:00") }
