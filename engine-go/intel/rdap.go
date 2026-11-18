package intel

// rdap.go —— 域名注册信息（WHOIS 的现代替代）：RDAP over HTTPS。
//
// 为什么不用 43 端口的 whois：国内网络对 43 端口与各 registry 的 whois 服务
// 限制多、解析各家用各家格式；RDAP 是 IANA 标准（RFC 9082/9083），
// 统一 JSON，且 data.iana.org 提供 TLD→服务端点的 bootstrap 表。
//
// 查询顺序：
//  1. data.iana.org/rdap/dns.json 取该 TLD 的 RDAP base URL（缓存一次）；
//  2. GET {base}domain/{domain}；
//  3. 归一化出注册商 / 注册/到期时间 / 状态 / NS / 注册人实体名。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// WhoisInfo 归一化后的域名注册信息（全部字段来自实测响应，缺失留空）。
type WhoisInfo struct {
	Domain       string   `json:"domain"`
	Provider     string   `json:"provider,omitempty"` // RDAP 服务端点
	Registrar    string   `json:"registrar,omitempty"`
	Status       []string `json:"status,omitempty"`
	RegisteredAt string   `json:"registered_at,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	UpdatedAt    string   `json:"updated_at,omitempty"`
	Nameservers  []string `json:"nameservers,omitempty"`
	Registrant   string   `json:"registrant,omitempty"`
	Error        string   `json:"error,omitempty"`
}

var (
	rdapBootstrapOnce sync.Once
	rdapBootstrap     map[string]string // tld → base url
	rdapBootstrapErr  error
	// BootstrapURL 可注入（测试打 httptest stub）。
	BootstrapURL = "https://data.iana.org/rdap/dns.json"
)

func loadBootstrap(ctx context.Context, o Options) (map[string]string, error) {
	rdapBootstrapOnce.Do(func() {
		body, _, err := fetchJSON(ctx, o, BootstrapURL, nil, nil, "GET")
		if err != nil {
			rdapBootstrapErr = err
			return
		}
		var data struct {
			Services [][][]string `json:"services"`
		}
		if err := json.Unmarshal([]byte(body), &data); err != nil {
			rdapBootstrapErr = fmt.Errorf("bootstrap 非 JSON")
			return
		}
		m := map[string]string{}
		for _, svc := range data.Services {
			if len(svc) < 2 || len(svc[1]) == 0 {
				continue
			}
			base := svc[1][0]
			for _, tld := range svc[0] {
				m[strings.ToLower(tld)] = base
			}
		}
		if len(m) == 0 {
			rdapBootstrapErr = fmt.Errorf("bootstrap 表为空")
			return
		}
		rdapBootstrap = m
	})
	return rdapBootstrap, rdapBootstrapErr
}

// Whois 查询域名注册信息。target 为域名；IP 请用 LookupIP。
func Whois(ctx context.Context, target string, o Options) *WhoisInfo {
	info := &WhoisInfo{Domain: target}
	if o.Timeout <= 0 {
		o.Timeout = 25 * time.Second
	}
	tld := target
	if i := strings.LastIndex(target, "."); i >= 0 {
		tld = target[i+1:]
	}
	boot, err := loadBootstrap(ctx, o)
	if err != nil {
		info.Error = "RDAP bootstrap 获取失败: " + err.Error()
		return info
	}
	base, ok := boot[strings.ToLower(tld)]
	if !ok {
		// RDAP 不覆盖该 TLD（实测 .cn 从未进入 bootstrap 表）→ 直接走 43 端口兜底
		fb := WhoisFallback(ctx, target, o)
		if fb.Error == "" {
			return fb
		}
		fb.Error = fmt.Sprintf("RDAP 无该 TLD 端点；43 端口兜底也失败：%s", fb.Error)
		return fb
	}
	info.Provider = base
	u := strings.TrimRight(base, "/") + "/domain/" + url.PathEscape(target)
	body, _, err := fetchJSON(ctx, o, u, nil, nil, "GET")
	if err != nil {
		fb := WhoisFallback(ctx, target, o)
		if fb.Error == "" {
			return fb
		}
		fb.Error = fmt.Sprintf("RDAP 请求失败（%s）；43 端口兜底也失败：%s", err, fb.Error)
		return fb
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		info.Error = "响应非 JSON"
		return info
	}
	parseRDAPDomain(data, info)
	return info
}

func parseRDAPDomain(data map[string]any, info *WhoisInfo) {
	info.Status = toStrings(data["status"])
	for _, ns := range asList(data["nameservers"]) {
		if n := pickStr(ns, "ldhName"); n != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(n))
		}
	}
	sort.Strings(info.Nameservers)
	for _, ev := range asList(data["events"]) {
		action := pickStr(ev, "eventAction")
		date := pickStr(ev, "eventDate")
		switch action {
		case "registration":
			info.RegisteredAt = date
		case "expiration":
			info.ExpiresAt = date
		case "last changed", "last update":
			info.UpdatedAt = date
		}
	}
	for _, ent := range asList(data["entities"]) {
		roles := toStrings(ent["roles"])
		name := entityName(ent)
		if name == "" {
			continue
		}
		if hasStr(roles, "registrar") && info.Registrar == "" {
			info.Registrar = name
		}
		if (hasStr(roles, "registrant") || hasStr(roles, "administrative")) && info.Registrant == "" {
			info.Registrant = name
		}
	}
}

func entityName(ent map[string]any) string {
	// vcardArray 是 ["vcard", [["version",{},"text","4.0"],["fn",{},"text","Name"],…]]
	// 注意：不能对 vcardArray 直接做字符串化——首元素恒为 "vcard" 标签，
	// 会把注册商写成 "vcard"（实测踩过）。
	if arr, ok := ent["vcardArray"].([]any); ok && len(arr) >= 2 {
		if props, ok := arr[1].([]any); ok {
			for _, p := range props {
				kv, ok := p.([]any)
				if !ok || len(kv) < 4 {
					continue
				}
				if key, _ := kv[0].(string); key == "fn" {
					if val, _ := kv[3].(string); val != "" {
						return val
					}
				}
			}
		}
	}
	if h, ok := ent["handle"].(string); ok {
		return h
	}
	return ""
}

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, it := range arr {
		if s, ok := it.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func hasStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// resetRDAPCache 仅供本包测试：清掉 bootstrap 缓存后重拉。
func resetRDAPCache() {
	rdapBootstrapOnce = sync.Once{}
	rdapBootstrap = nil
	rdapBootstrapErr = nil
}
