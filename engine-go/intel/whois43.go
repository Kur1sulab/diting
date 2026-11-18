package intel

// whois43.go —— 端口 43 WHOIS 兜底通道。
//
// 为什么需要它：RDAP 是 IANA 标准，但**并不是每个注册局都进了 bootstrap 表**——
// 实测 `data.iana.org/rdap/dns.json` 里 1203 个 TLD 完全没有 `cn`（CNNIC 未登记），
// 于是所有 .cn / .中国 域名走 RDAP 会直接落到「该 TLD 不在表内」。
// 而 43 端口 whois 对 .cn 一直可用（实测 whois.cnnic.cn 返回注册人/注册商/NS）。
//
// 策略：RDAP 优先（结构化、走 443），RDAP 覆盖不到或请求失败 → 落到本文件。
// 一次查询最多跟两跳 referral（iana → 注册局），防止环。
//
// 纪律：只读查询，不改任何注册信息；解析失败的字段留空，不猜。

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// whoisServers 常见 TLD → whois 服务器。命中即用，未命中走 whois.iana.org 取 referral。
// 只收录「已实测可连」或注册局公开文档写明的；拒绝连接的（如 whois.edu.cn）也记上，
// 让报错指向具体服务器而不是含糊的「查不到」。
var whoisServers = map[string]string{
	"cn":     "whois.cnnic.cn",
	"中国":     "whois.cnnic.cn",
	"公司":     "whois.cnnic.cn",
	"网络":     "whois.cnnic.cn",
	"com":    "whois.verisign-grs.com",
	"net":    "whois.verisign-grs.com",
	"org":    "whois.pir.org",
	"info":   "whois.afilias.net",
	"io":     "whois.nic.io",
	"co":     "whois.nic.co",
	"me":     "whois.nic.me",
	"dev":    "whois.nic.google",
	"app":    "whois.nic.google",
	"xyz":    "whois.nic.xyz",
	"top":    "whois.nic.top",
	"edu.cn": "whois.edu.cn", // 清华 CERNET 注册局；部分出口被拒（fail 时要如实说）
	"gov.cn": "whois.cnnic.cn",
	"ac.cn":  "whois.cnnic.cn",
	"com.cn": "whois.cnnic.cn",
	"net.cn": "whois.cnnic.cn",
	"org.cn": "whois.cnnic.cn",
}

// whoisTimeout 单次 43 连接的读写总时长。
var whoisTimeout = 12 * time.Second

// whoisRaw 向 server 发一次查询并读完响应；遇到 refer:/whois: 跳一次（最多 maxHops）。
func whoisRaw(ctx context.Context, server, query string, maxHops int) (string, string, error) {
	cur := server
	for hop := 0; hop <= maxHops; hop++ {
		text, err := whoisOnce(ctx, cur, query)
		if err != nil {
			return "", cur, err
		}
		next := referralServer(text)
		if next == "" || next == cur {
			return text, cur, nil
		}
		cur = next
	}
	return "", cur, fmt.Errorf("referral 跳数超限")
}

func whoisOnce(ctx context.Context, server, query string) (string, error) {
	d := net.Dialer{Timeout: whoisTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	if err != nil {
		return "", fmt.Errorf("%s:43 连接失败: %v", server, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(whoisTimeout))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", fmt.Errorf("%s 写入失败: %v", server, err)
	}
	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
			if sb.Len() > 1<<20 { // 1MB 上限：whois 响应不该更大
				break
			}
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

var referRe = regexp.MustCompile(`(?im)^\s*(?:refer|referralserver|whois|registrar whois server)\s*:\s*(\S+)`)

// referralServer 从响应里取下一跳 whois 服务器（iana 的 "refer:" 与部分注册局的
// "Registrar WHOIS Server:" 都认）。
func referralServer(text string) string {
	m := referRe.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	s := strings.TrimSpace(strings.TrimSuffix(m[1], "."))
	s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	if i := strings.IndexAny(s, "/:"); i > 0 {
		s = s[:i]
	}
	// 只接受形如 host 的值，挡掉 "whois.iana.org" 之外的噪声
	if !strings.Contains(s, ".") || strings.ContainsAny(s, " \t") {
		return ""
	}
	return s
}

// WhoisFallback 用 43 端口查域名注册信息。返回的 Provider 形如 "whois43:whois.cnnic.cn"。
func WhoisFallback(ctx context.Context, domain string, o Options) *WhoisInfo {
	info := &WhoisInfo{Domain: domain}
	tld := tldOf(domain)
	server, ok := whoisServers[strings.ToLower(tld)]
	if !ok {
		server = "whois.iana.org" // 未知 TLD：先问 IANA 要 referral
	}
	text, used, err := whoisRaw(ctx, server, domain, 2)
	if err != nil {
		info.Provider = "whois43:" + server
		info.Error = err.Error()
		return info
	}
	info.Provider = "whois43:" + used
	if strings.TrimSpace(text) == "" {
		info.Error = "注册局返回空响应"
		return info
	}
	// 注册局明确回「不在本注册局 / 无法在线注册」= 没有可解析数据，但当证据保留
	lower := strings.ToLower(text)
	if strings.Contains(lower, "out of this registry") || strings.Contains(lower, "can not be registered online") {
		info.Error = truncRunes(strings.TrimSpace(text), 120)
		return info
	}
	parseWhoisText(text, info)
	if info.Registrar == "" && len(info.Nameservers) == 0 && info.RegisteredAt == "" {
		info.Error = "响应中没有可识别的注册字段"
	}
	return info
}

func tldOf(domain string) string {
	// .edu.cn / .com.cn 这类二级后缀优先
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) >= 3 {
		two := parts[len(parts)-2] + "." + parts[len(parts)-1]
		switch two {
		case "edu.cn", "gov.cn", "ac.cn", "com.cn", "net.cn", "org.cn":
			return two
		}
	}
	if len(parts) >= 2 {
		return parts[len(parts)-1]
	}
	return domain
}

var (
	whoisRegRe   = regexp.MustCompile(`(?im)^\s*(?:sponsoring registrar|registrar name|registrar)\s*:\s*(.+)$`)
	whoisRegOrg  = regexp.MustCompile(`(?im)^\s*registrant(?:\s+organization)?\s*:\s*(.+)$`)
	whoisCreateR = regexp.MustCompile(`(?im)^\s*(?:registration time|creation date|created(?: on)?|registration date|domain registration date)\s*:\s*(.+)$`)
	whoisExpireR = regexp.MustCompile(`(?im)^\s*(?:expiration time|registry expiry date|expiration date|expiry date|paid-till)\s*:\s*(.+)$`)
	whoisUpdateR = regexp.MustCompile(`(?im)^\s*(?:updated date|last updated(?: on)?|update date|last-modified)\s*:\s*(.+)$`)
	whoisStatusR = regexp.MustCompile(`(?im)^\s*(?:domain status|status)\s*:\s*(.+)$`)
	whoisNSR     = regexp.MustCompile(`(?im)^\s*(?:name server|nserver|nameserver)\s*:\s*(.+)$`)
)

// parseWhoisText 从原始文本抽字段。各家格式不同，只取有把握的键。
func parseWhoisText(text string, info *WhoisInfo) {
	pick := func(re *regexp.Regexp) string {
		if m := re.FindStringSubmatch(text); len(m) > 1 {
			return strings.TrimSpace(m[1])
		}
		return ""
	}
	info.Registrar = pick(whoisRegRe)
	info.Registrant = pick(whoisRegOrg)
	info.RegisteredAt = pick(whoisCreateR)
	info.ExpiresAt = pick(whoisExpireR)
	info.UpdatedAt = pick(whoisUpdateR)
	seen := map[string]bool{}
	for _, m := range whoisStatusR.FindAllStringSubmatch(text, -1) {
		v := strings.TrimSpace(m[1])
		if v != "" && !seen[v] {
			seen[v] = true
			info.Status = append(info.Status, v)
		}
	}
	seenNS := map[string]bool{}
	for _, m := range whoisNSR.FindAllStringSubmatch(text, -1) {
		v := strings.ToLower(strings.TrimSpace(m[1]))
		if v == "" || seenNS[v] {
			continue
		}
		seenNS[v] = true
		info.Nameservers = append(info.Nameservers, v)
	}
}
