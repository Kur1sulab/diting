package intel

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// allProviders 注册表。顺序即输出顺序（先空间测绘引擎，后免 key 被动源）。
var allProviders = []Provider{
	// ── 空间测绘引擎（需 key，未配置自动跳过）──
	{Name: "fofa", Kind: "space", Env: []string{"FOFA_KEY"}, Doc: "FOFA  host=\"…\"/domain=\"…\"", Query: queryFOFA},
	{Name: "hunter", Kind: "space", Env: []string{"HUNTER_KEY"}, Doc: "奇安信 Hunter  domain=\"…\"", Query: queryHunter},
	{Name: "quake", Kind: "space", Env: []string{"QUAKE_TOKEN"}, Doc: "360 Quake  domain:\"…\"", Query: queryQuake},
	{Name: "zoomeye", Kind: "space", Env: []string{"ZOOMEYE_KEY"}, Doc: "ZoomEye  site:…", Query: queryZoomEye},
	{Name: "shodan", Kind: "space", Env: []string{"SHODAN_KEY"}, Doc: "Shodan  hostname:…", Query: queryShodan},
	{Name: "censys", Kind: "space", Env: []string{"CENSYS_TOKEN", "CENSYS_API_SECRET"}, Doc: "Censys v3  host.name:…", Query: queryCensys},
	{Name: "netlas", Kind: "space", Env: []string{"NETLAS_KEY"}, Doc: "Netlas  domain:…", Query: queryNetlas},
	{Name: "zerozone", Kind: "space", Env: []string{"ZEROZONE_KEY"}, Doc: "0.zone  domain", Query: queryZeroZone},

	// ── 免 key 被动源（默认开启）──
	{Name: "crtsh", Kind: "passive", Free: true, Doc: "crt.sh 证书透明日志", Query: queryCrtSh},
	{Name: "certspotter", Kind: "passive", Free: true, Doc: "Cert Spotter 证书日志", Query: queryCertSpotter},
	{Name: "hackertarget", Kind: "passive", Free: true, Doc: "hackertarget 被动 DNS", Query: queryHackerTarget},
	{Name: "rapiddns", Kind: "passive", Free: true, Doc: "RapidDNS 聚合 DNS", Query: queryRapidDNS},
	{Name: "urlscan", Kind: "passive", Free: true, Doc: "urlscan.io 公开扫描记录", Query: queryURLScan},
	{Name: "subdomaincenter", Kind: "passive", Free: true, Doc: "subdomain.center 聚合", Query: querySubdomainCenter},
}

// AllProviders 返回注册表副本（providers 子命令用）。
func AllProviders() []Provider {
	out := make([]Provider, len(allProviders))
	copy(out, allProviders)
	return out
}

// ProviderByName 按名取源（大小写不敏感）。
func ProviderByName(name string) (Provider, bool) {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, p := range allProviders {
		if p.Name == n {
			return p, true
		}
	}
	return Provider{}, false
}

// Configured 判断该源是否可用：免 key 源恒真；需 key 源要求 Env 里至少一项非空。
func Configured(p Provider) bool {
	if p.Free {
		return true
	}
	for _, n := range p.Env {
		if Env(n) != "" {
			return true
		}
	}
	return false
}

// selectProviders 按 Options 选源：
//   - Sources 非空 → 只跑列出的名字（拼错/未配置会返回 error stat 提示）；
//   - Sources 为空 → 跑全部已配置的源（含免 key 源）。
func selectProviders(o Options) []Provider {
	if len(o.Sources) == 0 {
		var out []Provider
		for _, p := range allProviders {
			if Configured(p) {
				out = append(out, p)
			}
		}
		return out
	}
	seen := map[string]bool{}
	var out []Provider
	for _, name := range o.Sources {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" || seen[n] || n == "all" {
			if n == "all" {
				return allProviders
			}
			continue
		}
		seen[n] = true
		if p, ok := ProviderByName(n); ok {
			out = append(out, p)
			continue
		}
		// 未知源名：塞一个只报错的占位 Provider，让汇总里能看见拼错
		out = append(out, Provider{
			Name: n, Kind: "unknown",
			Query: func(ctx context.Context, target string, opt Options) ([]Record, error) {
				return nil, fmt.Errorf("未知数据源 %q（可用：%s）", n, strings.Join(ProviderNames(), ","))
			},
		})
	}
	return out
}

// ProviderNames 全部源名（帮助文本/错误提示用）。
func ProviderNames() []string {
	var out []string
	for _, p := range allProviders {
		out = append(out, p.Name)
	}
	sort.Strings(out)
	return out
}

// StatusTable 打印源状态表（providers 子命令）。
func StatusTable(o Options) string {
	nameW, envW := 4, 3
	for _, p := range allProviders {
		if len(p.Name) > nameW {
			nameW = len(p.Name)
		}
		e := strings.Join(p.Env, " | ")
		if len(e) > envW {
			envW = len(e)
		}
	}
	if envW > 34 {
		envW = 34
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%-*s  %-8s  %-*s  %s\n", nameW, "源", "类型", envW, "凭据", "状态")
	sb.WriteString(strings.Repeat("─", nameW+envW+30) + "\n")
	for _, p := range allProviders {
		env := "-"
		status := "免 key（默认启用）"
		if !p.Free {
			env = strings.Join(p.Env, " | ")
			if Configured(p) {
				st := Status(p.Env...)
				status = "已配置 " + st.Masked
			} else {
				status = "未配置（跳过）"
			}
		}
		fmt.Fprintf(&sb, "%-*s  %-8s  %-*s  %s\n", nameW, p.Name, p.Kind, envW, truncASCII(env, envW), status)
	}
	if f := KeysFile(); f != "" {
		fmt.Fprintf(&sb, "\n凭据文件：%s\n", f)
	} else {
		sb.WriteString("\n凭据文件：未找到（~/.diting/keys.env）\n")
	}
	return sb.String()
}

func truncASCII(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
