// mailauth_cmd.go —— `diting mailauth -d <domain>` 邮件认证体检子命令。
//
// 只读：查询面仅 DNS TXT（不发 HTTP、不连 SMTP、不抓 BIMI 的 Logo/VMC 地址）。
// 产物：out/<domain>/mailauth.json + mailauth.txt，并收一份到
// out/<domain>/evidence/mailauth/（report 证据包打包范围）。
package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Kur1sulab/diting/engine-go/jsonx"
	"github.com/Kur1sulab/diting/engine-go/mailauth"
	"github.com/Kur1sulab/diting/engine-go/netutil"
)

const mailauthUsage = `mailauth -d <domain> [--selectors default,google,s1] [--timeout 5s] ` +
	`[--budget 60s] [--max-depth 5] [--json] [--no-save]
  只读邮件认证体检：DMARC 策略 / SPF include 链与 RFC 7208 lookup 计数 /
  DKIM 常见选择器公钥 / BIMI。纯 DNS TXT，零 HTTP 请求。`

// runMailauth 执行体检并落盘。lookup 为 nil 时走 net.DefaultResolver；
// 单测传假 resolver，避免 CI 打真 DNS（与 typosquat 的注入纪律一致）。
func runMailauth(rest []string) int {
	return runMailauthWith(rest, nil)
}

func runMailauthWith(rest []string, lookup mailauth.TXTLookup) int {
	fs := newFlagSet()
	d := fs.String("d", "", "")
	dAlias := fs.String("domain", "", "")
	selectors := fs.String("selectors", "", "")
	timeout := fs.Duration("timeout", 5*time.Second, "")
	budget := fs.Duration("budget", 60*time.Second, "")
	maxDepth := fs.Int("max-depth", 5, "")
	asJSON := fs.Bool("json", false, "")
	noSave := fs.Bool("no-save", false, "")

	if code := parseOrUsage(fs, rest, "mailauth", mailauthUsage); code >= 0 {
		return code
	}

	domain := strings.TrimSpace(pickAliasLastWins(rest, map[string]*string{
		"-d": d, "--domain": dAlias,
	}))
	if domain == "" {
		return missingArgs("mailauth", mailauthUsage)
	}
	if bad, why := invalidDomainShape(domain); bad {
		fmt.Printf("[!] 非法域名（%s）: %q\n", why, domain)
		return 2
	}

	opts := mailauth.Options{
		Domain:   domain,
		Timeout:  *timeout,
		Budget:   *budget,
		MaxDepth: *maxDepth,
		Resolver: lookup,
	}
	if s := strings.TrimSpace(*selectors); s != "" {
		var sel []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				sel = append(sel, p)
			}
		}
		opts.Selectors = sel
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	rep, err := mailauth.Run(ctx, opts)
	if err != nil {
		fmt.Printf("[!] 体检失败: %v\n", err)
		return 1
	}

	fmt.Print(mailauth.RenderText(rep))

	if *asJSON {
		fmt.Println(jsonx.Pretty(rep))
	}

	if *noSave {
		return 0
	}
	out, err := MakeOutdir(rep.Domain)
	if err != nil {
		fmt.Printf("[!] 产物目录创建失败: %v\n", err)
		return 1
	}
	body := jsonx.Pretty(rep)
	if _, err := netutil.SafeWrite(out, "mailauth.json", body); err != nil {
		fmt.Printf("[!] mailauth.json 写盘失败: %v\n", err)
		return 1
	}
	txtPath, err := netutil.SafeWrite(out, "mailauth.txt", mailauth.RenderText(rep))
	if err != nil {
		fmt.Printf("[!] mailauth.txt 写盘失败: %v\n", err)
	}
	if dir, err := netutil.SafeSubdir(out, "evidence", "mailauth"); err == nil {
		if _, err := netutil.SafeWrite(dir, "mailauth.json", body); err != nil {
			fmt.Printf("[!] 证据副本写盘失败（不影响主产物）: %v\n", err)
		}
	}

	fmt.Printf("\n[+] 产物: mailauth.json  mailauth.txt（%s）\n", out)
	if txtPath != "" {
		fmt.Printf("    证据: %s\n", txtPath)
	}
	return 0
}
