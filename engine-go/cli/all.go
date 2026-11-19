// Package cli —— `all` 子命令：一键全流程编排。
//
// 对应 diting.py:120-178 的 cmd_all（唯一行为基准）：
//   - 目标自动识别 IP / 域名，两条流水线分支；
//   - 每个模块级步骤都包一层 _run_step（diting.py:44-62）：发 start/done|fail
//     进度事件，fatal=true 时异常上抛终止流水线，fatal=false 时降级为警告；
//   - 步骤顺序、警告文案、输出目录语义与 Python 逐项对齐，不做"优化"。
//
// 终态差异（Go 侧比 Python 多）：patchdiff 不在 all 里跑（Python 同）——
// 它需要 -r 指定本地仓库，无法从 target 推导。
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Kur1sulab/diting/engine-go/apiunauth"
	"github.com/Kur1sulab/diting/engine-go/fingerprint"
	"github.com/Kur1sulab/diting/engine-go/icp"
	"github.com/Kur1sulab/diting/engine-go/intel"
	"github.com/Kur1sulab/diting/engine-go/netutil"
	"github.com/Kur1sulab/diting/engine-go/paths"
	"github.com/Kur1sulab/diting/engine-go/report"
	"github.com/Kur1sulab/diting/engine-go/reverseip"
	"github.com/Kur1sulab/diting/engine-go/subdomain"
)

// step 是 _run_step 的 Go 版：发事件 + 按 fatal 决定是否把错误当致命。
// 返回 (值, 是否继续)：err != nil && fatal 时调用方立即退出非零。
func step(name string, fatal bool, fn func() error) error {
	emit("start", name, "")
	if err := fn(); err != nil {
		emit("fail", name, err.Error())
		if fatal {
			return err
		}
		fmt.Printf("[!] %s 失败（不影响主流程）: %v\n", name, err)
		return nil
	}
	emit("done", name, "")
	return nil
}

// runAll 执行一键全流程，返回进程退出码。
func runAll(target string) int {
	out, err := MakeOutdir(target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}

	if IsIP(target) {
		return runAllIP(target, out)
	}
	return runAllDomain(target, out)
}

// runAllIP：diting.py:126-155 —— 反查域名 → 逐个 ICP → 指纹 → API → 端口/JS。
func runAllIP(target, out string) int {
	var doms []string
	// reverse 是 fatal 步骤：拿不到反查结果整个流水线没有意义，与 Python 一致。
	var revErr error
	if err := step("reverse", true, func() error {
		// 多源反查（hackertarget + rapiddns）；两源都空时退回旧单源实现再试一次。
		recs, _ := intel.ReverseIP(context.Background(), target, intel.Options{Ctx: context.Background(), Limit: 500})
		for _, r := range recs {
			doms = append(doms, r.Host)
		}
		if len(doms) == 0 {
			doms = reverseip.RunReverse(target, out)
			return nil
		}
		var sb strings.Builder
		for _, r := range recs {
			sb.WriteString(r.Host + "\n")
		}
		_, err := netutil.SafeWrite(out, "reverse.txt", sb.String())
		return err
	}); err != nil {
		revErr = err
	}
	if revErr != nil {
		fmt.Printf("[!] reverse: %v\n", revErr)
		return 1
	}

	// 备案查询最多查 5 个，避免限频；单条失败只打印不影响主流程（diting.py:131-137）。
	_ = step("icp", false, func() error {
		for i, d := range doms {
			if i >= 5 {
				break
			}
			func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Printf("[!] %s 备案查询失败: %v\n", d, r)
					}
				}()
				icp.RunICPChain(context.Background(), d, out, icp.ChainOptions{})
			}()
		}
		return nil
	})

	// IP 归属（geo/ISP/ASN，免 key）——非致命，失败只警告。
	_ = step("ipinfo", false, func() error {
		info := intel.LookupIP(context.Background(), target, intel.Options{})
		if info.Status != "success" {
			msg := info.Error
			if msg == "" {
				msg = "查询失败"
			}
			return fmt.Errorf("%s", msg)
		}
		b, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}
		_, err = netutil.SafeWrite(out, "ipinfo_"+target+".json", string(b))
		fmt.Printf("[+] IP 归属: %s\n", intel.FormatIPInfo(info))
		return err
	})

	// 裸 IP 常被按域名路由的站点返回 404，优先用反查出的域名探测（diting.py:139-143）。
	host := target
	if len(doms) > 0 {
		host = doms[0]
		fmt.Printf("[*] 用反查域名 %s 作为探测入口（裸 IP %s 直连多为 404/默认页）\n", host, target)
	}
	base := PickBase(host)
	fmt.Printf("[*] 目标站点探测 base = %s\n", base)

	if err := step("fingerprint", true, func() error {
		fingerprint.RunFingerprint(base, out)
		return nil
	}); err != nil {
		fmt.Printf("[!] fingerprint: %v\n", err)
		return 1
	}
	if err := step("api", true, func() error {
		_, err := apiunauth.RunAPI(base, out, false)
		return err
	}); err != nil {
		fmt.Printf("[!] api: %v\n", err)
		return 1
	}

	// 第二轮升级：端口扫描 + JS 情报（失败只警告，不阻断主流程；diting.py:150-154）。
	_ = step("portscan", false, func() error { return runPortStep(target, out) })
	_ = step("jsintel", false, func() error { return runJSStep(base, out) })

	return finishAll(out, target)
}

// runAllDomain：diting.py:156-173 —— 子域 → 存活 → 资产 → ICP → 指纹 → 路径 → API → JS/端口。
func runAllDomain(target, out string) int {
	if err := step("subdomain", true, func() error {
		_, err := subdomain.Run(target, out)
		return err
	}); err != nil {
		fmt.Printf("[!] subdomain: %v\n", err)
		return 1
	}

	// 审计补充：证书日志含大量失效域名，必须验证存活（diting.py:162）。
	_ = step("verify", true, func() error {
		subdomain.RunVerify(out, 8, true)
		return nil
	})

	if err := step("asset", true, func() error {
		// 多源资产测绘（空间测绘 + 免 key 被动源）。未配置 key 的源自动跳过，
		// 免 key 源仍会给结果；写盘失败才算这一步失败。
		_, err := intel.Run(target, out, intel.Options{Ctx: context.Background()})
		return err
	}); err != nil {
		fmt.Printf("[!] asset: %v\n", err)
		return 1
	}

	// 备案走三段链（apihz → 工信部官方 → beianx），限制频也要在报告里可辨。
	_ = step("icp", false, func() error {
		icp.RunICPChain(context.Background(), target, out, icp.ChainOptions{})
		return nil
	})

	// 域名注册信息（RDAP，免 key）——失败不阻断。
	_ = step("whois", false, func() error {
		info := intel.Whois(context.Background(), target, intel.Options{})
		if info.Error != "" {
			return fmt.Errorf("%s", info.Error)
		}
		b, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return err
		}
		_, err = netutil.SafeWrite(out, "whois_"+target+".json", string(b))
		return err
	})

	base := PickBase(target)
	fmt.Printf("[*] 目标站点探测 base = %s\n", base)

	if err := step("fingerprint", true, func() error {
		fingerprint.RunFingerprint(base, out)
		return nil
	}); err != nil {
		fmt.Printf("[!] fingerprint: %v\n", err)
		return 1
	}
	if err := step("paths", true, func() error {
		_, err := paths.RunPaths(base, out)
		return err
	}); err != nil {
		fmt.Printf("[!] paths: %v\n", err)
		return 1
	}
	if err := step("api", true, func() error {
		_, err := apiunauth.RunAPI(base, out, false)
		return err
	}); err != nil {
		fmt.Printf("[!] api: %v\n", err)
		return 1
	}

	// 第二轮升级：JS 情报 + 端口扫描（失败只警告，不阻断主流程；diting.py:169-173）。
	_ = step("jsintel", false, func() error { return runJSStep(base, out) })
	_ = step("portscan", false, func() error { return runPortStep(target, out) })

	return finishAll(out, target)
}

// finishAll：report 收尾（聚合资产档案 + 证据包），Python 侧同为 fatal 步骤。
func finishAll(out, target string) int {
	if err := step("report", true, func() error {
		report.RunReport(out, target)
		return nil
	}); err != nil {
		fmt.Printf("[!] report: %v\n", err)
		return 1
	}
	fmt.Printf("[+] 全流程完成，输出目录: %s\n", out)
	return 0
}
