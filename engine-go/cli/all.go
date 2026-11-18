// Package cli —— `all` 子命令：一键全流程编排。
//
// 对应 recon.py:120-178 的 cmd_all（唯一行为基准）：
//   - 目标自动识别 IP / 域名，两条流水线分支；
//   - 每个模块级步骤都包一层 _run_step（recon.py:44-62）：发 start/done|fail
//     进度事件，fatal=true 时异常上抛终止流水线，fatal=false 时降级为警告；
//   - 步骤顺序、警告文案、输出目录语义与 Python 逐项对齐，不做"优化"。
//
// 终态差异（Go 侧比 Python 多）：patchdiff 不在 all 里跑（Python 同）——
// 它需要 -r 指定本地仓库，无法从 target 推导。
package cli

import (
	"fmt"

	"github.com/Kur1sulab/src-recon-tool/engine-go/apiunauth"
	"github.com/Kur1sulab/src-recon-tool/engine-go/asset"
	"github.com/Kur1sulab/src-recon-tool/engine-go/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/paths"
	"github.com/Kur1sulab/src-recon-tool/engine-go/report"
	"github.com/Kur1sulab/src-recon-tool/engine-go/reverseip"
	"github.com/Kur1sulab/src-recon-tool/engine-go/subdomain"
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

// runAllIP：recon.py:126-155 —— 反查域名 → 逐个 ICP → 指纹 → API → 端口/JS。
func runAllIP(target, out string) int {
	var doms []string
	// reverse 是 fatal 步骤：拿不到反查结果整个流水线没有意义，与 Python 一致。
	var revErr error
	if err := step("reverse", true, func() error {
		doms = reverseip.RunReverse(target, out)
		return nil
	}); err != nil {
		revErr = err
	}
	if revErr != nil {
		fmt.Printf("[!] reverse: %v\n", revErr)
		return 1
	}

	// 备案查询最多查 5 个，避免限频；单条失败只打印不影响主流程（recon.py:131-137）。
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
				icp.RunICP(d, out)
			}()
		}
		return nil
	})

	// 裸 IP 常被按域名路由的站点返回 404，优先用反查出的域名探测（recon.py:139-143）。
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

	// 第二轮升级：端口扫描 + JS 情报（失败只警告，不阻断主流程；recon.py:150-154）。
	_ = step("portscan", false, func() error { return runPortStep(target, out) })
	_ = step("jsintel", false, func() error { return runJSStep(base, out) })

	return finishAll(out, target)
}

// runAllDomain：recon.py:156-173 —— 子域 → 存活 → 资产 → ICP → 指纹 → 路径 → API → JS/端口。
func runAllDomain(target, out string) int {
	if err := step("subdomain", true, func() error {
		_, err := subdomain.Run(target, out)
		return err
	}); err != nil {
		fmt.Printf("[!] subdomain: %v\n", err)
		return 1
	}

	// 审计补充：证书日志含大量失效域名，必须验证存活（recon.py:162）。
	_ = step("verify", true, func() error {
		subdomain.RunVerify(out, 8, true)
		return nil
	})

	if err := step("asset", true, func() error {
		asset.RunAsset(target, out)
		return nil
	}); err != nil {
		fmt.Printf("[!] asset: %v\n", err)
		return 1
	}

	_ = step("icp", false, func() error {
		icp.RunICP(target, out)
		return nil
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

	// 第二轮升级：JS 情报 + 端口扫描（失败只警告，不阻断主流程；recon.py:169-173）。
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
