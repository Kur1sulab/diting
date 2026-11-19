package cli

// recon_cmds.go —— 第二轮升级三个子命令（jsintel / portscan / patchdiff）的门面。
// 参数与 diting.py:196-213 的 argparse 定义逐项对齐（含默认值），
// 具体实现在 engine-go/jsintel、engine-go/portscan、engine-go/patchdiff。
//
// 与 Python 侧的对齐点（逐项可对照）：
//   jsintel   diting.py:198-200 → run_jsintel(url, out, workers=6, max_files=60)
//   portscan  diting.py:201-204 → run_portscan(target, out, ports="", timeout=1.5, workers=32)
//   patchdiff diting.py:211-213 → run_patchdiff(repo, commit, range, limit=20, emit_rule, outdir=out/patchdiff)

import (
	"fmt"

	"github.com/Kur1sulab/diting/engine-go/jsintel"
	"github.com/Kur1sulab/diting/engine-go/portscan"
)

// dispatchRecon 分发 jsintel / portscan 两个子命令（patchdiff 的 case 在 cli.go）。
func dispatchRecon(cmd string, rest []string) int {
	switch cmd {
	case "jsintel":
		return cmdJSIntel(rest)
	case "portscan":
		return dispatchPortscan(rest)
	}
	fmt.Printf("[!] 未知子命令: %q\n", cmd)
	return 2
}

// cmdJSIntel：jsintel -u/--url [--max-files 60] [--workers 6]
func cmdJSIntel(rest []string) int {
	fs := newFlagSet()
	u := fs.String("u", "", "")
	uAlias := fs.String("url", "", "")
	maxFiles := fs.Int("max-files", jsintel.DefaultMaxFiles, "最多下载的外链 JS 数")
	workers := fs.Int("workers", jsintel.DefaultWorkers, "下载并发")
	if c := parseOrUsage(fs, rest, "jsintel", "jsintel -u <url> [--max-files N] [--workers N]"); c != -1 {
		return c
	}
	url := pickAliasLastWins(rest, map[string]*string{"-u": u, "--url": uAlias})
	if url == "" {
		return missingArgs("jsintel", "jsintel -u <url>")
	}
	out, err := MakeOutdir(url)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}
	if _, err := jsintel.RunJSIntel(url, out, *workers, *maxFiles, jsintel.DefaultTimeout); err != nil {
		return 1
	}
	return 0
}

// dispatchPortscan：portscan -t/--target [--ports ""] [--timeout 1.5] [--workers 32]
// 逐项对齐 diting.py:201-204 的 argparse；`all` 流水线里的同名步骤在 port_step.go。
func dispatchPortscan(rest []string) int {
	fs := newFlagSet()
	t := fs.String("t", "", "")
	tAlias := fs.String("target", "", "")
	ports := fs.String("ports", "", "如 80,443,8000-8100（默认内置常用端口表 ~100 个）")
	timeout := fs.Float64("timeout", portscan.DefaultTimeout, "单端口连接超时秒数（默认 1.5）")
	workers := fs.Int("workers", portscan.DefaultWorkers, "并发数（默认 32，上限 32）")
	usage := "portscan -t <target> [--ports <spec>] [--timeout <s>] [--workers <n>]"
	if c := parseOrUsage(fs, rest, "portscan", usage); c != -1 {
		return c
	}
	target := pickAliasLastWins(rest, map[string]*string{"-t": t, "--target": tAlias})
	if target == "" {
		return missingArgs("portscan", usage)
	}
	out, err := MakeOutdir(target)
	if err != nil {
		fmt.Printf("[!] 输出目录创建失败: %v\n", err)
		return 1
	}
	if _, err := portscan.RunPortscan(target, out, *ports, *timeout, *workers); err != nil {
		return 1 // 写盘失败 → fail 事件 + exit 1（fix3 口径）
	}
	return 0
}
