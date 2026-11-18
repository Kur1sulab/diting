package cli

// port_step.go —— `all` 流水线里的 portscan 步骤接线（实现在 engine-go/portscan）。
// 默认参数对齐 shinra.py:153/173 的 run_portscan(target, out)；子命令入口在
// cli/recon_cmds.go:cmdPortscan（--ports/--timeout/--workers 逐项对齐 argparse）。

import "github.com/Kur1sulab/shinra/engine-go/portscan"

// runPortStep 是 `all` 流水线里的非致命端口扫描步骤；默认参数对齐
// shinra.py:153/173 的 run_portscan(target, out)。
func runPortStep(target, out string) error {
	_, err := portscan.RunPortscan(target, out, "", portscan.DefaultTimeout, portscan.DefaultWorkers)
	return err
}
