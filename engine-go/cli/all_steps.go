package cli

// all_steps.go —— `all` 流水线里 jsintel 步骤的接线层。
//
// 对应 Python：sweep.py:154（IP 分支）/ :172（域名分支）的 run_jsintel(base, out)：
// 默认参数 = workers=6 / max_files=60 / 单文件超时 10s（jsintel.Default*）。
// 端口扫描步骤的接线在 cli/port_cmd.go（runPortStep）。

import (
	"github.com/Kur1sulab/sweep/engine-go/jsintel"
)

// runJSStep：JS 情报（非致命步骤，失败只记警告不中断流水线）。
func runJSStep(base, out string) error {
	_, err := jsintel.RunJSIntel(base, out,
		jsintel.DefaultWorkers, jsintel.DefaultMaxFiles, jsintel.DefaultTimeout)
	return err
}
