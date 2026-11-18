package engine

// reconmods.go —— 第三轮升级接入的两个新模块（jsintel / portscan）的进程内直调实现。
//
// 参数口径与 engine-go cli 的对应子命令一致（默认值来自各自包的 Default* 常量，
// 即 recon.py argparse 的默认值）：jsintel --max-files 60 / --workers 6；
// portscan --ports "" / --timeout 1.5 / --workers 32。
// 目标归一：jsintel 吃 URL（session 层 isURLCmd 已保证带协议），portscan 吃裸域名/IP。

import (
	"context"
	"fmt"
	"strconv"

	"github.com/Kur1sulab/mappa/engine-go/jsintel"
	"github.com/Kur1sulab/mappa/engine-go/portscan"
)

// extraInt 读整数旗标（缺省/非法回落 def；与 argparse 的 int 解析同口径：
// 非法值在 ValidateExtraArgs 层不会漏进来，这里只做防御性回落）。
func extraInt(extra []string, name string, def int) int {
	raw, ok := extraFlagValue(extra, name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// extraFloat 读浮点旗标（缺省/非法回落 def）。
func extraFloat(extra []string, name string, def float64) float64 {
	raw, ok := extraFlagValue(extra, name)
	if !ok {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return f
}

// runJSIntel JS 情报：外链 JS ≤6 并发、单文件 ≤2MB、只 GET、超时 10s（包内硬约束）。
func (r *Runner) runJSIntel(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	workers := extraInt(extra, "--workers", jsintel.DefaultWorkers)
	maxFiles := extraInt(extra, "--max-files", jsintel.DefaultMaxFiles)
	_, err = jsintel.RunJSIntelContext(ctx, target, out, workers, maxFiles, jsintel.DefaultTimeout)
	return err
}

// runPortscan 端口扫描：默认内置常用端口表，并发夹到 ≤32。
func (r *Runner) runPortscan(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	portsSpec, _ := extraFlagValue(extra, "--ports")
	timeout := extraFloat(extra, "--timeout", portscan.DefaultTimeout)
	workers := extraInt(extra, "--workers", portscan.DefaultWorkers)
	_, err = portscan.RunPortscanContext(ctx, target, out, portsSpec, timeout, workers)
	return err
}
