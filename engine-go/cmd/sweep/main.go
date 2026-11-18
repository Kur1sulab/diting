// sweep 标准布局入口（engine-go/cmd/sweep）。
// 全部 CLI 逻辑在 cli 包，此处仅做薄壳——go build ./cmd/sweep。
package main

import (
	"os"

	"github.com/Kur1sulab/sweep/engine-go/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
