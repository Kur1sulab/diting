// atlas 标准布局入口（engine-go/cmd/atlas）。
// 全部 CLI 逻辑在 cli 包，此处仅做薄壳——go build ./cmd/atlas。
package main

import (
	"os"

	"github.com/Kur1sulab/atlas/engine-go/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
