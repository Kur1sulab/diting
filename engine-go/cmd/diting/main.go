// diting 标准布局入口（engine-go/cmd/diting）。
// 全部 CLI 逻辑在 cli 包，此处仅做薄壳——go build ./cmd/diting。
package main

import (
	"os"

	"github.com/Kur1sulab/diting/engine-go/cli"
	"github.com/Kur1sulab/diting/engine-go/serve"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "serve" {
		os.Exit(serve.Run(args[1:]))
	}
	os.Exit(cli.Run(args))
}
