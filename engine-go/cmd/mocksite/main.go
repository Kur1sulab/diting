// Command mocksite 起一个本地演示靶站，供 Web 控制台离线自测/截图用。
//
// 根路径即靶站（mockweb.DemoHandler）：swagger / actuator / .env /
// .git/config / backup.zip 等暴露面全摊在 / 下，于是 `shinra serve` 打
// 127.0.0.1:<端口> 就能得到真实的指纹、敏感路径、API 未授权命中。
//
//	go run ./cmd/mocksite -addr 127.0.0.1:18080
//
// 仅本机演示用：不联外网、不含真实凭据（里面全是占位口令）。
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Kur1sulab/shinra/engine-go/mockweb"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "监听地址")
	flag.Parse()

	srv := &http.Server{Addr: *addr, Handler: mockweb.DemoHandler(), ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("演示靶站已启动 http://%s（Ctrl-C 停止）\n", *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Printf("[!] %v\n", err)
		os.Exit(1)
	}
}
