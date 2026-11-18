package cli

// port_test.go —— portscan 子命令接线验收（engine-go/portscan → CLI）：
// 参数校验 exit 2 / 本机靶标 exit 0 / out/<target>/ports.json 落盘结构。
// 靶标只监听 127.0.0.1 随机端口，零外网。

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPortscanCLIWiring(t *testing.T) {
	resetProgress(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	dir := t.TempDir()
	t.Chdir(dir)
	code := Run([]string{"portscan", "-t", "127.0.0.1", "--ports", strconv.Itoa(port),
		"--timeout", "1", "--workers", "2"})
	if code != 0 {
		t.Fatalf("portscan exit=%d，期望 0", code)
	}
	raw, err := os.ReadFile(filepath.Join("out", "127.0.0.1", "ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Target string `json:"target"`
		IP     string `json:"ip"`
		Open   []struct {
			Port    int    `json:"port"`
			Service string `json:"service"`
			Banner  string `json:"banner"`
		} `json:"open"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("ports.json 解析失败: %v\n%s", err, raw)
	}
	if res.Target != "127.0.0.1" || res.IP != "127.0.0.1" || len(res.Open) != 1 {
		t.Fatalf("ports.json 结构异常: %+v", res)
	}
	if res.Open[0].Port != port || res.Open[0].Service != "SSH" {
		t.Fatalf("端口/服务识别异常: %+v", res.Open[0])
	}
	if _, err := os.Stat(filepath.Join("out", "127.0.0.1", "ports.txt")); err != nil {
		t.Fatalf("ports.txt 缺失: %v", err)
	}
}

func TestPortscanCLIArgErrors(t *testing.T) {
	resetProgress(t)
	if code := Run([]string{"portscan"}); code != 2 {
		t.Fatalf("缺少 -t 应 exit 2，得 %d", code)
	}
	if code := Run([]string{"portscan", "-t", "127.0.0.1", "--timeout", "abc"}); code != 2 {
		t.Fatalf("非法 --timeout 应 exit 2，得 %d", code)
	}
}
