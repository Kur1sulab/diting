package parity

// parity_portscan_test.go —— portscan（src/modules/portscan.py）Python↔Go parity：
//  ① ParsePorts 黄金例（默认表/区间/去重/非法/截断/Python int() 口径）；
//  ② ClassifyBanner 特征矩阵 + 端口兜底；
//  ③ 同一组本机 TCP 靶标（SSH 样 / Redis 样 / 静默 / 确定关闭）双引擎对打：
//     ports.json 反序列化后结构全等（target/ip/scanned/timeout/open 行），
//     ports.txt 去 \r 后逐字符全等。
//
// 方法学遵循 docs/PARITY.md ①：同一靶标、只比解析后结构 / strip('\r') 文本；
// 靶标由 Go 侧监听，Python 与 Go 打的是同一组端口（严禁各打各的 mock）。

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/Kur1sulab/atlas/engine-go/portscan"
)

// portscanPy 复用 PythonBin 的统一解析（实跑探针 + ATLAS_PYTHON/PYTHON 优先）。
// 早期本文件各自 LookPath("python")，在 ServBay / pyenv shim 占住 python
// 名字的机器上会「探测成功、执行失败」，把本应 Skip 的用例变成 FAIL——已收口。
func portscanPy(t *testing.T) string {
	t.Helper()
	if os.Getenv("CI") == "true" {
		t.Skip("CI 环境：parity=本地黄金对照门禁，跳过")
	}
	if p := PythonBin(); p != "" {
		return p
	}
	t.Skip("未找到可执行的 Python 3，跳过 parity 测试（纯 Go 测试不受影响）")
	return ""
}

func runPortscanPy(t *testing.T, code string, args ...string) string {
	t.Helper()
	cmd := exec.Command(portscanPy(t), append([]string{"-c", code}, args...)...)
	cmd.Dir = RepoRoot()
	cmd.Env = append(os.Environ(),
		"PYTHONUTF8=1",
		"PYTHONPATH="+filepath.Join(RepoRoot(), "src"),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python 执行失败: %v\n输出:\n%s", err, out)
	}
	return string(out)
}

// ── ① parse_ports ──
func TestParityParsePorts(t *testing.T) {
	portscanPy(t)
	specs := []string{
		"", "80,443", "8000-8003,80", "80,80,443,80", " 90 , 91 ",
		"abc,70000,0,-1,443", "500-100", "zz", "1-65535",
		"65530-70000", "0-5", "+80,1_0,80-", "80,,443,", "  ",
	}
	pyRaw := runPortscanPy(t, `
import contextlib, io, json, sys
from modules.portscan import parse_ports
specs = json.loads(sys.argv[1])
out = []
with contextlib.redirect_stdout(io.StringIO()):
    for s in specs:
        out.append(parse_ports(s))
print(json.dumps(out))
`, mustJSON(t, specs))

	var py [][]int
	if err := json.Unmarshal([]byte(lastJSONLine(pyRaw)), &py); err != nil {
		t.Fatalf("python 输出解析失败: %v\n%s", err, pyRaw)
	}
	if len(py) != len(specs) {
		t.Fatalf("python 返回 %d 组，期望 %d", len(py), len(specs))
	}
	for i, spec := range specs {
		goGot := portscan.ParsePorts(spec)
		if !reflect.DeepEqual(py[i], goGot) {
			t.Errorf("ParsePorts(%q):\n  py=%v (len %d)\n  go=%v (len %d)",
				spec, py[i], len(py[i]), goGot, len(goGot))
		}
	}
}

// ── ② classify_banner ──
func TestParityClassifyBanner(t *testing.T) {
	portscanPy(t)
	type kase struct {
		Banner string
		Port   int
	}
	cases := []kase{
		{"SSH-2.0-OpenSSH_9.0", 2222},
		{"ssh-2.0-dropbear", 1},
		{"HTTP/1.1 400 Bad Request", 1},
		{"-ERR unknown command", 1},
		{"+PONG", 1},
		{"  -ERR wrong number of arguments  ", 6379},
		{"220-vsftpd 3.0.3", 1},
		{"220 (vsFTPd 3.0.3)", 21},
		{"220 ProFTPD 1.3.5 Server ready", 21},
		{"220 mail.example.com ESMTP", 1},
		{"220 smtp.example.com ESMTP Postfix", 25},
		{"ERROR", 11211},
		{"memcached 1.6.21", 1},
		{"5.7.42-log mysql_native_password", 3306},
		{"mariadb", 1},
		{"mongodb 4.4", 27017},
		{"RFB 003.008\n", 5900},
		{"AMQP\x00\x00\x09\x01", 5672},
		{"cluster_name: es-test", 9300},
		{"elasticsearch", 1},
		{"login:", 23},
		{"user password:", 1},
		{"", 3306},
		{"", 80},
		{"", 12345},
		{"   ", 443},
	}
	pairs := make([][2]any, len(cases))
	for i, c := range cases {
		pairs[i] = [2]any{c.Banner, c.Port}
	}
	pyRaw := runPortscanPy(t, `
import json, sys
from modules.portscan import classify_banner
cases = json.loads(sys.argv[1])
print(json.dumps([classify_banner(b, int(p)) for b, p in cases], ensure_ascii=False))
`, mustJSON(t, pairs))

	var py []string
	if err := json.Unmarshal([]byte(lastJSONLine(pyRaw)), &py); err != nil {
		t.Fatalf("python 输出解析失败: %v\n%s", err, pyRaw)
	}
	if len(py) != len(cases) {
		t.Fatalf("python 返回 %d 项，期望 %d", len(py), len(cases))
	}
	for i, c := range cases {
		if got := portscan.ClassifyBanner(c.Banner, c.Port); got != py[i] {
			t.Errorf("ClassifyBanner(%q, %d): py=%q go=%q", c.Banner, c.Port, py[i], got)
		}
	}
}

// ── ③ 本机靶标对打（端到端）──
func TestParityPortscanLocalTargets(t *testing.T) {
	portscanPy(t)
	sshPort := parityPushServer(t, "SSH-2.0-OpenSSH_9.0\r\n")
	redisPort := parityEchoServer(t, "-ERR unknown command 'q'\r\n")
	silentPort := paritySilentServer(t)
	closedPort := parityClosedPort(t)
	spec := fmt.Sprintf("%d,%d,%d,%d", sshPort, redisPort, silentPort, closedPort)

	pyOut := t.TempDir()
	goOut := t.TempDir()

	pyRaw := runPortscanPy(t, `
import json, os, sys
from modules.portscan import run_portscan
out = sys.argv[1]
run_portscan("127.0.0.1", out, ports=sys.argv[2], timeout=1.0, workers=4)
with open(os.path.join(out, "ports.json"), encoding="utf-8") as f:
    print(json.dumps(json.load(f), ensure_ascii=False, sort_keys=True))
`, pyOut, spec)
	var pyRes map[string]any
	if err := json.Unmarshal([]byte(lastJSONLine(pyRaw)), &pyRes); err != nil {
		t.Fatalf("python ports.json 解析失败: %v\n输出:\n%s", err, pyRaw)
	}

	if _, err := portscan.RunPortscan("127.0.0.1", goOut, spec, 1.0, 4); err != nil {
		t.Fatalf("Go 扫描失败: %v", err)
	}
	goRaw, err := os.ReadFile(filepath.Join(goOut, "ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	var goRes map[string]any
	if err := json.Unmarshal(goRaw, &goRes); err != nil {
		t.Fatalf("Go ports.json 解析失败: %v\n%s", err, goRaw)
	}
	if !reflect.DeepEqual(pyRes, goRes) {
		pyPretty, _ := json.MarshalIndent(pyRes, "", "  ")
		goPretty, _ := json.MarshalIndent(goRes, "", "  ")
		t.Fatalf("ports.json 结构不一致:\n  py=%s\n  go=%s", pyPretty, goPretty)
	}

	pyTxt, err := os.ReadFile(filepath.Join(pyOut, "ports.txt"))
	if err != nil {
		t.Fatal(err)
	}
	goTxt, err := os.ReadFile(filepath.Join(goOut, "ports.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if StripCR(string(pyTxt)) != StripCR(string(goTxt)) {
		t.Fatalf("ports.txt 不一致:\n--- py ---\n%s\n--- go ---\n%s", StripCR(string(pyTxt)), StripCR(string(goTxt)))
	}
}

// ── 靶标与端口辅助 ──

func parityTCPServer(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				handle(c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// parityPushServer 连上就推一条横幅（真实 SSH 的行为）。
func parityPushServer(t *testing.T, banner string) int {
	return parityTCPServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte(banner))
	})
}

// parityEchoServer 收一行再回错误（真实 Redis 对未知命令的行为）。
func parityEchoServer(t *testing.T, reply string) int {
	return parityTCPServer(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte(reply))
	})
}

// paritySilentServer 连接成功但立即关闭、无横幅（判开、服务未知）。
func paritySilentServer(t *testing.T) int {
	return parityTCPServer(t, func(c net.Conn) {})
}

func parityClosedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
