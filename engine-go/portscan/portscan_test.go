package portscan

// portscan_test.go —— 对齐 tests/test_portscan.py 的 8 项断言 + Go 侧补充：
//  1) ParsePorts：默认表规模/排序/去重、区间/非法输入、超大区间截断；
//  2) ClassifyBanner：常见服务 banner 特征 + 端口名兜底；
//  3) 集成：本机起 SSH 样/Redis 样/静默三个 TCP 靶标 + 一个确定关闭的端口，
//     验证开放判定、服务识别、产出文件结构；关闭端口不误报；
//  4) 域名解析失败优雅降级（注入桩，不碰真网）；
//  5) 输出渲染逐字符对齐 Python render_txt；ctx 取消秒级收敛。

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTCPServer 起一个本机单连接靶标：handler 返回即关闭连接（对齐
// socketserver.BaseRequestHandler 的语义）。
func startTCPServer(t *testing.T, handler func(net.Conn)) int {
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
				handler(c)
			}(conn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// freeClosedPort 取一个刚释放的本机端口（确定无人监听 → 连接必然失败）。
func freeClosedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func TestCommonPortsTableSane(t *testing.T) {
	if n := len(CommonPorts); n < 90 || n > 110 {
		t.Fatalf("常用端口表规模 %d，期望 90-110", n)
	}
	seen := map[int]bool{}
	for _, p := range CommonPorts {
		if p.Port < 1 || p.Port > 65535 {
			t.Fatalf("端口越界: %d", p.Port)
		}
		if seen[p.Port] {
			t.Fatalf("端口重复: %d", p.Port)
		}
		seen[p.Port] = true
		if p.Name == "" {
			t.Fatalf("端口 %d 缺少服务名", p.Port)
		}
	}
	got := ParsePorts("")
	if len(got) != len(CommonPorts) {
		t.Fatalf("默认端口表 %d 项，ParsePorts(\"\") %d 项", len(CommonPorts), len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("默认端口表未排序去重: %v", got)
		}
	}
}

func TestParsePortsRangesAndDedup(t *testing.T) {
	cases := []struct {
		spec string
		want []int
	}{
		{"80,443", []int{80, 443}},
		{"8000-8003,80", []int{80, 8000, 8001, 8002, 8003}},
		{"80,80,443,80", []int{80, 443}},
		{" 90 , 91 ", []int{90, 91}},
		{"65530-70000", []int{65530, 65531, 65532, 65533, 65534, 65535}},
		{"0-5", []int{1, 2, 3, 4, 5}}, // Python max(1, lo) 语义
		{"+80,1_0,80-", []int{10, 80}},
	}
	for _, c := range cases {
		got := ParsePorts(c.spec)
		if len(got) != len(c.want) {
			t.Fatalf("ParsePorts(%q) = %v，期望 %v", c.spec, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("ParsePorts(%q) = %v，期望 %v", c.spec, got, c.want)
			}
		}
	}
}

func TestParsePortsInvalidIgnored(t *testing.T) {
	if got := ParsePorts("abc,70000,0,-1,443"); len(got) != 1 || got[0] != 443 {
		t.Fatalf("非法端口应被忽略，得到 %v", got)
	}
	if got := ParsePorts("500-100"); len(got) != 0 {
		t.Fatalf("区间颠倒应返回空，得到 %v", got)
	}
	if got := ParsePorts("zz"); len(got) != 0 {
		t.Fatalf("非数字应返回空，得到 %v", got)
	}
}

func TestParsePortsHugeRangeTruncated(t *testing.T) {
	got := ParsePorts("1-65535")
	if len(got) != MaxPortRange {
		t.Fatalf("超大区间应截断为 %d，得到 %d", MaxPortRange, len(got))
	}
	if got[0] != 1 || got[len(got)-1] != MaxPortRange {
		t.Fatalf("截断区间端点异常: %d..%d", got[0], got[len(got)-1])
	}
}

func TestClassifyKnownBanners(t *testing.T) {
	cases := []struct {
		banner string
		port   int
		want   string
	}{
		{"SSH-2.0-OpenSSH_9.0", 2222, "SSH"},
		{"HTTP/1.1 400 Bad Request", 1, "HTTP"},
		{"-ERR unknown command", 1, "Redis"},
		{"+PONG", 1, "Redis"},
		{"220-vsftpd 3.0.3", 1, "FTP"},
		{"220 mail.example.com ESMTP", 1, "SMTP"},
		{"220 ProFTPD 1.3.5 Server ready", 21, "FTP"},
		{"RFB 003.008\n", 5900, "VNC"},
		{"ERROR", 11211, "Memcached"},
		{"5.7.42-log mysql_native_password", 3306, "MySQL"},
		{"cluster_name: es-test", 9300, "Elasticsearch"},
		{"login:", 23, "Telnet"},
	}
	for _, c := range cases {
		if got := ClassifyBanner(c.banner, c.port); got != c.want {
			t.Errorf("ClassifyBanner(%q, %d) = %q，期望 %q", c.banner, c.port, got, c.want)
		}
	}
}

func TestClassifyFallbackByPort(t *testing.T) {
	if got := ClassifyBanner("", 3306); got != "mysql" {
		t.Fatalf("端口兜底 mysql，得到 %q", got)
	}
	if got := ClassifyBanner("", 80); got != "http" {
		t.Fatalf("端口兜底 http，得到 %q", got)
	}
	if got := ClassifyBanner("", 12345); got != "" {
		t.Fatalf("未知端口应回空，得到 %q", got)
	}
}

func TestScanPortClosed(t *testing.T) {
	port := freeClosedPort(t)
	row := ScanPort("127.0.0.1", port, 0.5)
	if row.Open || row.Service != "" || row.Banner != "" || row.Port != port {
		t.Fatalf("关闭端口不应误报: %+v", row)
	}
}

// TestScanLocalTargets 对齐 tests/test_portscan.py:TestPortscanIntegration。
func TestScanLocalTargets(t *testing.T) {
	sshPort := startTCPServer(t, func(c net.Conn) {
		_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
	})
	redisPort := startTCPServer(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("-ERR unknown command 'q'\r\n"))
	})
	silentPort := startTCPServer(t, func(c net.Conn) {})
	closedPort := freeClosedPort(t)

	portsSpec := itoaList(sshPort, redisPort, silentPort, closedPort)
	out := t.TempDir()
	rows, err := RunPortscan("127.0.0.1", out, portsSpec, 1.0, 4)
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	got := map[int]Row{}
	for _, r := range rows {
		got[r.Port] = r
	}
	if _, ok := got[closedPort]; ok {
		t.Fatal("关闭端口被误报为开放")
	}
	for _, p := range []int{sshPort, redisPort, silentPort} {
		if _, ok := got[p]; !ok {
			t.Fatalf("端口 %d 应判开放，得到 %v", p, rows)
		}
	}
	if got[sshPort].Service != "SSH" || !strings.Contains(got[sshPort].Banner, "SSH-2.0") {
		t.Fatalf("SSH 识别失败: %+v", got[sshPort])
	}
	if got[redisPort].Service != "Redis" {
		t.Fatalf("Redis 识别失败: %+v", got[redisPort])
	}
	if got[silentPort].Service != "" {
		t.Fatalf("静默服务应为未知（不算误报）: %+v", got[silentPort])
	}

	// 产出文件：结构与 Python ports.json 同键同值。
	raw, err := os.ReadFile(filepath.Join(out, "ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("ports.json 解析失败: %v\n%s", err, raw)
	}
	if res.Target != "127.0.0.1" || res.IP != "127.0.0.1" || res.Scanned != 4 || len(res.Open) != 3 {
		t.Fatalf("ports.json 结构异常: %+v", res)
	}
	txt, err := os.ReadFile(filepath.Join(out, "ports.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(txt) == 0 || !strings.Contains(string(txt), "127.0.0.1") {
		t.Fatalf("ports.txt 内容异常: %q", txt)
	}
}

func TestDNSFailureDegrades(t *testing.T) {
	old := lookupIP
	lookupIP = func(ctx context.Context, network, host string) ([]net.IP, error) {
		return nil, errors.New("resolve fail")
	}
	defer func() { lookupIP = old }()

	out := t.TempDir()
	rows, err := RunPortscan("nonexistent.invalid", out, "80", 0.5, 32)
	if err != nil {
		t.Fatalf("解析失败应优雅降级（不返回 error）: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("解析失败应返回空结果，得到 %v", rows)
	}
	raw, err := os.ReadFile(filepath.Join(out, "ports.json"))
	if err != nil {
		t.Fatal(err)
	}
	var res Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.IP != "" || len(res.Open) != 0 {
		t.Fatalf("降级结果应 ip=\"\" / open=[]: %+v", res)
	}
	if !strings.Contains(string(raw), `"open": []`) {
		t.Fatalf("空结果应写 [] 而非 null: %s", raw)
	}
}

func TestResultJSONLiteral(t *testing.T) {
	// ports.json 的 timeout 与 Python json.dumps 同字面量（1.0），空 open 为 []。
	b, err := json.Marshal(Result{Target: "x", IP: "1.2.3.4", Scanned: 1, Timeout: 1.0, Open: []Row{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"timeout":1.0`) {
		t.Fatalf("timeout 应渲染为 1.0（Python json.dumps 口径）: %s", b)
	}
	if !strings.Contains(string(b), `"open":[]`) {
		t.Fatalf("空 open 应渲染为 []: %s", b)
	}
}

func TestRenderTxtGolden(t *testing.T) {
	got := RenderTxt(Result{
		Target: "example.com", IP: "", Scanned: 2, Timeout: 1.5,
		Open: []Row{{Port: 22, Open: true, Service: "SSH", Banner: "SSH-2.0-x"}},
	})
	want := "# 端口扫描 — example.com（解析失败）\n" +
		"- 扫描 2 个端口（常用端口表，并发 ≤32，超时 1.5s）\n" +
		"- 声明: 仅限授权目标；服务名是启发式识别，以人工复核为准\n" +
		"\n" +
		"[+] 22/tcp  SSH  banner: SSH-2.0-x\n"
	if got != want {
		t.Fatalf("render 与 Python 不一致:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	empty := RenderTxt(Result{Target: "127.0.0.1", IP: "127.0.0.1", Scanned: 1, Timeout: 1.0})
	wantEmpty := "# 端口扫描 — 127.0.0.1（127.0.0.1）\n" +
		"- 扫描 1 个端口（常用端口表，并发 ≤32，超时 1.0s）\n" +
		"- 声明: 仅限授权目标；服务名是启发式识别，以人工复核为准\n" +
		"\n" +
		"（开放端口：无）\n"
	if empty != wantEmpty {
		t.Fatalf("空结果 render 不一致:\n--- got ---\n%s\n--- want ---\n%s", empty, wantEmpty)
	}
}

func TestRunPortscanContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	rows, err := RunPortscanContext(ctx, "127.0.0.1", t.TempDir(), "1-8192", 1.0, 32)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("已取消 ctx 应秒级返回，实耗 %s", elapsed)
	}
	if err == nil {
		t.Fatal("已取消 ctx 应返回 ctx.Err()")
	}
	if rows != nil {
		t.Fatalf("取消后应 nil，得到 %v", rows)
	}
}

func itoaList(ns ...int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}
