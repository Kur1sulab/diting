// Package portscan：常用端口扫描，移植 src/modules/portscan.py（纯 Go 标准库，
// 零第三方依赖）。
//
// 安全约束（设计即边界，与 Python 版逐条对齐）：
//   - 默认只扫内置常用端口表（96 个，参考 nmap top-ports 思路 + 国内常见服务）；
//   - 并发 ≤32、连接超时默认 1.5s、banner 抓取每步等待 ≤1s；
//   - banner 以**被动接收**为主，收不到时最多补发一个换行（对服务无副作用）催
//     一次；HTTP 端口则补一个只读的 HEAD 请求——全程不发送任何可能改变状态的输入；
//   - 域名目标先解析（取首个 A 记录），解析失败优雅降级为空结果；
//   - ⚠️ 仅限授权目标：未授权端口扫描是违法行为，README/输出中均已注明。
//
// 输出 out/<target>/ports.json + ports.txt。
package portscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Kur1sulab/diting/engine-go/netutil"
)

const (
	DefaultTimeout = 1.5  // 单端口连接超时（秒）
	DefaultWorkers = 32   // 并发上限（克制）
	BannerWait     = 1.0  // banner 抓取单步等待（秒）
	MaxPortRange   = 8192 // 单段 --ports a-b 最大跨度（防失控）
)

// Port 对齐 portscan.py:29 的 (端口, 常见服务名) 二元组。
type Port struct {
	Port int
	Name string
}

// CommonPorts 96 个常用端口，逐条对照 portscan.py:29-45（顺序一致）。
var CommonPorts = []Port{
	{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
	{69, "tftp"}, {80, "http"}, {81, "http-alt"}, {88, "kerberos"}, {110, "pop3"},
	{111, "rpcbind"}, {135, "msrpc"}, {139, "netbios-ssn"}, {143, "imap"}, {161, "snmp"},
	{389, "ldap"}, {443, "https"}, {445, "smb"}, {465, "smtps"}, {500, "isakmp"},
	{514, "syslog"}, {515, "printer"}, {548, "afp"}, {554, "rtsp"}, {587, "submission"},
	{623, "ipmi"}, {636, "ldaps"}, {873, "rsync"}, {993, "imaps"}, {995, "pop3s"},
	{1080, "socks"}, {1099, "java-rmi"}, {1194, "openvpn"}, {1433, "mssql"}, {1434, "mssql-dac"},
	{1521, "oracle"}, {1723, "pptp"}, {1883, "mqtt"}, {2049, "nfs"}, {2082, "cpanel"},
	{2083, "cpanel-ssl"}, {2181, "zookeeper"}, {2375, "docker"}, {2376, "docker-tls"}, {2379, "etcd"},
	{3128, "squid"}, {3268, "ldap-gc"}, {3306, "mysql"}, {3389, "rdp"}, {5432, "postgresql"},
	{5555, "adb"}, {5601, "kibana"}, {5672, "amqp"}, {5900, "vnc"}, {5984, "couchdb"},
	{6379, "redis"}, {6443, "k8s-api"}, {7001, "weblogic"}, {7002, "weblogic-ssl"}, {8000, "http-alt"},
	{8001, "http-alt"}, {8009, "ajp"}, {8010, "http-alt"}, {8069, "odoo"}, {8080, "http-proxy"},
	{8081, "http-alt"}, {8088, "http-alt"}, {8089, "http-alt"}, {8090, "http-alt"}, {8161, "activemq"},
	{8181, "http-alt"}, {8443, "https-alt"}, {8500, "consul"}, {8848, "nacos"}, {8899, "http-alt"},
	{9000, "http-alt"}, {9001, "http-alt"}, {9042, "cassandra"}, {9090, "http-alt"}, {9092, "kafka"},
	{9200, "elasticsearch"}, {9300, "es-cluster"}, {9999, "http-alt"}, {10000, "webmin"}, {10050, "zabbix-agent"},
	{10051, "zabbix"}, {11211, "memcached"}, {15672, "rabbitmq-mgmt"}, {27017, "mongodb"}, {27018, "mongodb"},
	{27019, "mongodb"}, {28017, "mongo-web"}, {50000, "sap"}, {50070, "hadoop-namenode"}, {61616, "activemq"},
	{18080, "http-alt"},
}

// portName 对齐 Python `_PORT_NAME = dict(COMMON_PORTS)`（同端口后者覆盖前者；
// 当前表无重复，保留覆盖语义以防后续加表漂移）。
var portName = func() map[int]string {
	m := make(map[int]string, len(CommonPorts))
	for _, p := range CommonPorts {
		m[p.Port] = p.Name
	}
	return m
}()

// httpLikely 对齐 portscan.py:50-52 的 _HTTP_LIKELY：banner 被动收不到时用只读
// HEAD 探测的端口集合。
var httpLikely = map[int]bool{
	80: true, 81: true, 443: true, 591: true, 7001: true, 8000: true, 8001: true,
	8008: true, 8009: true, 8010: true, 8069: true, 8080: true, 8081: true,
	8088: true, 8089: true, 8090: true, 8161: true, 8181: true, 8443: true,
	8848: true, 8899: true, 9000: true, 9001: true, 9090: true, 9200: true,
	9443: true, 9999: true, 10000: true, 18080: true, 28017: true,
}

// Row 单端口扫描结果，JSON 键对齐 portscan.py scan_port 的返回 dict。
type Row struct {
	Port    int    `json:"port"`
	Open    bool   `json:"open"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

// Result 扫描汇总，JSON 键对齐 portscan.py run_portscan 的 result dict。
// 注意 Open 必须初始化为空切片：Python 写 `[]`，nil 切片会 marshal 成 `null`。
type Result struct {
	Target  string  `json:"target"`
	IP      string  `json:"ip"`
	Scanned int     `json:"scanned"`
	Timeout PyFloat `json:"timeout"`
	Open    []Row   `json:"open"`
}

// PyFloat 让浮点字段按 Python json.dumps 的字面输出（1.0 而非 1）。
// 不加这层，ports.json 与 Python 版只差 "timeout": 1.0 / 1 一处，
// 字节级 parity 断言就会永远红（审计要求：产物字节可比对）。
// 导出类型便于外部构造 Result（untyped 常量可直接赋值，显式转换用 PyFloat(v)）。
type PyFloat float64

// MarshalJSON 走 pyFloat（FormatFloat 'f' + 补 .0），与 Python repr 对齐。
func (f PyFloat) MarshalJSON() ([]byte, error) { return []byte(pyFloat(float64(f))), nil }

// ParsePorts 把 '80,443,8000-8100' 解析为有序去重端口表；空 → 内置常用端口表。
// 非法段跳过并告警；单段跨度 >8192 截断（防失控扫描）。逐行对齐
// portscan.py:76-112（含 Python int() 的空白/下划线容忍口径）。
func ParsePorts(spec string) []int {
	if strings.TrimSpace(spec) == "" {
		out := make([]int, 0, len(CommonPorts))
		for _, p := range CommonPorts {
			out = append(out, p.Port)
		}
		sort.Ints(out)
		return out
	}
	set := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			a, b, _ := strings.Cut(part, "-")
			lo, okLo := pyAtoi(a)
			hi, okHi := pyAtoi(b)
			if !okLo || !okHi {
				fmt.Printf("[!] 端口段 '%s' 非法，忽略\n", part)
				continue
			}
			if lo < 1 {
				lo = 1
			}
			if hi > 65535 {
				hi = 65535
			}
			if lo > hi {
				fmt.Printf("[!] 端口段 '%s' 范围颠倒，忽略\n", part)
				continue
			}
			if hi-lo+1 > MaxPortRange {
				fmt.Printf("[!] 端口段 '%s' 跨度过大（>%d），截断\n", part, MaxPortRange)
				hi = lo + MaxPortRange - 1
			}
			for p := lo; p <= hi; p++ {
				set[p] = true
			}
			continue
		}
		p, ok := pyAtoi(part)
		if !ok {
			fmt.Printf("[!] 端口 '%s' 非法，忽略\n", part)
			continue
		}
		if p >= 1 && p <= 65535 {
			set[p] = true
		} else {
			fmt.Printf("[!] 端口 '%s' 超出 1-65535，忽略\n", part)
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// pyAtoi 近似 Python int() 在本模块用到的解析口径：容忍首尾空白与数字之间的
// 单个下划线（int("1_0") == 10）；首尾/连续下划线仍判非法（Python 同样拒绝）。
// 不做 unicode 数字归一（Python 接受 "８０"，实际调用面不存在）。
func pyAtoi(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.Contains(s, "_") {
		rs := []rune(s)
		for i, r := range rs {
			if r != '_' {
				continue
			}
			if i == 0 || i == len(rs)-1 || !isASCIIDigit(rs[i-1]) || !isASCIIDigit(rs[i+1]) {
				return 0, false
			}
		}
		s = strings.ReplaceAll(s, "_", "")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// ClassifyBanner banner 特征 → 服务名；认不出时退回端口表里的常见服务名。
// 逐条对齐 portscan.py:55-72 的 _SIGS（顺序即优先级）。
func ClassifyBanner(banner string, port int) string {
	b := strings.ToLower(strings.TrimSpace(banner))
	switch {
	case strings.HasPrefix(b, "ssh-"):
		return "SSH"
	case strings.HasPrefix(b, "http/"):
		return "HTTP"
	case strings.HasPrefix(b, "220") && containsAny(b, "ftp", "vsftpd", "proftpd", "filezilla", "pure-ftpd"):
		return "FTP"
	case strings.Contains(b, "esmtp") || strings.Contains(b, "smtp") ||
		(strings.HasPrefix(b, "220") && strings.Contains(b, "mail")):
		return "SMTP"
	case strings.Contains(b, "redis") || strings.HasPrefix(b, "-err") || strings.Contains(b, "+pong"):
		return "Redis"
	case strings.Contains(b, "memcached") || b == "error":
		return "Memcached"
	case strings.Contains(b, "mysql") || strings.Contains(b, "mariadb"):
		return "MySQL"
	case strings.Contains(b, "mongodb"):
		return "MongoDB"
	case strings.HasPrefix(b, "rfb "):
		return "VNC"
	case strings.Contains(b, "amqp"):
		return "AMQP"
	case strings.Contains(b, "elasticsearch") || strings.Contains(b, "cluster_name"):
		return "Elasticsearch"
	case strings.Contains(b, "login:") || strings.Contains(b, "password:"):
		return "Telnet"
	}
	return portName[port]
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func recvSome(conn net.Conn) []byte {
	_ = conn.SetReadDeadline(time.Now().Add(seconds(BannerWait)))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil
	}
	return buf[:n]
}

// grabBanner 被动收 banner；收不到时补一次最小探测（HTTP 口发只读 HEAD，
// 其余发换行）。对齐 portscan.py:121-134。
func grabBanner(conn net.Conn, port int) string {
	data := recvSome(conn)
	if len(data) == 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(seconds(BannerWait)))
		probe := []byte("\r\n") // 空行：多数服务回一条错误/横幅
		if httpLikely[port] {
			probe = []byte("HEAD / HTTP/1.0\r\n\r\n") // 只读请求，无副作用
		}
		if _, err := conn.Write(probe); err == nil {
			data = recvSome(conn)
		}
	}
	if len(data) > 512 {
		data = data[:512]
	}
	// Python: re.sub(r"\s+", " ", text).strip()[:200]——按字符（rune）截断。
	text := strings.Join(strings.Fields(pyDecodeReplace(data)), " ")
	return truncRunes(text, 200)
}

// pyDecodeReplace 等价 Python bytes.decode("utf-8", "replace") 的错误处理：
// 每个非法字节替换为一个 U+FFFD（Go 的 ToValidUTF8 会把连续非法字节压成一个）。
func pyDecodeReplace(b []byte) string {
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			sb.WriteRune(utf8.RuneError)
			b = b[1:]
			continue
		}
		sb.Write(b[:size])
		b = b[size:]
	}
	return sb.String()
}

// ScanPort TCP connect + 轻量 banner；返回 {port, open, service, banner}（不抛异常）。
// 对齐 portscan.py:137-148。
func ScanPort(host string, port int, timeout float64) Row {
	row := Row{Port: port}
	d := net.Dialer{Timeout: seconds(timeout)}
	conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return row
	}
	defer conn.Close()
	row.Open = true
	row.Banner = grabBanner(conn, port)
	row.Service = ClassifyBanner(row.Banner, port)
	return row
}

// RenderTxt 渲染 ports.txt，逐行对齐 portscan.py:151-163（含 f-string 的
// 空格数与 Python str(float) 的超时渲染）。
func RenderTxt(r Result) string {
	ip := r.IP
	if ip == "" {
		ip = "解析失败"
	}
	L := []string{
		fmt.Sprintf("# 端口扫描 — %s（%s）", r.Target, ip),
		fmt.Sprintf("- 扫描 %d 个端口（常用端口表，并发 ≤%d，超时 %ss）", r.Scanned, DefaultWorkers, pyFloat(float64(r.Timeout))),
		"- 声明: 仅限授权目标；服务名是启发式识别，以人工复核为准",
		"",
	}
	if len(r.Open) == 0 {
		L = append(L, "（开放端口：无）")
	}
	for _, row := range r.Open {
		svc := row.Service
		if svc == "" {
			svc = "未知"
		}
		line := fmt.Sprintf("[+] %d/tcp  %s", row.Port, svc)
		if row.Banner != "" {
			line += "  banner: " + row.Banner
		}
		L = append(L, line)
	}
	return strings.Join(L, "\n") + "\n"
}

// lookupIP 可注入（单测桩解析失败；默认走系统解析器的 A 记录）。
var lookupIP = net.DefaultResolver.LookupIP

// RunPortscan target 接受域名或 IP；域名先解析首个 A 记录，两者都记入产出。
// 对齐 portscan.py:166-208；写盘失败返回 error（fix3 口径：CLI exit 1）。
func RunPortscan(target, out, ports string, timeout float64, workers int) ([]Row, error) {
	return RunPortscanContext(context.Background(), target, out, ports, timeout, workers)
}

// RunPortscanContext 是 RunPortscan 的取消变体（仓库「取消能力注入」约定）：
// 入口与每个端口任务前设检查点，取消后立即收敛并返回 ctx.Err()。
func RunPortscanContext(ctx context.Context, target, out, ports string, timeout float64, workers int) ([]Row, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	fmt.Printf("[*] 端口扫描: %s（仅限授权目标；未授权扫描违法）\n", target)
	out = netutil.SafeOutdir(out) // 目录穿越防御（见 netutil.SafeOutdir）
	if math.IsNaN(timeout) {      // Python: max(0.2, min(nan, 10)) == 0.2
		timeout = 0.2
	}
	timeout = math.Max(0.2, math.Min(timeout, 10))
	if workers < 1 {
		workers = 1
	}
	if workers > DefaultWorkers {
		workers = DefaultWorkers
	}
	portList := ParsePorts(ports)
	ip := ""
	if net.ParseIP(target) != nil {
		ip = target
	} else {
		addrs, err := lookupIP(ctx, "ip4", target)
		if err == nil && len(addrs) == 0 {
			err = fmt.Errorf("无 A 记录")
		}
		if err != nil {
			fmt.Printf("[!] 域名解析失败（%v），输出空结果（优雅降级）\n", err)
		} else {
			ip = addrs[0].String()
			fmt.Printf("[*] %s -> %s\n", target, ip)
		}
	}
	result := Result{Target: target, IP: ip, Scanned: len(portList), Timeout: PyFloat(timeout), Open: []Row{}}
	if ip != "" {
		if err := ctx.Err(); err != nil {
			fmt.Println("[!] 端口扫描已取消")
			return nil, err
		}
		fmt.Printf("[*] 扫描 %d 个常用端口（并发 ≤%d，连接超时 %ss）\n", len(portList), workers, pyFloat(timeout))
		rows := scanAll(ctx, ip, portList, timeout, workers)
		if err := ctx.Err(); err != nil {
			fmt.Println("[!] 端口扫描已取消")
			return nil, err
		}
		for _, r := range rows {
			if !r.Open {
				continue
			}
			result.Open = append(result.Open, r)
			b := ""
			if r.Banner != "" {
				b = "  banner: " + truncRunes(r.Banner, 60)
			}
			svc := r.Service
			if svc == "" {
				svc = "未知服务"
			}
			fmt.Printf("[+] %s:%d 开放  %s%s\n", ip, r.Port, svc, b)
		}
	}
	sort.Slice(result.Open, func(i, j int) bool { return result.Open[i].Port < result.Open[j].Port })
	// SetEscapeHTML(false) 对齐 Python json.dumps(ensure_ascii=False)：banner 里的
	// <, >, & 不转义成 \u003c（原样落盘，解析后语义相同但字节更接近 Python）。
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return nil, err
	}
	payload := strings.TrimSuffix(buf.String(), "\n")
	p1, err := netutil.SafeWrite(out, "ports.json", payload)
	if err != nil {
		fmt.Printf("[!] ports.json 写盘失败: %v\n", err)
		return nil, err
	}
	if _, err := netutil.SafeWrite(out, "ports.txt", RenderTxt(result)); err != nil {
		fmt.Printf("[!] ports.txt 写盘失败: %v\n", err)
		return nil, err
	}
	fmt.Printf("[+] 端口扫描完成：开放 %d/%d -> %s\n", len(result.Open), len(portList), p1)
	return result.Open, nil
}

// scanAll 有界并发扫描，结果按 portList 下标落位（对齐 ThreadPoolExecutor.map
// 的保序语义；每个任务独立建连，无共享可变状态）。
func scanAll(ctx context.Context, ip string, ports []int, timeout float64, workers int) []Row {
	rows := make([]Row, len(ports))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil {
					return
				}
				rows[i] = ScanPort(ip, ports[i], timeout)
			}
		}()
	}
	for i := range ports {
		select {
		case jobs <- i:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return rows
}

func seconds(f float64) time.Duration {
	if f <= 0 {
		f = DefaultTimeout
	}
	return time.Duration(f * float64(time.Second))
}

// pyFloat 对齐 Python str(float)：整数值补 ".0"（1 → "1.0"）。
func pyFloat(f float64) string {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
