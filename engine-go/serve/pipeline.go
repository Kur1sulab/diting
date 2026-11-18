package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Kur1sulab/shinra/engine-go/apiunauth"
	"github.com/Kur1sulab/shinra/engine-go/cli"
	"github.com/Kur1sulab/shinra/engine-go/fingerprint"
	"github.com/Kur1sulab/shinra/engine-go/netutil"
	"github.com/Kur1sulab/shinra/engine-go/paths"
	"github.com/Kur1sulab/shinra/engine-go/portscan"
	"github.com/Kur1sulab/shinra/engine-go/subdomain"
)

// Result 是一次测绘的实测结果集（全部来自真实执行，无推演字段）。
type Result struct {
	Target  string                `json:"target"`
	Base    string                `json:"base"`
	Subs    []subdomain.VerifyRow `json:"subs"`
	Ports   []portscan.Row        `json:"ports"`
	Paths   []paths.Row           `json:"paths"`
	APIs    []map[string]any      `json:"apis"`
	Finger  []fingerprint.Hit     `json:"finger"`
	Elapsed int64                 `json:"elapsed_ms"`
}

// Counters 汇总各项命中数。
func (r *Result) Counters() Counters {
	if r == nil {
		return Counters{}
	}
	return Counters{
		Subs: len(r.Subs), Ports: len(r.Ports), Paths: len(r.Paths),
		APIs: len(r.APIs), Finger: len(r.Finger),
	}
}

// 端口清单：常见暴露面，够快又能覆盖绝大多数「门没关」的情况。
const defaultPorts = "21,22,23,25,53,80,110,143,443,445,873,1080,1433,2375,3000,3306,3389,5432,5601,6379,7001,8000,8080,8081,8443,8888,9000,9090,9200,11211,27017"

func normalizeTarget(raw string) (string, error) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", errors.New("目标不能为空")
	}
	for _, bad := range []string{" ", "\t", "\n"} {
		if strings.Contains(t, bad) {
			return "", errors.New("目标不能包含空白字符")
		}
	}
	if strings.Contains(t, "://") {
		u, err := url.Parse(t)
		if err != nil {
			return "", fmt.Errorf("目标解析失败: %w", err)
		}
		t = u.Host
	}
	t = strings.TrimSuffix(strings.TrimSpace(t), "/")
	if t == "" || strings.ContainsAny(t, "\\\"'`;&|$") {
		return "", errors.New("目标含非法字符")
	}
	return t, nil
}

// start 建任务并异步跑流水线。
func (srv *Server) start(target string) (*Job, error) {
	t, err := normalizeTarget(target)
	if err != nil {
		return nil, err
	}
	kind := "domain"
	if cli.IsIP(strings.Split(t, ":")[0]) {
		kind = "ip"
	}
	out, err := cli.MakeOutdir(t)
	if err != nil {
		return nil, fmt.Errorf("产物目录创建失败: %w", err)
	}
	if abs, aerr := filepath.Abs(out); aerr == nil {
		out = abs
	}

	now := time.Now()
	j := &Job{
		ID:      fmt.Sprintf("%d-%s", now.UnixMilli(), shortHash(t)),
		Target:  t,
		Kind:    kind,
		Out:     out,
		Status:  JobQueued,
		Created: now,
		subs:    map[chan Event]struct{}{},
	}
	if kind == "domain" {
		j.Steps = []*Step{
			{Key: "subdomain", Name: "子域枚举", Status: StatusPending},
			{Key: "verify", Name: "存活验证", Status: StatusPending},
			{Key: "ports", Name: "端口扫描", Status: StatusPending},
			{Key: "probe", Name: "入口探测", Status: StatusPending},
			{Key: "finger", Name: "指纹识别", Status: StatusPending},
			{Key: "paths", Name: "敏感路径", Status: StatusPending},
			{Key: "api", Name: "API 未授权", Status: StatusPending},
		}
	} else {
		j.Steps = []*Step{
			{Key: "ports", Name: "端口扫描", Status: StatusPending},
			{Key: "probe", Name: "入口探测", Status: StatusPending},
			{Key: "finger", Name: "指纹识别", Status: StatusPending},
			{Key: "paths", Name: "敏感路径", Status: StatusPending},
			{Key: "api", Name: "API 未授权", Status: StatusPending},
		}
	}
	srv.store.Add(j)

	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	go srv.run(ctx, j)
	return j, nil
}

// run 执行流水线。每步都有独立计时与结果计数，失败不吞（写入步骤与日志）。
func (srv *Server) run(ctx context.Context, j *Job) {
	j.mu.Lock()
	j.Status = JobRunning
	j.mu.Unlock()
	j.emit(Event{Type: "job", Job: j.View()})
	j.logf("info", "开始测绘 %s（%s）", j.Target, kindName(j.Kind))
	j.logf("info", "产物目录 %s", j.Out)

	res := &Result{Target: j.Target}
	started := time.Now()

	// ── 1. 子域枚举 ────────────────────────────────────────────
	host := j.Target
	if j.Kind == "domain" {
		stepStart := time.Now()
		j.setStep("subdomain", StatusRunning, "证书透明度 + 字典爆破", -1, -1)
		j.logf("info", "子域枚举：crt.sh / certspotter + 字典")
		subs, err := srv.subsCall(ctx, j.Target, j.Out)
		ms := time.Since(stepStart).Milliseconds()
		switch {
		case err != nil && ctx.Err() != nil:
			j.setStep("subdomain", StatusFailed, "已取消", len(subs), ms)
			j.stopWith(ctx, res, started)
			return
		case err != nil:
			j.setStep("subdomain", StatusFailed, err.Error(), len(subs), ms)
			j.logf("err", "子域枚举失败: %v（继续后续步骤）", err)
		default:
			j.setStep("subdomain", StatusDone, fmt.Sprintf("%d 个子域", len(subs)), len(subs), ms)
			j.logf("ok", "子域枚举完成：%d 个", len(subs))
		}

		// ── 2. 存活验证 ────────────────────────────────────────
		if len(subs) > 0 {
			stepStart = time.Now()
			j.setStep("verify", StatusRunning, "DNS + HTTP 探活", -1, -1)
			j.logf("info", "存活验证：%d 个子域", len(subs))
			rows := srv.verifyCall(ctx, j.Out, 16)
			ms = time.Since(stepStart).Milliseconds()
			alive := 0
			for _, r := range rows {
				if r.Alive {
					alive++
				}
			}
			res.Subs = rows
			j.setStep("verify", StatusDone, fmt.Sprintf("%d 存活 / %d 总数", alive, len(rows)), alive, ms)
			j.logf("ok", "存活验证完成：%d/%d 存活", alive, len(rows))
			if len(rows) > 0 {
				host = strings.TrimPrefix(rows[0].Host, "*.")
			}
		} else {
			j.setStep("verify", StatusSkipped, "无子域可验证", 0, 0)
		}
	}

	// ── 3. 端口扫描 ────────────────────────────────────────────
	// 目标若显式带了端口（如 127.0.0.1:18080），该端口并进扫描清单——
	// 否则「打自己搭的靶站」永远扫不出东西，用户以为是工具坏了。
	scanHost, explicitPort := splitHostPort(host)
	ports := defaultPorts
	if explicitPort != "" && !strings.Contains(","+defaultPorts+",", ","+explicitPort+",") {
		ports = explicitPort + "," + defaultPorts
	}
	portStart := time.Now()
	j.setStep("ports", StatusRunning, "常见端口", -1, -1)
	j.logf("info", "端口扫描：%s（%d 个端口）", scanHost, len(strings.Split(ports, ",")))
	rows, perr := portscan.RunPortscanContext(ctx, scanHost, j.Out, ports, 3, 64)
	ms := time.Since(portStart).Milliseconds()
	if ctx.Err() != nil {
		j.setStep("ports", StatusFailed, "已取消", len(rows), ms)
		j.stopWith(ctx, res, started)
		return
	}
	res.Ports = rows
	if perr != nil {
		j.setStep("ports", StatusFailed, perr.Error(), len(rows), ms)
		j.logf("err", "端口扫描失败: %v", perr)
	} else {
		j.setStep("ports", StatusDone, fmt.Sprintf("%d 个开放端口", len(rows)), len(rows), ms)
		j.logf("ok", "端口扫描完成：%d 个开放", len(rows))
	}

	// ── 4-6. 需要一个可用的 HTTP 入口 ──────────────────────────
	j.setStep("probe", StatusRunning, "https → http 逐跳探测", -1, -1)
	j.logf("info", "探测站点入口（先 https 再 http，单协议最多 10s）")
	probeStart := time.Now()
	base := cli.PickBase(host)
	probeMs := time.Since(probeStart).Milliseconds()
	if base == "" {
		j.setStep("probe", StatusFailed, "无可用的 HTTP 入口", 0, probeMs)
		for _, k := range []string{"finger", "paths", "api"} {
			j.setStep(k, StatusSkipped, "目标无可用的 HTTP 入口", 0, 0)
		}
		j.logf("warn", "目标没有可用的 HTTP 入口，指纹/路径/API 三步跳过")
		res.Base = ""
		j.finish(res, started)
		return
	}
	j.setStep("probe", StatusDone, base, 1, probeMs)
	res.Base = base
	j.logf("info", "站点入口 %s", base)

	// ── 4. 指纹识别 ────────────────────────────────────────────
	stepStart := time.Now()
	j.setStep("finger", StatusRunning, "响应头 + 正文特征库", -1, -1)
	fr := netutil.Fetch(base, netutil.FetchOpt{Timeout: 12 * time.Second, Follow: true,
		HopCheck: netutil.HopPolicy(base), Ctx: ctx})
	if ctx.Err() != nil {
		j.setStep("finger", StatusFailed, "已取消", 0, time.Since(stepStart).Milliseconds())
		j.stopWith(ctx, res, started)
		return
	}
	var hdr strings.Builder
	keys := make([]string, 0, len(fr.Headers))
	for k := range fr.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hdr.WriteString(k)
		hdr.WriteString(": ")
		hdr.WriteString(fr.Headers[k])
		hdr.WriteString("\n")
	}
	hits := fingerprint.MatchHeaders(strings.ToLower(hdr.String()), strings.ToLower(fr.Body))
	res.Finger = hits
	ms = time.Since(stepStart).Milliseconds()
	label := make([]string, 0, len(hits))
	for _, h := range hits {
		label = append(label, h.Name)
	}
	j.setStep("finger", StatusDone, strings.Join(label, " · "), len(hits), ms)
	if len(hits) > 0 {
		j.logf("ok", "指纹命中：%s", strings.Join(label, " / "))
	} else {
		j.logf("info", "指纹库无命中（%d，%dB）", fr.Status, fr.Size)
	}

	// ── 5. 敏感路径 ────────────────────────────────────────────
	stepStart = time.Now()
	j.setStep("paths", StatusRunning, "字典探测 + 形态比对", -1, -1)
	j.logf("info", "敏感路径探测：%s", base)
	prows, pathErr := paths.RunPathsContext(ctx, base, j.Out)
	ms = time.Since(stepStart).Milliseconds()
	if ctx.Err() != nil {
		j.setStep("paths", StatusFailed, "已取消", len(prows), ms)
		j.stopWith(ctx, res, started)
		return
	}
	res.Paths = prows
	if pathErr != nil {
		j.setStep("paths", StatusFailed, pathErr.Error(), len(prows), ms)
		j.logf("err", "敏感路径探测失败: %v", pathErr)
	} else {
		j.setStep("paths", StatusDone, fmt.Sprintf("%d 条可疑路径", len(prows)), len(prows), ms)
		j.logf("ok", "敏感路径：%d 条命中", len(prows))
	}

	// ── 6. API 未授权 ──────────────────────────────────────────
	stepStart = time.Now()
	j.setStep("api", StatusRunning, "端点矩阵 + 基线比对", -1, -1)
	j.logf("info", "API 未授权探测：%s", base)
	arows, apiErr := apiunauth.RunAPIContext(ctx, base, j.Out, false)
	ms = time.Since(stepStart).Milliseconds()
	if ctx.Err() != nil {
		j.setStep("api", StatusFailed, "已取消", len(arows), ms)
		j.stopWith(ctx, res, started)
		return
	}
	res.APIs = arows
	if apiErr != nil {
		j.setStep("api", StatusFailed, apiErr.Error(), len(arows), ms)
		j.logf("err", "API 探测失败: %v", apiErr)
	} else {
		j.setStep("api", StatusDone, fmt.Sprintf("%d 个端点命中", len(arows)), len(arows), ms)
		j.logf("ok", "API 未授权：%d 个端点命中", len(arows))
	}

	j.finish(res, started)
}

// finish 正常收尾。
func (j *Job) finish(res *Result, started time.Time) {
	res.Elapsed = time.Since(started).Milliseconds()
	now := time.Now()
	j.mu.Lock()
	j.Status = JobDone
	j.Ended = &now
	j.Result = res
	j.mu.Unlock()
	c := res.Counters()
	j.logf("ok", "测绘完成：%d 子域 / %d 端口 / %d 路径 / %d API 命中，用时 %.1fs",
		c.Subs, c.Ports, c.Paths, c.APIs, float64(res.Elapsed)/1000)
	j.emit(Event{Type: "job", Job: j.View()})
}

// stopWith 取消收尾（保留已跑出的部分结果）。
func (j *Job) stopWith(ctx context.Context, res *Result, started time.Time) {
	res.Elapsed = time.Since(started).Milliseconds()
	now := time.Now()
	j.mu.Lock()
	j.Status = JobStopped
	j.Ended = &now
	j.Result = res
	j.mu.Unlock()
	j.logf("warn", "任务已停止（保留已得到的 %d 条结果）", res.Counters().Ports+res.Counters().Paths+res.Counters().APIs)
	j.emit(Event{Type: "job", Job: j.View()})
}

func kindName(k string) string {
	if k == "ip" {
		return "IP 目标"
	}
	return "域名目标"
}

// splitHostPort 把 host[:port] 拆开；没写端口时返回原串与空端口。
func splitHostPort(s string) (string, string) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p
	}
	return s, ""
}

func shortHash(s string) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	b := make([]byte, 4)
	for i := range b {
		b[i] = alpha[h%uint32(len(alpha))]
		h /= uint32(len(alpha))
	}
	return string(b)
}
