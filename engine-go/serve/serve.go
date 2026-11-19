package serve

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/diting/engine-go/cli"
	"github.com/Kur1sulab/diting/engine-go/report"
	"github.com/Kur1sulab/diting/engine-go/subdomain"
)

//go:embed web
var webFS embed.FS

// Server 是 Web 控制台的进程内状态。
type Server struct {
	store *Store
	ai    AIConfig

	// 下面两个是子域/存活两步的注入点：默认走真实实现，
	// 测试里换成桩函数，域分支就能离线跑通（不联 crt.sh）。
	subsFn   func(ctx context.Context, domain, out string) ([]string, error)
	verifyFn func(ctx context.Context, out string, workers int, doHTTP bool) []subdomain.VerifyRow
}

// Run 是 `diting serve` 的入口。
//
//	diting serve [--addr 127.0.0.1:8788] [--open]
func Run(args []string) int {
	addr := "127.0.0.1:8788"
	open := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--addr", "-addr":
			if i+1 < len(args) {
				addr = args[i+1]
				i++
			}
		case "--open", "-open":
			open = true
		case "--help", "-h", "help":
			fmt.Print(`diting serve —— Web 控制台

  diting serve [--addr 127.0.0.1:8788] [--open]

环境变量（AI 研判 / 问答；旧名 DITING_AI_* 仍兼容读取）:
  DITING_AI_BASE    OpenAI 兼容端点，默认 https://api.openai.com/v1
  DITING_AI_KEY     API key；本地端点可留空
  DITING_AI_MODEL   模型名，默认 gpt-4o-mini
`)
			return 0
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Printf("[!] 未知参数: %s\n", args[i])
				return 2
			}
		}
	}

	srv := &Server{
		store:    NewStore(),
		ai:       LoadAIConfig(),
		subsFn:   subdomain.RunContext,
		verifyFn: subdomain.RunVerifyContext,
	}
	mux := buildMux(srv)
	hs := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	url := "http://" + addr
	fmt.Printf("diting %s · Web 控制台\n", cli.Version)

	// 端口被占（本地常驻代理很容易撞 8788）就顺延找空位，最多试 10 个。
	ln, realAddr, lerr := listenWithFallback(addr, 10)
	if lerr != nil {
		fmt.Printf("[!] 服务启动失败: %v\n", lerr)
		return 1
	}
	if realAddr != addr {
		fmt.Printf("  端口   %s 被占用，已顺延到 %s\n", addr, realAddr)
	}
	url = "http://" + realAddr
	fmt.Printf("  地址   %s\n", url)
	fmt.Printf("  AI     %s\n", aiStatusLine(srv.ai))
	fmt.Printf("  停止   Ctrl-C\n")
	if open {
		go func() {
			time.Sleep(400 * time.Millisecond)
			openBrowser(url)
		}()
	}
	if err := hs.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Printf("[!] 服务异常退出: %v\n", err)
		return 1
	}
	return 0
}

// listenWithFallback 从 addr 起顺延找可用端口（host 不变，端口 +1）。
func listenWithFallback(addr string, tries int) (net.Listener, string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, addr, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, addr, err
	}
	var lastErr error
	for i := 0; i < tries; i++ {
		try := net.JoinHostPort(host, strconv.Itoa(port+i))
		ln, err := net.Listen("tcp", try)
		if err == nil {
			return ln, try, nil
		}
		lastErr = err
	}
	return nil, addr, lastErr
}

// buildMux 组装路由（单独拆出来，测试可以直接对着它发请求）。
// 静态页面自带禁缓存头——本地工具改完前端要能立刻看到效果。
func buildMux(srv *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/env", srv.hEnv)
	mux.HandleFunc("GET /api/jobs", srv.hList)
	mux.HandleFunc("POST /api/jobs", srv.hCreate)
	mux.HandleFunc("GET /api/jobs/{id}", srv.hDetail)
	mux.HandleFunc("POST /api/jobs/{id}/stop", srv.hStop)
	mux.HandleFunc("GET /api/jobs/{id}/events", srv.hEvents)
	mux.HandleFunc("GET /api/coverage", srv.handleCoverage)
	mux.HandleFunc("POST /api/ai/analyze", srv.hAnalyze)
	mux.HandleFunc("POST /api/ai/ask", srv.hAsk)
	mux.HandleFunc("GET /api/jobs/{id}/report.md", srv.hReport)
	mux.HandleFunc("/", srv.hStatic)
	return noCache(mux)
}

func aiStatusLine(c AIConfig) string {
	if c.Ready {
		return fmt.Sprintf("就绪（%s @ %s）", c.Model, c.Base)
	}
	return "未配置（" + c.Note + "）"
}

// noCache：本地页面禁用缓存，避免改了前端却被浏览器旧副本顶住。
func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, map[string]any{"error": fmt.Sprintf(format, args...)})
}

// ── 子域/存活两步的注入点（测试可替换）──────────────────────────

func (s *Server) subsCall(ctx context.Context, domain, out string) ([]string, error) {
	if s.subsFn != nil {
		return s.subsFn(ctx, domain, out)
	}
	return subdomain.RunContext(ctx, domain, out)
}

func (s *Server) verifyCall(ctx context.Context, out string, workers int) []subdomain.VerifyRow {
	if s.verifyFn != nil {
		return s.verifyFn(ctx, out, workers, true)
	}
	return subdomain.RunVerifyContext(ctx, out, workers, true)
}

// ── 基础信息 ────────────────────────────────────────────────────

func (s *Server) hEnv(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"name":     "diting",
		"version":  cli.Version,
		"go":       runtime.Version(),
		"platform": runtime.GOOS + "/" + runtime.GOARCH,
		"ai": map[string]any{
			"ready": s.ai.Ready, "model": s.ai.Model, "base": s.ai.Base, "note": s.ai.Note,
		},
	})
}

// ── 任务 ────────────────────────────────────────────────────────

func (s *Server) hList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"jobs": s.store.List()})
}

func (s *Server) hCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		errJSON(w, 400, "请求体解析失败")
		return
	}
	j, err := s.start(req.Target)
	if err != nil {
		errJSON(w, 400, "%v", err)
		return
	}
	writeJSON(w, 201, j.View())
}

func (s *Server) hDetail(w http.ResponseWriter, r *http.Request) {
	j, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	writeJSON(w, 200, j.View())
}

func (s *Server) hStop(w http.ResponseWriter, r *http.Request) {
	j, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	if j.cancel != nil {
		j.cancel()
	}
	writeJSON(w, 200, j.View())
}

// hEvents 用 SSE 推实时日志与步骤状态；连上先发一次全量快照。
func (s *Server) hEvents(w http.ResponseWriter, r *http.Request) {
	j, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		errJSON(w, 500, "当前连接不支持流式推送")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)

	ch := j.subscribe()
	defer j.unsubscribe(ch)

	send := func(e Event) bool {
		b, err := json.Marshal(e)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	if !send(Event{Type: "job", Job: j.View()}) {
		return
	}
	hb := time.NewTicker(20 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !send(e) {
				return
			}
		case <-hb.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// ── AI ──────────────────────────────────────────────────────────

func (s *Server) hAnalyze(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
	j, ok := s.store.Get(req.ID)
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	rep, err := s.analyze(ctx, j)
	if err != nil {
		errJSON(w, 502, "%v", err)
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) hAsk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
		Q  string `json:"q"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&req); err != nil {
		errJSON(w, 400, "请求体解析失败")
		return
	}
	if strings.TrimSpace(req.Q) == "" {
		errJSON(w, 400, "问题不能为空")
		return
	}
	j, ok := s.store.Get(req.ID)
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	ans, err := s.ask(ctx, j, req.Q)
	if err != nil {
		errJSON(w, 502, "%v", err)
		return
	}
	writeJSON(w, 200, map[string]any{"answer": ans})
}

// ── 报告导出 ────────────────────────────────────────────────────

// hReport 把产物目录里的实测结果渲染成 Markdown 报告（报告内容全部来自落盘产物）。
func (s *Server) hReport(w http.ResponseWriter, r *http.Request) {
	j, ok := s.store.Get(r.PathValue("id"))
	if !ok {
		errJSON(w, 404, "任务不存在")
		return
	}
	b := report.Collect(j.Out, j.Target)
	md := report.RenderMD(b)
	name := "diting-" + cli.OutdirName(j.Target) + ".md"
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write([]byte(md))
}

// ── 静态资源 ────────────────────────────────────────────────────

func (s *Server) hStatic(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		http.Error(w, "静态资源缺失", 500)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	b, err := fs.ReadFile(sub, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	_, _ = w.Write(b)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("打开浏览器失败（请手动访问 %s）", url)
	}
}
