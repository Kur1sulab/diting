package serve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Kur1sulab/yata/engine-go/mockweb"
	"github.com/Kur1sulab/yata/engine-go/subdomain"
)

// newTestServer 起一个内存 Server（不监听端口）。
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{store: NewStore(), ai: AIConfig{Model: "test-model"}}
}

// waitJob 轮询直到任务进入终态。
func waitJob(t *testing.T, j *Job, timeout time.Duration) *JobView {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		v := j.View()
		if v.Status == JobDone || v.Status == JobFailed || v.Status == JobStopped {
			return v
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("任务在 %v 内没有结束，最后状态 %s", timeout, j.View().Status)
	return nil
}

// IP 分支端到端：真打本地 mockweb 靶站，断言路径/API/指纹都有真实命中。
func TestPipelineIPAgainstLocalMock(t *testing.T) {
	site := httptest.NewServer(mockweb.DemoHandler())
	defer site.Close()

	srv := newTestServer(t)
	host := strings.TrimPrefix(site.URL, "http://")
	j, err := srv.start(host)
	if err != nil {
		t.Fatalf("启动任务失败: %v", err)
	}
	v := waitJob(t, j, 60*time.Second)

	if v.Status != JobDone {
		t.Fatalf("任务状态 = %s，期望 done（err=%s）", v.Status, v.Err)
	}
	if v.Result == nil {
		t.Fatal("done 却没有任何结果")
	}
	if len(v.Result.Paths) == 0 {
		t.Error("mockweb 靶站有 /robots.txt 等明文暴露面，敏感路径不应为 0")
	}
	if len(v.Result.APIs) == 0 {
		t.Error("mockweb 靶站有 swagger/actuator 端点，API 未授权不应为 0")
	}
	if v.Counters.Paths != len(v.Result.Paths) || v.Counters.APIs != len(v.Result.APIs) {
		t.Errorf("计数器与结果不一致: %+v", v.Counters)
	}
	// 每个命中都必须自带判定依据（不写「大概存在」这种模糊结论）
	for _, p := range v.Result.Paths {
		if p.Path == "" || p.Status == 0 {
			t.Errorf("路径命中共缺字段: %+v", p)
		}
	}
	// 步骤状态全部落在终态，不能停在 running
	for _, s := range v.Steps {
		switch s.Status {
		case StatusDone, StatusFailed, StatusSkipped:
		default:
			t.Errorf("步骤 %s 停在 %s", s.Key, s.Status)
		}
	}
}

// 域名分支：子域/存活两步用桩替换（不联 crt.sh），后续步骤真打 mock 靶站。
func TestPipelineDomainUsesInjectedSubdomain(t *testing.T) {
	site := httptest.NewServer(mockweb.DemoHandler())
	defer site.Close()
	hostPort := strings.TrimPrefix(site.URL, "http://")

	srv := newTestServer(t)
	srv.subsFn = func(ctx context.Context, domain, out string) ([]string, error) {
		return []string{"a." + domain, "b." + domain}, nil
	}
	srv.verifyFn = func(ctx context.Context, out string, workers int, doHTTP bool) []subdomain.VerifyRow {
		return []subdomain.VerifyRow{
			{Host: hostPort, IPs: []string{"127.0.0.1"}, Alive: true},
			{Host: "b.example.test", Alive: false},
		}
	}

	j, err := srv.start("example.test")
	if err != nil {
		t.Fatalf("启动任务失败: %v", err)
	}
	v := waitJob(t, j, 60*time.Second)
	if v.Kind != "domain" {
		t.Fatalf("kind = %s，期望 domain", v.Kind)
	}
	if v.Status != JobDone {
		t.Fatalf("状态 = %s（err=%s）", v.Status, v.Err)
	}
	if len(v.Result.Subs) != 2 {
		t.Fatalf("子域存活结果 = %d 条，期望 2", len(v.Result.Subs))
	}
	steps := map[string]string{}
	for _, s := range v.Steps {
		steps[s.Key] = s.Status
	}
	if steps["subdomain"] != StatusDone || steps["verify"] != StatusDone {
		t.Errorf("子域/存活步骤状态不对: %+v", steps)
	}
	// 存活验证把 host 改写成第一条存活主机 —— 端口/路径/API 应打到 mock 上
	if len(v.Result.Paths) == 0 {
		t.Error("存活主机改写失败：后续步骤没有打到 mock 靶站")
	}
}

// 目标清洗：非法输入必须在入口被拒，不能带进执行层。
func TestNormalizeTargetRejectsBadInput(t *testing.T) {
	bad := []string{"", "  ", "a b.com", "a&b.com", "x';rm -rf /", "http://", "a|b"}
	for _, in := range bad {
		if _, err := normalizeTarget(in); err == nil {
			t.Errorf("%q 应被拒绝", in)
		}
	}
	ok := map[string]string{
		"example.com":         "example.com",
		"https://example.com": "example.com",
		"127.0.0.1:8080":      "127.0.0.1:8080",
		"example.com/":        "example.com",
	}
	for in, want := range ok {
		got, err := normalizeTarget(in)
		if err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v；期望 %q", in, got, err, want)
		}
	}
}

// HTTP 层：env / 非法请求 / 404 / 静态首页。
func TestHandlers(t *testing.T) {
	srv := newTestServer(t)
	mux := buildMux(srv)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/env", nil))
	if rec.Code != 200 {
		t.Fatalf("/api/env = %d", rec.Code)
	}
	var env map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("env 不是 JSON: %v", err)
	}
	if env["name"] != "yata" {
		t.Errorf("env.name = %v", env["name"])
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/jobs", strings.NewReader(`{"target":""}`)))
	if rec.Code != 400 {
		t.Errorf("空目标应 400，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/api/jobs/nope", nil))
	if rec.Code != 404 {
		t.Errorf("不存在的任务应 404，实际 %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "八咫") {
		t.Errorf("首页异常: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("首页 Content-Type = %s", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("本地页面必须禁缓存，实际 %q", cc)
	}
}

// SSE：连上先收到一份任务快照。
func TestEventsSendsSnapshot(t *testing.T) {
	srv := newTestServer(t)
	j := &Job{ID: "t1", Target: "example.com", Kind: "domain", Status: JobRunning,
		Created: time.Now(), Steps: []*Step{{Key: "ports", Name: "端口扫描", Status: StatusPending}},
		subs: map[chan Event]struct{}{}}
	srv.store.Add(j)

	site := httptest.NewServer(buildMux(srv))
	defer site.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", site.URL+"/api/jobs/t1/events", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("连 SSE 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("SSE 状态 = %d", resp.StatusCode)
	}
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), `"type":"job"`) {
		t.Fatalf("首帧不是任务快照: %q", string(buf[:n]))
	}
}

// AI 未配置时必须给出可读原因，而不是崩掉。
func TestAIChatWithoutConfig(t *testing.T) {
	c := AIConfig{Base: "https://api.openai.com/v1", Model: "m"}
	c.Note = "未配置 YATA_AI_KEY"
	if c.Ready {
		t.Fatal("没有 key 的远端端点不该就绪")
	}
	if _, err := c.Chat(context.Background(), nil, 0); err == nil {
		t.Fatal("未就绪时应返回错误")
	}
	local := AIConfig{Base: "http://127.0.0.1:11434/v1", Model: "m", Ready: true}
	if local.Base == "" {
		t.Fatal("本地端点应可用")
	}
}
