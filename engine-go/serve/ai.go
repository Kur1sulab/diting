package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// AIConfig 是 OpenAI 兼容后端的配置（本地 / 云端都吃）。
type AIConfig struct {
	Base  string `json:"base"`
	Model string `json:"model"`
	Ready bool   `json:"ready"`
	Note  string `json:"note"`
	key   string
}

// LoadAIConfig 从环境变量读配置；没配 key 也能给本地端点用。
func LoadAIConfig() AIConfig {
	base := firstEnv("SHINRA_AI_BASE", "SHINRA_AI_BASE", "OPENAI_BASE_URL")
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	base = strings.TrimRight(base, "/")
	key := firstEnv("SHINRA_AI_KEY", "SHINRA_AI_KEY", "OPENAI_API_KEY", "SHINRA_AI_TOKEN", "SHINRA_AI_TOKEN")
	model := firstEnv("SHINRA_AI_MODEL", "SHINRA_AI_MODEL", "OPENAI_MODEL")
	if model == "" {
		model = "gpt-4o-mini"
	}
	c := AIConfig{Base: base, Model: model, key: key}
	local := strings.Contains(base, "127.0.0.1") || strings.Contains(base, "localhost")
	switch {
	case key != "":
		c.Ready = true
	case local:
		c.Ready = true
		c.Note = "本地端点，未用 key"
	default:
		c.Note = "未配置 SHINRA_AI_KEY，AI 功能不可用；设置环境变量后重启 shinra serve"
	}
	return c
}

func firstEnv(names ...string) string {
	for _, n := range names {
		if v := strings.TrimSpace(os.Getenv(n)); v != "" {
			return v
		}
	}
	return ""
}

// AIReport 是一次 AI 研判的产物。
type AIReport struct {
	Markdown    string    `json:"markdown"`
	Model       string    `json:"model"`
	GeneratedAt time.Time `json:"generated_at"`
	Ms          int64     `json:"ms"`
}

type chatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatReq struct {
	Model       string    `json:"model"`
	Messages    []chatMsg `json:"messages"`
	Temperature float64   `json:"temperature"`
	Stream      bool      `json:"stream"`
}

type chatResp struct {
	Choices []struct {
		Message chatMsg `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Chat 调一次对话补全，返回正文。
func (c AIConfig) Chat(ctx context.Context, msgs []chatMsg, temperature float64) (string, error) {
	if !c.Ready {
		return "", errors.New(c.Note)
	}
	body, _ := json.Marshal(chatReq{Model: c.Model, Messages: msgs, Temperature: temperature})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("调用 AI 失败: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("AI 后端返回 %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	var cr chatResp
	if err := json.Unmarshal(raw, &cr); err != nil {
		return "", fmt.Errorf("AI 响应解析失败: %w", err)
	}
	if cr.Error != nil {
		return "", errors.New("AI 后端错误: " + cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return "", errors.New("AI 返回空结果")
	}
	return strings.TrimSpace(cr.Choices[0].Message.Content), nil
}

// facts 把实测结果压成一份紧凑事实清单（喂给模型，不让它自由发挥）。
func facts(r *Result, limit int) string {
	if r == nil {
		return "（暂无实测结果）"
	}
	var b strings.Builder
	c := r.Counters()
	fmt.Fprintf(&b, "目标: %s\n站点入口: %s\n产物: 子域 %d（存活）/ 开放端口 %d / 敏感路径 %d / API 命中 %d / 指纹 %d\n",
		r.Target, dash(r.Base), c.Subs, c.Ports, c.Paths, c.APIs, c.Finger)

	var fp []string
	for _, h := range r.Finger {
		fp = append(fp, h.Name)
	}
	if len(fp) > 0 {
		fmt.Fprintf(&b, "\n指纹: %s\n", strings.Join(fp, " / "))
	}

	if len(r.Ports) > 0 {
		b.WriteString("\n开放端口:\n")
		for i, p := range r.Ports {
			if i >= limit {
				fmt.Fprintf(&b, "- …（其余 %d 条省略）\n", len(r.Ports)-i)
				break
			}
			svc := p.Service
			banner := strings.TrimSpace(p.Banner)
			if len(banner) > 80 {
				banner = truncate(banner, 80)
			}
			fmt.Fprintf(&b, "- %d/%s%s %s\n", p.Port, dash(svc), "", banner)
		}
	}
	if len(r.Paths) > 0 {
		b.WriteString("\n可疑路径:\n")
		for i, p := range r.Paths {
			if i >= limit {
				fmt.Fprintf(&b, "- …（其余 %d 条省略）\n", len(r.Paths)-i)
				break
			}
			fmt.Fprintf(&b, "- %s → %d %s %s\n", p.Path, p.Status, p.Ctype, dash(p.Verdict))
		}
	}
	if len(r.APIs) > 0 {
		b.WriteString("\nAPI 端点命中:\n")
		for i, a := range r.APIs {
			if i >= limit {
				fmt.Fprintf(&b, "- …（其余 %d 条省略）\n", len(r.APIs)-i)
				break
			}
			fmt.Fprintf(&b, "- %s（%s，风险=%s）status=%s marker=%s\n",
				str(a["path"]), str(a["name"]), str(a["risk"]), str(a["status"]), str(a["marker"]))
		}
	}
	if len(r.Subs) > 0 {
		alive := make([]string, 0, len(r.Subs))
		for _, s := range r.Subs {
			if s.Alive {
				alive = append(alive, s.Host)
			}
		}
		if len(alive) > 0 {
			if len(alive) > limit {
				alive = alive[:limit]
			}
			fmt.Fprintf(&b, "\n存活主机（前 %d）: %s\n", len(alive), strings.Join(alive, ", "))
		}
	}
	return b.String()
}

const sysAnalyze = `你是资深红队攻击面分析师。用户给你一份「外部资产测绘的实测结果」，你要据此写中文研判。

硬规则：
1. 只允许使用给定事实，禁止编造资产、端口、版本、CVE 编号。信息不足就写「需补测」。
2. 区分「实测」与「推断」：实测=结果里出现的；推断=你基于它推的可能性，必须写明是推断。
3. 输出 Markdown，结构固定为四段：
   ## 攻击面判断（3-5 条要点，按可利用性排序）
   ## 值得先打的位置（每条给出目标 + 为什么 + 用什么手法）
   ## 下一步补测（3-4 条具体动作，能直接被扫描器执行的）
   ## 结论（一句话，给决策人看的）
4. 不写免责声明、不写「安全合规」类套话，讲技术。`

const sysAsk = `你是资深红队分析师，正在和操作员讨论一次外部资产测绘的结果。只用给定事实回答，缺信息就说缺什么、怎么补测。中文回答，简洁、直接、给可执行动作。`

// Analyze 生成研判报告。
func (srv *Server) analyze(ctx context.Context, j *Job) (*AIReport, error) {
	view := j.View()
	if view.Result == nil {
		return nil, errors.New("任务还没有结果，先跑一次测绘")
	}
	start := time.Now()
	j.logf("ai", "AI 研判开始（模型 %s）", srv.ai.Model)
	md, err := srv.ai.Chat(ctx, []chatMsg{
		{Role: "system", Content: sysAnalyze},
		{Role: "user", Content: "实测结果如下：\n\n" + facts(view.Result, 40)},
	}, 0.3)
	if err != nil {
		j.logf("err", "AI 研判失败: %v", err)
		return nil, err
	}
	rep := &AIReport{Markdown: md, Model: srv.ai.Model, GeneratedAt: time.Now(), Ms: time.Since(start).Milliseconds()}
	j.mu.Lock()
	j.AI = rep
	j.mu.Unlock()
	j.logf("ai", "AI 研判完成（%.1fs）", float64(rep.Ms)/1000)
	j.emit(Event{Type: "ai", AI: rep})
	return rep, nil
}

// ask 就当前结果回答追问。
func (srv *Server) ask(ctx context.Context, j *Job, q string) (string, error) {
	view := j.View()
	if view.Result == nil {
		return "", errors.New("任务还没有结果")
	}
	return srv.ai.Chat(ctx, []chatMsg{
		{Role: "system", Content: sysAsk},
		{Role: "system", Content: "实测结果：\n\n" + facts(view.Result, 40)},
		{Role: "user", Content: q},
	}, 0.4)
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func str(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		return dash(x)
	case float64:
		return fmt.Sprintf("%.0f", x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}
