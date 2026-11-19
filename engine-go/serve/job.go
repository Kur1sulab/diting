// Package serve：diting 的 Web 控制台后端。
//
// 定位：把 engine-go 里现成的侦察能力（subdomain / portscan / paths /
// apiunauth / fingerprint）编排成可观测的任务流水线，用一杯 HTTP + SSE
// 暴露给浏览器，并接一层 AI（OpenAI 兼容接口）做研判与问答。
//
// 纪律：界面上的每个数字都来自真实执行结果；AI 只做解释与排序，
// 不允许它凭空补资产——提示词里明确禁止编造，前端也标注「实测 / AI 推断」。
package serve

import (
	"fmt"
	"sync"
	"time"
)

// 步骤状态机
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

// 任务状态机
const (
	JobQueued  = "queued"
	JobRunning = "running"
	JobDone    = "done"
	JobFailed  = "failed"
	JobStopped = "stopped"
)

// Step 是流水线里的一步（子域 / 端口 / 指纹 …）。
type Step struct {
	Key    string `json:"key"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
	Count  int    `json:"count"`
	Ms     int64  `json:"ms"`
}

// LogLine 是控制台里的一行。
type LogLine struct {
	TS  int64  `json:"ts"`
	Lvl string `json:"lvl"` // info | ok | warn | err | ai
	Msg string `json:"msg"`
	Seq int    `json:"seq"`
}

// Job 是一次测绘任务。
type Job struct {
	ID      string     `json:"id"`
	Target  string     `json:"target"`
	Kind    string     `json:"kind"` // domain | ip
	Out     string     `json:"out"`
	Status  string     `json:"status"`
	Err     string     `json:"err,omitempty"`
	Created time.Time  `json:"created"`
	Ended   *time.Time `json:"ended,omitempty"`
	Steps   []*Step    `json:"steps"`
	Result  *Result    `json:"result,omitempty"`
	AI      *AIReport  `json:"ai,omitempty"`

	mu     sync.Mutex
	logs   []LogLine
	seq    int
	subs   map[chan Event]struct{}
	cancel func()
}

// Event 是 SSE 推给前端的一条消息。
type Event struct {
	Type string    `json:"type"` // log | step | job | ai
	Log  *LogLine  `json:"log,omitempty"`
	Step *Step     `json:"step,omitempty"`
	Job  *JobView  `json:"job,omitempty"`
	AI   *AIReport `json:"ai,omitempty"`
}

// JobView 是给前端的任务快照（不含锁与订阅者）。
type JobView struct {
	ID       string     `json:"id"`
	Target   string     `json:"target"`
	Kind     string     `json:"kind"`
	Out      string     `json:"out"`
	Status   string     `json:"status"`
	Err      string     `json:"err,omitempty"`
	Created  time.Time  `json:"created"`
	Ended    *time.Time `json:"ended,omitempty"`
	Elapsed  int64      `json:"elapsed_ms"`
	Steps    []*Step    `json:"steps"`
	Logs     []LogLine  `json:"logs"`
	Result   *Result    `json:"result,omitempty"`
	AI       *AIReport  `json:"ai,omitempty"`
	Counters Counters   `json:"counters"`
}

// Counters 是顶栏四张卡片的数据源。
type Counters struct {
	Subs   int `json:"subs"`
	Ports  int `json:"ports"`
	Paths  int `json:"paths"`
	APIs   int `json:"apis"`
	Finger int `json:"finger"`
}

// View 生成快照。
func (j *Job) View() *JobView {
	j.mu.Lock()
	defer j.mu.Unlock()
	v := &JobView{
		ID: j.ID, Target: j.Target, Kind: j.Kind, Out: j.Out, Status: j.Status,
		Err: j.Err, Created: j.Created, Ended: j.Ended, Steps: j.Steps,
		Result: j.Result, AI: j.AI,
		Logs: append([]LogLine(nil), j.logs...),
	}
	if j.Ended != nil {
		v.Elapsed = j.Ended.Sub(j.Created).Milliseconds()
	} else {
		v.Elapsed = time.Since(j.Created).Milliseconds()
	}
	if j.Result != nil {
		v.Counters = j.Result.Counters()
	}
	return v
}

// ── 日志与事件总线 ──────────────────────────────────────────────

func (j *Job) logf(lvl, format string, args ...any) {
	j.mu.Lock()
	j.seq++
	ln := LogLine{TS: time.Now().UnixMilli(), Lvl: lvl, Msg: fmt.Sprintf(format, args...), Seq: j.seq}
	j.logs = append(j.logs, ln)
	if len(j.logs) > 4000 { // 环形上限：长任务不撑爆内存
		j.logs = j.logs[len(j.logs)-4000:]
	}
	subs := make([]chan Event, 0, len(j.subs))
	for c := range j.subs {
		subs = append(subs, c)
	}
	j.mu.Unlock()

	ev := Event{Type: "log", Log: &ln}
	for _, c := range subs {
		select {
		case c <- ev:
		default: // 慢消费者丢事件，前端靠快照兜底
		}
	}
}

func (j *Job) emit(e Event) {
	j.mu.Lock()
	subs := make([]chan Event, 0, len(j.subs))
	for c := range j.subs {
		subs = append(subs, c)
	}
	j.mu.Unlock()
	for _, c := range subs {
		select {
		case c <- e:
		default:
		}
	}
}

func (j *Job) setStep(key, status, msg string, count int, ms int64) {
	j.mu.Lock()
	for _, s := range j.Steps {
		if s.Key == key {
			s.Status = status
			if msg != "" {
				s.Msg = msg
			}
			if count >= 0 {
				s.Count = count
			}
			if ms >= 0 {
				s.Ms = ms
			}
			cp := *s
			j.mu.Unlock()
			j.emit(Event{Type: "step", Step: &cp})
			return
		}
	}
	j.mu.Unlock()
}

func (j *Job) subscribe() chan Event {
	c := make(chan Event, 512)
	j.mu.Lock()
	j.subs[c] = struct{}{}
	j.mu.Unlock()
	return c
}

func (j *Job) unsubscribe(c chan Event) {
	j.mu.Lock()
	if _, ok := j.subs[c]; ok {
		delete(j.subs, c)
		close(c)
	}
	j.mu.Unlock()
}

// ── 任务仓库 ────────────────────────────────────────────────────

// Store 是内存任务表（单机本地工具，重启即清）。
type Store struct {
	mu   sync.RWMutex
	jobs map[string]*Job
	ord  []string
}

// NewStore 构造任务表。
func NewStore() *Store { return &Store{jobs: map[string]*Job{}} }

// Add 登记任务。
func (s *Store) Add(j *Job) {
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.ord = append([]string{j.ID}, s.ord...)
	if len(s.ord) > 200 {
		for _, id := range s.ord[200:] {
			delete(s.jobs, id)
		}
		s.ord = s.ord[:200]
	}
	s.mu.Unlock()
}

// Get 取任务。
func (s *Store) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

// List 按时间倒序列出任务快照。
func (s *Store) List() []*JobView {
	s.mu.RLock()
	ids := append([]string(nil), s.ord...)
	s.mu.RUnlock()
	out := make([]*JobView, 0, len(ids))
	for _, id := range ids {
		if j, ok := s.Get(id); ok {
			out = append(out, j.View())
		}
	}
	return out
}
