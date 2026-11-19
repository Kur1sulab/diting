// coverage.go —— 覆盖矩阵的只读数据面：目标 × 检查类型。
//
// 回答「这块资产我测了没有」：主区指标卡只有总量（子域 N / 端口 N …），
// 表达不了盲区——某目标端口测了、敏感路径一次没跑，总量视图里看不出来。
// 本文件把 out/ 下每个目标目录的产物文件翻译成三态格子：
//
//	missing 未跑      —— 产物文件不存在（该检查从未在此目标上执行）
//	empty   已跑无命中 —— 产物存在且命中计数为 0（各模块 0 命中也写盘，已核对）
//	hits    命中 N    —— 产物存在且计数 > 0
//
// 纪律：纯只读。不触发任何扫描、不改引擎行为、不写任何文件；只 os.ReadDir /
// os.ReadFile 现有产物。目录名来自磁盘（建目录时已过 cli.OutdirName 清洗），
// 本 API 无用户输入参数，无路径穿越面。服务仍只绑 127.0.0.1。
package serve

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Kur1sulab/diting/engine-go/cli"
)

// 单文件读取上限：产物正常在 KB~MB 级；防病态大文件把内存吃光。
// 超限按「解析失败」处理（格子仍算已跑——文件确实存在）。
const coverageReadCap = 16 << 20

// CoverageCheck 矩阵横轴：7 类检查（与任务口径一致）。
type CoverageCheck struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// coverageChecks 横轴固定顺序。baseline 是 8 项聚合检查，格子显示 k/8。
var coverageChecks = []CoverageCheck{
	{Key: "subs", Name: "子域"},
	{Key: "ports", Name: "端口"},
	{Key: "finger", Name: "指纹"},
	{Key: "paths", Name: "敏感路径"},
	{Key: "api", Name: "API"},
	{Key: "jsintel", Name: "JS 线索"},
	{Key: "baseline", Name: "基线"},
}

// baselineArtifacts 基线 8 检查的产物文件名主干（= baseline.Check* 常量值，
// 与 report.Collect 的读取清单逐项一致）。
var baselineArtifacts = []string{
	"secheaders", "webfiles", "mailsec", "archives",
	"sslchain", "dnsrec", "whois", "geoasn",
}

// CoverageCell 一个格子。Text 是最终显示文案（未跑 / 0 / N / k/8），
// Detail 进悬停提示，说明计数口径。
type CoverageCell struct {
	State   string `json:"state"`
	N       int    `json:"n"`
	Text    string `json:"text"`
	Detail  string `json:"detail"`
	Partial bool   `json:"partial,omitempty"` // 基线只跑了 k/8（k<8）：格内提示还有未跑项
}

// CoverageTarget 矩阵纵轴：out/ 下一个目标目录 = 一行。
type CoverageTarget struct {
	Target    string                  `json:"target"` // 目录名（清洗后的目标）
	Kind      string                  `json:"kind"`   // domain | ip
	Updated   string                  `json:"updated"` // 最新产物 mtime（RFC3339）
	Cells     map[string]CoverageCell `json:"cells"`
	Missing   int                     `json:"missing"` // 未跑检查数（盲区）
	JobID     string                  `json:"job_id,omitempty"`
	JobStatus string                  `json:"job_status,omitempty"`
}

// CoverageSummary 全矩阵三态计数（面板徽章用）。
type CoverageSummary struct {
	Targets int `json:"targets"`
	Cells   int `json:"cells"`
	Missing int `json:"missing"`
	Empty   int `json:"empty"`
	Hits    int `json:"hits"`
}

// CoverageView GET /api/coverage 的响应。
type CoverageView struct {
	Checks    []CoverageCheck  `json:"checks"`
	Targets   []CoverageTarget `json:"targets"`
	Summary   CoverageSummary  `json:"summary"`
	Root      string           `json:"root"`
	Truncated bool             `json:"truncated,omitempty"`
}

// coverageRowCap 行数上限：out/ 经年累积可能上百目录，前端一屏读不完。
const coverageRowCap = 500

// coverage 读当前工作目录下的 out/（与 cli.MakeOutdir 的落盘位置同契约）。
func (s *Server) coverage() CoverageView {
	return coverageAt("out", s.store.List())
}

// coverageAt 纯函数版（根目录与任务快照注入），供单测直接构造产物夹具。
// jobs 用于把行与在跑/历史任务关联（前端高亮当前任务行）。
func coverageAt(root string, jobs []*JobView) CoverageView {
	v := CoverageView{
		Checks:  coverageChecks,
		Targets: make([]CoverageTarget, 0),
		Root:    root,
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return v // out/ 不存在 = 还没跑过任何任务，空态而非错误
	}
	// 目录名 → 最新任务（store.List 已按创建时间倒序，首个匹配即最新）。
	// 优先用任务记录的真实 Out（绝对路径取 Base），回退 OutdirName 清洗契约。
	jobByDir := make(map[string]*JobView)
	for _, j := range jobs {
		d := cli.OutdirName(j.Target)
		if j.Out != "" {
			d = filepath.Base(j.Out)
		}
		if _, ok := jobByDir[d]; !ok {
			jobByDir[d] = j
		}
	}
	for _, e := range ents {
		name := e.Name()
		// 跳过测试夹具（_unittest*）、隐藏目录与工具固定目录
		// （patchdiff 是补丁差异产物，不是资产目标，见 cli.go MakeOutdir("patchdiff")）；
		// 非目录不是目标产物。
		if !e.IsDir() || name == "patchdiff" || strings.HasPrefix(name, "_") || strings.HasPrefix(name, ".") {
			continue
		}
		if len(v.Targets) >= coverageRowCap {
			v.Truncated = true
			break
		}
		dir := filepath.Join(root, name)
		t := CoverageTarget{
			Target:  name,
			Kind:    coverageKind(name),
			Cells:   coverageCells(dir),
			Updated: coverageUpdated(dir),
		}
		for _, c := range t.Cells {
			if c.State == "missing" {
				t.Missing++
			}
		}
		if j := jobByDir[name]; j != nil {
			t.JobID, t.JobStatus = j.ID, j.Status
		}
		v.Targets = append(v.Targets, t)
	}
	// 排序：在跑/排队任务置顶（正在填格子），其余按最新产物时间倒序。
	sort.SliceStable(v.Targets, func(i, j int) bool {
		a, b := v.Targets[i], v.Targets[j]
		ra, rb := coverageActive(a.JobStatus), coverageActive(b.JobStatus)
		if ra != rb {
			return ra
		}
		if a.Updated != b.Updated {
			return a.Updated > b.Updated
		}
		return a.Target < b.Target
	})
	for _, t := range v.Targets {
		v.Summary.Targets++
		for _, c := range t.Cells {
			v.Summary.Cells++
			switch c.State {
			case "missing":
				v.Summary.Missing++
			case "empty":
				v.Summary.Empty++
			case "hits":
				v.Summary.Hits++
			}
		}
	}
	return v
}

func coverageActive(status string) bool {
	return status == JobRunning || status == JobQueued
}

// coverageKind 目录名 → ip/domain：去掉尾部 _<端口数字> 后按 cli.IsIP 判定
// （serve 任务目标形如 127.0.0.1:18080，OutdirName 把 : 洗成 _）。
func coverageKind(dirName string) string {
	cand := dirName
	if i := strings.LastIndex(dirName, "_"); i > 0 {
		suf := dirName[i+1:]
		if suf != "" && strings.Trim(suf, "0123456789") == "" {
			cand = dirName[:i]
		}
	}
	if cli.IsIP(cand) {
		return "ip"
	}
	return "domain"
}

// coverageUpdated 取 7 类主产物 + 8 项基线产物的最新 mtime；都没有则用目录 mtime。
func coverageUpdated(dir string) string {
	names := []string{
		"subdomains.txt", "ports.json", "fingerprint.json",
		"paths.json", "api_unauth.json", "jsintel.json",
	}
	for _, b := range baselineArtifacts {
		names = append(names, b+".json")
	}
	var latest time.Time
	for _, n := range names {
		if fi, err := os.Stat(filepath.Join(dir, n)); err == nil && fi.ModTime().After(latest) {
			latest = fi.ModTime()
		}
	}
	if latest.IsZero() {
		if fi, err := os.Stat(dir); err == nil {
			latest = fi.ModTime()
		}
	}
	if latest.IsZero() {
		return ""
	}
	return latest.Format(time.RFC3339)
}

// coverageCells 逐检查读产物 → 三态格子。文件存在 = 已跑（各模块 0 命中也写盘：
// subdomain.go:256 / portscan.go:429 / fingerprint.go:149 / paths.go:129 /
// apiunauth.go:370 / jsintel.go:837 均无条件 SafeWrite）；解析失败不改变
// 「已跑」事实，计数记 0 并在 Detail 里说明。
func coverageCells(dir string) map[string]CoverageCell {
	cells := make(map[string]CoverageCell, len(coverageChecks))

	// 子域：subdomains.txt 非空行数（与前端指标卡同口径）。
	if lines, ok := coverageReadFile(filepath.Join(dir, "subdomains.txt")); ok {
		n := 0
		sc := bufio.NewScanner(bytes.NewReader(lines))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) != "" {
				n++
			}
		}
		cells["subs"] = covCell(n, "枚举到 "+itoa(n)+" 个子域（subdomains.txt）")
	} else {
		cells["subs"] = covMissing("未跑 —— 无 subdomains.txt 产物")
	}

	// 端口：ports.json 的 open 数组长度；scanned 进提示（「只测了 3 个」的口径）。
	if raw, ok := coverageReadFile(filepath.Join(dir, "ports.json")); ok {
		var doc struct {
			Scanned int               `json:"scanned"`
			Open    []json.RawMessage `json:"open"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			cells["ports"] = covBroken("ports.json 存在但解析失败")
		} else {
			cells["ports"] = covCell(len(doc.Open),
				"开放 "+itoa(len(doc.Open))+" 个 · 扫描 "+itoa(doc.Scanned)+" 个端口（ports.json）")
		}
	} else {
		cells["ports"] = covMissing("未跑 —— 无 ports.json 产物")
	}

	// 指纹：fingerprint.json 顶层数组长度。
	if raw, ok := coverageReadFile(filepath.Join(dir, "fingerprint.json")); ok {
		var hits []json.RawMessage
		if err := json.Unmarshal(raw, &hits); err != nil {
			cells["finger"] = covBroken("fingerprint.json 存在但解析失败")
		} else {
			cells["finger"] = covCell(len(hits), "命中 "+itoa(len(hits))+" 条指纹（fingerprint.json）")
		}
	} else {
		cells["finger"] = covMissing("未跑 —— 无 fingerprint.json 产物")
	}

	// 敏感路径：paths.json 的 alive 数组长度（探测总数进提示）。
	if raw, ok := coverageReadFile(filepath.Join(dir, "paths.json")); ok {
		var doc struct {
			Alive []json.RawMessage `json:"alive"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			cells["paths"] = covBroken("paths.json 存在但解析失败")
		} else {
			cells["paths"] = covCell(len(doc.Alive), "存活敏感路径 "+itoa(len(doc.Alive))+" 条（paths.json）")
		}
	} else {
		cells["paths"] = covMissing("未跑 —— 无 paths.json 产物")
	}

	// API：api_unauth.json 的 hits 数组长度。
	if raw, ok := coverageReadFile(filepath.Join(dir, "api_unauth.json")); ok {
		var doc struct {
			Hits []json.RawMessage `json:"hits"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			cells["api"] = covBroken("api_unauth.json 存在但解析失败")
		} else {
			cells["api"] = covCell(len(doc.Hits), "未授权命中 "+itoa(len(doc.Hits))+" 条（api_unauth.json）")
		}
	} else {
		cells["api"] = covMissing("未跑 —— 无 api_unauth.json 产物")
	}

	// JS 线索：jsintel.json 的 endpoints + sensitive 计数。
	if raw, ok := coverageReadFile(filepath.Join(dir, "jsintel.json")); ok {
		var doc struct {
			Endpoints []string          `json:"endpoints"`
			Sensitive []json.RawMessage `json:"sensitive"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			cells["jsintel"] = covBroken("jsintel.json 存在但解析失败")
		} else {
			n := len(doc.Endpoints) + len(doc.Sensitive)
			cells["jsintel"] = covCell(n,
				"端点线索 "+itoa(len(doc.Endpoints))+" · 敏感信息 "+itoa(len(doc.Sensitive))+"（jsintel.json）")
		}
	} else {
		cells["jsintel"] = covMissing("未跑 —— 无 jsintel.json 产物（serve 流水线不含此步，需 CLI jsintel/all）")
	}

	// 基线：8 项检查各自落盘，格子显示 k/8；风险数 = 各产物 risks 中 warn/fail 条数。
	k, risks := 0, 0
	var ran []string
	for _, b := range baselineArtifacts {
		raw, ok := coverageReadFile(filepath.Join(dir, b+".json"))
		if !ok {
			continue
		}
		k++
		ran = append(ran, b)
		var doc struct {
			Risks []struct {
				Level string `json:"level"`
			} `json:"risks"`
		}
		if err := json.Unmarshal(raw, &doc); err == nil {
			for _, r := range doc.Risks {
				if r.Level == "warn" || r.Level == "fail" {
					risks++
				}
			}
		}
	}
	if k == 0 {
		cells["baseline"] = covMissing("未跑 —— 8 项基线检查均无产物（需 CLI baseline）")
	} else {
		c := covCell(risks, "已跑 "+itoa(k)+"/8 项（"+strings.Join(ran, "、")+"）· 风险 "+itoa(risks)+" 处")
		c.Text = itoa(k) + "/8"
		if k < 8 {
			c.Partial = true
			c.Detail += "（其余 " + itoa(8-k) + " 项未跑）"
		}
		cells["baseline"] = c
	}
	return cells
}

// covCell 已跑格子：n>0 = hits，n==0 = empty。
func covCell(n int, detail string) CoverageCell {
	st := "empty"
	if n > 0 {
		st = "hits"
	}
	return CoverageCell{State: st, N: n, Text: itoa(n), Detail: "已跑 · " + detail}
}

func covMissing(detail string) CoverageCell {
	return CoverageCell{State: "missing", N: 0, Text: "未跑", Detail: detail}
}

// covBroken 产物存在但解析失败：仍算已跑（文件在），计数不可信记 0。
func covBroken(detail string) CoverageCell {
	return CoverageCell{State: "empty", N: 0, Text: "0", Detail: "已跑 · " + detail + "，计数不可信"}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}

// coverageReadFile 带上限读文件；不存在/读失败返回 ok=false。
func coverageReadFile(path string) ([]byte, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, coverageReadCap+1))
	if err != nil || len(b) > coverageReadCap {
		return nil, false
	}
	return b, true
}

// handleCoverage GET /api/coverage —— 只读，无参数，无副作用。
func (s *Server) handleCoverage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.coverage())
}
