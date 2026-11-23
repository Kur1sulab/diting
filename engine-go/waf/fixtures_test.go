package waf

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureFile 是录制式样本集：响应快照手工构造、不联网、可逐条复核。
type fixtureFile struct {
	Note  string        `json:"note"`
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Response struct {
		Status     int               `json:"status"`
		Headers    map[string]string `json:"headers"`
		Cookies    []string          `json:"cookies"`
		Body       string            `json:"body"`
		URL        string            `json:"url"`
		BodyRepeat int               `json:"body_repeat"` // >0：正文重复 N 遍，用来造「正常大页面」陷阱
	} `json:"response"`
	Want struct {
		Vendor      string `json:"vendor"` // "" = 不应产生任何属性
		Confidence  string `json:"confidence"`
		Challenge   string `json:"challenge"`
		MinEvidence int    `json:"min_evidence"`
	} `json:"want"`
}

func loadFixtures(t *testing.T) []fixtureCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fixtures.json"))
	if err != nil {
		t.Fatalf("读取 fixtures 失败: %v", err)
	}
	var ff fixtureFile
	if err := json.Unmarshal(raw, &ff); err != nil {
		t.Fatalf("解析 fixtures 失败: %v", err)
	}
	if len(ff.Cases) == 0 {
		t.Fatal("fixtures 为空")
	}
	return ff.Cases
}

// toResponse 把 fixture 展开成判定输入（body_repeat 用于构造正常大页面）。
func (c fixtureCase) toResponse() Response {
	body := c.Response.Body
	if c.Response.BodyRepeat > 1 {
		body = strings.Repeat(body, c.Response.BodyRepeat)
	}
	return Response{
		Status:  c.Response.Status,
		Headers: c.Response.Headers,
		Cookies: c.Response.Cookies,
		Body:    body,
		URL:     c.Response.URL,
	}
}

// TestFixtures 逐条断言 fixture 的期望。这是回归主闸：任何规则改动都要先过它。
func TestFixtures(t *testing.T) {
	cases := loadFixtures(t)
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got := Detect(c.toResponse())
			if c.Want.Vendor == "" {
				if got != nil {
					t.Fatalf("应无任何 WAF 属性，实际判成 %s（证据 %v）", got.String(), got.Evidence)
				}
				return
			}
			if got == nil {
				t.Fatalf("应判出 %s，实际 nil", c.Want.Vendor)
			}
			if got.Vendor != c.Want.Vendor {
				t.Fatalf("vendor = %q, want %q（证据 %v）", got.Vendor, c.Want.Vendor, got.Evidence)
			}
			if got.Confidence != c.Want.Confidence {
				t.Fatalf("confidence = %q, want %q（证据 %v）", got.Confidence, c.Want.Confidence, got.Evidence)
			}
			if got.Challenge != c.Want.Challenge {
				t.Fatalf("challenge = %q, want %q（证据 %v）", got.Challenge, c.Want.Challenge, got.Evidence)
			}
			if len(got.Evidence) < c.Want.MinEvidence {
				t.Fatalf("证据条数 %d < 期望 %d: %v", len(got.Evidence), c.Want.MinEvidence, got.Evidence)
			}
		})
	}
}

// TestFixturesTable 把判定结果打成 markdown 表，供验收时贴原始输出：
//
//	go test ./waf -run TestFixturesTable -v
func TestFixturesTable(t *testing.T) {
	cases := loadFixtures(t)
	var b strings.Builder
	b.WriteString("\n| # | fixture | 状态码 | 判定 vendor | 置信度 | 挑战 | 证据 |\n")
	b.WriteString("|---|---------|-------|------------|-------|------|------|\n")
	positives, traps := 0, 0
	for i, c := range cases {
		got := Detect(c.toResponse())
		vendor, conf, chal, ev := "—(无)", "—", "—", "—"
		if got != nil {
			vendor, conf, chal = got.Vendor, got.Confidence, got.Challenge
			ev = strings.Join(got.Evidence, "<br>")
		}
		if c.Want.Vendor == "" {
			traps++
		} else {
			positives++
		}
		fmt.Fprintf(&b, "| %d | %s | %d | %s | %s | %s | %s |\n",
			i+1, c.Name, c.Response.Status, vendor, conf, chal, ev)
	}
	b.WriteString(fmt.Sprintf("\n合计 %d 条：正例 %d / 误报陷阱 %d\n", len(cases), positives, traps))
	t.Log(b.String())
}
