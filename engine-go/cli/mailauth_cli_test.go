package cli

// mailauth_cli_test.go —— mailauth 子命令契约：
//   - 注册：knownCmds 含 mailauth、helpText 有用法行（桌面/脚本发现面）
//   - 参数：缺 -d → exit 2；域名形状非法 → exit 2；-h → exit 0
//   - 产物：mailauth.json / mailauth.txt / evidence/mailauth/mailauth.json
//   - 只读：全部 DNS 走注入的假 resolver，不打真网络

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMailauthInKnownCmds(t *testing.T) {
	if !knownCmds["mailauth"] {
		t.Error("mailauth 应在 knownCmds（否则 dispatch 直接 exit 2）")
	}
	if !strings.Contains(helpText, "mailauth -d") {
		t.Error("helpText 应含 mailauth 用法行")
	}
	if !strings.Contains(mailauthUsage, "只读") {
		t.Error("mailauthUsage 应写明只读语义")
	}
}

func TestMailauthMissingDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := Run([]string{"mailauth"}); code != 2 {
		t.Errorf("缺 -d 应 exit 2，得 %d", code)
	}
	if code := Run([]string{"mailauth", "--selectors", "default"}); code != 2 {
		t.Errorf("只给 --selectors 也应 exit 2，得 %d", code)
	}
}

func TestMailauthBadDomainShape(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, bad := range []string{"bad/../dom", "a b.com", "x&y=1.com"} {
		if code := Run([]string{"mailauth", "-d", bad}); code != 2 {
			t.Errorf("非法域名 %q 应 exit 2，得 %d", bad, code)
		}
	}
}

func TestMailauthHelp(t *testing.T) {
	t.Chdir(t.TempDir())
	if code := Run([]string{"mailauth", "-h"}); code != 0 {
		t.Errorf("-h 应 exit 0，得 %d", code)
	}
}

// fakeCLILookup cli 层假 resolver（只实现 LookupTXT）。
type fakeCLILookup struct{ recs map[string][]string }

func (f fakeCLILookup) LookupTXT(_ context.Context, name string) ([]string, error) {
	if r, ok := f.recs[name]; ok {
		return r, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestMailauthProducts(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	fake := fakeCLILookup{recs: map[string][]string{
		"_dmarc.example.com":        {"v=DMARC1; p=reject; pct=100; rua=mailto:agg@example.com"},
		"example.com":               {"v=spf1 include:_spf.a.example.net -all"},
		"_spf.a.example.net":        {"v=spf1 ip4:192.0.2.0/24 -all"},
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}

	code := runMailauthWith([]string{"-d", "example.com", "--selectors", "default,google"}, fake)
	if code != 0 {
		t.Fatalf("体检应 exit 0，得 %d", code)
	}

	base := filepath.Join(dir, "out", "example.com")
	for _, p := range []string{
		filepath.Join(base, "mailauth.json"),
		filepath.Join(base, "mailauth.txt"),
		filepath.Join(base, "evidence", "mailauth", "mailauth.json"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("产物缺失: %s", p)
		}
	}

	b, err := os.ReadFile(filepath.Join(base, "mailauth.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep map[string]any
	if err := json.Unmarshal(b, &rep); err != nil {
		t.Fatalf("mailauth.json 非法 JSON: %v", err)
	}
	for _, k := range []string{"domain", "grade", "severity", "dmarc", "spf", "dkim", "bimi", "findings"} {
		if _, ok := rep[k]; !ok {
			t.Errorf("mailauth.json 缺键 %q", k)
		}
	}
	if rep["domain"] != "example.com" {
		t.Errorf("domain 键错误: %v", rep["domain"])
	}
	if rep["severity"] != "p=reject" {
		t.Errorf("severity 应为 p=reject，得 %v", rep["severity"])
	}

	txt, err := os.ReadFile(filepath.Join(base, "mailauth.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"邮件认证体检", "DMARC", "SPF", "DKIM", "BIMI", "现状：", "风险：", "建议："} {
		if !strings.Contains(string(txt), want) {
			t.Errorf("mailauth.txt 缺 %q", want)
		}
	}
}

func TestMailauthNoSave(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	fake := fakeCLILookup{recs: map[string][]string{"example.com": {"v=spf1 -all"}}}
	if code := runMailauthWith([]string{"-d", "example.com", "--no-save", "--selectors", "default"}, fake); code != 0 {
		t.Fatalf("--no-save 应 exit 0，得 %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "out")); !os.IsNotExist(err) {
		t.Errorf("--no-save 不该建 out 目录（err=%v）", err)
	}
}

// TestMailauthDomainAliasLastWins -d/--domain 是同一参数的两个写法，
// 重复出现取命令行里最后一个（argparse last-wins，与 pickAliasLastWins 契约一致）。
func TestMailauthDomainAliasLastWins(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	fake := fakeCLILookup{}
	code := runMailauthWith([]string{"--domain", "first.example", "-d", "last.example", "--selectors", "default"}, fake)
	if code != 0 {
		t.Fatalf("exit 0 期望，得 %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "last.example")); err != nil {
		t.Errorf("应以最后一个 -d/--domain 为准，产物目录缺失: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "out", "first.example")); !os.IsNotExist(err) {
		t.Error("不该按先出现的 --domain 建目录")
	}
}
