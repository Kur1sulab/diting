package typosquat

// fuzz_test.go —— 六种核心 fuzzer 的输出形态 + Generate 集成约束。

import (
	"strings"
	"testing"
)

func hasDomain(cands []Candidate, d string) *Candidate {
	for i := range cands {
		if cands[i].Domain == d {
			return &cands[i]
		}
	}
	return nil
}

func TestFuzzerReplacement(t *testing.T) {
	stems := fuzzReplacement("example")
	if len(stems) == 0 {
		t.Fatal("replacement 无输出")
	}
	found := false
	for _, s := range stems {
		if len(s) != len("example") {
			t.Fatalf("replacement 改变长度: %q", s)
		}
		if s == "examp1e" { // l→1 形近替换（实测已注册且配 MX 的手法）
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少形近替换 examp1e，got %v", stems)
	}
	cands := Generate("example.com", GenerateOptions{})
	c := hasDomain(cands, "examp1e.com")
	if c == nil || c.Fuzzer != FuzzReplacement {
		t.Fatalf("examp1e.com 来源应为 replacement: %+v", c)
	}
}

func TestFuzzerInsertion(t *testing.T) {
	stems := fuzzInsertion("example")
	found := false
	for _, s := range stems {
		if len(s) != len("example")+1 {
			t.Fatalf("insertion 长度应 +1: %q", s)
		}
		if s == "exaample" { // 字符双写
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少双写 exaample，got %v", stems)
	}
	// 邻键插入：x 的邻键 z（zxcvbnm 行左邻）插到 x 前 → ezxample
	if !containsString(stems, "ezxample") {
		t.Fatalf("缺少邻键插入 ezxample，got %v", stems)
	}
}

func TestFuzzerOmission(t *testing.T) {
	stems := fuzzOmission("example")
	for _, s := range stems {
		if len(s) != len("example")-1 {
			t.Fatalf("omission 长度应 -1: %q", s)
		}
	}
	if !containsString(stems, "examle") { // 删 p
		t.Fatalf("缺少 examle，got %v", stems)
	}
	if !containsString(stems, "exampl") { // 删尾部 e
		t.Fatalf("缺少 exampl，got %v", stems)
	}
}

func TestFuzzerTransposition(t *testing.T) {
	stems := fuzzTransposition("example")
	for _, s := range stems {
		if len(s) != len("example") {
			t.Fatalf("transposition 长度应不变: %q", s)
		}
	}
	if !containsString(stems, "examlpe") { // p/l 换位
		t.Fatalf("缺少 examlpe，got %v", stems)
	}
	// 相同字符不换位
	for _, s := range fuzzTransposition("aaa") {
		t.Fatalf("aaa 不应产生换位: %q", s)
	}
}

func TestFuzzerPlural(t *testing.T) {
	if got := fuzzPlural("example"); !containsString(got, "examples") {
		t.Fatalf("example → examples, got %v", got)
	}
	if got := fuzzPlural("box"); !containsString(got, "boxes") {
		t.Fatalf("box → boxes, got %v", got)
	}
	if got := fuzzPlural("city"); !containsString(got, "cities") {
		t.Fatalf("city → cities, got %v", got)
	}
	if got := fuzzPlural("watch"); !containsString(got, "watches") {
		t.Fatalf("watch → watches, got %v", got)
	}
}

func TestFuzzerTLDSwap(t *testing.T) {
	cands := Generate("example.com", GenerateOptions{})
	for _, d := range []string{"example.net", "example.org", "example.cn", "example.com.cn", "example.top", "example.vip"} {
		c := hasDomain(cands, d)
		if c == nil {
			t.Fatalf("缺少 TLD 替换候选 %s", d)
		}
		if c.Fuzzer != FuzzTLDSwap {
			t.Fatalf("%s 来源应为 tld-swap, got %s", d, c.Fuzzer)
		}
		if c.Stem != "example" {
			t.Fatalf("%s 词干应保持 example, got %s", d, c.Stem)
		}
	}
	if hasDomain(cands, "example.com") != nil {
		t.Fatal("原域不应出现在候选中")
	}
}

func TestFuzzerSuffix(t *testing.T) {
	cands := Generate("example.com", GenerateOptions{})
	for _, d := range []string{
		"example-security.com", "examplesecurity.com",
		"example-login.com", "examplelogin.com",
		"example-vip.com", "examplevip.com",
		"example-pay.com", "examplepay.com",
	} {
		c := hasDomain(cands, d)
		if c == nil {
			t.Fatalf("缺少后缀词候选 %s", d)
		}
		if c.Fuzzer != FuzzSuffix {
			t.Fatalf("%s 来源应为 suffix, got %s", d, c.Fuzzer)
		}
	}
}

func TestGenerateInvariants(t *testing.T) {
	cands := Generate("example.com", GenerateOptions{})
	if len(cands) < 100 {
		t.Fatalf("example.com 候选量异常偏少: %d", len(cands))
	}
	seen := map[string]bool{}
	prev := ""
	for _, c := range cands {
		if seen[c.Domain] {
			t.Fatalf("重复候选: %s", c.Domain)
		}
		seen[c.Domain] = true
		if c.Domain == "example.com" {
			t.Fatal("原域混入候选")
		}
		if !validDomain(c.Domain) {
			t.Fatalf("非法域名: %s", c.Domain)
		}
		if c.Fuzzer == "" || len(c.Fuzzers) == 0 {
			t.Fatalf("候选缺来源 fuzzer: %+v", c)
		}
		if prev != "" && c.Domain < prev {
			t.Fatalf("未按域名排序: %s < %s", c.Domain, prev)
		}
		prev = c.Domain
	}
	// 多来源合并：同一域被多个 fuzzer 命中时 Fuzzers 应合并。
	// example 无跨 fuzzer 碰撞（置换改两位≠替换改一位），用 boxs 构造必然碰撞：
	// plural(boxs)=boxss 与 insertion 双写尾部 s=boxss。
	multi := Generate("boxs.com", GenerateOptions{})
	c := hasDomain(multi, "boxss.com")
	if c == nil || len(c.Fuzzers) != 2 ||
		!containsString(c.Fuzzers, FuzzPlural) || !containsString(c.Fuzzers, FuzzInsertion) {
		t.Fatalf("boxss.com 应合并 plural+insertion 来源: %+v", c)
	}
}

func TestGenerateSeedForms(t *testing.T) {
	// 裸词、带 scheme、多级 TLD
	a := Generate("example", GenerateOptions{})
	if hasDomain(a, "examp1e.com") == nil {
		t.Fatal("裸词种子应默认 .com")
	}
	b := Generate("https://example.com/path", GenerateOptions{})
	if hasDomain(b, "examp1e.com") == nil {
		t.Fatal("scheme/path 应被剥掉")
	}
	c := Generate("example.com.cn", GenerateOptions{})
	if hasDomain(c, "examp1e.com.cn") == nil {
		t.Fatal("多级 TLD 应整体保留")
	}
	if hasDomain(c, "example.cn") == nil {
		t.Fatal("com.cn → cn 替换缺失")
	}
	if Generate("", GenerateOptions{}) != nil {
		t.Fatal("空种子应返回 nil")
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestValidLabel(t *testing.T) {
	bad := []string{"", "-abc", "abc-", "a_b", "a.b", strings.Repeat("a", 64), "淘"}
	for _, s := range bad {
		if validLabel(s) {
			t.Fatalf("应非法: %q", s)
		}
	}
	for _, s := range []string{"a", "examp1e", "a-b", "123"} {
		if !validLabel(s) {
			t.Fatalf("应合法: %q", s)
		}
	}
}