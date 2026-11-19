package typosquat

// pinyin_test.go —— 中文语境扩展：拼音全拼 / 首字母缩写 / 后缀词组合。

import "testing"

func TestPinyinExpansion(t *testing.T) {
	cands := Generate("淘宝", GenerateOptions{})
	cases := map[string]string{
		"taobao.com":          FuzzPinyinFull,     // 全拼
		"tb.com":              FuzzPinyinInitials, // 首字母缩写
		"taobao-security.com": FuzzSuffix,         // 拼音词干 + 后缀词
		"taobaosecurity.com":  FuzzSuffix,
		"taobao-vip.com":      FuzzSuffix,
		"taobaopay.com":       FuzzSuffix,
		"taoba0.com":          FuzzReplacement, // 全拼词干再跑核心 fuzzer（o→0）
		"taobao.cn":           FuzzTLDSwap,
	}
	for d, want := range cases {
		c := hasDomain(cands, d)
		if c == nil {
			t.Fatalf("缺少中文语境候选 %s", d)
		}
		if c.Fuzzer != want {
			t.Fatalf("%s 来源应为 %s, got %s", d, want, c.Fuzzer)
		}
	}
}

func TestPinyinFullAndInitials(t *testing.T) {
	table := mergedPinyin(nil)
	if full, ok := pinyinFull("淘宝", table); !ok || full != "taobao" {
		t.Fatalf("淘宝 → taobao, got %q ok=%v", full, ok)
	}
	if ini, ok := pinyinInitials("淘宝", table); !ok || ini != "tb" {
		t.Fatalf("淘宝 → tb, got %q ok=%v", ini, ok)
	}
	if full, ok := pinyinFull("支付宝", table); !ok || full != "zhifubao" {
		t.Fatalf("支付宝 → zhifubao, got %q ok=%v", full, ok)
	}
	if full, ok := pinyinFull("微信", table); !ok || full != "weixin" {
		t.Fatalf("微信 → weixin, got %q ok=%v", full, ok)
	}
	// 混合：ASCII 原样保留
	if full, ok := pinyinFull("淘宝go", table); !ok || full != "taobaogo" {
		t.Fatalf("淘宝go → taobaogo, got %q ok=%v", full, ok)
	}
}

func TestPinyinUnknownHanSkipped(t *testing.T) {
	table := mergedPinyin(nil)
	if _, ok := pinyinFull("鑫鱻", table); ok {
		t.Fatal("表外汉字不应猜读音")
	}
	cands := Generate("鑫鱻", GenerateOptions{})
	if len(cands) != 0 {
		t.Fatalf("表外汉字品牌应无候选（不猜），got %d: %v", len(cands), cands)
	}
}

func TestPinyinCustomTable(t *testing.T) {
	o := GenerateOptions{Pinyin: map[rune]string{'鑫': "xin", '品': "pin", '牌': "pai"}}
	cands := Generate("鑫品牌", o)
	if hasDomain(cands, "xinpinpai.com") == nil {
		t.Fatal("自定义拼音表未生效")
	}
	if hasDomain(cands, "xpp.com") == nil {
		t.Fatal("自定义拼音首字母未生效")
	}
	// 覆盖内置读音
	o2 := GenerateOptions{Pinyin: map[rune]string{'淘': "tao2"}}
	if _, ok := pinyinFull("淘宝", mergedPinyin(o2.Pinyin)); ok {
		// tao2 含数字仍合法，应成功且被覆盖
		full, _ := pinyinFull("淘宝", mergedPinyin(o2.Pinyin))
		if full != "tao2bao" {
			t.Fatalf("自定义覆盖未生效: %q", full)
		}
	} else {
		t.Fatal("tao2bao 应为合法标签")
	}
}

func TestPinyinFuzzDisable(t *testing.T) {
	cands := Generate("淘宝", GenerateOptions{DisablePinyinFuzz: true})
	if hasDomain(cands, "taobao.com") == nil {
		t.Fatal("全拼候选本身应保留")
	}
	if hasDomain(cands, "taoba0.com") != nil {
		t.Fatal("DisablePinyinFuzz 时不应对拼音词干跑核心 fuzzer")
	}
	// 后缀词仍作用于拼音词干
	if hasDomain(cands, "taobao-security.com") == nil {
		t.Fatal("后缀词应仍作用于拼音词干")
	}
}