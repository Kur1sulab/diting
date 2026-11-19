package typosquat

// fuzz.go —— 六种核心 fuzzer（对词干操作，TLD 保持不变）：
// replacement / insertion / omission / transposition / plural / tld-swap。
// 参考 dnstwist 的排列思路，但为配额控制做了收敛（邻键+形近 ASCII，
// 不含 bitsquatting/全 Unicode 同形字——那些留待二期）。

import (
	"sort"
	"strings"
)

// qwerty 邻键表：同排左右 + 上下排近似物理位置（程序化构建，确定性）。
var adjacentKeys = buildAdjacentKeys()

func buildAdjacentKeys() map[rune][]rune {
	rows := []string{"1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"}
	m := map[rune][]rune{}
	add := func(c, n rune) {
		if n == 0 || c == n {
			return
		}
		for _, x := range m[c] {
			if x == n {
				return
			}
		}
		m[c] = append(m[c], n)
	}
	for ri, row := range rows {
		for i := 0; i < len(row); i++ {
			c := rune(row[i])
			if i > 0 {
				add(c, rune(row[i-1]))
			}
			if i+1 < len(row) {
				add(c, rune(row[i+1]))
			}
			if ri > 0 {
				up := rows[ri-1]
				if i < len(up) {
					add(c, rune(up[i]))
				}
				if i+1 < len(up) {
					add(c, rune(up[i+1]))
				}
			}
			if ri+1 < len(rows) {
				dn := rows[ri+1]
				if i < len(dn) {
					add(c, rune(dn[i]))
				}
				if i+1 < len(dn) {
					add(c, rune(dn[i+1]))
				}
			}
		}
	}
	return m
}

// homoglyphs ASCII 形近替换表（l→1、o→0 这类肉眼难辨的抢注手法）。
var homoglyphs = map[rune][]rune{
	'a': {'4'}, 'b': {'6', 'd'}, 'c': {'e'}, 'd': {'b'}, 'e': {'3'},
	'g': {'9', 'q'}, 'h': {'n'}, 'i': {'1', 'l', 'j'}, 'j': {'i'},
	'l': {'1', 'i'}, 'm': {'n'}, 'n': {'m', 'h'}, 'o': {'0'},
	'p': {'q'}, 'q': {'p', 'g'}, 'r': {'n'}, 's': {'5'}, 't': {'7'},
	'u': {'v'}, 'v': {'u'}, 'y': {'v'}, 'z': {'2'},
	'0': {'o'}, '1': {'l', 'i'}, '2': {'z'}, '3': {'e'}, '5': {'s'},
	'6': {'b'}, '7': {'t'}, '9': {'g'},
}

// fuzzReplacement 字符替换：每个位置换成邻键或形近字符。
func fuzzReplacement(stem string) []string {
	var out []string
	seen := map[string]bool{}
	for i, c := range stem {
		cands := append([]rune{}, adjacentKeys[c]...)
		cands = append(cands, homoglyphs[c]...)
		for _, n := range cands {
			s := stem[:i] + string(n) + stem[i+1:]
			if s != stem && !seen[s] && validLabel(s) {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

// fuzzInsertion 字符插入：在每个位置插入邻键字符；另加字符双写（exaample）。
func fuzzInsertion(stem string) []string {
	var out []string
	seen := map[string]bool{}
	push := func(s string) {
		if s != stem && !seen[s] && validLabel(s) {
			seen[s] = true
			out = append(out, s)
		}
	}
	for i, c := range stem {
		for _, n := range adjacentKeys[c] {
			push(stem[:i] + string(n) + stem[i:])
			push(stem[:i+1] + string(n) + stem[i+1:])
		}
		push(stem[:i+1] + string(c) + stem[i+1:]) // 双写
	}
	return out
}

// fuzzOmission 字符删除：每个位置删一次（连续重复字符去重）。
func fuzzOmission(stem string) []string {
	var out []string
	seen := map[string]bool{}
	for i := range stem {
		s := stem[:i] + stem[i+1:]
		if s != stem && !seen[s] && validLabel(s) {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fuzzTransposition 相邻字符换位：交换 i 与 i+1（相同字符跳过）。
func fuzzTransposition(stem string) []string {
	var out []string
	seen := map[string]bool{}
	for i := 0; i+1 < len(stem); i++ {
		if stem[i] == stem[i+1] {
			continue
		}
		s := stem[:i] + string(stem[i+1]) + string(stem[i]) + stem[i+2:]
		if !seen[s] && validLabel(s) {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fuzzPlural 复数化：+s；s/x/z/ch/sh 结尾 +es；辅音+y → ies。
func fuzzPlural(stem string) []string {
	var out []string
	push := func(s string) {
		if s != stem && validLabel(s) {
			out = append(out, s)
		}
	}
	push(stem + "s")
	switch {
	case strings.HasSuffix(stem, "s"), strings.HasSuffix(stem, "x"),
		strings.HasSuffix(stem, "z"), strings.HasSuffix(stem, "ch"),
		strings.HasSuffix(stem, "sh"):
		push(stem + "es")
	}
	if len(stem) >= 2 && strings.HasSuffix(stem, "y") && !isVowel(rune(stem[len(stem)-2])) {
		push(stem[:len(stem)-1] + "ies")
	}
	return dedupStrings(out)
}

func isVowel(c rune) bool {
	return strings.ContainsRune("aeiou", c)
}

// validLabel 校验单个 DNS 标签：1–63 字符，[a-z0-9-]，不以 - 开头/结尾。
func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func validDomain(d string) bool {
	if len(d) > 253 {
		return false
	}
	for _, lab := range strings.Split(d, ".") {
		if !validLabel(lab) {
			return false
		}
	}
	return true
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// multiLevelTLDs 常见多级后缀，切词干时整体保留。
var multiLevelTLDs = []string{"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk", "com.au", "co.jp"}

// splitDomain 把种子切成词干+TLD；无 TLD 时用 def。
func splitDomain(seed, def string) (stem, tld string) {
	if def == "" {
		def = "com"
	}
	for _, ml := range multiLevelTLDs {
		if strings.HasSuffix(seed, "."+ml) {
			return strings.TrimSuffix(seed, "."+ml), ml
		}
	}
	if i := strings.LastIndex(seed, "."); i > 0 && i+1 < len(seed) {
		return seed[:i], seed[i+1:]
	}
	return seed, def
}

// Generate 由品牌种子生成全部候选（已去重合并来源、按域名排序）。
// 种子可以是域名（example.com / example.com.cn）或裸词（example / 淘宝）。
// 中文种子：拼音全拼/首字母直接成为候选，全拼词干再跑核心 fuzzer（可关）。
func Generate(brand string, o GenerateOptions) []Candidate {
	seed := normalizeBrand(brand)
	if seed == "" {
		return nil
	}
	if o.DefaultTLD == "" {
		o.DefaultTLD = "com"
	}
	tlds := o.TLDs
	if len(tlds) == 0 {
		tlds = DefaultTLDs
	}
	suffixes := o.Suffixes
	if len(suffixes) == 0 {
		suffixes = DefaultSuffixes
	}
	table := mergedPinyin(o.Pinyin)

	stem, tld := splitDomain(seed, o.DefaultTLD)
	original := stem + "." + tld

	type stemSrc struct {
		stem   string
		fuzzer string // 该词干来源（original 表示种子本身）
		pinyin bool   // 拼音派生词干：DisablePinyinFuzz 只关字符级 fuzzer，后缀/TLD 扩展保留
	}
	stems := []stemSrc{{stem: stem}}

	byDomain := map[string]*Candidate{}
	var order []string
	add := func(s, t, fuzzer string) {
		if !validLabel(s) || !validDomain(s+"."+t) {
			return
		}
		d := s + "." + t
		if d == original {
			return
		}
		if c, ok := byDomain[d]; ok {
			for _, f := range c.Fuzzers {
				if f == fuzzer {
					return
				}
			}
			c.Fuzzers = append(c.Fuzzers, fuzzer)
			sort.Strings(c.Fuzzers)
			return
		}
		byDomain[d] = &Candidate{Domain: d, Stem: s, TLD: t, Fuzzer: fuzzer, Fuzzers: []string{fuzzer}}
		order = append(order, d)
	}

	// 中文语境：拼音全拼 + 首字母缩写。
	if hasHan(stem) {
		if full, ok := pinyinFull(stem, table); ok {
			add(full, tld, FuzzPinyinFull)
			stems = append(stems, stemSrc{stem: full, fuzzer: FuzzPinyinFull, pinyin: true})
		}
		if ini, ok := pinyinInitials(stem, table); ok {
			add(ini, tld, FuzzPinyinInitials)
		}
	}

	// 六种核心 fuzzer 作用于每个活跃词干。
	for _, src := range stems {
		if !(src.pinyin && o.DisablePinyinFuzz) {
			for _, s := range fuzzReplacement(src.stem) {
				add(s, tld, FuzzReplacement)
			}
			for _, s := range fuzzInsertion(src.stem) {
				add(s, tld, FuzzInsertion)
			}
			for _, s := range fuzzOmission(src.stem) {
				add(s, tld, FuzzOmission)
			}
			for _, s := range fuzzTransposition(src.stem) {
				add(s, tld, FuzzTransposition)
			}
			for _, s := range fuzzPlural(src.stem) {
				add(s, tld, FuzzPlural)
			}
		}
		for _, alt := range tlds {
			if alt != tld {
				add(src.stem, alt, FuzzTLDSwap)
			}
		}
	}

	// 后缀词组合（combosquatting）：带连字符与不带两种形态。
	for _, src := range stems {
		for _, suf := range suffixes {
			add(src.stem+"-"+suf, tld, FuzzSuffix)
			add(src.stem+suf, tld, FuzzSuffix)
		}
	}

	out := make([]Candidate, 0, len(order))
	for _, d := range order {
		out = append(out, *byDomain[d])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}