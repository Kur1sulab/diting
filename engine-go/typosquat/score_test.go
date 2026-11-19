package typosquat

// score_test.go —— 评分边界：新注册+MX 必须高分；品牌方封顶；分量可审计。

import (
	"testing"
	"time"
)

var scoreNow = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func TestScoreNewRegisteredWithMXIsHigh(t *testing.T) {
	// 新注册（10 天）+ 有 MX + 第三方 → 满分档
	r := Score(ScoreInput{
		RegisteredAt: scoreNow.AddDate(0, 0, -10),
		HasMX:        true,
		Ownership:    OwnershipThirdParty,
		Fuzzers:      []string{FuzzReplacement},
		Now:          scoreNow,
	})
	if r.Score < 90 {
		t.Fatalf("新注册+MX+第三方应 ≥90, got %d (%+v)", r.Score, r)
	}
	if r.Level != "critical" {
		t.Fatalf("应为 critical, got %s", r.Level)
	}
	// 新注册 + MX + 归属未知（DNS-only 轮的典型形态）→ 仍高分
	r2 := Score(ScoreInput{
		RegisteredAt: scoreNow.AddDate(0, 0, -10),
		HasMX:        true,
		Ownership:    OwnershipUnknown,
		Fuzzers:      []string{FuzzReplacement},
		Now:          scoreNow,
	})
	if r2.Score < 80 || r2.Level != "critical" {
		t.Fatalf("新注册+MX 应高分 ≥80, got %d/%s", r2.Score, r2.Level)
	}
}

func TestScoreAgeBuckets(t *testing.T) {
	cases := []struct {
		days int
		want int
	}{
		{0, 40}, {30, 40}, {31, 32}, {90, 32}, {91, 22},
		{365, 22}, {366, 12}, {1095, 12}, {1096, 5}, {3650, 5},
	}
	for _, c := range cases {
		r := Score(ScoreInput{
			RegisteredAt: scoreNow.AddDate(0, 0, -c.days),
			Ownership:    OwnershipUnknown,
			Now:          scoreNow,
		})
		if r.Age != c.want {
			t.Fatalf("域龄 %dd 分量应 %d, got %d", c.days, c.want, r.Age)
		}
	}
	// 域龄未知 → 中性 15
	r := Score(ScoreInput{Ownership: OwnershipUnknown, Now: scoreNow})
	if r.Age != 15 {
		t.Fatalf("未知域龄应 15, got %d", r.Age)
	}
}

func TestScoreMXAndOwnership(t *testing.T) {
	base := ScoreInput{Now: scoreNow, Ownership: OwnershipUnknown, Fuzzers: []string{FuzzReplacement}}
	withMX := base
	withMX.HasMX = true
	if Score(withMX).MX != 30 || Score(base).MX != 0 {
		t.Fatal("MX 分量应 30/0")
	}
	third := base
	third.Ownership = OwnershipThirdParty
	if Score(third).Ownership != 30 {
		t.Fatal("第三方归属分量应 30")
	}
	if Score(base).Ownership != 18 {
		t.Fatal("未知归属分量应 18")
	}
}

func TestScoreBrandOwnedCapped(t *testing.T) {
	// 品牌方防御性注册：即便新注册+MX 也封顶 10 分
	r := Score(ScoreInput{
		RegisteredAt: scoreNow.AddDate(0, 0, -5),
		HasMX:        true,
		Ownership:    OwnershipBrand,
		Fuzzers:      []string{FuzzReplacement},
		Now:          scoreNow,
	})
	if r.Score > 10 || r.Level != "low" {
		t.Fatalf("品牌方自有应封顶 10/low, got %d/%s", r.Score, r.Level)
	}
}

func TestScoreOldDomainLow(t *testing.T) {
	r := Score(ScoreInput{
		RegisteredAt: scoreNow.AddDate(-10, 0, 0),
		HasMX:        false,
		Ownership:    OwnershipBrand,
		Fuzzers:      []string{FuzzTLDSwap},
		Now:          scoreNow,
	})
	if r.Score > 10 {
		t.Fatalf("老域+无MX+品牌方应低分, got %d", r.Score)
	}
}

func TestScoreClampAndLevels(t *testing.T) {
	r := Score(ScoreInput{
		RegisteredAt: scoreNow.AddDate(0, 0, -1),
		HasMX:        true,
		Ownership:    OwnershipThirdParty,
		Fuzzers:      []string{FuzzReplacement, FuzzInsertion},
		Now:          scoreNow,
	})
	if r.Score != 100 { // 40+30+30+5=105 → 封顶 100
		t.Fatalf("应封顶 100, got %d", r.Score)
	}
	// DNS-only 形态：未知域龄 + MX + 未知归属 + 编辑距离1 → 68 high
	r2 := Score(ScoreInput{HasMX: true, Ownership: OwnershipUnknown, Fuzzers: []string{FuzzReplacement}, Now: scoreNow})
	if r2.Score != 68 || r2.Level != "high" {
		t.Fatalf("DNS-only 高分形态应 68/high, got %d/%s", r2.Score, r2.Level)
	}
	for score, want := range map[int]string{
		100: "critical", 80: "critical", 79: "high", 60: "high",
		59: "medium", 40: "medium", 39: "low", 0: "low",
	} {
		if got := LevelOf(score); got != want {
			t.Fatalf("LevelOf(%d)=%s, want %s", score, got, want)
		}
	}
	if LevelZh("critical") != "严重" || LevelZh("high") != "高危" {
		t.Fatal("中文等级标签错误")
	}
}

func TestScoreSimilarityWeights(t *testing.T) {
	mk := func(f string) ScoreResult {
		return Score(ScoreInput{Ownership: OwnershipUnknown, Fuzzers: []string{f}, Now: scoreNow})
	}
	if mk(FuzzReplacement).Similarity != 5 {
		t.Fatal("编辑距离1类相似度应 5")
	}
	if mk(FuzzPlural).Similarity != 3 || mk(FuzzPinyinFull).Similarity != 3 {
		t.Fatal("plural/pinyin 相似度应 3")
	}
	if mk(FuzzTLDSwap).Similarity != 2 || mk(FuzzSuffix).Similarity != 2 {
		t.Fatal("tld-swap/suffix 相似度应 2")
	}
	// 多来源取最强
	r := Score(ScoreInput{Ownership: OwnershipUnknown, Fuzzers: []string{FuzzSuffix, FuzzOmission}, Now: scoreNow})
	if r.Similarity != 5 {
		t.Fatal("多来源应取最强相似度")
	}
}