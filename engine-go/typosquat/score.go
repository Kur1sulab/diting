package typosquat

// score.go —— 风险评分：域龄（新注册权重高）× MX 存在 × 归属判定，
// 辅以 fuzzer 相似度权重，输出 0–100 分与等级。分量透明可审计。
//
// 分量设计（满分 100，封顶截断）：
//   - 域龄：≤30d=40，≤90d=32，≤365d=22，≤3y=12，>3y=5，未知=15（中性偏警惕）
//   - MX：存在=30（具备邮件截收能力，钓鱼可直接收信），无=0
//   - 归属：第三方=30，未知=18，品牌方=0（且总分封顶 10，防御性注册不报警）
//   - 相似度：编辑距离 1 类 fuzzer=5，plural/pinyin=3，tld-swap/suffix=2
//
// 等级：≥80 critical（严重），≥60 high（高危），≥40 medium（中危），其余 low。

import "time"

// ScoreInput 评分输入。RegisteredAt 零值=域龄未知；Now 零值=取当前时间。
type ScoreInput struct {
	RegisteredAt time.Time
	HasMX        bool
	Ownership    Ownership
	Fuzzers      []string
	Now          time.Time
}

// ScoreResult 评分输出（分量保留，供台账审计）。
type ScoreResult struct {
	Score      int    `json:"score"`
	Level      string `json:"level"`
	Age        int    `json:"age_component"`
	MX         int    `json:"mx_component"`
	Ownership  int    `json:"ownership_component"`
	Similarity int    `json:"similarity_component"`
}

var fuzzerSimilarity = map[string]int{
	FuzzReplacement:    5,
	FuzzInsertion:      5,
	FuzzOmission:       5,
	FuzzTransposition:  5,
	FuzzPlural:         3,
	FuzzPinyinFull:     3,
	FuzzPinyinInitials: 3,
	FuzzTLDSwap:        2,
	FuzzSuffix:         2,
}

// Score 计算风险分。纯函数，无副作用。
func Score(in ScoreInput) ScoreResult {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := ScoreResult{}

	// 域龄分量
	switch {
	case in.RegisteredAt.IsZero():
		r.Age = 15 // 未知：RDAP 未富化，中性偏警惕
	default:
		days := now.Sub(in.RegisteredAt).Hours() / 24
		switch {
		case days <= 30:
			r.Age = 40
		case days <= 90:
			r.Age = 32
		case days <= 365:
			r.Age = 22
		case days <= 1095:
			r.Age = 12
		default:
			r.Age = 5
		}
	}

	// MX 分量
	if in.HasMX {
		r.MX = 30
	}

	// 归属分量
	switch in.Ownership {
	case OwnershipThirdParty:
		r.Ownership = 30
	case OwnershipBrand:
		r.Ownership = 0
	default:
		r.Ownership = 18
	}

	// 相似度分量（取最强 fuzzer）
	for _, f := range in.Fuzzers {
		if w := fuzzerSimilarity[f]; w > r.Similarity {
			r.Similarity = w
		}
	}

	total := r.Age + r.MX + r.Ownership + r.Similarity
	if in.Ownership == OwnershipBrand && total > 10 {
		total = 10 // 品牌方自有（防御性注册）：封顶低分
	}
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}
	r.Score = total
	r.Level = LevelOf(total)
	return r
}

// LevelOf 分数→等级。
func LevelOf(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// LevelZh 等级中文标签（报告用）。
func LevelZh(level string) string {
	switch level {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	default:
		return "低危"
	}
}