// Package typosquat 实现品牌仿冒域（typosquatting / cousin domain）汇洞监控：
//
//	品牌种子 → 候选生成（6 种核心 fuzzer + 中文拼音/首字母/后缀词）
//	        → 限速批量 DNS 判活（A/AAAA + MX，可配 resolver/QPS/缓存）
//	        → RDAP 富化（注册日期/注册商/到期日，本地 JSON 缓存 + 退避）
//	        → 风险评分（域龄 × MX × 归属，0–100 分 + 等级）
//	        → 增量台账（JSON ledger，下一轮只重查新增/变化项）+ 白名单
//
// 设计依据：~/hermes-wiki/research/defense-landscape/10-email-dns.md §5。
// 独立包，不接入 CLI 主流程；只用 Go 标准库，不引入任何第三方依赖。
//
// 边界（明示）：单机没有下架（takedown）能力，只产出告警/导出台账；
// 未注册排列 ≠ 安全，应纳入台账持续监控；合法相似域（品牌方防御性注册、
// 无关同名词）通过白名单排除。
package typosquat

import (
	"strings"
	"time"
)

// Candidate 一个仿冒候选域。Fuzzer 是首要来源，Fuzzers 是去重合并后的全部来源
// （台账需要写清每个候选是怎么来的）。
type Candidate struct {
	Domain  string   `json:"domain"`  // 完整域名，小写
	Stem    string   `json:"stem"`    // 主体标签（TLD 之前）
	TLD     string   `json:"tld"`     // 后缀，可多级（com.cn）
	Fuzzer  string   `json:"fuzzer"`  // 首要来源 fuzzer 名
	Fuzzers []string `json:"fuzzers"` // 全部来源（合并去重，字典序）
}

// Fuzzer 名称常量（台账/评分引用，勿随意改名）。
const (
	FuzzReplacement    = "replacement"     // 邻键/形近字符替换
	FuzzInsertion      = "insertion"       // 邻键插入 + 字符双写
	FuzzOmission       = "omission"        // 字符删除
	FuzzTransposition  = "transposition"   // 相邻字符换位
	FuzzPlural         = "plural"          // 复数化
	FuzzTLDSwap        = "tld-swap"        // TLD 替换
	FuzzPinyinFull     = "pinyin-full"     // 中文品牌拼音全拼
	FuzzPinyinInitials = "pinyin-initials" // 中文品牌拼音首字母缩写
	FuzzSuffix         = "suffix"          // 常见后缀词组合（-security/-login/-vip/-pay 等）
)

// Ownership 归属判定结果。
type Ownership string

const (
	OwnershipUnknown    Ownership = "unknown"     // 未富化/无法判定
	OwnershipBrand      Ownership = "brand"       // 品牌方自有（含防御性注册）
	OwnershipThirdParty Ownership = "third-party" // 非品牌方
)

// GenerateOptions 候选生成配置。零值可用：nil 列表回落到内置默认。
type GenerateOptions struct {
	DefaultTLD      string            // 种子不带 TLD 时的默认后缀，默认 "com"
	TLDs            []string          // tld-swap 目标列表，nil 用默认
	Suffixes        []string          // 后缀词列表，nil 用默认
	Pinyin          map[rune]string   // 自定义/补充拼音表（覆盖内置同字条目）
	DisablePinyinFuzz bool            // true 时不对拼音全拼词干再跑核心 fuzzer（省配额）
}

// DefaultTLDs tld-swap 默认目标（国内语境含 cn/com.cn/top/vip/shop 等）。
var DefaultTLDs = []string{
	"com", "net", "org", "cn", "com.cn", "info", "biz", "top", "xyz",
	"vip", "cc", "co", "io", "site", "online", "shop", "app", "club", "me", "tv",
}

// DefaultSuffixes 常见后缀词（钓鱼/仿冒高频组合词）。
var DefaultSuffixes = []string{
	"security", "login", "vip", "pay", "official", "online", "app", "shop", "mail", "sso",
}

// DNSOptions 批量 DNS 判活配置。
type DNSOptions struct {
	QPS      float64       // 每秒查询上限（全部查询类型合计），默认 20（保守）
	Workers  int           // 并发 worker 数，默认 16
	Timeout  time.Duration // 单次查询超时，默认 3s
	Resolver string        // 指定 resolver（"223.5.5.5" 或 "8.8.8.8:53"），空=系统
	CheckMX  bool          // 对已解析域查 MX（邮件截收能力），默认建议 true
	CheckNS  bool          // 对 NXDOMAIN 域补查 NS（判注册未解析），默认 false（省配额）
	CacheDir string        // 本地 DNS 缓存目录，空=不落盘
	CacheTTL time.Duration // 缓存有效期，默认 24h

	// lookup 仅供测试注入假 resolver；生产路径为 nil（走 net.Resolver）。
	lookup lookupAPI
}

func (o DNSOptions) withDefaults() DNSOptions {
	if o.QPS <= 0 {
		o.QPS = 20
	}
	if o.Workers <= 0 {
		o.Workers = 16
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 24 * time.Hour
	}
	return o
}

// RDAPOptions RDAP 查询配置。
type RDAPOptions struct {
	QPS          float64       // 默认 1（registry 限速严，保守）
	Timeout      time.Duration // 默认 15s
	CacheDir     string        // 本地 JSON 缓存目录，空=不落盘
	CacheTTL     time.Duration // 域名缓存有效期，默认 7 天
	MaxRetries   int           // 429/5xx 重试次数，默认 3
	BaseBackoff  time.Duration // 指数退避基数，默认 2s
	BootstrapURL string        // 覆盖 IANA bootstrap 地址（测试用）
}

func (o RDAPOptions) withDefaults() RDAPOptions {
	if o.QPS <= 0 {
		o.QPS = 1
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	if o.CacheTTL <= 0 {
		o.CacheTTL = 7 * 24 * time.Hour
	}
	if o.MaxRetries <= 0 {
		o.MaxRetries = 3
	}
	if o.BaseBackoff <= 0 {
		o.BaseBackoff = 2 * time.Second
	}
	if o.BootstrapURL == "" {
		o.BootstrapURL = "https://data.iana.org/rdap/dns.json"
	}
	return o
}

// normalizeBrand 归一化品牌种子：小写、去空白、剥 scheme/path。
func normalizeBrand(brand string) string {
	b := strings.ToLower(strings.TrimSpace(brand))
	if i := strings.Index(b, "://"); i >= 0 {
		b = b[i+3:]
	}
	if i := strings.IndexAny(b, "/?#"); i >= 0 {
		b = b[:i]
	}
	b = strings.Trim(b, ".")
	return b
}