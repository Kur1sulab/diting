package typosquat

// pinyin.go —— 中文语境扩展：品牌拼音全拼、首字母缩写。
// 零依赖约束下内置常用品牌汉字读音表（单读音，取品牌语境最常见读法），
// 可通过 GenerateOptions.Pinyin 补充/覆盖。表外汉字无法罗马化 → 跳过该
// 拼音 fuzzer（不猜读音，宁缺毋滥）。

import (
	"strings"
	"unicode"
)

// DefaultPinyin 内置常用汉字→拼音表（品牌/机构名高频字）。
var DefaultPinyin = map[rune]string{
	// 互联网平台
	'淘': "tao", '宝': "bao", '支': "zhi", '付': "fu", '微': "wei", '信': "xin",
	'京': "jing", '东': "dong", '百': "bai", '度': "du", '腾': "teng", '讯': "xun",
	'阿': "a", '里': "li", '华': "hua", '为': "wei", '小': "xiao", '米': "mi",
	'天': "tian", '猫': "mao", '精': "jing", '灵': "ling", '盒': "he", '马': "ma",
	'云': "yun", '闪': "shan", '送': "song", '美': "mei", '团': "tuan", '饿': "e",
	'了': "le", '么': "me", '滴': "di", '出': "chu", '租': "zu", '车': "che",
	'拼': "pin", '多': "duo", '抖': "dou", '音': "yin", '快': "kuai", '手': "shou",
	'哔': "bi", '哩': "li", '站': "zhan", '红': "hong", '书': "shu", '知': "zhi",
	'乎': "hu", '简': "jian", '掘': "jue", '携': "xie", '程': "cheng", '去': "qu",
	'哪': "na", '儿': "er", '飞': "fei", '猪': "zhu", '途': "tu", '艺': "yi",
	'龙': "long", '网': "wang", '易': "yi", '邮': "you", '箱': "xiang", '狐': "hu",
	'搜': "sou", '狗': "gou", '奇': "qi", '虎': "hu", '爱': "ai", '婚': "hun",
	'恋': "lian", '佳': "jia", '缘': "yuan", '珍': "zhen", '世': "shi", '纪': "ji",
	// 金融/银行/保险
	'平': "ping", '安': "an", '招': "zhao", '商': "shang", '建': "jian", '设': "she",
	'工': "gong", '农': "nong", '业': "ye", '中': "zhong", '国': "guo", '银': "yin",
	'行': "hang", '民': "min", '生': "sheng", '光': "guang", '永': "yong", '亨': "heng",
	'利': "li", '证': "zheng", '券': "quan", '基': "ji", '金': "jin", '财': "cai",
	'富': "fu", '寿': "shou", '险': "xian", '保': "bao", '浦': "pu", '发': "fa",
	'兴': "xing", '丰': "feng", '田': "tian", '大': "da", '众': "zhong", '万': "wan",
	'达': "da", '广': "guang", '汇': "hui", '链': "lian", '块': "kuai", '币': "bi",
	// 运营商/能源/交通
	'移': "yi", '动': "dong", '联': "lian", '通': "tong", '电': "dian", '石': "shi",
	'化': "hua", '油': "you", '铁': "tie", '路': "lu", '航': "hang", '空': "kong",
	// 数字/常用字
	'三': "san", '六': "liu", '零': "ling", '二': "er", '一': "yi", '五': "wu",
	'八': "ba", '九': "jiu", '十': "shi", '特': "te", '斯': "si", '拉': "la",
	'宁': "ning", '和': "he", '家': "jia", '乐': "le", '福': "fu", '娃': "wa",
	'哈': "ha", '蒙': "meng", '牛': "niu", '伊': "yi", '同': "tong", '仁': "ren",
	'健': "jian", '康': "kang", '医': "yi", '药': "yao", '堂': "tang", '老': "lao",
	'窖': "jiao", '酒': "jiu", '汾': "fen", '河': "he", '洋': "yang", '液': "ye",
	'粮': "liang", '台': "tai", '茅': "mao",
	// 物流/消费/品牌音译字
	'巢': "chao", '鸟': "niao", '菜': "cai", '驿': "yi", '圆': "yuan", '申': "shen",
	'韵': "yun", '顺': "shun", '极': "ji", '兔': "tu", '喜': "xi", '茶': "cha",
	'雪': "xue", '冰': "bing", '城': "cheng", '蜜': "mi", '蓝': "lan", '色': "se",
	'经': "jing", '典': "dian", '味': "wei", '千': "qian", '禾': "he", '道': "dao",
	'香': "xiang", '格': "ge", '夏': "xia", '贝': "bei", '尔': "er", '肯': "ken",
	'德': "de", '麦': "mai", '当': "dang", '劳': "lao", '汉': "han", '堡': "bao",
	'王': "wang", '朝': "chao", '廷': "ting", '莱': "lai", '士': "shi", '尼': "ni",
	'克': "ke", '迪': "di", '耐': "nai", '李': "li", '踏': "ta", '鸿': "hong",
	'星': "xing", '匹': "pi", '乔': "qiao", '丹': "dan", '锐': "rui", '步': "bu",
	'森': "sen", '威': "wei", '伦': "lun", '佐': "zuo", '奴': "nu", '卡': "ka",
	'侬': "nong", '波': "bo", '司': "si", '登': "deng", '帕': "pa", '沙': "sha",
	'驰': "chi", '奥': "ao", '古': "gu", '欧': "ou", '雅': "ya", '诗': "shi",
	'兰': "lan", '蔻': "kou", '倩': "qian", '碧': "bi", '珀': "po", '芳': "fang",
	'奈': "nai",
}

func mergedPinyin(custom map[rune]string) map[rune]string {
	if len(custom) == 0 {
		return DefaultPinyin
	}
	m := make(map[rune]string, len(DefaultPinyin)+len(custom))
	for k, v := range DefaultPinyin {
		m[k] = v
	}
	for k, v := range custom {
		m[k] = v
	}
	return m
}

func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// pinyinFull 全拼：汉字逐字取读音拼接；ASCII 字母/数字原样保留；
// 出现表外汉字或非法字符 → ok=false（不猜）。
func pinyinFull(stem string, table map[rune]string) (string, bool) {
	var b strings.Builder
	for _, r := range stem {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case unicode.Is(unicode.Han, r):
			p, ok := table[r]
			if !ok || p == "" {
				return "", false
			}
			b.WriteString(p)
		default:
			return "", false
		}
	}
	s := b.String()
	if !validLabel(s) {
		return "", false
	}
	return s, true
}

// pinyinInitials 首字母缩写：每个汉字取读音首字母（淘宝 → tb）。
func pinyinInitials(stem string, table map[rune]string) (string, bool) {
	var b strings.Builder
	for _, r := range stem {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case unicode.Is(unicode.Han, r):
			p, ok := table[r]
			if !ok || p == "" {
				return "", false
			}
			b.WriteByte(p[0])
		default:
			return "", false
		}
	}
	s := b.String()
	if len(s) < 2 || !validLabel(s) {
		return "", false
	}
	return s, true
}