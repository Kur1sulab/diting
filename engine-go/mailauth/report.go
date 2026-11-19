package mailauth

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// buildFindings 生成三段式体检项：每条都给「现状 / 风险 / 建议」。
// 顺序固定（DMARC → SPF → DKIM → BIMI），与报告章节同序。
func buildFindings(rep *Report) []Finding {
	var out []Finding
	out = append(out, dmarcFindings(rep)...)
	out = append(out, spfFindings(rep)...)
	out = append(out, dkimFindings(rep)...)
	out = append(out, bimiFindings(rep)...)
	return out
}

func dmarcFindings(rep *Report) []Finding {
	d := rep.DMARC
	dom := rep.Domain
	const sec = "dmarc"
	const label = "DMARC"

	switch {
	case !d.Found && d.Error != "":
		return []Finding{{
			Section: sec, Key: "dmarc", Label: label, Level: LevelWarn,
			Status: fmt.Sprintf("DMARC 查询失败，本次未取得结果（%s）：%s", d.Name, d.Error),
			Risk:   "这是「没查到」而不是「没配」：本次结论不能当作该域未发布 DMARC。",
			Advice: "换网络或加 --timeout 8s 重跑一次再下结论。",
		}}
	case !d.Found:
		return []Finding{{
			Section: sec, Key: "dmarc", Label: label, Level: LevelFail,
			Status: fmt.Sprintf("未发布 DMARC 记录（%s 无 TXT）", d.Name),
			Risk:   "收件方没有任何策略可依，任何人拿该域名伪造发件人都会正常投递到收件箱；这是品牌钓鱼最难防的一类，因为信封域是真的。",
			Advice: fmt.Sprintf("发布 TXT：%s IN TXT \"v=DMARC1; p=none; rua=mailto:dmarc@%s\"；先只收聚合报告，确认合法发信源全部通过后再收紧。", d.Name, dom),
		}}
	case d.Invalid:
		return []Finding{{
			Section: sec, Key: "dmarc", Label: label, Level: LevelFail,
			Status: "记录存在但无效：" + d.InvalidReason,
			Risk:   "无效记录等同无记录——RFC 7489 规定解析失败的 DMARC 必须整体忽略，收件方按无策略处理。",
			Advice: "按 RFC 7489 §6.4 重写：v 必须是第一个标签，p 必须是 none/quarantine/reject 之一；改完用 dig 复验再观察 rua 报告。",
		}}
	}

	var out []Finding
	switch d.Policy {
	case "reject":
		out = append(out, Finding{
			Section: sec, Key: "dmarc", Label: label, Level: LevelOK,
			Status: fmt.Sprintf("p=reject（sp=%s，pct=%d）", orDefault(d.SubdomainPol, "继承 p"), d.Pct),
			Risk:   "无。失败邮件被收件方直接拒收，是 DMARC 的终态。",
			Advice: "保持现状；持续看 rua 报告，防止新增的合法发信源（新营销平台/新票据系统）上线后静默失败。",
		})
	case "quarantine":
		out = append(out, Finding{
			Section: sec, Key: "dmarc", Label: label, Level: LevelOK,
			Status: fmt.Sprintf("p=quarantine（sp=%s，pct=%d）", orDefault(d.SubdomainPol, "继承 p"), d.Pct),
			Risk:   "失败邮件进垃圾箱而非拒收，仍有被用户翻出并点击的可能；对高价值品牌略欠。",
			Advice: "rua 报告确认无合法源失败后，把 p 提到 reject；若短期不敢全量，用 pct=25 起步逐级放量。",
		})
	case "none":
		out = append(out, Finding{
			Section: sec, Key: "dmarc", Label: label, Level: LevelWarn,
			Status: fmt.Sprintf("p=none（只监控，不处置；sp=%s，pct=%d）", orDefault(d.SubdomainPol, "继承 p"), d.Pct),
			Risk:   "伪造邮件照样进收件箱——p=none 只产生报告，不改变投递结果。配了 DMARC 却没有防护效果，是最常见的「看起来做了」状态。",
			Advice: "用 rua 报告核对全部合法发信源（自建邮局/营销平台/工单系统）已同时通过 SPF 与 DKIM，然后把 p 提升到 quarantine，稳定后再到 reject。",
		})
	default:
		out = append(out, Finding{
			Section: sec, Key: "dmarc", Label: label, Level: LevelWarn,
			Status: fmt.Sprintf("p=%q 非标准值", d.Policy),
			Risk:   "非标准策略值会被解析器拒绝，实际按无策略处理。",
			Advice: "改成 none / quarantine / reject 三者之一。",
		})
	}

	if d.Multiple {
		out = append(out, Finding{
			Section: sec, Key: "dmarc-multiple", Label: label, Level: LevelFail,
			Status: fmt.Sprintf("同一名字返回 %d 条 DMARC 记录", len(d.Records)),
			Risk:   "RFC 7489 §6.6.3：多条记录一律按「无策略」处理，等于白配。",
			Advice: "合并成一条 TXT，删掉其余记录（含历史遗留的 _dmarc 子域委派记录）。",
		})
	}
	if len(d.RUA) == 0 {
		out = append(out, Finding{
			Section: sec, Key: "dmarc-rua", Label: label + " 报告地址", Level: LevelWarn,
			Status: "未配置 rua=（无聚合报告接收地址）",
			Risk:   "没有报告就看不清谁在冒充、哪些合法源在失败；策略收紧时只能盲改，容易把业务邮件一起打死。",
			Advice: fmt.Sprintf("加 rua=mailto:dmarc@%s（可多个，逗号分隔）；报告是 XML，建议接一个聚合分析服务再收。", rep.Domain),
		})
	}
	if d.Pct < 100 && d.Pct > 0 {
		out = append(out, Finding{
			Section: sec, Key: "dmarc-pct", Label: label + " 覆盖率", Level: LevelWarn,
			Status: fmt.Sprintf("pct=%d（策略只对 %d%% 的邮件生效）", d.Pct, d.Pct),
			Risk:   fmt.Sprintf("剩余 %d%% 的邮件不做 DMARC 处置，攻击者只要多试就能落到未覆盖的那部分。", 100-d.Pct),
			Advice: "灰度期结束就设回 pct=100；长期停在低百分比等于给自己留后门。",
		})
	}
	if d.PctInvalid {
		out = append(out, Finding{
			Section: sec, Key: "dmarc-pct-invalid", Label: label + " 覆盖率", Level: LevelWarn,
			Status: "pct= 不是 0-100 的整数，已按缺省 100 处理",
			Risk:   "解析器对非法 pct 的处理不一致，部分实现会整条忽略。",
			Advice: "改成 0-100 的整数或直接删掉 pct 标签。",
		})
	}
	return out
}

func spfFindings(rep *Report) []Finding {
	s := rep.SPF
	dom := rep.Domain
	const sec = "spf"
	const label = "SPF"

	if !s.Found {
		if s.Status == StError && s.Error != "" {
			return []Finding{{
				Section: sec, Key: "spf", Label: label, Level: LevelWarn,
				Status: fmt.Sprintf("SPF 查询失败，本次未取得结果（%s）：%s", dom, s.Error),
				Risk:   "这是「没查到」而不是「没配」：若据此判定该域无 SPF，会把一次 DNS 抖动写成安全结论。",
				Advice: "换网络或加 --timeout 8s 重跑一次再下结论。",
			}}
		}
		return []Finding{{
			Section: sec, Key: "spf", Label: label, Level: LevelFail,
			Status: fmt.Sprintf("未发布 SPF 记录（%s 无 v=spf1 TXT）", dom),
			Risk:   "收件方无法用 IP 白名单校验发信源，配合缺失的 DMARC 时伪造几乎零成本。",
			Advice: fmt.Sprintf("发布 TXT：%s IN TXT \"v=spf1 <你的发信 IP/网段> include:<邮件服务商> -all\"；先列全合法发信源再写 all。", dom),
		}}
	}

	var out []Finding
	base := fmt.Sprintf("%s（lookup %d/%d，深度 %d）", truncRec(s.Record), s.Lookups, s.Limit, s.Depth)

	if s.Multiple {
		out = append(out, Finding{
			Section: sec, Key: "spf-multiple", Label: label, Level: LevelFail,
			Status: fmt.Sprintf("同一域返回 %d 条 v=spf1 记录", len(s.Records)),
			Risk:   "RFC 7208 §4.5：多条 SPF 记录即 permerror，收件方按失败处理——SPF 完全失效，比没有更糟（有记录却必然失败）。",
			Advice: "合并成一条 TXT，把所有 include 与 ip4/ip6 写进同一条；删掉其余记录。",
		})
	}
	if s.Loop {
		out = append(out, Finding{
			Section: sec, Key: "spf-loop", Label: label, Level: LevelFail,
			Status: "include 链存在回环",
			Risk:   "回环使 SPF 求值无法收敛，收件方按 permerror 处理。",
			Advice: "找出互相 include 的两条记录，改成单向（被 include 方不要再 include 回来）。",
		})
	}
	if s.ExceedsLimit {
		out = append(out, Finding{
			Section: sec, Key: "spf-lookups", Label: label + " lookup 次数", Level: LevelFail,
			Status: fmt.Sprintf("展开后 DNS lookup %d 次，超过 RFC 7208 §4.6.4 的 %d 次上限（%s）", s.Lookups, s.Limit, base),
			Risk:   "超限即 permerror：收件方直接判 SPF 失败，合法邮件也会被拒或进垃圾箱，且报错信息通常只写「too many DNS lookups」，很难定位。",
			Advice: spfLookupAdvice(s),
		})
	} else {
		lv := LevelOK
		adv := "留 2-3 次余量给日后新增的发信平台；每加一个 include 都要重新数一遍。"
		if s.Lookups >= s.Limit-2 {
			lv = LevelWarn
			adv = fmt.Sprintf("已用 %d/%d，只剩 %d 次余量：再新增一个发信平台就可能越限。建议先把不再使用的 include 清掉。", s.Lookups, s.Limit, s.Limit-s.Lookups)
		}
		out = append(out, Finding{
			Section: sec, Key: "spf-lookups", Label: label + " lookup 次数", Level: lv,
			Status: fmt.Sprintf("展开后 DNS lookup %d 次 / 上限 %d（%s）", s.Lookups, s.Limit, base),
			Risk:   "在限内，合规。",
			Advice: adv,
		})
	}

	switch s.All {
	case "+all":
		out = append(out, Finding{
			Section: sec, Key: "spf-all", Label: label + " all 机制", Level: LevelFail,
			Status: "+all（所有发信源都通过）",
			Risk:   "等于宣布「谁发都合法」，SPF 形同虚设，且给钓鱼邮件提供了合法背书。",
			Advice: "改成 -all；发信源没列全就先补 include，不要用 +all 兜。",
		})
	case "":
		out = append(out, Finding{
			Section: sec, Key: "spf-all", Label: label + " all 机制", Level: LevelWarn,
			Status: "记录里没有 all 机制（按 RFC 等同 ?all 中性）",
			Risk:   "未匹配的 IP 得到 Neutral 结果，收件方不会因此减分，等于没有结论。",
			Advice: "在记录末尾补 -all（或过渡期用 ~all）。",
		})
	case "?all":
		out = append(out, Finding{
			Section: sec, Key: "spf-all", Label: label + " all 机制", Level: LevelWarn,
			Status: "?all（中性，未匹配不发结论）",
			Risk:   "未授权 IP 不会被判失败，SPF 对伪造没有任何约束力。",
			Advice: "发信源列全后改成 ~all 过渡，最终 -all。",
		})
	case "~all":
		out = append(out, Finding{
			Section: sec, Key: "spf-all", Label: label + " all 机制", Level: LevelOK,
			Status: "~all（软失败，标记但不拒收）",
			Risk:   "未授权 IP 被标记为 softfail，多数收件方会加分降级但不会直接拒；对伪造的拦截弱于 -all。",
			Advice: "作为过渡期可接受；发信源稳定后建议收紧到 -all（并确保 DMARC 已到 quarantine/reject 兜底）。",
		})
	case "-all":
		out = append(out, Finding{
			Section: sec, Key: "spf-all", Label: label + " all 机制", Level: LevelOK,
			Status: "-all（硬失败，未列出的发信源一律不通过）",
			Risk:   "无。这是 SPF 的期望终态。",
			Advice: "保持；新增发信平台时先加 include 再上线，否则新平台邮件会被判失败。",
		})
	}

	// include 链里出现问题的子节点单独点名，便于定位是哪一跳坏了。
	for _, row := range s.Chain {
		if row.Depth == 0 {
			continue
		}
		switch row.Status {
		case StNXDomain:
			out = append(out, Finding{
				Section: sec, Key: "spf-chain-nx", Label: label + " include 链", Level: LevelWarn,
				Status: fmt.Sprintf("include 目标不存在：%s（深度 %d，经由 %s）", row.Domain, row.Depth, row.Via),
				Risk:   "失效 include 仍占用 1 次 lookup 配额，且该分支永远匹配不到任何 IP。",
				Advice: "确认该服务商是否已停用；停用就从记录里删掉这条 include，把配额让出来。",
			})
		case StNoSPF:
			out = append(out, Finding{
				Section: sec, Key: "spf-chain-nospf", Label: label + " include 链", Level: LevelWarn,
				Status: fmt.Sprintf("include 目标没有 SPF 记录：%s（经由 %s）", row.Domain, row.Via),
				Risk:   "include 一个无 SPF 的域，permerror 风险高，且这一跳不贡献任何合法 IP。",
				Advice: "核对服务商文档给出的 include 域名是否写错；已废弃就删掉。",
			})
		case StDepthLimit:
			out = append(out, Finding{
				Section: sec, Key: "spf-chain-depth", Label: label + " include 链", Level: LevelWarn,
				Status: fmt.Sprintf("include 链展开到深度上限仍未收敛：%s（深度 %d）", row.Domain, row.Depth),
				Risk:   "链路过深通常意味着服务商层层转包，实际 lookup 数很容易越限。",
				Advice: "用服务商给出的「扁平」include 域名（多数厂商提供聚合入口），减少中转层级。",
			})
		case StError:
			out = append(out, Finding{
				Section: sec, Key: "spf-chain-error", Label: label + " include 链", Level: LevelWarn,
				Status: fmt.Sprintf("include 目标查询失败，本次未展开：%s（经由 %s）：%s", row.Domain, row.Via, row.Error),
				Risk:   "本次计数少了这一跳，真实 lookup 数可能更高；若该跳超限，评估结论会偏乐观。",
				Advice: "本地 resolver 抖动可先 --timeout 8s 重跑；持续失败说明该域权威 DNS 异常或已废弃，核实后再决定是否保留这条 include。",
			})
		}
	}
	return out
}

func spfLookupAdvice(s SPFResult) string {
	var heavy []string
	for _, row := range s.Chain {
		if row.Depth > 0 && row.Lookups >= 3 {
			heavy = append(heavy, fmt.Sprintf("%s(%d)", row.Domain, row.Lookups))
		}
	}
	adv := "把多个 include 合并成一个聚合入口（多数厂商提供），或把静态 IP 段直接写成 ip4:/ip6:（不占 lookup 配额）。"
	if len(heavy) > 0 {
		adv += " 当前占用最多的是：" + strings.Join(heavy, "、") + "。"
	}
	return adv
}

func dkimFindings(rep *Report) []Finding {
	const sec = "dkim"
	const label = "DKIM"

	var found []DKIMResult
	var weak []DKIMResult
	for _, d := range rep.DKIM {
		if !d.Found {
			continue
		}
		found = append(found, d)
		// 1024 位是 RFC 8301 允许的下限而非推荐值：仍能用，但已属该升级
		// 的一档，所以和「已吊销」「低于下限」一起进弱项清单。
		if d.Revoked || (d.KeyBits > 0 && d.KeyBits <= 1024) {
			weak = append(weak, d)
		}
	}

	if len(found) == 0 {
		return []Finding{{
			Section: sec, Key: "dkim", Label: label, Level: LevelWarn,
			Status: fmt.Sprintf("在 %d 个常见选择器上均未发现有效公钥（%s）", len(rep.DKIM), strings.Join(selectorNames(rep.DKIM), " / ")),
			Risk:   "没有可验证的签名公钥，收件方无法确认邮件未被篡改；DMARC 对齐也因此只能靠 SPF，转发场景（SPF 必失效）彻底失守。",
			Advice: "在邮件系统里启用 DKIM 签名（选择器建议 default 或 s1），把公钥发布到 <选择器>._domainkey." + rep.Domain + "；若已在用非常规选择器，用 --selectors 追加探测。",
		}}
	}

	var names []string
	for _, d := range found {
		bits := ""
		if d.KeyBits > 0 {
			bits = fmt.Sprintf(" %d-bit", d.KeyBits)
			if d.Estimated {
				bits += "（估算）"
			}
		}
		names = append(names, d.Selector+"("+d.KeyType+bits+")")
	}
	lv := LevelOK
	if len(found) > 0 && len(weak) == len(found) {
		lv = LevelWarn
	} else if len(weak) > 0 {
		lv = LevelWarn
	}
	out := []Finding{{
		Section: sec, Key: "dkim", Label: label, Level: lv,
		Status: fmt.Sprintf("已发现 %d 个可用选择器：%s", len(found), strings.Join(names, "、")),
		Risk:   "在。公钥可用于验证签名真实性。",
		Advice: "保持；轮换密钥时新旧选择器并存一段时间再下线旧的（避免在途邮件验签失败）。",
	}}
	for _, d := range weak {
		st := fmt.Sprintf("选择器 %s 公钥偏弱/失效：%d-bit", d.Selector, d.KeyBits)
		if d.Revoked {
			st = fmt.Sprintf("选择器 %s 的公钥已吊销（p= 为空）", d.Selector)
		}
		out = append(out, Finding{
			Section: sec, Key: "dkim-weak-" + d.Selector, Label: label, Level: LevelWarn,
			Status: st,
			Risk:   "1024 位只是 RFC 8301 的下限：多数收件方按 2048 位评估，该长度的签名更容易被判降权；低于 1024 位或已吊销则可能全量验签失败。",
			Advice: "生成 2048 位新密钥，用新选择器发布，切换签名配置后再吊销旧选择器。",
		})
	}
	return out
}

func bimiFindings(rep *Report) []Finding {
	const sec = "bimi"
	const label = "BIMI"
	b := rep.BIMI
	if !b.Found {
		return []Finding{{
			Section: sec, Key: "bimi", Label: label, Level: LevelInfo,
			Status: "未配置 BIMI（" + b.Name + " 无 TXT）",
			Risk:   "不影响投递与安全，只是收件端不显示品牌 Logo，缺少一个用户可肉眼识别的正品标记。",
			Advice: "可选增强：DMARC 到 p=quarantine/reject 后，发布 v=BIMI1; l=<SVG Logo 地址>；需要 VMC 时再加 a=<证书地址>（证书需付费并向 CA 证明品牌所有权）。",
		}}
	}
	if b.Invalid {
		return []Finding{{
			Section: sec, Key: "bimi", Label: label, Level: LevelWarn,
			Status: "BIMI 记录存在但缺少 l= 与 a=，无法生效",
			Risk:   "记录被解析器忽略，等于没配。",
			Advice: "补上 l=<SVG Tiny PS 格式 Logo 的 HTTPS 地址>。",
		}}
	}
	return []Finding{{
		Section: sec, Key: "bimi", Label: label, Level: LevelInfo,
		Status: fmt.Sprintf("已配置：l=%s，a=%s", orDefault(b.Logo, "（无）"), orDefault(b.VMC, "（无，仅 Logo 无 VMC）")),
		Risk:   "无（仅在 DMARC 已到 quarantine/reject 时才会被收件端采用）。",
		Advice: "确认 Logo 是 SVG Tiny PS 且可从公网 HTTPS 直取；要蓝色认证标需额外部署 VMC。",
	}}
}

func selectorNames(ds []DKIMResult) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, d.Selector)
	}
	return out
}

// ────────────────────────────── 评分 / 定级 ──────────────────────────────

// grade 权重：DMARC 45 / SPF 30 / DKIM 20 / BIMI 5。DMARC 是唯一能
// 独立兜住伪造的机制，故占比最高；BIMI 纯展示，只作加分。
func grade(rep *Report) (int, string, string) {
	score := 0

	switch rep.DMARC.Severity {
	case SevReject:
		score += 45
	case SevQuarantine:
		score += 38
	case SevPolicyNone:
		score += 12
	}
	if rep.DMARC.Pct < 100 && rep.DMARC.Pct > 0 {
		score -= 5
	}
	if rep.DMARC.Multiple || rep.DMARC.Invalid {
		score -= 20
	}

	switch {
	case !rep.SPF.Found:
		// 0 分
	case rep.SPF.Multiple || rep.SPF.ExceedsLimit || rep.SPF.Loop || rep.SPF.All == "+all":
		score += 8
	default:
		score += 30
		switch rep.SPF.All {
		case "~all":
			score -= 2
		case "?all", "":
			score -= 8
		}
		if rep.SPF.Lookups >= rep.SPF.Limit-2 {
			score -= 3
		}
	}

	// DKIM 的「未探到」与「未启用」不是一回事：选择器名由发信方自定且不公开，
	// 无法枚举。故未探到时给半分（10/20），探到弱钥（<1024）给 8，正常给 20。
	// 把「没探到」直接判零会让 google.com 这种自定选择器的域无故掉一级。
	best := 0
	for _, d := range rep.DKIM {
		if !d.Found || d.Revoked {
			continue
		}
		b := 20
		if d.KeyBits > 0 && d.KeyBits < 1024 {
			b = 8
		}
		if b > best {
			best = b
		}
	}
	if best == 0 && len(rep.DKIM) > 0 {
		best = 10
	}
	score += best

	if rep.BIMI.Found && !rep.BIMI.Invalid {
		score += 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	var g string
	switch {
	case score >= 90:
		g = "A"
	case score >= 75:
		g = "B"
	case score >= 60:
		g = "C"
	case score >= 40:
		g = "D"
	default:
		g = "F"
	}
	return score, g, rep.DMARC.Severity
}

func summarize(rep *Report) string {
	var parts []string
	switch rep.DMARC.Severity {
	case SevNone:
		if rep.DMARC.Found {
			parts = append(parts, "DMARC 记录无效")
		} else {
			parts = append(parts, "DMARC 缺失")
		}
	case SevPolicyNone:
		parts = append(parts, "DMARC p=none（只监控不处置）")
	case SevQuarantine:
		parts = append(parts, "DMARC p=quarantine")
	case SevReject:
		parts = append(parts, "DMARC p=reject")
	}
	if rep.SPF.Found {
		parts = append(parts, fmt.Sprintf("SPF lookup %d/%d", rep.SPF.Lookups, rep.SPF.Limit))
		if rep.SPF.ExceedsLimit {
			parts[0] += "，SPF 超限 permerror"
		}
	} else if rep.SPF.Status == StError {
		parts = append(parts, "SPF 查询失败（未取得结果）")
	} else {
		parts = append(parts, "SPF 缺失")
	}
	n := 0
	for _, d := range rep.DKIM {
		if d.Found && !d.Revoked {
			n++
		}
	}
	if n == 0 {
		parts = append(parts, "DKIM 未发现")
	} else {
		parts = append(parts, fmt.Sprintf("DKIM %d 个选择器", n))
	}
	if !rep.BIMI.Found {
		parts = append(parts, "BIMI 未配置")
	}
	return strings.Join(parts, "；")
}

// SortFindings 按等级排序（fail → warn → info → ok），同级保持生成序。
func SortFindings(fs []Finding) []Finding {
	rank := map[string]int{LevelFail: 0, LevelWarn: 1, LevelInfo: 2, LevelOK: 3}
	out := append([]Finding(nil), fs...)
	sort.SliceStable(out, func(i, j int) bool {
		ri, ok1 := rank[out[i].Level]
		rj, ok2 := rank[out[j].Level]
		if !ok1 {
			ri = 4
		}
		if !ok2 {
			rj = 4
		}
		return ri < rj
	})
	return out
}

// ────────────────────────────── 文本渲染 ──────────────────────────────

// LevelTag 等级 → 中文标签（终端与 txt 产物共用，避免两处文案漂移）。
func LevelTag(level string) string {
	switch level {
	case LevelFail:
		return "严重"
	case LevelWarn:
		return "警告"
	case LevelOK:
		return "合规"
	case LevelInfo:
		return "提示"
	}
	return level
}

func truncRec(rec string) string {
	r := strings.TrimSpace(rec)
	if r == "" {
		return "（无记录）"
	}
	if len(r) > 120 {
		return r[:117] + "..."
	}
	return r
}

// RenderText 生成中文体检报告（终端打印与 .txt 产物共用同一份实现）。
func RenderText(rep *Report) string {
	var b strings.Builder
	line := strings.Repeat("─", 62)

	fmt.Fprintf(&b, "邮件认证体检 · %s\n", rep.Domain)
	fmt.Fprintf(&b, "时间 %s · DNS 查询 %d 次 · 耗时 %dms\n", rep.GeneratedAt, rep.Queries, rep.ElapsedMS)
	fmt.Fprintf(&b, "综合评级 %s（%d/100） · DMARC 严重度 %s\n", rep.Grade, rep.Score, rep.Severity)
	fmt.Fprintf(&b, "结论：%s\n", rep.Summary)
	if rep.Incomplete {
		fmt.Fprintf(&b, "[!] 本次有 %d 项查询失败（%s），结论不完整——「未发现」不等于「未配置」，重跑后再定论。\n",
			len(rep.Failed), strings.Join(rep.Failed, "、"))
	}

	// DMARC
	fmt.Fprintf(&b, "\n%s\nDMARC  %s\n", line, rep.DMARC.Name)
	if rep.DMARC.Found {
		fmt.Fprintf(&b, "  记录 : %s\n", truncRec(rep.DMARC.Raw))
		fmt.Fprintf(&b, "  策略 : p=%s  sp=%s  pct=%d\n",
			orDefault(rep.DMARC.Policy, "（缺失）"),
			orDefault(rep.DMARC.SubdomainPol, "（继承 p）"), rep.DMARC.Pct)
		fmt.Fprintf(&b, "  对齐 : adkim=%s  aspf=%s\n",
			orDefault(rep.DMARC.ADKIM, "r（宽松，缺省）"), orDefault(rep.DMARC.ASPF, "r（宽松，缺省）"))
		fmt.Fprintf(&b, "  报告 : rua=%s\n", fmtList(rep.DMARC.RUA))
		if len(rep.DMARC.RUF) > 0 {
			fmt.Fprintf(&b, "         ruf=%s\n", fmtList(rep.DMARC.RUF))
		}
	} else {
		if rep.DMARC.Error != "" {
			fmt.Fprintf(&b, "  查询失败，未取得结果：%s\n", rep.DMARC.Error)
		} else {
			b.WriteString("  未发现记录\n")
		}
	}

	// SPF
	fmt.Fprintf(&b, "\n%s\nSPF\n", line)
	if !rep.SPF.Found {
		if rep.SPF.Status == StError && rep.SPF.Error != "" {
			fmt.Fprintf(&b, "  查询失败，未取得结果：%s\n", rep.SPF.Error)
		} else {
			b.WriteString("  未发现 v=spf1 记录\n")
		}
	} else {
		fmt.Fprintf(&b, "  记录 : %s\n", truncRec(rep.SPF.Record))
		if rep.SPF.Multiple {
			fmt.Fprintf(&b, "  [!] 同域 %d 条 SPF 记录 → permerror\n", len(rep.SPF.Records))
		}
		fmt.Fprintf(&b, "  all  : %s\n", orDefault(rep.SPF.All, "（无 all 机制，等同 ?all）"))
		flag := ""
		if rep.SPF.ExceedsLimit {
			flag = "  [!] 超限 → permerror"
		}
		fmt.Fprintf(&b, "  lookup: %d / %d%s\n", rep.SPF.Lookups, rep.SPF.Limit, flag)
		if len(rep.SPF.Chain) > 1 {
			b.WriteString("  include 链:\n")
			for _, row := range rep.SPF.Chain {
				indent := strings.Repeat("  ", row.Depth)
				mark := "└"
				if row.Depth == 0 {
					mark = "•"
				}
				fmt.Fprintf(&b, "    %s%s %s（%s，自身 %d，累计 %d，%s）\n",
					indent, mark, row.Domain, row.Via, row.Lookups, row.Total, row.Status)
				if row.Error != "" {
					fmt.Fprintf(&b, "    %s      └ %s\n", indent, row.Error)
				}
			}
		}
	}

	// DKIM
	fmt.Fprintf(&b, "\n%s\nDKIM（常见选择器探测）\n", line)
	for _, d := range rep.DKIM {
		switch {
		case d.Revoked:
			fmt.Fprintf(&b, "  %-9s 已吊销  %s\n", d.Selector, d.Note)
		case d.Found:
			bits := "长度未测定"
			if d.KeyBits > 0 {
				bits = strconv.Itoa(d.KeyBits) + "-bit"
				if d.Estimated {
					bits += "（估算）"
				}
			}
			fmt.Fprintf(&b, "  %-9s 存在    %s %s\n", d.Selector, d.KeyType, bits)
		default:
			fmt.Fprintf(&b, "  %-9s 未发现\n", d.Selector)
		}
	}
	b.WriteString("  注：选择器名由发信方自定且不公开，未探到只说明上述名字下无公钥，不等于该域未启用 DKIM。\n")

	// BIMI
	fmt.Fprintf(&b, "\n%s\nBIMI  %s\n", line, rep.BIMI.Name)
	if rep.BIMI.Found {
		fmt.Fprintf(&b, "  记录 : %s\n", truncRec(rep.BIMI.Record))
		fmt.Fprintf(&b, "  Logo : %s\n", orDefault(rep.BIMI.Logo, "（未设置）"))
		fmt.Fprintf(&b, "  VMC  : %s\n", orDefault(rep.BIMI.VMC, "（未设置）"))
	} else {
		b.WriteString("  未发现记录（可选增强，不影响投递）\n")
	}

	// 体检项
	fmt.Fprintf(&b, "\n%s\n体检项（按严重度排序）\n", line)
	for _, f := range SortFindings(rep.Findings) {
		fmt.Fprintf(&b, "\n[%s] %s\n", LevelTag(f.Level), f.Label)
		fmt.Fprintf(&b, "  现状：%s\n", f.Status)
		fmt.Fprintf(&b, "  风险：%s\n", f.Risk)
		fmt.Fprintf(&b, "  建议：%s\n", f.Advice)
	}
	return b.String()
}
