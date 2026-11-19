package mailauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// ────────────────────────────── DMARC ──────────────────────────────

// probeDMARC 查 _dmarc.<domain> 并解析策略标签。
func probeDMARC(ctx context.Context, r *runner, domain string) DMARCResult {
	res := DMARCResult{Name: "_dmarc." + domain, Pct: 100}
	recs, err := r.txtOf(ctx, res.Name)
	if err != nil && !errors.Is(err, errNXDomain) {
		res.Error = err.Error()
	}
	var hits []string
	for _, rec := range recs {
		if isDMARCRecord(rec) {
			hits = append(hits, rec)
		}
	}
	res.Records = hits
	if len(hits) == 0 {
		res.Severity = SevNone
		return res
	}
	res.Found = true
	res.Raw = hits[0]
	res.Multiple = len(hits) > 1

	tags := parseTags(hits[0])
	res.Version = tags["v"]
	res.Policy = strings.ToLower(tags["p"])
	res.SubdomainPol = strings.ToLower(tags["sp"])
	res.ADKIM = strings.ToLower(tags["adkim"])
	res.ASPF = strings.ToLower(tags["aspf"])
	res.FO = tags["fo"]
	res.RUA = splitURIs(tags["rua"])
	res.RUF = splitURIs(tags["ruf"])
	if v, ok := tags["pct"]; ok && v != "" {
		if n, e := strconv.Atoi(v); e == nil && n >= 0 && n <= 100 {
			res.Pct = n
		} else {
			res.PctInvalid = true
		}
	}
	if !strings.EqualFold(tags["v"], "DMARC1") {
		res.Invalid = true
		res.InvalidReason = "缺少 v=DMARC1 版本标签（RFC 7489 §6.4 要求 v 必须是第一个标签）"
	}
	if !validPolicy(res.Policy) {
		res.Invalid = true
		if res.InvalidReason != "" {
			res.InvalidReason += "；"
		}
		res.InvalidReason += "缺少或非法的 p= 策略（合法值 none/quarantine/reject）"
	}
	res.Severity = severityOf(res)
	return res
}

func validPolicy(p string) bool {
	switch p {
	case "none", "quarantine", "reject":
		return true
	}
	return false
}

// severityOf 把 DMARC 状态映射到四级严重度。无效记录按「无记录」计——
// 对收件方而言两者等价：没有可执行的策略。
func severityOf(d DMARCResult) string {
	if !d.Found || d.Invalid {
		return SevNone
	}
	switch d.Policy {
	case "reject":
		return SevReject
	case "quarantine":
		return SevQuarantine
	case "none":
		return SevPolicyNone
	}
	return SevNone
}

func isDMARCRecord(rec string) bool {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), "v") && strings.EqualFold(strings.TrimSpace(v), "DMARC1") {
			return true
		}
	}
	return false
}

// splitURIs 拆 rua=/ruf= 的逗号列表，保留原始 URI（含 !10m 尺寸后缀）。
func splitURIs(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ────────────────────────────── SPF ──────────────────────────────

// spfWalker SPF include 链展开器。深度 + 回环 + 节点总数三重上限，
// 保证敌意/畸形记录（互相 include、扇出爆炸）不会把体检拖死。
type spfWalker struct {
	r        *runner
	maxDepth int
	maxNodes int
	nodes    int
	rows     []SPFChainRow
	maxSeen  int
}

// probeSPF 查 <domain> 的 SPF 记录并递归展开 include 链，统计 RFC 7208
// §4.6.4 意义上的 DNS lookup 次数（include/a/mx/ptr/exists/redirect 各计 1）。
func probeSPF(ctx context.Context, r *runner, domain string, o Options) SPFResult {
	w := &spfWalker{r: r, maxDepth: o.MaxDepth, maxNodes: o.MaxNodes}
	root, total := w.walk(ctx, domain, 0, nil, "根")

	res := SPFResult{
		Limit:    o.MaxLookups,
		Lookups:  total,
		Depth:    w.maxSeen,
		Status:   root.Status,
		Root:     &root,
		Chain:    w.rows,
		Record:   root.Record,
		Records:  root.Records,
		Multiple: root.Multiple,
		Found:    len(root.Records) > 0,
		Error:    root.Error,
	}
	res.ExceedsLimit = total > o.MaxLookups
	for _, row := range w.rows {
		if row.Status == StLoop {
			res.Loop = true
		}
	}
	res.All = allQualifier(root.Mechanisms)
	return res
}

// walk 展开一次记录。返回节点与「本记录 + 全部子链」的 lookup 累计数。
// path 是当前递归栈（不是全局 visited）——菱形 include（两条分支指向同一
// 域）是合法的，只有真正回到栈上的域才算回环。
func (w *spfWalker) walk(ctx context.Context, domain string, depth int, path []string, via string) (SPFNode, int) {
	node := SPFNode{Domain: domain, Depth: depth}
	row := SPFChainRow{Domain: domain, Depth: depth, Via: via}
	idx := len(w.rows)
	w.rows = append(w.rows, row)
	w.maxSeen = max(w.maxSeen, depth)

	finish := func(status string) (SPFNode, int) {
		node.Status = status
		w.rows[idx].Status = status
		w.rows[idx].Record = node.Record
		w.rows[idx].Error = node.Error
		return node, 0
	}

	if depth > w.maxDepth {
		return finish(StDepthLimit)
	}
	for _, p := range path {
		if strings.EqualFold(p, domain) {
			return finish(StLoop)
		}
	}
	w.nodes++
	if w.nodes > w.maxNodes {
		return finish(StBudget)
	}

	// 复制而非 append 复用底层数组：兄弟分支互不覆盖对方的栈内容。
	np := make([]string, len(path)+1)
	copy(np, path)
	np[len(path)] = domain

	recs, err := w.r.txtOf(ctx, domain)
	if err != nil {
		if errors.Is(err, errNXDomain) {
			return finish(StNXDomain)
		}
		node.Error = err.Error()
		return finish(StError)
	}
	var spf []string
	for _, rec := range recs {
		if looksLikeSPF(rec) {
			spf = append(spf, rec)
		}
	}
	node.Records = spf
	if len(spf) == 0 {
		return finish(StNoSPF)
	}
	node.Multiple = len(spf) > 1
	if node.Multiple {
		// RFC 7208 §3.2：一个域只能有一条 v=spf1，多条即 permerror，
		// 收件方会把整域判失败——后续展开没有意义，如实记录即可。
		node.Record = spf[0]
		return finish(StMultiple)
	}

	node.Record = spf[0]
	mechs, perr := parseSPFMechs(spf[0])
	if perr != nil {
		node.Error = perr.Error()
		return finish(StInvalid)
	}
	node.Mechanisms = mechs

	own := 0
	total := 0
	for _, m := range mechs {
		if !m.Lookup {
			continue
		}
		own++
		target := m.Value
		if target == "" {
			target = domain
		}
		switch m.Name {
		case "include", "redirect":
			child, sub := w.walk(ctx, normalizeDomain(target), depth+1, np, m.Name+":"+m.Value)
			node.Children = append(node.Children, child)
			total += sub
		}
		// a / mx / ptr / exists：各计 1 次 lookup，但不再递归展开
		// （它们解析的是 A/AAAA/MX，不是 SPF 记录，没有下一层）。
	}
	total += own

	node.Lookups = own
	node.Total = total
	w.rows[idx].Lookups = own
	w.rows[idx].Total = total
	w.rows[idx].Record = node.Record
	w.rows[idx].Error = node.Error
	status := StOK
	if node.Multiple {
		status = StMultiple
	}
	node.Status = status
	w.rows[idx].Status = status
	return node, total
}

func looksLikeSPF(rec string) bool {
	f := strings.Fields(strings.TrimSpace(rec))
	return len(f) > 0 && strings.EqualFold(f[0], "v=spf1")
}

// parseSPFMechs 解析 `v=spf1 ...` 的机制列表。
func parseSPFMechs(rec string) ([]SPFMechanism, error) {
	fields := strings.Fields(strings.TrimSpace(rec))
	if len(fields) == 0 || !strings.EqualFold(fields[0], "v=spf1") {
		return nil, errBadSPF
	}
	out := make([]SPFMechanism, 0, len(fields)-1)
	for _, f := range fields[1:] {
		out = append(out, parseSPFToken(f))
	}
	return out, nil
}

// parseSPFToken 解析单个机制：可选 qualifier、name[:value] 或 name=value、
// 去掉 a/24 这类 CIDR 后缀。
func parseSPFToken(tok string) SPFMechanism {
	m := SPFMechanism{Raw: tok}
	s := tok
	if s == "" {
		return m
	}
	switch s[0] {
	case '+', '-', '~', '?':
		m.Qualifier = string(s[0])
		s = s[1:]
	}
	// 修饰符 redirect= / exp=
	if i := strings.IndexByte(s, '='); i > 0 {
		m.Name = strings.ToLower(s[:i])
		m.Value = s[i+1:]
		m.Lookup = m.Name == "redirect"
		return m
	}
	name, value := s, ""
	if i := strings.IndexByte(s, ':'); i > 0 {
		name, value = s[:i], s[i+1:]
	}
	if i := strings.IndexByte(value, '/'); i > 0 {
		value = value[:i]
	}
	if i := strings.IndexByte(name, '/'); i > 0 {
		name = name[:i]
	}
	m.Name = strings.ToLower(name)
	m.Value = value
	switch m.Name {
	case "include", "a", "mx", "ptr", "exists":
		m.Lookup = true
	}
	return m
}

// allQualifier 取根记录里 all 机制的实际形态（-all / ~all / ?all / +all）。
// 无 all 机制时返回空串——按 RFC 默认等同等 ?all（中性，不设防）。
func allQualifier(mechs []SPFMechanism) string {
	for _, m := range mechs {
		if m.Name != "all" {
			continue
		}
		q := m.Qualifier
		if q == "" {
			q = "+"
		}
		return q + "all"
	}
	return ""
}

// ────────────────────────────── DKIM ──────────────────────────────

// probeDKIM 逐个探测常见选择器。只报存在性与模长，公钥材料不回显。
func probeDKIM(ctx context.Context, r *runner, domain string, selectors []string) []DKIMResult {
	out := make([]DKIMResult, 0, len(selectors))
	for _, sel := range selectors {
		sel = strings.TrimSpace(strings.ToLower(sel))
		if sel == "" {
			continue
		}
		name := sel + "._domainkey." + domain
		res := DKIMResult{Selector: sel, Name: name}
		recs, err := r.txtOf(ctx, name)
		if err != nil {
			if !errors.Is(err, errNXDomain) {
				res.Note = "DNS 查询失败：" + err.Error()
			}
			out = append(out, res)
			continue
		}
		var hit string
		for _, rec := range recs {
			if isDKIMRecord(rec) {
				hit = rec
				break
			}
		}
		if hit == "" {
			out = append(out, res)
			continue
		}
		res.Found = true
		tags := parseTags(hit)
		kty := strings.ToLower(strings.TrimSpace(tags["k"]))
		if kty == "" {
			kty = "rsa" // RFC 6376 §3.6.1 默认 k=rsa
		}
		res.KeyType = kty
		p := stripSpace(tags["p"])
		switch {
		case p == "":
			res.Revoked = true
			res.Note = "p= 为空，该选择器公钥已吊销（记录保留用于标记撤销）"
		default:
			bits, est := keyBits(kty, p)
			res.KeyBits = bits
			res.Estimated = est
			note := "v=" + orDefault(tags["v"], "（缺省）") + " k=" + kty
			if est {
				note += " · 长度按 DER 长度估算（标准解析器不接受该公钥格式）"
			}
			if bits > 0 && bits < 1024 {
				note += " · 低于 RFC 8301 的 1024 位下限，主流收件方会判签名不可信"
			} else if bits == 1024 {
				note += " · 处于 RFC 8301 下限（推荐 2048 位）"
			}
			res.Note = note
		}
		res.Record = dkimRedact(tags, res)
		out = append(out, res)
	}
	return out
}

// dkimRedact 生成可回显的记录摘要——p= 只留长度，不留任何密钥字节。
func dkimRedact(tags map[string]string, res DKIMResult) string {
	var b strings.Builder
	b.WriteString("v=")
	b.WriteString(orDefault(tags["v"], "DKIM1"))
	b.WriteString("; k=")
	b.WriteString(orDefault(res.KeyType, "rsa"))
	if res.Revoked {
		b.WriteString("; p=（已吊销）")
	} else {
		b.WriteString("; p=<")
		if res.KeyBits > 0 {
			b.WriteString(strconv.Itoa(res.KeyBits))
			b.WriteString("-bit")
			if res.Estimated {
				b.WriteString(" 估算")
			}
		} else {
			b.WriteString("无法测定长度")
		}
		b.WriteString("，密钥已省略>")
	}
	return b.String()
}

func isDKIMRecord(rec string) bool {
	t := parseTags(rec)
	_, hasP := t["p"]
	return hasP
}

// keyBits 取公钥模长。RSA 走 SPKI/PKCS#1 解析拿 N 的位长；解析不了
// 就按 DER 长度估算并标记 Estimated，绝不假装精确。
func keyBits(kty, p string) (int, bool) {
	if kty == "ed25519" {
		return 256, false
	}
	der, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		if der, err = base64.RawStdEncoding.DecodeString(p); err != nil {
			return 0, false
		}
	}
	if pub, err := x509.ParsePKIXPublicKey(der); err == nil {
		switch k := pub.(type) {
		case *rsa.PublicKey:
			return k.N.BitLen(), false
		case ed25519.PublicKey:
			return ed25519.PublicKeySize * 8, false
		}
	}
	if k, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return k.N.BitLen(), false
	}
	if len(der) > 64 {
		guess := (len(der) - 36) * 8 // SPKI 头约 36 字节
		for _, std := range []int{1024, 2048, 3072, 4096} {
			if guess > std-256 && guess < std+256 {
				return std, true
			}
		}
		return guess, true
	}
	return 0, false
}

// ────────────────────────────── BIMI ──────────────────────────────

// probeBIMI 查 default._bimi.<domain>。l=/a= 只读取，不抓取 URL——
// 体检不该向目标资产发出任何非 DNS 请求。
func probeBIMI(ctx context.Context, r *runner, domain string) BIMIResult {
	res := BIMIResult{Name: "default._bimi." + domain}
	recs, err := r.txtOf(ctx, res.Name)
	if err != nil {
		return res
	}
	for _, rec := range recs {
		tags := parseTags(rec)
		if !strings.EqualFold(orDefault(tags["v"], ""), "BIMI1") {
			continue
		}
		res.Found = true
		res.Record = rec
		res.Version = tags["v"]
		res.Logo = tags["l"]
		res.VMC = tags["a"]
		if strings.TrimSpace(res.Logo) == "" && strings.TrimSpace(res.VMC) == "" {
			res.Invalid = true
		}
		break
	}
	return res
}

// ────────────────────────────── 小工具 ──────────────────────────────

func stripSpace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

var errBadSPF = errSPF("记录首 token 不是 v=spf1")

type errSPF string

func (e errSPF) Error() string { return string(e) }
