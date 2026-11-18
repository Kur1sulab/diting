package icp

// chain.go —— ICP 备案多源链。
//
// 单源时代的问题很实在：apihz 一条接口限频就整块失明。现在按顺序试三条通道，
// 谁先给出确定答案就算谁的，并把「试过哪些、各自为什么失败」一并留档——
// 这样「没查到备案」和「接口挂了」在报告里能区分开，不会把限频写成未备案。
//
//	① apihz  —— 需 APIHZ_ID/APIHZ_KEY；未配置时可用 --demo 走官方公开示例凭据
//	              （额度共享、限频严重，仅供功能验证，输出会打印警告）
//	② miit   —— 工信部官方接口（authKey=md5(timestamp) 取 token 再查）
//	③ beianx —— 第三方站点 HTML 解析（兜底，最不稳）
//
// 三者都是只读 GET/POST 查询，不改动任何目标数据。

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Kur1sulab/yata/engine-go/netutil"
)

// 备案号与主办单位名（beianx 兜底解析用）。备案号形如：粤B2-20090059-5 / 渝ICP备06004549号-3
var (
	regexpICP  = regexp.MustCompile(`[京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川贵云藏陕甘青宁新][A-Z]?[0-9]*-?[0-9]*号?-?[0-9]*`)
	regexpUnit = regexp.MustCompile(`(?:主办单位|备案主体|单位名称)[^0-9A-Za-z\p{Han}]{0,8}([0-9A-Za-z()（）·\-\p{Han}]{2,40})`)
)

// envAPIHZ 读 apihz 凭据（环境变量优先，其次供 --demo 判定）。
func envAPIHZ() (string, string) {
	return strings.TrimSpace(os.Getenv("APIHZ_ID")), strings.TrimSpace(os.Getenv("APIHZ_KEY"))
}

// ProviderAttempt 单个通道的尝试结果（留档用）。
type ProviderAttempt struct {
	Provider string `json:"provider"`
	Filed    bool   `json:"filed"`
	Message  string `json:"message,omitempty"`
}

// ChainResult 多源链的最终结论。
type ChainResult struct {
	Filed    bool              `json:"filed"`
	ICP      string            `json:"icp,omitempty"`
	Unit     string            `json:"unit,omitempty"`
	Type     string            `json:"type,omitempty"`
	Domain   string            `json:"domain"`
	Time     string            `json:"time,omitempty"`
	Provider string            `json:"provider,omitempty"`
	Msg      string            `json:"msg,omitempty"`
	Tried    []ProviderAttempt `json:"tried,omitempty"`
}

// 可注入端点（测试打 httptest stub）。
var (
	MIITAuthURL  = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
	MIITQueryURL = "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition"
	BeianxURL    = "https://www.beianx.cn/search/"

	// apihz 官方文档公开的示例凭据（id/key 都是 88888888）；仅供 --demo 功能验证，
	// 共享额度、限频严重，生产必须用 APIHZ_ID/APIHZ_KEY 覆盖。
	apihzDemoID  = "88888888"
	apihzDemoKey = "88888888"

	chainSleep = time.Sleep
)

// ChainOptions 链行为开关。
type ChainOptions struct {
	Demo    bool // 允许用 apihz 官方公开 demo 凭据（无 APIHZ_ID/KEY 时）
	Timeout time.Duration
}

// QueryICPChain 依次尝试三条通道，返回首个确定结论。
//
// 注意「确定结论」的定义：拿到备案号 → filed=true；接口明确说没有备案 →
// 记一笔 not-found 并继续下一条（换源可能查到）；网络/限频/解析失败 → 记 error 继续。
func QueryICPChain(ctx context.Context, domain string, opt ChainOptions) ChainResult {
	res := ChainResult{Domain: domain}
	if opt.Timeout <= 0 {
		opt.Timeout = 20 * time.Second
	}
	type prov struct {
		name string
		fn   func(context.Context, string, ChainOptions) ChainResult
	}
	list := []prov{
		{"apihz", queryAPIHZ},
		{"miit", queryMIIT},
		{"beianx", queryBeianx},
	}
	notFound := ""
	for _, p := range list {
		r := p.fn(ctx, domain, opt)
		att := ProviderAttempt{Provider: p.name, Filed: r.Filed, Message: r.Msg}
		res.Tried = append(res.Tried, att)
		if r.Filed {
			r.Provider = p.name
			r.Tried = res.Tried
			return r
		}
		if strings.Contains(r.Msg, "未备案") || strings.Contains(r.Msg, "没有备案") {
			notFound = r.Msg
		}
		if ctx.Err() != nil {
			break
		}
		chainSleep(300 * time.Millisecond)
	}
	if notFound != "" {
		res.Msg = notFound
	} else if len(res.Tried) > 0 {
		res.Msg = "三条通道均未给出确定结果：" + summarizeTried(res.Tried)
	} else {
		res.Msg = "无可用通道"
	}
	return res
}

func summarizeTried(tried []ProviderAttempt) string {
	var parts []string
	for _, t := range tried {
		m := t.Message
		if m == "" {
			m = "无结论"
		}
		parts = append(parts, t.Provider+": "+trunc(m, 60))
	}
	return strings.Join(parts, "；")
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// queryAPIHZ apihz 通道：复用 ParseICP 的归一化与限频陷阱判定。
// 共享额度上限很硬（实测 329 次/分钟），提示「请 N 秒后再试」时按提示退避重试一次。
func queryAPIHZ(ctx context.Context, domain string, opt ChainOptions) ChainResult {
	cid, key, demo := demoOrEnv(opt)
	if cid == "" || key == "" {
		return ChainResult{Domain: domain, Msg: "未配置 APIHZ_ID/APIHZ_KEY（加 --demo 可用官方公开示例凭据）"}
	}
	if demo {
		fmt.Println("[!] ICP：正在使用 apihz 官方公开 demo 凭据（额度共享、可能限频），生产请配置 APIHZ_ID/APIHZ_KEY")
	}
	u := APIHZURL + "?" + buildAPIHZQuery(cid, key, domain).Encode()
	var last ChainResult
	for attempt := 0; attempt < 2; attempt++ {
		r := netutil.Fetch(u, netutil.FetchOpt{Timeout: opt.Timeout, Follow: false, Ctx: ctx})
		if !r.OK || r.Status != 200 || r.Body == "" {
			msg := r.Err
			if msg == "" {
				msg = fmt.Sprintf("HTTP %d", r.Status)
			}
			last = ChainResult{Domain: domain, Msg: "apihz 请求失败: " + msg}
			break
		}
		parsed := ParseICP(r.Body)
		out := ChainResult{Domain: domain}
		if filed, _ := parsed["filed"].(bool); filed {
			out.Filed = true
			out.ICP = str(parsed["icp"])
			out.Unit = str(parsed["unit"])
			out.Type = str(parsed["type"])
			out.Time = str(parsed["time"])
			if d := str(parsed["domain"]); d != "" {
				out.Domain = d
			}
			return out
		}
		out.Msg = str(parsed["msg"])
		last = out
		// 限频提示形如「请25秒后再试」——按提示退避一次（上限 35s），不硬撞
		if secs, ok := retryHint(out.Msg); ok && attempt == 0 {
			wait := time.Duration(secs+2) * time.Second
			if wait > 35*time.Second {
				wait = 35 * time.Second
			}
			fmt.Printf("[*] ICP：apihz 限频，按提示退避 %s 后重试一次\n", wait)
			select {
			case <-ctx.Done():
				return last
			case <-time.After(wait):
			}
			continue
		}
		break
	}
	return last
}

// retryHint 从「请25秒后再试」/「请 25 秒后重试」里取出秒数。
var retryHintRe = regexp.MustCompile(`请\s*(\d{1,3})\s*秒后`)

func retryHint(msg string) (int, bool) {
	m := retryHintRe.FindStringSubmatch(msg)
	if len(m) < 2 {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
		return 0, false
	}
	return n, n > 0
}

func demoOrEnv(opt ChainOptions) (id, key string, demo bool) {
	id, key = envAPIHZ()
	if id != "" && key != "" {
		return id, key, false
	}
	if opt.Demo {
		return apihzDemoID, apihzDemoKey, true
	}
	return "", "", false
}

// queryMIIT 工信部官方通道。
//
// 流程：POST /api/auth（authKey=md5(timestamp)、timeStamp=毫秒）拿 token，
// 再 POST /api/icpAbbreviateInfo/queryByCondition（头 token）查备案。
// 官方接口对来源校验严格，失败是常态——失败原因会原样留档，不伪装成「未备案」。
func queryMIIT(ctx context.Context, domain string, opt ChainOptions) ChainResult {
	out := ChainResult{Domain: domain}
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	sum := md5.Sum([]byte(ts))
	authKey := hex.EncodeToString(sum[:])
	form := url.Values{}
	form.Set("authKey", authKey)
	form.Set("timeStamp", ts)
	r := netutil.Fetch(MIITAuthURL, netutil.FetchOpt{
		Timeout: opt.Timeout, Follow: true, Ctx: ctx,
		Method: "POST",
		Data:   []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Origin":       "https://beian.miit.gov.cn",
			"Referer":      "https://beian.miit.gov.cn/",
		},
	})
	if !r.OK || r.Status != 200 {
		out.Msg = "miit 取 token 失败: " + firstNonEmptyStr(r.Err, fmt.Sprintf("HTTP %d", r.Status))
		return out
	}
	var auth struct {
		Success bool   `json:"success"`
		Code    int    `json:"code"`
		Msg     string `json:"msg"`
		Params  string `json:"params"`
	}
	if err := json.Unmarshal([]byte(r.Body), &auth); err != nil {
		out.Msg = "miit 取 token 响应非 JSON"
		return out
	}
	if !auth.Success || auth.Params == "" {
		out.Msg = fmt.Sprintf("miit 取 token 被拒（code=%d %s）", auth.Code, firstNonEmptyStr(auth.Msg, "无 msg"))
		return out
	}
	payload, _ := json.Marshal(map[string]any{
		"pageNum": "1", "pageSize": "10", "unitName": "", "serviceType": 1, "domain": domain,
	})
	q := netutil.Fetch(MIITQueryURL, netutil.FetchOpt{
		Timeout: opt.Timeout, Follow: true, Ctx: ctx,
		Method: "POST",
		Data:   payload,
		Headers: map[string]string{
			"Content-Type": "application/json",
			"token":        auth.Params,
			"Origin":       "https://beian.miit.gov.cn",
			"Referer":      "https://beian.miit.gov.cn/",
		},
	})
	if !q.OK || q.Status != 200 {
		out.Msg = "miit 查询失败: " + firstNonEmptyStr(q.Err, fmt.Sprintf("HTTP %d", q.Status))
		return out
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(q.Body), &body); err != nil {
		out.Msg = "miit 查询响应非 JSON"
		return out
	}
	params, _ := body["params"].(map[string]any)
	list, _ := params["list"].([]any)
	if len(list) == 0 {
		msg := firstNonEmptyStr(strOfAny(body["msg"]), "未查询到备案记录")
		out.Msg = "miit: " + msg
		return out
	}
	first, _ := list[0].(map[string]any)
	unit := firstNonEmptyStr(strOfAny(first["unitName"]), strOfAny(first["mainUnitName"]))
	lic := firstNonEmptyStr(strOfAny(first["serviceLicence"]), strOfAny(first["mainLicence"]))
	if lic == "" && unit == "" {
		out.Msg = "miit: 返回结构无法解析"
		return out
	}
	out.Filed = true
	out.ICP = lic
	out.Unit = unit
	out.Time = strOfAny(first["updateRecordTime"])
	out.Type = serviceTypeName(int(numOfAny(first["serviceType"])))
	out.Domain = firstNonEmptyStr(strOfAny(first["domain"]), domain)
	return out
}

// queryBeianx 第三方站点兜底：抓搜索结果页里的备案号/主体名。
func queryBeianx(ctx context.Context, domain string, opt ChainOptions) ChainResult {
	out := ChainResult{Domain: domain}
	u := strings.TrimRight(BeianxURL, "/") + "/" + url.PathEscape(domain)
	r := netutil.Fetch(u, netutil.FetchOpt{Timeout: opt.Timeout, Follow: true, MaxBytes: 2 << 20, Ctx: ctx})
	if !r.OK || r.Status != 200 || r.Body == "" {
		out.Msg = "beianx 请求失败: " + firstNonEmptyStr(r.Err, fmt.Sprintf("HTTP %d", r.Status))
		return out
	}
	icp := regexpICP.FindString(r.Body)
	unit := regexpUnit.FindStringSubmatch(r.Body)
	if icp == "" {
		out.Msg = "beianx: 页面未匹配到备案号（可能需浏览器渲染或未备案）"
		return out
	}
	out.Filed = true
	out.ICP = icp
	if len(unit) > 1 {
		out.Unit = strings.TrimSpace(unit[1])
	}
	return out
}

func serviceTypeName(t int) string {
	switch t {
	case 1:
		return "网站"
	case 2:
		return "APP"
	case 3:
		return "小程序"
	case 4:
		return "快应用"
	}
	return ""
}

func strOfAny(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", v)
}

func numOfAny(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		var f float64
		fmt.Sscanf(t, "%f", &f)
		return f
	}
	return 0
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// RunICPChain 跑多源链并写 icp_<domain>.json（字段是旧格式的超集，向后兼容）。
func RunICPChain(ctx context.Context, domain, out string, opt ChainOptions) ChainResult {
	fmt.Printf("[*] ICP 备案查询（多源链）: %s\n", domain)
	res := QueryICPChain(ctx, domain, opt)
	row := map[string]any{
		"domain":   res.Domain,
		"filed":    res.Filed,
		"icp":      res.ICP,
		"unit":     res.Unit,
		"type":     res.Type,
		"time":     res.Time,
		"provider": res.Provider,
		"tried":    res.Tried,
	}
	if res.Msg != "" {
		row["msg"] = res.Msg
	}
	body, _ := json.MarshalIndent(row, "", "  ")
	if path, err := netutil.SafeWrite(out, "icp_"+domain+".json", string(body)); err == nil {
		row["_path"] = path
	}
	if res.Filed {
		fmt.Printf("[+] 备案号: %s（来源: %s）\n", res.ICP, res.Provider)
		fmt.Printf("    主办单位: %s    类型: %s    审核: %s\n",
			dash(res.Unit), dash(res.Type), dash(res.Time))
	} else {
		fmt.Printf("[!] 未取得确定备案结果（%s）\n", res.Msg)
		fmt.Println("    说明：接口限频/网络失败 ≠ 未备案，人工复核 beian.miit.gov.cn")
	}
	for _, t := range res.Tried {
		fmt.Printf("    · %-8s %s %s\n", t.Provider, map[bool]string{true: "命中", false: "未命中"}[t.Filed], t.Message)
	}
	if p, ok := row["_path"].(string); ok {
		fmt.Printf("    -> %s\n", p)
	}
	return res
}
