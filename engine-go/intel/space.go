package intel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// ── 通用取值助手（第三方返回结构漂移频繁，取值为「多候选键 + 宽容失败」）──

func pickStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := dig(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				return strings.TrimSpace(t)
			}
		case float64:
			return fmt.Sprintf("%v", t)
		case []any:
			if len(t) > 0 {
				if s, ok := t[0].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func pickInt(m map[string]any, keys ...string) int {
	for _, k := range keys {
		v, ok := dig(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			return int(t)
		case string:
			var n int
			if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
				return n
			}
		}
	}
	return 0
}

// dig 按 a.b.c 取嵌套值。
func dig(m map[string]any, path string) (any, bool) {
	cur := any(m)
	for _, part := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func asList(v any) []map[string]any {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(arr))
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ── FOFA ──
//
// GET https://fofa.info/api/v1/search/all?key=…&qbase64=…&size=…&fields=…
// 返回 {"error":bool,"errmsg":"…","results":[[col1,col2,…],…]}
// 列顺序 = fields 参数顺序，按位置解析（官方契约）。
func queryFOFA(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("FOFA_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 FOFA_KEY")
	}
	q := o.RawQuery
	if q == "" {
		q = fmt.Sprintf(`domain="%s"`, target)
	}
	fields := o.Fields
	if len(fields) == 0 {
		fields = []string{"host", "ip", "port", "protocol", "title", "server", "domain"}
	}
	pv := url.Values{}
	pv.Set("key", key)
	pv.Set("qbase64", base64.StdEncoding.EncodeToString([]byte(q)))
	pv.Set("size", fmt.Sprintf("%d", o.limit()))
	pv.Set("fields", strings.Join(fields, ","))
	if email := Env("FOFA_EMAIL"); email != "" {
		pv.Set("email", email) // 老账号仍需 email，新账号可省
	}
	base := o.endpoint("fofa", "https://fofa.info/api/v1/search/all")
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var data struct {
		Error   bool    `json:"error"`
		Errmsg  string  `json:"errmsg"`
		Results [][]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Error {
		return nil, fmt.Errorf("%s", firstNonEmpty(data.Errmsg, "FOFA 返回 error=true"))
	}
	idx := map[string]int{}
	for i, f := range fields {
		idx[f] = i
	}
	cell := func(row []any, f string) any {
		if i, ok := idx[f]; ok && i < len(row) {
			return row[i]
		}
		return nil
	}
	out := make([]Record, 0, len(data.Results))
	for _, row := range data.Results {
		r := Record{
			Source:   "fofa",
			Host:     pyStr(cell(row, "host")),
			IP:       pyStr(cell(row, "ip")),
			Protocol: pyStr(cell(row, "protocol")),
			Domain:   pyStr(cell(row, "domain")),
			Server:   strOf(cell(row, "server")),
			Title:    strOf(cell(row, "title")),
			ICP:      strOf(cell(row, "icp")),
		}
		if p := cell(row, "port"); p != nil {
			r.Port = int(numOf(p))
		}
		out = append(out, r)
	}
	return out, nil
}

// ── Hunter（奇安信）──
//
// GET https://hunter.qianxin.com/openApi/search?api-key=…&search=<base64url>&page=1&page_size=…
// 响应 {"code":200,"data":{"arr":[{…}]}}；code≠200 时 message 为错误原因。
func queryHunter(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("HUNTER_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 HUNTER_KEY")
	}
	q := o.RawQuery
	if q == "" {
		q = fmt.Sprintf(`domain="%s"`, target)
	}
	now := time.Now()
	end := now.Format("2006-01-02")
	start := now.AddDate(0, 0, -30).Format("2006-01-02")
	pv := url.Values{}
	pv.Set("api-key", key)
	pv.Set("search", base64.RawURLEncoding.EncodeToString([]byte(q)))
	pv.Set("page", "1")
	pv.Set("page_size", fmt.Sprintf("%d", o.limit()))
	pv.Set("is_web", "3")
	pv.Set("start_time", start)
	pv.Set("end_time", end)
	base := o.endpoint("hunter", "https://hunter.qianxin.com/openApi/search")
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var data struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Arr []map[string]any `json:"arr"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Code != 200 {
		return nil, fmt.Errorf("%s（code=%d）", firstNonEmpty(data.Message, "Hunter 返回错误"), data.Code)
	}
	out := make([]Record, 0, len(data.Data.Arr))
	for _, a := range data.Data.Arr {
		out = append(out, Record{
			Source:   "hunter",
			Host:     pickStr(a, "url", "domain"),
			Domain:   pickStr(a, "domain"),
			IP:       pickStr(a, "ip"),
			Port:     pickInt(a, "port"),
			Protocol: pickStr(a, "protocol"),
			Title:    pickStr(a, "web_title", "title"),
			Server:   pickStr(a, "component", "server"),
			Country:  pickStr(a, "country"),
			Org:      pickStr(a, "as_org", "company"),
			Updated:  pickStr(a, "updated_at"),
		})
	}
	return out, nil
}

// ── 360 Quake ──
//
// POST https://quake.360.net/api/v3/search/quake_service，头 X-QuakeToken。
// 坑（实测）：必须 POST；include 字段白名单很严（title/asname 会 q2001），不传；
// 限频返回 q3005。
func queryQuake(ctx context.Context, target string, o Options) ([]Record, error) {
	token := Env("QUAKE_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("未配置 QUAKE_TOKEN")
	}
	q := o.RawQuery
	if q == "" {
		q = fmt.Sprintf(`domain:"%s"`, target)
	}
	payload, _ := json.Marshal(map[string]any{
		"query":        q,
		"start":        0,
		"size":         o.limit(),
		"ignore_cache": true,
	})
	base := o.endpoint("quake", "https://quake.360.net/api/v3/search/quake_service")
	body, status, err := fetchJSON(ctx, o, base,
		map[string]string{"X-QuakeToken": token, "Content-Type": "application/json"},
		payload, "POST")
	if err != nil {
		return nil, err
	}
	var data struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		if status == 401 {
			return nil, fmt.Errorf("token 无效（401，返回的是登录页）")
		}
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Code != 0 {
		msg := firstNonEmpty(data.Message, "Quake 返回错误")
		if strings.Contains(msg, "q3005") || data.Code == 429 {
			msg += "（限频 q3005，稍后重试）"
		}
		return nil, fmt.Errorf("%s（code=%d）", msg, data.Code)
	}
	out := make([]Record, 0, len(data.Data))
	for _, d := range data.Data {
		proto := pickStr(d, "service.name", "transport")
		out = append(out, Record{
			Source:   "quake",
			Host:     firstNonEmpty(pickStr(d, "hostname"), pickStr(d, "domain")),
			Domain:   pickStr(d, "domain"),
			IP:       pickStr(d, "ip"),
			Port:     pickInt(d, "port"),
			Protocol: proto,
			Title:    pickStr(d, "service.http.title"),
			Server:   pickStr(d, "service.http.server"),
			Product:  pickStr(d, "service.product"),
			Country:  firstNonEmpty(pickStr(d, "location.country_cn"), pickStr(d, "location.country_en")),
			Updated:  pickStr(d, "time"),
		})
	}
	return out, nil
}

// ── ZoomEye ──
//
// POST https://api.zoomeye.org/v2/search，头 API-KEY，body {"qbase64": "…"}。
// 注意：api.zoomeye.ai 对国内出口返回 403（区域限制），必须用 .org。
func queryZoomEye(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("ZOOMEYE_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 ZOOMEYE_KEY")
	}
	q := o.RawQuery
	if q == "" {
		q = fmt.Sprintf("site:%s", target)
	}
	payload, _ := json.Marshal(map[string]any{
		"qbase64":  base64.StdEncoding.EncodeToString([]byte(q)),
		"page":     1,
		"pagesize": o.limit(),
	})
	base := o.endpoint("zoomeye", "https://api.zoomeye.org/v2/search")
	body, _, err := fetchJSON(ctx, o, base,
		map[string]string{"API-KEY": key, "Content-Type": "application/json"},
		payload, "POST")
	if err != nil {
		return nil, err
	}
	var data struct {
		Code    int              `json:"code"`
		Message string           `json:"message"`
		Data    []map[string]any `json:"data"`
		Items   []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Code != 0 && data.Message != "" {
		return nil, fmt.Errorf("%s（code=%d）", data.Message, data.Code)
	}
	rows := data.Data
	if len(rows) == 0 {
		rows = data.Items
	}
	out := make([]Record, 0, len(rows))
	for _, d := range rows {
		out = append(out, Record{
			Source:   "zoomeye",
			Host:     pickStr(d, "url", "domain", "hostname"),
			Domain:   pickStr(d, "domain", "hostname"),
			IP:       pickStr(d, "ip"),
			Port:     pickInt(d, "port"),
			Protocol: pickStr(d, "protocol", "service"),
			Title:    pickStr(d, "title"),
			Server:   pickStr(d, "server", "app"),
			Product:  pickStr(d, "app"),
			Country:  pickStr(d, "geoinfo.country.names.en", "country"),
			Updated:  pickStr(d, "update_time", "time"),
		})
	}
	return out, nil
}

// ── Shodan ──
//
// GET https://api.shodan.io/shodan/host/search?key=…&query=hostname:<d>
func queryShodan(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("SHODAN_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 SHODAN_KEY")
	}
	q := o.RawQuery
	if q == "" {
		q = "hostname:" + target
	}
	pv := url.Values{}
	pv.Set("key", key)
	pv.Set("query", q)
	base := o.endpoint("shodan", "https://api.shodan.io/shodan/host/search")
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var data struct {
		Matches []map[string]any `json:"matches"`
		Error   string           `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Error != "" {
		return nil, fmt.Errorf("%s", data.Error)
	}
	out := make([]Record, 0, len(data.Matches))
	for _, d := range data.Matches {
		out = append(out, Record{
			Source:   "shodan",
			Host:     firstNonEmpty(pickStr(d, "hostnames"), pickStr(d, "domains")),
			Domain:   pickStr(d, "domains"),
			IP:       pickStr(d, "ip_str"),
			Port:     pickInt(d, "port"),
			Protocol: pickStr(d, "transport"),
			Title:    pickStr(d, "http.title"),
			Server:   pickStr(d, "http.server"),
			Product:  pickStr(d, "product"),
			Country:  pickStr(d, "location.country_name"),
			ASN:      pickStr(d, "asn"),
			Org:      pickStr(d, "org"),
			Updated:  pickStr(d, "timestamp"),
		})
	}
	return out, nil
}

// ── Censys v3 ──
//
// POST https://api.platform.censys.io/v3/global/search/query，头 Authorization: Bearer <token>。
// 注意：Censys Legacy Search 已于 2026-09-30 下线，只能走 platform v3。
func queryCensys(ctx context.Context, target string, o Options) ([]Record, error) {
	token := Env("CENSYS_TOKEN")
	auth := ""
	if token != "" {
		auth = "Bearer " + token
	} else if id, sec := Env("CENSYS_API_ID"), Env("CENSYS_API_SECRET"); id != "" && sec != "" {
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+sec))
	}
	if auth == "" {
		return nil, fmt.Errorf("未配置 CENSYS_TOKEN（或 CENSYS_API_ID+CENSYS_API_SECRET）")
	}
	q := o.RawQuery
	if q == "" {
		q = fmt.Sprintf(`host.name: "%s"`, target)
	}
	payload, _ := json.Marshal(map[string]any{
		"query":     q,
		"page_size": o.limit(),
	})
	base := o.endpoint("censys", "https://api.platform.censys.io/v3/global/search/query")
	body, _, err := fetchJSON(ctx, o, base,
		map[string]string{"Authorization": auth, "Content-Type": "application/json"},
		payload, "POST")
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if e, ok := data["error"].(map[string]any); ok {
		return nil, fmt.Errorf("%s", firstNonEmpty(pickStr(e, "message"), "Censys 返回错误"))
	}
	res, _ := data["result"].(map[string]any)
	hits := asList(res["hits"])
	out := make([]Record, 0, len(hits))
	for _, h := range hits {
		host, _ := h["host"].(map[string]any)
		if host == nil {
			host = h
		}
		rec := Record{
			Source:  "censys",
			Host:    pickStr(host, "name"),
			Domain:  pickStr(host, "name"),
			IP:      pickStr(host, "ip"),
			Country: pickStr(host, "location.country"),
		}
		if svcs := asList(host["services"]); len(svcs) > 0 {
			svc := svcs[0]
			rec.Port = pickInt(svc, "port")
			rec.Protocol = firstNonEmpty(pickStr(svc, "transport_protocol"), pickStr(svc, "service_name"))
			rec.Product = pickStr(svc, "service_name")
			rec.Title = pickStr(svc, "http.response.html_title")
			rec.Server = pickStr(svc, "http.response.headers.server")
		}
		out = append(out, rec)
	}
	return out, nil
}

// ── Netlas ──
//
// GET https://app.netlas.io/api/responses/?q=domain:…&token=…&size=…
func queryNetlas(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("NETLAS_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 NETLAS_KEY")
	}
	q := o.RawQuery
	if q == "" {
		q = "domain:" + target
	}
	pv := url.Values{}
	pv.Set("q", q)
	pv.Set("token", key)
	pv.Set("size", fmt.Sprintf("%d", o.limit()))
	pv.Set("start", "0")
	base := o.endpoint("netlas", "https://app.netlas.io/api/responses/")
	body, _, err := fetchJSON(ctx, o, base+"?"+pv.Encode(), nil, nil, "GET")
	if err != nil {
		return nil, err
	}
	var data struct {
		Items []map[string]any `json:"items"`
		Error string           `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if data.Error != "" {
		return nil, fmt.Errorf("%s", data.Error)
	}
	out := make([]Record, 0, len(data.Items))
	for _, it := range data.Items {
		d, _ := it["data"].(map[string]any)
		if d == nil {
			d = it
		}
		out = append(out, Record{
			Source:   "netlas",
			Host:     firstNonEmpty(pickStr(d, "domain"), pickStr(d, "host")),
			Domain:   pickStr(d, "domain"),
			IP:       pickStr(d, "ip"),
			Port:     pickInt(d, "port"),
			Protocol: pickStr(d, "protocol"),
			Title:    pickStr(d, "http.title"),
			Server:   pickStr(d, "http.server"),
			Product:  pickStr(d, "product", "http.server"),
		})
	}
	return out, nil
}

// ── 0.zone ──
//
// POST https://0.zone/api/data/，表单 key/query/query_type=domain/page。
func queryZeroZone(ctx context.Context, target string, o Options) ([]Record, error) {
	key := Env("ZEROZONE_KEY")
	if key == "" {
		return nil, fmt.Errorf("未配置 ZEROZONE_KEY")
	}
	form := url.Values{}
	form.Set("key", key)
	form.Set("query", target)
	form.Set("query_type", "domain")
	form.Set("page", "1")
	base := o.endpoint("zerozone", "https://0.zone/api/data/")
	body, _, err := fetchJSON(ctx, o, base,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		[]byte(form.Encode()), "POST")
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		return nil, fmt.Errorf("响应非 JSON")
	}
	if code := pickInt(data, "code"); code != 0 && code != 200 {
		return nil, fmt.Errorf("%s（code=%d）", firstNonEmpty(pickStr(data, "message"), "0.zone 返回错误"), code)
	}
	dd, _ := data["data"].(map[string]any)
	rows := asList(dd["list"])
	if len(rows) == 0 {
		rows = asList(dd["data"])
	}
	out := make([]Record, 0, len(rows))
	for _, d := range rows {
		out = append(out, Record{
			Source:   "zerozone",
			Host:     firstNonEmpty(pickStr(d, "domain"), pickStr(d, "host"), pickStr(d, "url")),
			Domain:   pickStr(d, "domain"),
			IP:       pickStr(d, "ip"),
			Port:     pickInt(d, "port"),
			Protocol: pickStr(d, "protocol", "service"),
			Title:    pickStr(d, "title"),
			Server:   pickStr(d, "server", "component"),
			Product:  pickStr(d, "component"),
			Country:  pickStr(d, "country"),
		})
	}
	return out, nil
}

// ── 小工具 ──

func strOf(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprintf("%v", v))
}

func numOf(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		var f float64
		_, _ = fmt.Sscanf(t, "%f", &f)
		return f
	}
	return 0
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
