# 更新日志

版本号按 [语义化版本](https://semver.org/lang/zh-CN/)：修 bug 走 patch，加能力走 minor，
输出格式或产物契约不兼容才走 major。

> 本文件自 v4.0.4 起维护；更早的版本沿革见 `git log` 与 GitHub Releases。

## v4.0.4 — 2026-11-23

### 新增 · WAF / bot 指纹作为资产属性（总纲 3 P1）

「被拦」和「不存在」终于是两件事。以前目标前面挡着 WAF 时，扫描把它当成站点挂了 ——
漏报就这样被写进报告。现在每个存活资产都带上 `http.waf` 属性：

```json
{"vendor": "cloudflare", "confidence": "high", "challenge": "js_challenge",
 "evidence": ["header:cf-ray=8f2a…", "cookie:__cf_bm"]}
```

- **离线指纹库**：Cloudflare / Akamai / F5 / Imperva / 阿里云 / 腾讯云 / 长亭雷池 / 安全狗 /
  360 / AWS / ModSecurity / 瑞数 / 顶象 / 极验，共 24 条 fixture（16 正例 + 8 条误报陷阱）。
- **置信度是算出来的不是拍的**：强特征 ≥2 或「1 强 + 2 弱」才是 high；单强特征最高 medium；
  单弱特征 low；无特征直接不发属性（`http.waf == null` 表示"探过、没 WAF"，与"没探活"区分开）。
- **三道误报闸门**：大页面正文（>8KB 且 200）不算证据；通用兜底要求拦截状态码 + 拦截页文案
  同时成立；`202 Accepted` 不再被判成瑞数。

### 新增 · 域名汇洞（typosquat）

七类变异（同形/插字/删字/换位/连字符/TLD 替换/键盘邻近）+ DNS 存活判定 + 台账增量续跑；
`--export-ioc` 直接导出心之壁可导入的 IOC，打通总纲第 7 节情报闭环。
判活失败不再落库抬分，下一轮无条件重查 —— 「查不到」不等于「不存在」。

### 新增 · 邮件认证体检（mailauth）

DMARC 策略与对齐、SPF 展开（含 include 递归与 10 次 DNS 查询上限）、DKIM 选择器探测、BIMI。

### 新增 · 控制台覆盖面页

把「哪些能力还没跑」直接摆到界面上，不再靠人记 —— 没跑的能力和跑过没命中的能力是两回事。

### 变更 · 视觉层

控制台接入 AR TEX 视觉层，默认主题改为深色毛玻璃。

## v4.0.0 — 2026-11-19

更名 八咫 Yata → 谛听 Diting（仓库 `Kur1sulab/diting`，旧地址重定向）。
