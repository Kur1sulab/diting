# PARITY.md —— Python↔Go 双引擎 parity 对照（c3 收口）

> 基线：HEAD `108ce88`（fix2 落定后）。本文所有数字来自本轮实跑（2026-10-02），
> 证据文件在 `engine-go/docs/parity-samples/`。引用历史口径处均注明。

## ① 方法论

1. **同一靶站对打**：两引擎打**同一个 Go httptest 靶站**（`engine-go/internal/mockweb`，
   与 `tests/mock_server.py` 逐字节对齐并有漂移守卫测试）。严禁各打各的 mock——
   Python BaseHTTPRequestHandler 自带 `Server:` 头、Go httptest 无，各打各的会污染 header 类断言。
2. **python -c 探针**：Go 测试内通过 `python -c` 调 `modules.netutil / modules.subdomain /
   modules.icp / modules.reverse_ip / modules.api_unauth / modules.poc_engine / modules.report`，
   环境固定 `PYTHONUTF8=1`、`PYTHONPATH=src`、cwd=仓库根（`internal/parity/parity.go:RunPy`）。
3. **python 缺失即 Skip**：`RequiresPython(t)` 探测 PATH 无 python 时 `t.Skip`——纯 Go 测试不受影响（铁律）。
4. **只比解析后结构与 strip('\r') 文本**：Python 在 Windows 写 CRLF、Go 写 LF；
   JSON 键序两侧不保证一致（Python dict 插入序 vs Go map 字母序）——一律反序列化后比对，
   文本类先 `StripCR`（`parity.go`）。
5. **不可比项显式豁免**：baseline 探针随机串（两引擎进程级各自 crypto/rand）、生成时间戳、
   zip 文件名时间戳——断言只比"结构位置"或跳过该行。

## ② parity 测试矩阵（24 项；1-14 为 HEAD 108ce88 基线，15-17 portscan 移植轮，18-21 patchdiff 移植轮，22-24 jsintel 移植轮）

| # | 测试（internal/parity/） | 断言内容 | 最近实跑 |
|---|---|---|---|
| 1 | TestParityBaseline | baseline 五场景 kind+status+sha1(digest)+size+ctype；redirect 场景 final_url 全等；其余场景 final_url 只比"停在探针 1 路径"（随机串豁免） | PASS |
| 2 | TestParityFetch | 6 条 URL（swagger/heapdump/waf/api404/empty/loginredirect）ok/status/size/sha1/ctype/body/final_url 全字段 | PASS |
| 3 | TestParityFingerprint | /real /fppage /soft404 命中序列（name+type+顺序）与 fingerprint.json 解析结果 | PASS |
| 4 | TestParityHTTPProbe | 127.0.0.1 字面量+同靶站端口：scheme/status/ctype/title/final_url（server 两侧均空） | PASS |
| 5 | TestParityVerifySubs | verify_subs(["127.0.0.1"], do_http=False) rows（host/ips/alive/http 空）——DNS 锚点用 IP 字面量，禁 NXDOMAIN 断言 | PASS |
| 6 | TestParityOneForAll | 同一 fixture（尾逗号/重复/前导点/大写/脏行）→ 同一排序子域列表（4 项） | PASS |
| 7 | TestParityParseICP | 四例黄金：filed/限频假200/400/非 JSON，比 filed+msg+icp+unit | PASS |
| 8 | TestParityParseHackerTarget | 黄金样例（大写归一/尾点/ip6.arpa/错误文案行） | PASS |
| 9 | TestParityClassify | 六例黄金（heapdump 魔数/多特征≥2/404/HTML200），body 走 stdin | PASS |
| 10 | TestParityPocMatch | _match 黄金四例（status 命中/未命中/contains/and） | PASS |
| 11 | TestParityRenderMD | 同一合成 bundle 两侧渲染 → 70 行逐行 diff（跳过"生成时间"行）；曾抓出 anyList 类型归一/数值断言两处真缺陷 | PASS |
| 12 | TestParityPathsAndAPIFullChain | 五陷阱场景（soft404/api404/waf/loginredirect/empty）两版零命中 + real 必含五端点全 live + paths 三路径全 verified（两版 CLI 全链路） | PASS |
| 13 | TestParityAssetParsers | FOFA/Hunter 解析推导式 python 内联重放 vs Go 纯函数，同 fixture 同输出（含 None→"None"） | PASS |
| 14 | TestParityPackEvidence | 两侧各打包 → arcname 集合（正斜杠规范化）+ 成员内容逐字节 | PASS |
| 15 | TestParityParsePorts | 14 条 spec（默认表/区间/去重/非法/`1-65535` 截断/`+80`、`1_0` 的 Python int 口径）逐条比 ParsePorts 输出 | PASS |
| 16 | TestParityClassifyBanner | 27 例 banner 特征矩阵（SSH/HTTP/FTP/SMTP/Redis/Memcached/MySQL/Mongo/VNC/AMQP/ES/Telnet + 端口兜底） | PASS |
| 17 | TestParityPortscanLocalTargets | 同一组本机 TCP 靶标（SSH 样/Redis 样/静默/关闭）双引擎对打：ports.json 反序列化后结构全等 + ports.txt 去 `\r` 逐字符全等 | PASS |
| 18 | TestParityPatchdiffClassify | 80 行逐行语料（12 修复信号 + 8 漏洞痕迹 + `\b` 的 CJK 词边界 + execute/占位符上下文 + 去重保序 + 样本截 10 行）→ fix/vuln 标签与顺序全等 | PASS |
| 19 | TestParityPatchdiffEmitRule | 转义/短行与注释过滤/120 字符截断（含中文，按码点）/去重/12 条上限 → 规则文件逐字节全等 | PASS |
| 20 | TestParityPatchdiffRun | 同一本地 fixture 仓库（8 提交，含空提交/二进制/重命名/CJK/`--` 注释行）→ commits+hunks 结构、规则文件、终端摘要（输出目录归一）全等 | PASS |
| 21 | TestParityPatchdiffCommits | `--grep` 关键词 / `--range` / `--commit` / `--limit` 四种挑法 → sha 列表全等 | PASS |
| 22 | TestParityJSIntelPure | mask/normalize/endpoints/sensitive/domains/scripts 六组纯函数逐样本对打（stdin 喂源码 → stdout JSON，含模板占位/静态资源/内网 IP/公网噪声；另含 endpoint/domain/sensitive 三路正则的 CJK 词边界 Python Unicode 语义、lone `\r`/`\f` 行号-片段错位 quirk） | PASS |
| 23 | TestParityJSIntelFullChain | jssite / waf / soft404 三场景：`jsintel.json` 反序列化结构全等 + `jsintel.txt` 逐字符全等（strip `\r`） + 全量敏感值不落盘 | PASS |
| 24 | TestParityJSIntelTrickySite | 自建陷阱站同站对打：协议相对 URL / `data:` / 静态资源 / 二进制 / 空 JS / 内联序号 / 同行多敏感键，脚本计数与线索锚点双断言 | PASS |

复跑命令：`cd engine-go && go test -count=1 ./internal/parity/`。portscan 3 项与
patchdiff 4 项自带 `python`→`python3` 回退探测（本机 Homebrew 只有 python3），其余
parity 项沿用 `RequiresPython` 的 `python` 口径；CI=true 时全部 Skip（本地黄金门禁）。
已知在案：`TestParityOneForAll` 依赖 PATH 里有 `python` 可执行文件（toolrun 适配层
按 `python` 起 OneForAll 子进程），python3-only 机器上该测试与其余 `RequiresPython`
项一样走 Skip——不是本轮引入的缺口。

## ③ mock 全场景关键输出对照表（两版 CLI 实跑，2026-10-02）

靶站：`python tests/mock_server.py 8799`（python 官方 mock，7 场景；`fppage`/`r302` 为 Go mockweb
与 redteam-adv2 自建场景，见下注）。证据：`engine-go/docs/parity-samples/mock_matrix_7scenarios.txt`。

| 场景 | api hits（py/go） | api live（py/go） | catch-all 过滤（py/go） | paths alive（py/go） | paths notes（py/go） |
|---|---|---|---|---|---|
| soft404 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| waf | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| loginredirect | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 19 / 19 |
| empty | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| api404 | 0 / 0 | 0 / 0 | **1 / 1**（/metrics 命中泛化 JSON 被刷） | 0 / 0 | 19 / 19 |
| real | **5 / 5** | **5 / 5** | 0 / 0 | **5 / 5** | 0 / 0 |
| fppage* | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |

- baseline kind（两版一致，实证于 TestParityBaseline 与 `tests/test_probe_integration.py:89-93`）：
  soft404→`soft404`、waf→`uniform403`、loginredirect→`redirect(302)`、empty→`normal`、api404→`soft404`。
- fingerprint（CLI 对 python mock 根路径）：real/fppage 两版均 0 命中（根路径 404，两版一致）；
  fppage 显式头+ThinkPHP 特征命中由 Go mockweb 靶站的 parity/单元测试覆盖（TestMatchFpPage：[ThinkPHP, Nginx]）。
- **r302**（redteam-adv2 自建临时靶站：soft404 壳 + 全端点真命中，验证"重定向落地后 catch-all
  过滤不误杀真命中"）：Go 版 25 个端点全命中且全存活——证据 `engine-go/docs/parity-samples/api_r302_stdout.txt`
  （同目录 fp_r302 / paths_r302 / api_direct_lan 为同轮采样）。
- **口径说明**：「mock 全流程对照」= 模块全集逐个对照（api/paths/fingerprint/baseline/verify/poc），
  **不含 `all` 一键全流程**——该表是 2026-10-02 抽样，all 当时未移植；第三轮升级后 Go 侧
  `all` 已落地（cli/all.go，10 步编排），实跑证据见 ⑥「第三轮 all 实跑」。
- jssite 场景属 jsintel，已由 `TestParityJSIntelFullChain` 覆盖（见 ② 矩阵 22-24）。

## ④ 已知口径差异清单（两轮沉淀，全部"可解释且已对齐"）

| 差异点 | 说明 | 对齐方式 |
|---|---|---|
| digest | 内容形态指纹 sha256(raw) hex 前 16 位（fix1 起，sha1 弃用） | 两引擎同步迁移，TestParityBaseline/Fetch 断言相等 |
| CRLF vs LF | Python write_text 在 Windows 产 CRLF，Go 产 LF | parity 只比 strip('\r') 文本/解析后结构 |
| 动态 JSON 键 | Go struct omitempty vs Python dict 动态键；map 键序字母序 vs 插入序 | 反序列化后按键比对，不比键序/键存在性 |
| RE2 label 改写 | reverse 正则 `(?!-)/(?<!-)` lookaround RE2 不支持 → label 校验函数 | 黄金用例+TestParityParseHackerTarget 钉死等价 |
| 时间戳 | generated_at/zip 文件名/collected_at 不可 byte 比 | clock 注入 + diff 跳时间行 + arcname 集合比 |
| baseline 探针串 | 进程级随机（token_hex(5) vs crypto/rand） | final_url 只比"探针 1 路径"后缀，redirect 场景全等 |
| 数字类型 | JSON→float64 vs Go int 字面量 | 渲染层 numOf 通用提取（c2 parity 抓出后修） |
| 子进程超时 | Python TimeoutExpired 炸穿 vs Go 告警返空走降级链 | README 差异说明（行为等价：该通道无结果） |
| 私网全集 | Go 标准库缺 Python 的私网/保留段（含 198.18.0.0/15 fake-ip 段） | 自实现全集 + 动态 python 探针单测逐 IP 钉死 |
| portscan timeout 字面量 | Python json.dumps 写 `1.0`，Go float64 默认写 `1` | `Result.Timeout` 用 `PyFloat.MarshalJSON` 输出 `1.0`；ports.json / ports.txt 实测与 Python 逐字节一致（本机 diff 为空） |
| portscan 写盘/退出码 | Python safe_write 抛异常未捕获 → traceback exit 1；Go 返回 error → CLI exit 1 | 行为等价（写盘失败即失败），日志文案不同 |
| patchdiff 失败口径 | Python `run_patchdiff` 非仓库时返回 `{'ok': False, 'error': …}`，但 recon.py 不看返回值 → **exit 0**；Go 返回 error → CLI `[!]` + exit 1 | **有意偏差**（脚本不该把「不是 git 仓库」当成功继续跑）；契约面：Go 以 error 表达 ok=False |
| patchdiff limit=0 | Python 显式 `limit=0` → `git log -n 0` → 空结果；Go `Limit<=0` 视同未设置取默认 20 | 有意偏差（库 API 零值可用；CLI 恒显式传 20，无差异面） |
| 私网表的 Python 版本口径 | ipaddress 私网表随 CPython 版本漂移：3.8 与 3.13 差异段 = IPv4 192.0.0.0/29(+170/31)→/24、IPv6 新增 64:ff9b:1::/48、2002::/16、3fff::/20。**Go 表统一按 3.13 口径**（与 CI runner 一致）；本机 3.8 引擎在上述 4 个极端段上更宽松（不影响 fake-ip/RFC1918/回环等核心场景） | 探针测试版本感知：python <3.9 跳过版本差异段对照（netutil:TestIPBlockedMatchesPython） |

## ⑤ 真实目标对照（xycovo.com，白名单内自有资产，人工验收 2026-10-02 20:14-20:20）

命令集（两版各跑一遍，单次无并发克制执行）：
`fingerprint -u https://xycovo.com`、`paths -u https://xycovo.com`、`api -u https://xycovo.com`、
`subdomain -d xycovo.com --verify`、`report -t xycovo.com`。

| 指标 | Python 版 | Go 版 | 一致性 |
|---|---|---|---|
| 指纹命中 | 0（无） | 0（无） | ✅ |
| paths 基线 | normal（404, 14691B） | normal（404, 14691B） | ✅ |
| paths 基线 digest | `1229a80e9158c935` | `1229a80e9158c935` | ✅ **完全相同** |
| paths alive | 1（/robots.txt, 200, 71B, 复验通过） | 1（同） | ✅ |
| api hits / 过滤 | 0 / 0 | 0 / 0 | ✅ |
| 子域数量 | 0 | 0 | ✅ |
| 子域链路 | crt.sh→私网阻断（198.18.0.178）→certspotter→阻断（198.18.0.182）→空 | 同 | ✅ |
| report | 生成，无证据跳过 zip | 同 | ✅ |
| fingerprint.json | — | — | ✅ 逐字节一致 |
| paths.json | 差异=键序+随机探针串 final_url | 同左 | ✅ 可解释（④清单第 5/6 行） |
| report.md | 差异=生成时间行 | 同左 | ✅ 可解释 |

**差异解释与合理性结论**：无实质差异。①指纹/路径/API 三模块两版输出逐项相同，基线 digest
两版对同一 14691B 的 404 页算出**同一 SHA-256 前 16 位**（真实环境佐证 digest 口径对齐）；
②子域 0 条系本机 Clash fake-ip 把 crt.sh/certspotter 解析到 198.18.0.0/15，两版 SSRF 防御
（私网全集阻断）**同样正确工作**——这不是数据源时变差异，而是防御语义 parity 的实证；
预期中的"干净静态博客"画像（软 404 基线 normal、无 API 暴露、仅 /robots.txt 可访问）两版判定一致。
47.100.49.228 本轮未测（计划不强制）。

## ⑥ 第三轮 all/jsintel/portscan/patchdiff 实跑（macOS arm64，2026-11-18）

环境：go1.24.13 darwin/arm64；Python 3（`python3`）；靶站 = `tests/mock_server.py`
（127.0.0.1:8811，`/jssite/` 场景自带外链 JS + 内联敏感值 + 第三方域 + 内网 IP 线索）。
命令两版各跑一遍，产物逐字节比对。

| 模块 | 比对对象 | 结果 |
|---|---|---|
| jsintel | `jsintel.json` | ✅ **md5 相同**（`893389ec9ae96cb600b1ab80a9a01163` 两侧同值） |
| jsintel | `jsintel.txt` | ✅ `diff` 空（含「线索≠漏洞」声明行与打码值） |
| portscan | `ports.json` / `ports.txt` | ✅ 逐字节一致（`timeout` 字面经 `PyFloat` 修正后 `1.0` 与 Python 同形） |
| patchdiff | `patchdiff.json` | ✅ 逐字节一致（同一 fixture 仓库 `--limit 3`：3 提交 / 3 hunk / 修复信号同序） |
| all | `mappa all -t 127.0.0.1` | ✅ exit 0，10 步全跑通（reverse→icp→fingerprint→api→portscan→jsintel→report），`report.md` 落盘 |

jsintel 实跑摘要（两版同）：端点 4 条（`/api/v1/users`、`/api/v2/login`、`/v3/pay`、
`/weather/beijing`）／敏感 3 条（全部打码到前 4 位）／第三方域 1／内网 IP 1。

`all` 编排核对：Go 侧步骤序与 `recon.py cmd_all` 一致（域名分支 jsintel→portscan，
IP 分支 portscan→jsintel），jsintel/portscan 均为非致命步骤——本地靶站端口扫描失败
也照常进入 report 收尾（desktop-native `TestIntegrationAllDomainBranchRunsNewSteps` 钉住）。
