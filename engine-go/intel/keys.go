package intel

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// 凭据来源优先级（高→低）：
//  1. 进程环境变量（export FOFA_KEY=...）
//  2. keys.env 文件（默认 ~/.diting/keys.env，可用 DITING_KEYS_FILE 覆盖；
//     兼容 ~/.config/diting/keys.env）
//
// 文件格式：每行 KEY=VALUE，# 开头为注释；允许引号；允许空行。
// 纪律：本包不写任何真实凭据字面量，文件权限建议 chmod 600。
var (
	keysOnce sync.Once
	keysMap  map[string]string
	keysPath string
)

// KeysFile 返回实际使用的 keys.env 路径（可能不存在）。
func KeysFile() string {
	keysOnce.Do(loadKeys)
	return keysPath
}

func loadKeys() {
	keysMap = map[string]string{}
	cands := []string{}
	if p := strings.TrimSpace(os.Getenv("DITING_KEYS_FILE")); p != "" {
		cands = append(cands, p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		cands = append(cands,
			filepath.Join(home, ".diting", "keys.env"),
			filepath.Join(home, ".config", "diting", "keys.env"),
			// 改名前的目录：老机器上凭据还躺在这里。读不到的后果是"静默无凭据"，
			// 排查代价远高于多留一条兜底路径。
			filepath.Join(home, ".yata", "keys.env"),
			filepath.Join(home, ".config", "yata", "keys.env"),
		)
	}
	for _, p := range cands {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if keysPath == "" {
			keysPath = p
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			v = strings.Trim(v, `"'`)
			if k != "" && keysMap[k] == "" {
				keysMap[k] = v
			}
		}
	}
}

// Env 读凭据：先环境变量，再 keys.env。
func Env(name string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	keysOnce.Do(loadKeys)
	return keysMap[name]
}

// EnvAny 按顺序取第一个非空凭据。
func EnvAny(names ...string) string {
	for _, n := range names {
		if v := Env(n); v != "" {
			return v
		}
	}
	return ""
}

// Mask 凭据脱敏：保留前 4 位 + 长度提示，绝不回显全文。
func Mask(v string) string {
	if v == "" {
		return ""
	}
	r := []rune(v)
	if len(r) <= 6 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:4]) + strings.Repeat("*", 4)
}

// KeyStatus 一个凭据的配置状态（providers 子命令展示用）。
type KeyStatus struct {
	Names      []string `json:"names"`
	Configured bool     `json:"configured"`
	Masked     string   `json:"masked,omitempty"`
	Origin     string   `json:"origin,omitempty"` // env / file
}

// Status 查询一组环境变量名的配置状态。
func Status(names ...string) KeyStatus {
	st := KeyStatus{Names: names}
	for _, n := range names {
		if strings.TrimSpace(os.Getenv(n)) != "" {
			st.Configured = true
			st.Masked = Mask(os.Getenv(n))
			st.Origin = "env"
			return st
		}
	}
	keysOnce.Do(loadKeys)
	for _, n := range names {
		if v := keysMap[n]; v != "" {
			st.Configured = true
			st.Masked = Mask(v)
			st.Origin = "file:" + keysPath
			return st
		}
	}
	return st
}

// resetKeysCache 仅供本包测试：清掉缓存后重读 keys.env。
func resetKeysCache() {
	keysOnce = sync.Once{}
	keysMap = nil
	keysPath = ""
}
