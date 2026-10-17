package rule

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"flow-monitoring/internal/modules/rule/suricata"
)

// LoadIssue 一条加载期问题（不致命，但必须报告）。
type LoadIssue struct {
	File   string // 相对 root 的路径
	Reason string // 人类可读原因
}

// TextTranslator 把一段规则文本翻译为编译结果。
//
// issues 承载词法/编译错误等“加载期问题”，由 LoadDir 落到具体文件上。
// 完整实现由 pipeline 包在 init 中注入；未注入时使用本文件内的降级实现，
// 以避免 rule -> pipeline 的导入环（pipeline 及其依赖的 kw 都依赖 rule）。
type TextTranslator func(text string, src Source) (rules []*CompiledRule, issues []string)

// textTranslator 默认为降级实现；pipeline.init 会将其替换为完整翻译器。
var textTranslator TextTranslator = translateFallback

// SetTextTranslator 注入规则文本翻译器（仅供 pipeline 包在启动期调用）。
func SetTextTranslator(t TextTranslator) {
	if t != nil {
		textTranslator = t
	}
}

// dirSources 规则目录名 -> 来源。未知目录名一律报问题，绝不猜测。
var dirSources = map[string]Source{
	"builtin": SourceBuiltin,
	"local":   SourceCustom,
	"et":      SourceSuricata,
	"public":  SourcePublic,
}

// sourceDirs 来源 -> 规则目录名（ExportSource 使用）。
var sourceDirs = map[Source]string{
	SourceBuiltin:  "builtin",
	SourceCustom:   "local",
	SourceSuricata: "et",
	SourcePublic:   "public",
}

// LoadDir 递归加载 root 下按来源分目录的 .rules 文件，按来源校验 sid。
//
// 目录约定：rules/builtin ⇒ builtin，rules/local ⇒ custom，
// rules/et ⇒ suricata，rules/public ⇒ public；未知顶层目录报一条 LoadIssue
// 并跳过，不做任何猜测。
//
// 返回值：全部成功编译且通过 sid 校验的规则（已填好 Source）、问题清单。
// 所有 sid 问题（缺失/非法/越界/跨文件重复）都会记入问题清单，不会静默跳过。
func LoadDir(root string) ([]*CompiledRule, []LoadIssue, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, fmt.Errorf("rule: 无法访问规则根目录 %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("rule: 规则根路径 %q 不是目录", root)
	}

	rules := make([]*CompiledRule, 0)
	issues := make([]LoadIssue, 0)
	seenSID := make(map[uint32]string) // sid -> 首次出现它的相对文件

	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		if d.IsDir() {
			if rel == "." {
				return nil
			}
			// 只有 root 的直接子目录参与来源判定；更深层目录继承顶层来源。
			if !strings.Contains(rel, "/") {
				if _, ok := dirSources[rel]; !ok {
					issues = append(issues, LoadIssue{
						File:   rel,
						Reason: fmt.Sprintf("未知来源目录 %q（可用：builtin/local/et/public）", rel),
					})
					return filepath.SkipDir
				}
			}
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(d.Name()), ".rules") {
			return nil
		}

		top := rel
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			top = rel[:i]
		}
		src, ok := dirSources[top]
		if !ok || top == rel {
			issues = append(issues, LoadIssue{
				File:   rel,
				Reason: fmt.Sprintf("规则文件不在已知来源目录下（顶层 %q）", top),
			})
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			issues = append(issues, LoadIssue{File: rel, Reason: fmt.Sprintf("读取失败: %v", readErr)})
			return nil
		}

		translated, textIssues := textTranslator(string(data), src)
		for _, ti := range textIssues {
			issues = append(issues, LoadIssue{File: rel, Reason: ti})
		}

		for _, cr := range translated {
			if cr == nil {
				continue
			}
			sid, sidErr := sourceIDSID(cr)
			if sidErr != nil {
				issues = append(issues, LoadIssue{File: rel, Reason: sidErr.Error()})
				continue
			}
			if vErr := ValidateSID(src, sid); vErr != nil {
				issues = append(issues, LoadIssue{File: rel, Reason: vErr.Error()})
				continue
			}
			if first, dup := seenSID[sid]; dup {
				issues = append(issues, LoadIssue{
					File:   rel,
					Reason: fmt.Sprintf("sid %d 重复（首次出现于 %s）", sid, first),
				})
				continue
			}
			seenSID[sid] = rel
			cr.Source = src // 兜底：翻译器应已设置，这里再保证一次
			rules = append(rules, cr)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("rule: 遍历规则根目录 %q 失败: %w", root, err)
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].File != issues[j].File {
			return issues[i].File < issues[j].File
		}
		return issues[i].Reason < issues[j].Reason
	})
	return rules, issues, nil
}

// sourceIDSID 从编译结果里取出数字 sid。
func sourceIDSID(cr *CompiledRule) (uint32, error) {
	if cr.SourceID == "" {
		return 0, fmt.Errorf("规则 %q 缺少 sid，无法校验号段", cr.ID)
	}
	v, err := strconv.ParseUint(cr.SourceID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("规则 %q 的 sid %q 非法: %v", cr.ID, cr.SourceID, err)
	}
	return uint32(v), nil
}

// ---------------------------------------------------------------------------
// 降级翻译器：仅在 pipeline 尚未注入实现时使用（例如 rule 包自身的独立测试）。
// 生产路径始终使用 pipeline 注入的完整翻译器，语义与关键字插件完全一致。
// ---------------------------------------------------------------------------

var fallbackBuffers = map[string]Buffer{
	"payload":          BufPayload,
	"stream":           BufStream,
	"http_uri":         BufHTTPURI,
	"http_header":      BufHTTPHeader,
	"http_method":      BufHTTPMethod,
	"http_client_body": BufHTTPClientBody,
	"dns_query":        BufDNSQuery,
	"tls_sni":          BufTLSSNI,
}

var fallbackClasstypes = map[string][2]string{
	"web-application-attack": {"web", "high"},
	"attempted-admin":        {"web", "medium"},
	"attempted-user":         {"web", "low"},
	"trojan-activity":        {"c2", "high"},
	"scan":                   {"scanner", "medium"},
	"attempted-recon":        {"scanner", "medium"},
	"attempted-dos":          {"proto", "high"},
	"misc-attack":            {"proto", "medium"},
	"misc-activity":          {"proto", "medium"},
	"policy-violation":       {"proto", "low"},
}

func translateFallback(text string, src Source) ([]*CompiledRule, []string) {
	raws, lexErrs := suricata.LexAll(text)
	rules := make([]*CompiledRule, 0, len(raws))
	issues := make([]string, 0, len(lexErrs))
	for _, le := range lexErrs {
		issues = append(issues, fmt.Sprintf("line %d: %s", le.Line, le.Err))
	}
	for _, raw := range raws {
		if raw == nil {
			continue
		}
		r, err := buildFallbackRule(raw)
		if err != nil {
			issues = append(issues, fmt.Sprintf("line %d: %s", raw.Line, err))
			continue
		}
		r.Source = src
		c, err := Compile(r)
		if err != nil {
			issues = append(issues, fmt.Sprintf("line %d: %s", raw.Line, err))
			continue
		}
		c.Source = src
		rules = append(rules, c)
	}
	return rules, issues
}

func buildFallbackRule(raw *suricata.RawRule) (*Rule, error) {
	r := &Rule{
		Enabled: true,
		Source:  SourceSuricata,
		Match: Match{
			Proto:   fallbackProto(raw.Header.Proto),
			SrcIP:   fallbackNetSpec(raw.Header.SrcIP),
			DstIP:   fallbackNetSpec(raw.Header.DstIP),
			SrcPort: fallbackPortSpec(raw.Header.SrcPort),
			DstPort: fallbackPortSpec(raw.Header.DstPort),
		},
	}

	curBuf := BufPayload
	if r.Match.Proto == ProtoTCP {
		curBuf = BufStream
	}

	for _, opt := range raw.Options {
		switch opt.Key {
		case "msg":
			r.Name = opt.Value
		case "sid":
			if _, err := strconv.Atoi(opt.Value); err != nil {
				return nil, err
			}
			r.SourceID = opt.Value
			r.ID = "suricata-" + opt.Value
		case "rev", "priority":
			if _, err := strconv.Atoi(opt.Value); err != nil {
				return nil, err
			}
		case "reference":
			r.References = append(r.References, opt.Value)
		case "content", "pcre":
			value, negate := fallbackStripNegate(opt.Value)
			var flags CondFlags
			if negate {
				flags |= FlagNegate
			}
			kind := CondContent
			if opt.Key == "pcre" {
				kind = CondPCRE
			}
			r.Match.Conditions = append(r.Match.Conditions, Condition{
				Kind:   kind,
				Buffer: curBuf,
				Value:  value,
				Flags:  flags,
			})
		case "nocase":
			fallbackLastContent(r, func(c *Condition) { c.Flags |= FlagNoCase })
		case "fast_pattern":
			fallbackLastContent(r, func(c *Condition) { c.Flags |= FlagFastPattern })
		case "depth":
			n, err := strconv.Atoi(opt.Value)
			if err != nil {
				return nil, err
			}
			fallbackLastContent(r, func(c *Condition) { c.Depth = n })
		case "offset":
			n, err := strconv.Atoi(opt.Value)
			if err != nil {
				return nil, err
			}
			fallbackLastContent(r, func(c *Condition) { c.Offset = n })
		case "flow":
			r.Match.Flow = fallbackFlow(opt.Value)
		case "classtype":
			if v, ok := fallbackClasstypes[opt.Value]; ok {
				r.Category, r.Severity = v[0], v[1]
			} else {
				r.Category, r.Severity = "unknown", "medium"
			}
			r.Action.Kind = opt.Value
		default:
			if buf, ok := fallbackBuffers[opt.Key]; ok {
				curBuf = buf
			}
		}
	}

	fallbackFinalize(r)
	return r, nil
}

func fallbackLastContent(r *Rule, apply func(*Condition)) {
	for i := len(r.Match.Conditions) - 1; i >= 0; i-- {
		if r.Match.Conditions[i].Kind == CondContent {
			apply(&r.Match.Conditions[i])
			return
		}
	}
}

func fallbackFinalize(r *Rule) {
	if r.Category == "" {
		r.Category = "unknown"
	}
	if r.Severity == "" {
		r.Severity = "medium"
	}
	if r.Action.Kind == "" {
		r.Action.Kind = "suricata_alert"
	}
	r.Action.Severity = r.Severity
	switch r.Severity {
	case "critical":
		r.Action.Weight = 100
	case "high":
		r.Action.Weight = 80
	case "medium":
		r.Action.Weight = 50
	case "low":
		r.Action.Weight = 20
	default:
		r.Action.Weight = 50
	}
	r.Action.Confidence = 1.0
}

func fallbackStripNegate(v string) (string, bool) {
	if len(v) == 0 || v[0] != '!' {
		return v, false
	}
	value := v[1:]
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	return value, true
}

func fallbackFlow(v string) FlowSpec {
	var stateless, established, toServer bool
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.Contains(part, "stateless"):
			stateless = true
		case strings.Contains(part, "established"):
			established = true
		case strings.Contains(part, "to_server"), strings.Contains(part, "from_client"):
			toServer = true
		}
	}
	switch {
	case stateless:
		return FlowStateless
	case established:
		return FlowEstablished
	case toServer:
		return FlowToServer
	default:
		return ""
	}
}

func fallbackProto(s string) Protocol {
	switch s {
	case "tcp":
		return ProtoTCP
	case "udp":
		return ProtoUDP
	case "icmp":
		return ProtoICMP
	case "http":
		return ProtoHTTP
	case "dns":
		return ProtoDNS
	case "tls":
		return ProtoTLS
	case "ssh":
		return ProtoSSH
	default:
		return ProtoAny
	}
}

func fallbackNetSpec(s string) NetSpec {
	s = strings.TrimSpace(s)

	var negate bool
	if strings.HasPrefix(s, "!") {
		negate = true
		s = strings.TrimSpace(s[1:])
	}
	if s == "" || s == "any" {
		return NetSpec{}
	}
	if len(s) >= 2 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	ns := NetSpec{Negate: negate}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			ns.Networks = append(ns.Networks, part)
		}
	}
	return ns
}

func fallbackPortSpec(s string) PortSpec {
	s = strings.TrimSpace(s)

	if strings.HasPrefix(s, "!") {
		return PortSpec{Any: true}
	}
	if s == "" || s == "any" {
		return PortSpec{Any: true}
	}
	if len(s) >= 2 && strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}

	ps := PortSpec{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, ":") {
			fields := strings.SplitN(part, ":", 2)
			from, errFrom := strconv.Atoi(strings.TrimSpace(fields[0]))
			to, errTo := strconv.Atoi(strings.TrimSpace(fields[1]))
			if errFrom != nil || errTo != nil {
				continue
			}
			ps.Ranges = append(ps.Ranges, PortRange{From: uint16(from), To: uint16(to)})
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		ps.Ports = append(ps.Ports, uint16(p))
	}
	return ps
}
