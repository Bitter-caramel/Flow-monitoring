package rule

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "更新 golden 快照")

type goldenFile struct {
	Rules       []goldenRule `json:"rules"`
	LexErrors   []string     `json:"lex_errors"`
	CompileErrs []string     `json:"compile_errors"`
	Total       int          `json:"total"`
	Compiled    int          `json:"compiled"`
	Failed      int          `json:"failed"`
	Unsupported []string     `json:"unsupported"`
}

type goldenRule struct {
	ID             string          `json:"id"`
	Source         string          `json:"source"`
	SourceID       string          `json:"source_id"`
	Name           string          `json:"name"`
	Category       string          `json:"category"`
	Severity       string          `json:"severity"`
	Enabled        bool            `json:"enabled"`
	Match          goldenMatch     `json:"match"`
	ActionKind     string          `json:"action_kind"`
	ActionSeverity string          `json:"action_severity"`
	Weight         int             `json:"weight"`
	Confidence     float64         `json:"confidence"`
	AnyPort        bool            `json:"any_port"`
	Ports          []uint16        `json:"ports"`
	PortRanges     []string        `json:"port_ranges"`
	Matchers       []goldenMatcher `json:"matchers"`
	Unsupported    []string        `json:"unsupported"`
}

type goldenMatch struct {
	Proto      string       `json:"proto"`
	SrcIP      string       `json:"src_ip"`
	DstIP      string       `json:"dst_ip"`
	SrcPort    string       `json:"src_port"`
	DstPort    string       `json:"dst_port"`
	Flow       string       `json:"flow"`
	Conditions []goldenCond `json:"conditions"`
}

type goldenCond struct {
	Kind   string `json:"kind"`
	Buffer string `json:"buffer"`
	Value  string `json:"value"`
	Flags  int    `json:"flags"`
	Offset int    `json:"offset"`
	Depth  int    `json:"depth"`
}

type goldenMatcher struct {
	Kind        string `json:"kind"`
	Buffer      string `json:"buffer"`
	Content     string `json:"content"`
	Lower       string `json:"lower"`
	Regex       string `json:"regex"`
	NoCase      bool   `json:"nocase"`
	Negate      bool   `json:"negate"`
	FastPattern bool   `json:"fast_pattern"`
	Offset      int    `json:"offset"`
	Depth       int    `json:"depth"`
}

func TestGolden(t *testing.T) {
	srcPath := filepath.Join("testdata", "basic.rules")
	goldenPath := filepath.Join("testdata", "basic.golden.json")

	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	tr := Translate(string(data))
	out, err := json.MarshalIndent(buildGolden(tr), "", "  ")
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	out = append(out, '\n')

	if *update {
		if err := os.WriteFile(goldenPath, out, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden updated")
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	// Windows 检出会把 golden 转成 CRLF，所以比较前必须归一化行尾。
	wantNorm := strings.ReplaceAll(string(want), "\r\n", "\n")
	if wantNorm != string(out) {
		t.Errorf("golden mismatch\n--- want (golden) ---\n%s\n--- got (generate) ---\n%s", truncate4000(wantNorm), truncate4000(string(out)))
	}
}

func truncate4000(s string) string {
	if len(s) > 4000 {
		return s[:4000]
	}
	return s
}

func buildGolden(tr *TranslateResult) goldenFile {
	gf := goldenFile{
		Rules:       make([]goldenRule, 0, len(tr.Rules)),
		LexErrors:   make([]string, 0, len(tr.LexErrors)),
		CompileErrs: make([]string, 0, len(tr.CompileErrs)),
		Unsupported: make([]string, 0),
		Total:       tr.Total,
		Compiled:    tr.Compiled,
		Failed:      tr.Failed,
	}
	for _, le := range tr.LexErrors {
		gf.LexErrors = append(gf.LexErrors, "line "+strconv.Itoa(le.Line)+": "+le.Error())
	}
	for _, ce := range tr.CompileErrs {
		gf.CompileErrs = append(gf.CompileErrs, ce.Error())
	}
	gf.Unsupported = buildUnsupported(tr.Unsupported)
	for _, cr := range tr.Rules {
		gf.Rules = append(gf.Rules, buildRule(cr))
	}
	return gf
}

func buildRule(cr *CompiledRule) goldenRule {
	r := cr.Rule
	gr := goldenRule{
		ID:             r.ID,
		Source:         string(r.Source),
		SourceID:       r.SourceID,
		Name:           r.Name,
		Category:       r.Category,
		Severity:       r.Severity,
		Enabled:        r.Enabled,
		Match:          buildMatch(r.Match),
		ActionKind:     r.Action.Kind,
		ActionSeverity: r.Action.Severity,
		Weight:         r.Action.Weight,
		Confidence:     r.Action.Confidence,
		AnyPort:        cr.AnyPort,
		Ports:          make([]uint16, 0, len(cr.Ports)),
		PortRanges:     make([]string, 0, len(cr.PortRanges)),
		Matchers:       make([]goldenMatcher, 0, len(cr.Matchers)),
		Unsupported:    make([]string, 0, len(cr.Unsupported)),
	}
	gr.Ports = append(gr.Ports, cr.Ports...)
	for _, pr := range cr.PortRanges {
		gr.PortRanges = append(gr.PortRanges, strconv.FormatUint(uint64(pr.From), 10)+"-"+strconv.FormatUint(uint64(pr.To), 10))
	}
	for _, m := range cr.Matchers {
		gr.Matchers = append(gr.Matchers, buildMatcher(m))
	}
	gr.Unsupported = append(gr.Unsupported, cr.Unsupported...)
	return gr
}

func buildMatch(m Match) goldenMatch {
	gm := goldenMatch{
		Proto:      string(m.Proto),
		SrcIP:      buildNet(m.SrcIP),
		DstIP:      buildNet(m.DstIP),
		SrcPort:    buildPort(m.SrcPort),
		DstPort:    buildPort(m.DstPort),
		Flow:       string(m.Flow),
		Conditions: make([]goldenCond, 0, len(m.Conditions)),
	}
	for _, c := range m.Conditions {
		gm.Conditions = append(gm.Conditions, goldenCond{
			Kind:   string(c.Kind),
			Buffer: string(c.Buffer),
			Value:  c.Value,
			Flags:  int(c.Flags),
			Offset: c.Offset,
			Depth:  c.Depth,
		})
	}
	return gm
}

func buildMatcher(m Matcher) goldenMatcher {
	rgx := ""
	if m.Regex != nil {
		rgx = m.Regex.String()
	}
	return goldenMatcher{
		Kind:        string(m.Kind),
		Buffer:      string(m.Buffer),
		Content:     m.Content,
		Lower:       m.Lower,
		Regex:       rgx,
		NoCase:      m.NoCase,
		Negate:      m.Negate,
		FastPattern: m.FastPattern,
		Offset:      m.Offset,
		Depth:       m.Depth,
	}
}

func buildNet(n NetSpec) string {
	return "negate=" + strconv.FormatBool(n.Negate) + " nets=[" + strings.Join(n.Networks, ",") + "]"
}

func buildPort(p PortSpec) string {
	if p.Any {
		return "any"
	}
	ports := make([]string, 0, len(p.Ports))
	for _, v := range p.Ports {
		ports = append(ports, strconv.FormatUint(uint64(v), 10))
	}
	ranges := make([]string, 0, len(p.Ranges))
	for _, r := range p.Ranges {
		ranges = append(ranges, strconv.FormatUint(uint64(r.From), 10)+"-"+strconv.FormatUint(uint64(r.To), 10))
	}
	return "ports=[" + strings.Join(ports, ",") + "] ranges=[" + strings.Join(ranges, ",") + "]"
}

func buildUnsupported(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+" x"+strconv.Itoa(m[k]))
	}
	return out
}
