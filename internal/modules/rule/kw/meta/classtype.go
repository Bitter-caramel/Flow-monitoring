package meta

import (
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

// classtypeTable 把 Suricata 的 classtype 映射为 (分类, 严重度)。
var classtypeTable = map[string][2]string{
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

func init() {
	kw.Register(classtypeKW{})
}

// classtypeKW 处理 classtype 关键字：查表得到分类与严重度，并记下原始动作类型。
type classtypeKW struct{}

func (classtypeKW) Name() string { return "classtype" }

func (classtypeKW) Handle(st *kw.State, opt suricata.Option) error {
	if v, ok := classtypeTable[opt.Value]; ok {
		st.Rule.Category = v[0]
		st.Rule.Severity = v[1]
	} else {
		st.Rule.Category = "unknown"
		st.Rule.Severity = "medium"
	}
	st.Rule.Action.Kind = opt.Value
	return nil
}

// Finalize 补齐规则默认值，并按严重度计算动作权重与置信度。
func Finalize(st *kw.State) {
	if st.Rule.Category == "" {
		st.Rule.Category = "unknown"
	}
	if st.Rule.Severity == "" {
		st.Rule.Severity = "medium"
	}
	if st.Rule.Action.Kind == "" {
		st.Rule.Action.Kind = "suricata_alert"
	}
	st.Rule.Action.Severity = st.Rule.Severity

	switch st.Rule.Severity {
	case "critical":
		st.Rule.Action.Weight = 100
	case "high":
		st.Rule.Action.Weight = 80
	case "medium":
		st.Rule.Action.Weight = 50
	case "low":
		st.Rule.Action.Weight = 20
	default:
		st.Rule.Action.Weight = 50
	}
	st.Rule.Action.Confidence = 1.0
}
