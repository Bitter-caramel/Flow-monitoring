package flow

import (
	"strings"

	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

func init() {
	kw.Register(flowKW{})
}

// flowKW 处理 flow 关键字：把选项值拆项后按优先级映射为流向限定。
type flowKW struct{}

func (flowKW) Name() string { return "flow" }

func (flowKW) Handle(st *kw.State, opt suricata.Option) error {
	var stateless, established, toServer bool
	for _, part := range strings.Split(opt.Value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
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
		st.Rule.Match.Flow = rule.FlowStateless
	case established:
		st.Rule.Match.Flow = rule.FlowEstablished
	case toServer:
		st.Rule.Match.Flow = rule.FlowToServer
	}
	return nil
}
