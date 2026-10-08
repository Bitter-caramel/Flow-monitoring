package match

import (
	"strconv"

	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

// lastContent 从条件列表末尾往前找第一个 content 条件。
// 修饰项（nocase / fast_pattern / depth / offset 等）作用于"它前面最近的那个 content"，
// 因此统一通过这个辅助函数定位目标条件；找不到返回 nil。
func lastContent(st *kw.State) *rule.Condition {
	for i := len(st.Rule.Match.Conditions) - 1; i >= 0; i-- {
		if st.Rule.Match.Conditions[i].Kind == rule.CondContent {
			return &st.Rule.Match.Conditions[i]
		}
	}
	return nil
}

// nocaseKW 实现 nocase 修饰项：给前面最近的 content 加上忽略大小写标记。
type nocaseKW struct{}

func (nocaseKW) Name() string { return "nocase" }

func (nocaseKW) Handle(st *kw.State, opt suricata.Option) error {
	c := lastContent(st)
	if c == nil {
		st.Unsupported["nocase"]++
		return nil
	}
	c.Flags |= rule.FlagNoCase
	return nil
}

// fastPatternKW 实现 fast_pattern 修饰项：给前面最近的 content 加上快速匹配标记。
type fastPatternKW struct{}

func (fastPatternKW) Name() string { return "fast_pattern" }

func (fastPatternKW) Handle(st *kw.State, opt suricata.Option) error {
	c := lastContent(st)
	if c == nil {
		st.Unsupported["fast_pattern"]++
		return nil
	}
	c.Flags |= rule.FlagFastPattern
	return nil
}

// depthKW 实现 depth 修饰项：设置前面最近的 content 的匹配深度。
type depthKW struct{}

func (depthKW) Name() string { return "depth" }

func (depthKW) Handle(st *kw.State, opt suricata.Option) error {
	c := lastContent(st)
	if c == nil {
		st.Unsupported["depth"]++
		return nil
	}
	n, err := strconv.Atoi(opt.Value)
	if err != nil {
		return err
	}
	c.Depth = n
	return nil
}

// offsetKW 实现 offset 修饰项：设置前面最近的 content 的匹配起始偏移。
type offsetKW struct{}

func (offsetKW) Name() string { return "offset" }

func (offsetKW) Handle(st *kw.State, opt suricata.Option) error {
	c := lastContent(st)
	if c == nil {
		st.Unsupported["offset"]++
		return nil
	}
	n, err := strconv.Atoi(opt.Value)
	if err != nil {
		return err
	}
	c.Offset = n
	return nil
}

// distanceKW 实现 distance 修饰项：IR 暂时表达不了，记为 unsupported（不报错）。
type distanceKW struct{}

func (distanceKW) Name() string { return "distance" }

func (distanceKW) Handle(st *kw.State, opt suricata.Option) error {
	st.Unsupported["distance"]++
	return nil
}

// withinKW 实现 within 修饰项：IR 暂时表达不了，记为 unsupported（不报错）。
type withinKW struct{}

func (withinKW) Name() string { return "within" }

func (withinKW) Handle(st *kw.State, opt suricata.Option) error {
	st.Unsupported["within"]++
	return nil
}

func init() {
	kw.Register(nocaseKW{})
	kw.Register(fastPatternKW{})
	kw.Register(depthKW{})
	kw.Register(offsetKW{})
	kw.Register(distanceKW{})
	kw.Register(withinKW{})
}
