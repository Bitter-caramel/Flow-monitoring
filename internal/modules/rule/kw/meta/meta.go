package meta

import (
	"strconv"

	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

func init() {
	kw.Register(msgKW{})
	kw.Register(sidKW{})
	kw.Register(revKW{})
	kw.Register(priorityKW{})
	kw.Register(referenceKW{})
	kw.Register(metadataKW{})
}

// msgKW 处理 msg 关键字：把选项值写入规则名。
type msgKW struct{}

func (msgKW) Name() string { return "msg" }

func (msgKW) Handle(st *kw.State, opt suricata.Option) error {
	st.Rule.Name = opt.Value
	return nil
}

// sidKW 处理 sid 关键字：校验整数并写入来源 ID 与内部 ID。
type sidKW struct{}

func (sidKW) Name() string { return "sid" }

func (sidKW) Handle(st *kw.State, opt suricata.Option) error {
	if _, err := strconv.Atoi(opt.Value); err != nil {
		return err
	}
	st.Rule.SourceID = opt.Value
	st.Rule.ID = "suricata-" + opt.Value
	return nil
}

// revKW 处理 rev 关键字：仅校验整数，不落字段。
type revKW struct{}

func (revKW) Name() string { return "rev" }

func (revKW) Handle(st *kw.State, opt suricata.Option) error {
	if _, err := strconv.Atoi(opt.Value); err != nil {
		return err
	}
	return nil
}

// priorityKW 处理 priority 关键字：仅校验整数，不落字段。
type priorityKW struct{}

func (priorityKW) Name() string { return "priority" }

func (priorityKW) Handle(st *kw.State, opt suricata.Option) error {
	if _, err := strconv.Atoi(opt.Value); err != nil {
		return err
	}
	return nil
}

// referenceKW 处理 reference 关键字：把选项值追加进参考列表。
type referenceKW struct{}

func (referenceKW) Name() string { return "reference" }

func (referenceKW) Handle(st *kw.State, opt suricata.Option) error {
	st.Rule.References = append(st.Rule.References, opt.Value)
	return nil
}

// metadataKW 处理 metadata 关键字：本层不建模，仅按 key 记账。
type metadataKW struct{}

func (metadataKW) Name() string { return "metadata" }

func (metadataKW) Handle(st *kw.State, opt suricata.Option) error {
	st.Unsupported[opt.Key]++
	return nil
}
