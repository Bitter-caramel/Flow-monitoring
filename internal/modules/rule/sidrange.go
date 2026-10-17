package rule

import "fmt"

// sidRange 是某来源允许的 sid 闭区间。
type sidRange struct {
	min uint32
	max uint32
}

// sidRanges 来源 → 允许的 sid 号段。
//
// 号段划分（任务 14-1 已拍板）：
//   - builtin  ：1        – 999,999
//   - custom   ：1,000,000 – 1,999,999
//   - suricata ：2,000,000 – 2,999,999
//   - public   ：9,000,000 – 9,999,999
//
// 该表是包级只读数据：只在包初始化时写入，运行期不修改。
var sidRanges = map[Source]sidRange{
	SourceBuiltin:  {min: 1, max: 999_999},
	SourceCustom:   {min: 1_000_000, max: 1_999_999},
	SourceSuricata: {min: 2_000_000, max: 2_999_999},
	SourcePublic:   {min: 9_000_000, max: 9_999_999},
}

// SIDRange 返回某来源允许的 sid 闭区间。ok=false 表示该来源未定义号段。
func SIDRange(src Source) (min, max uint32, ok bool) {
	r, ok := sidRanges[src]
	if !ok {
		return 0, 0, false
	}
	return r.min, r.max, true
}

// ValidateSID 校验 sid 是否落在该来源的号段内。
//
// 返回的错误信息包含来源名、sid 与允许区间，便于人直接定位问题；
// 来源未定义号段时同样返回错误（不猜、不放行）。
func ValidateSID(src Source, sid uint32) error {
	min, max, ok := SIDRange(src)
	if !ok {
		return fmt.Errorf("规则来源 %q 未定义 sid 号段，无法校验 sid %d", string(src), sid)
	}
	if sid < min || sid > max {
		return fmt.Errorf("sid %d 超出规则来源 %q 的允许区间 [%d, %d]", sid, string(src), min, max)
	}
	return nil
}
