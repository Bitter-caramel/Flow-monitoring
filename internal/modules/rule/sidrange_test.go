package rule

import (
	"fmt"
	"strings"
	"testing"
)

// TestSIDRange 校验四个来源的号段常量与边界。
func TestSIDRange(t *testing.T) {
	cases := []struct {
		src      Source
		min, max uint32
	}{
		{SourceBuiltin, 1, 999_999},
		{SourceCustom, 1_000_000, 1_999_999},
		{SourceSuricata, 2_000_000, 2_999_999},
		{SourcePublic, 9_000_000, 9_999_999},
	}
	for _, c := range cases {
		min, max, ok := SIDRange(c.src)
		if !ok {
			t.Errorf("SIDRange(%q) ok = false，期望 true", c.src)
			continue
		}
		if min != c.min || max != c.max {
			t.Errorf("SIDRange(%q) = [%d,%d]，期望 [%d,%d]", c.src, min, max, c.min, c.max)
		}
	}

	if _, _, ok := SIDRange(Source("no_such_source")); ok {
		t.Error("未知来源的 SIDRange ok = true，期望 false")
	}
}

// TestValidateSID 每个来源测一个合法值 + 一个越界值，并覆盖 999,999 / 1,000,000 边界。
func TestValidateSID(t *testing.T) {
	cases := []struct {
		name  string
		src   Source
		sid   uint32
		valid bool
	}{
		{"builtin 下界", SourceBuiltin, 1, true},
		{"builtin 上界", SourceBuiltin, 999_999, true},
		{"builtin 越上界", SourceBuiltin, 1_000_000, false},
		{"custom 下界", SourceCustom, 1_000_000, true},
		{"custom 上界", SourceCustom, 1_999_999, true},
		{"custom 越下界", SourceCustom, 999_999, false},
		{"suricata 下界", SourceSuricata, 2_000_000, true},
		{"suricata 上界", SourceSuricata, 2_999_999, true},
		{"suricata 越下界", SourceSuricata, 1_999_999, false},
		{"public 下界", SourcePublic, 9_000_000, true},
		{"public 上界", SourcePublic, 9_999_999, true},
		{"public 越上界", SourcePublic, 10_000_000, false},
	}

	for _, c := range cases {
		err := ValidateSID(c.src, c.sid)
		if c.valid {
			if err != nil {
				t.Errorf("%s: ValidateSID(%q,%d) = %v，期望 nil", c.name, c.src, c.sid, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: ValidateSID(%q,%d) = nil，期望 error", c.name, c.src, c.sid)
			continue
		}
		msg := err.Error()
		min, max, _ := SIDRange(c.src)
		for _, want := range []string{string(c.src), fmt.Sprint(c.sid), fmt.Sprint(min), fmt.Sprint(max)} {
			if !strings.Contains(msg, want) {
				t.Errorf("%s: 错误信息 %q 应包含 %q", c.name, msg, want)
			}
		}
	}

	if err := ValidateSID(Source("no_such_source"), 1); err == nil {
		t.Error("未知来源的 ValidateSID = nil，期望 error")
	}
}
