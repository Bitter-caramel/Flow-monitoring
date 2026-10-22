package alert

import "flow-monitoring/internal/modules/detect"

// TopicAlertLifecycle 是告警生命周期事件的主题。
const TopicAlertLifecycle = "alert.lifecycle"

// Event 是发布到 alert.lifecycle 的事件。CaptureID 由调用方填
// （命令行回放填文件名、导入填导入批次号）。
//
// RunID / Mode 来自 detect.feature 载荷（一次分析任务 / 工作台 live|static），
// 用 omitempty 保证兼容不含这两个字段的旧 JSONL（任务 17 的归档）。
type Event struct {
	CaptureID string       `json:"capture_id"`
	RunID     string       `json:"run_id,omitempty"`
	Mode      string       `json:"mode,omitempty"`
	Alert     detect.Alert `json:"alert"`
}
