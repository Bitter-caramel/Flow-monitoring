package alert

import "flow-monitoring/internal/modules/detect"

// TopicAlertLifecycle 是告警生命周期事件的主题。
const TopicAlertLifecycle = "alert.lifecycle"

// Event 是发布到 alert.lifecycle 的事件。CaptureID 由调用方填
// （命令行回放填文件名、导入填导入批次号）。
type Event struct {
	CaptureID string       `json:"capture_id"`
	Alert     detect.Alert `json:"alert"`
}
