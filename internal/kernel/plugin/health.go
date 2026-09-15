package plugin

// HealthStatus 插件健康状态。
type HealthStatus struct {
	Healthy bool   // 是否健康
	Message string // 不健康时的说明
}

// HealthChecker 可选健康探针接口。
//
// 插件可选实现此接口（用类型断言检测）；未实现的插件
// 只按生命周期状态（Started/Error）判断健康。
type HealthChecker interface {
	Health() HealthStatus
}
