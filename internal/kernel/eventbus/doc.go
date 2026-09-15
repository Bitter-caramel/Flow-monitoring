// Package eventbus 是进程内事件总线（广播喇叭）。
//
// 设计依据：
//   - v3 流程梯队 1.6："eventbus：发消息/听消息可用（先进程内版）"
//   - 文件结构第 3.1 节："模块之间不直接打电话，对着喇叭喊一声，感兴趣的人自己听（解耦用）"
//   - v0.3 架构第 9.7 节资源自保护："特征事件队列有界，满则丢弃最低优先级特征并记 dropped 计数"
//   - 实施方案 2.0 第 5.3 节事件主题约定
//
// 主题命名约定（点分，对应实施方案 2.0 第 5.3 节）：
//
//	traffic.raw       原始包/包块引用
//	traffic.flow      流统计与健康
//	traffic.app       HTTP/DNS/TLS 应用事件
//	detect.sig        Suricata/YARA 命中
//	detect.behavior   行为规则命中
//	alert.lifecycle   告警生成/合并/抑制/处置
//	case.lifecycle    案件变化
//	plugin.event      插件注册与运行事件
//	capture.health    队列水位、丢包、延迟
//
// 特性：
//   - 精确主题匹配（不做通配符，保持最小够用；需要时后续迭代增加）
//   - 非阻塞投递：订阅者 channel 满时丢弃事件并累计 dropped（可观测）
//   - 有界订阅缓冲：每个订阅者独立 bufSize，防止慢消费者拖垮快消费者
//   - 每个订阅者独立 goroutine 投递（隔离慢消费者，避免阻塞 Publish）
//   - 优雅关闭：Close 后禁止 Publish，所有订阅 channel 关闭
package eventbus
