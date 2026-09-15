// Package l7 是应用层（L7）协议解析器。
//
// 设计依据：
//   - pcapng解包逻辑拆解.md §4.7（dispatch 的 UDP 端口优先 / TCP 内容嗅探优先）
//   - PacketLens 源码 PA.app.dispatch（index.html:3889）及 DNS/HTTP/TLS 解析器
//
// 当前实现范围（P0，覆盖最常见协议）：
//   - DNS：查询/响应、question/answer 解析、域名指针压缩、常见 RR 类型
//   - HTTP：请求行/状态行 + 头部解析
//   - TLS：记录层 + 握手类型 + ClientHello SNI 提取
//
// 分发策略（对应 PacketLens dispatch）：
//   - UDP：端口优先（53/5353 → DNS）
//   - TCP：内容嗅探优先（HTTP 特征 → HTTP；TLS 记录头 → TLS；SSH banner → SSH）
//
// 本包只依赖 datamodel（不依赖 decoder），由 decoder 的 tcp/udp 在填完
// PayloadOff/PayloadLen 后调用 Dispatch 进行应用层识别。
package l7
