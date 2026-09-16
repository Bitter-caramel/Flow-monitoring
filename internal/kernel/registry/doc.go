// Package registry 是模块登记本（manifest 文件驱动）。
//
// 与旧版的关键区别：
//   - 不再用 init() 自注册 + 全局单例，改为读 registry/backend-modules/*.json
//   - Descriptor 是装配的唯一事实来源；模块二进制仅用于运行期一致性与健康检查
package registry
