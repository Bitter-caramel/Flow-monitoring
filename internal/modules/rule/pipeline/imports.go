package pipeline

// 这里集中挂载所有关键字插件。
// Go 里子包的 init() 只有被导入才会执行，所以新增一个关键字类别时，
// 要在这个文件里加一行 blank import。
// match 是内容匹配类关键字（content / pcre 及其修饰项）。
import (
	_ "flow-monitoring/internal/modules/rule/kw/buffer"
	_ "flow-monitoring/internal/modules/rule/kw/flow"
	_ "flow-monitoring/internal/modules/rule/kw/match"
	_ "flow-monitoring/internal/modules/rule/kw/meta"
)
