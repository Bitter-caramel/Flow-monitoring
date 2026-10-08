package buffer

import (
	"flow-monitoring/internal/modules/rule"
	"flow-monitoring/internal/modules/rule/kw"
	"flow-monitoring/internal/modules/rule/suricata"
)

// bufTable 把 Suricata 缓冲关键字名映射为 IR 的 Buffer 取值。
var bufTable = map[string]rule.Buffer{
	"payload":          rule.BufPayload,
	"http_uri":         rule.BufHTTPURI,
	"http_header":      rule.BufHTTPHeader,
	"http_method":      rule.BufHTTPMethod,
	"http_client_body": rule.BufHTTPClientBody,
	"dns_query":        rule.BufDNSQuery,
	"tls_sni":          rule.BufTLSSNI,
}

// bufKW 是缓冲类关键字的通用 Handler，只负责切换当前粘性缓冲。
type bufKW struct {
	name string
	buf  rule.Buffer
}

func (k bufKW) Name() string { return k.name }

func (k bufKW) Handle(st *kw.State, opt suricata.Option) error {
	st.CurBuf = k.buf
	return nil
}

func init() {
	for name, buf := range bufTable {
		kw.Register(bufKW{name: name, buf: buf})
	}
}
