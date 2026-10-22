package plugin

import (
	"errors"
	"net"
	"net/rpc"
)

// errRunStoreUnsupported 表示宿主实现没有提供 Run 持久化能力。
//
// 模块侧会先做 RunStore 类型断言；正常情况下不会走到这里。保留该错误是为了
// 让自定义宿主（或测试桩）在不支持时得到明确失败，而不是静默丢数据。
var errRunStoreUnsupported = errors.New("plugin: host does not implement RunStore")

// HostServiceName 宿主桥接服务在 net/rpc 中的注册名。
const HostServiceName = "Host"

// —— 参数/结果结构（gob 安全，跨进程序列化用） ——

// LogArgs 日志调用参数。
type LogArgs struct {
	Level string
	Msg   string
}

// PublishArgs 事件发布参数。
type PublishArgs struct {
	Topic string
	Data  []byte
}

// PollArgs 事件拉取参数（since 为游标，返回 Seq > since 的事件）。
type PollArgs struct {
	Topic string
	Since uint64
	Max   int
}

// RegisterHTTPArgs 模块上报 HTTP 地址参数。
type RegisterHTTPArgs struct {
	HTTPBase string
	Addr     string
	ModuleID string
}

// IDArg 单 ID 参数。
type IDArg struct {
	ID string
}

// CaptureGetResult 抓包查询结果。
type CaptureGetResult struct {
	Rec   CaptureRecord
	Found bool
}

// PacketSaveArgs 批量写包参数。
type PacketSaveArgs struct {
	CaptureID string
	Packets   []PacketRecord
}

// PacketListArgs 分页查包参数。
type PacketListArgs struct {
	CaptureID string
	Page      Page
}

// ServiceLookupResult 服务查询结果。
type ServiceLookupResult struct {
	Ref   ServiceRef
	Found bool
}

// RunListArgs Run 历史查询参数。
type RunListArgs struct {
	Limit int
}

// —— 宿主侧：net/rpc 服务端 ——

// HostRPCServer 承载 Host 实现的 net/rpc 服务端。
type HostRPCServer struct {
	Impl Host
}

// ServeHost 在 ln 上服务 Host 接口（阻塞，宿主侧启动 goroutine 调用）。
func ServeHost(ln net.Listener, impl Host) error {
	srv := rpc.NewServer()
	if err := srv.RegisterName(HostServiceName, &HostRPCServer{Impl: impl}); err != nil {
		return err
	}
	srv.Accept(ln)
	return nil
}

func (s *HostRPCServer) Config(_ struct{}, reply *ConfigSnapshot) error {
	*reply = s.Impl.Config()
	return nil
}

func (s *HostRPCServer) Log(args *LogArgs, _ *Void) error {
	s.Impl.Log(args.Level, args.Msg)
	return nil
}

func (s *HostRPCServer) Publish(args *PublishArgs, _ *Void) error {
	return s.Impl.Publish(args.Topic, args.Data)
}

func (s *HostRPCServer) Poll(args *PollArgs, reply *[]EventRecord) error {
	*reply = s.Impl.Poll(args.Topic, args.Since, args.Max)
	return nil
}

func (s *HostRPCServer) RegisterHTTP(args *RegisterHTTPArgs, _ *Void) error {
	return s.Impl.RegisterHTTP(args.HTTPBase, args.Addr, args.ModuleID)
}

func (s *HostRPCServer) RegisterService(args *ServiceRef, _ *Void) error {
	return s.Impl.RegisterService(*args)
}

func (s *HostRPCServer) LookupService(args *IDArg, reply *ServiceLookupResult) error {
	ref, found := s.Impl.LookupService(args.ID)
	*reply = ServiceLookupResult{Ref: ref, Found: found}
	return nil
}

func (s *HostRPCServer) UnregisterService(args *IDArg, _ *Void) error {
	return s.Impl.UnregisterService(args.ID)
}

func (s *HostRPCServer) CaptureCreate(args *CaptureRecord, _ *Void) error {
	return s.Impl.CaptureCreate(*args)
}

func (s *HostRPCServer) CaptureGet(args *IDArg, reply *CaptureGetResult) error {
	rec, found := s.Impl.CaptureGet(args.ID)
	*reply = CaptureGetResult{Rec: rec, Found: found}
	return nil
}

func (s *HostRPCServer) CaptureList(args *Page, reply *CapturePage) error {
	*reply = s.Impl.CaptureList(*args)
	return nil
}

func (s *HostRPCServer) CaptureDelete(args *IDArg, _ *Void) error {
	return s.Impl.CaptureDelete(args.ID)
}

func (s *HostRPCServer) PacketSaveBatch(args *PacketSaveArgs, _ *Void) error {
	return s.Impl.PacketSaveBatch(args.CaptureID, args.Packets)
}

func (s *HostRPCServer) PacketList(args *PacketListArgs, reply *PacketPage) error {
	*reply = s.Impl.PacketList(args.CaptureID, args.Page)
	return nil
}

func (s *HostRPCServer) PacketCount(args *IDArg, reply *int) error {
	*reply = s.Impl.PacketCount(args.ID)
	return nil
}

func (s *HostRPCServer) PacketDelete(args *IDArg, _ *Void) error {
	return s.Impl.PacketDelete(args.ID)
}

// RunSave 持久化一条 Run 记录（Host 的可选 RunStore 扩展）。
func (s *HostRPCServer) RunSave(args *RunRecord, _ *Void) error {
	rs, ok := s.Impl.(RunStore)
	if !ok {
		return errRunStoreUnsupported
	}
	return rs.RunSave(*args)
}

// RunList 查询 Run 历史（Host 的可选 RunStore 扩展）。
func (s *HostRPCServer) RunList(args *RunListArgs, reply *[]RunRecord) error {
	rs, ok := s.Impl.(RunStore)
	if !ok {
		// RunList 在可选接口里没有 error 返回值：明确返回空列表，
		// 让模块按"没有历史"处理；RunSave 会返回错误让调用方感知。
		*reply = nil
		return errRunStoreUnsupported
	}
	*reply = rs.RunList(args.Limit)
	return nil
}

// —— 模块侧：net/rpc 客户端 ——

// DialHost 从模块进程回连宿主桥接服务。
//
// addr 来自环境变量 FLOW_HOST_BRIDGE（宿主启动模块前写入）。
func DialHost(addr string) (Host, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client := rpc.NewClient(conn)
	return &hostRPCClient{client: client}, nil
}

// hostRPCClient 模块侧：远程调用宿主服务。
type hostRPCClient struct {
	client *rpc.Client
}

var (
	_ Host     = (*hostRPCClient)(nil)
	_ RunStore = (*hostRPCClient)(nil)
)

func (c *hostRPCClient) Config() ConfigSnapshot {
	var r ConfigSnapshot
	_ = c.client.Call(HostServiceName+".Config", struct{}{}, &r)
	return r
}

func (c *hostRPCClient) Log(level, msg string) {
	_ = c.client.Call(HostServiceName+".Log", &LogArgs{Level: level, Msg: msg}, &Void{})
}

func (c *hostRPCClient) Publish(topic string, data []byte) error {
	return c.client.Call(HostServiceName+".Publish", &PublishArgs{Topic: topic, Data: data}, &Void{})
}

func (c *hostRPCClient) Poll(topic string, since uint64, max int) []EventRecord {
	var r []EventRecord
	_ = c.client.Call(HostServiceName+".Poll", &PollArgs{Topic: topic, Since: since, Max: max}, &r)
	return r
}

func (c *hostRPCClient) RegisterHTTP(httpBase, addr, moduleID string) error {
	return c.client.Call(HostServiceName+".RegisterHTTP",
		&RegisterHTTPArgs{HTTPBase: httpBase, Addr: addr, ModuleID: moduleID}, &Void{})
}

func (c *hostRPCClient) RegisterService(ref ServiceRef) error {
	return c.client.Call(HostServiceName+".RegisterService", &ref, &Void{})
}

func (c *hostRPCClient) LookupService(name string) (ServiceRef, bool) {
	var r ServiceLookupResult
	_ = c.client.Call(HostServiceName+".LookupService", &IDArg{ID: name}, &r)
	return r.Ref, r.Found
}

func (c *hostRPCClient) UnregisterService(name string) error {
	return c.client.Call(HostServiceName+".UnregisterService", &IDArg{ID: name}, &Void{})
}

func (c *hostRPCClient) CaptureCreate(rec CaptureRecord) error {
	return c.client.Call(HostServiceName+".CaptureCreate", &rec, &Void{})
}

func (c *hostRPCClient) CaptureGet(id string) (CaptureRecord, bool) {
	var r CaptureGetResult
	_ = c.client.Call(HostServiceName+".CaptureGet", &IDArg{ID: id}, &r)
	return r.Rec, r.Found
}

func (c *hostRPCClient) CaptureList(page Page) CapturePage {
	var r CapturePage
	_ = c.client.Call(HostServiceName+".CaptureList", &page, &r)
	return r
}

func (c *hostRPCClient) CaptureDelete(id string) error {
	return c.client.Call(HostServiceName+".CaptureDelete", &IDArg{ID: id}, &Void{})
}

func (c *hostRPCClient) PacketSaveBatch(captureID string, packets []PacketRecord) error {
	return c.client.Call(HostServiceName+".PacketSaveBatch",
		&PacketSaveArgs{CaptureID: captureID, Packets: packets}, &Void{})
}

func (c *hostRPCClient) PacketList(captureID string, page Page) PacketPage {
	var r PacketPage
	_ = c.client.Call(HostServiceName+".PacketList", &PacketListArgs{CaptureID: captureID, Page: page}, &r)
	return r
}

func (c *hostRPCClient) PacketCount(captureID string) int {
	var r int
	_ = c.client.Call(HostServiceName+".PacketCount", &IDArg{ID: captureID}, &r)
	return r
}

func (c *hostRPCClient) PacketDelete(captureID string) error {
	return c.client.Call(HostServiceName+".PacketDelete", &IDArg{ID: captureID}, &Void{})
}

// RunSave 远程持久化一条 Run 记录（Host 的可选 RunStore 扩展）。
func (c *hostRPCClient) RunSave(rec RunRecord) error {
	return c.client.Call(HostServiceName+".RunSave", &rec, &Void{})
}

// RunList 远程查询 Run 历史（Host 的可选 RunStore 扩展）。
func (c *hostRPCClient) RunList(limit int) []RunRecord {
	var r []RunRecord
	_ = c.client.Call(HostServiceName+".RunList", &RunListArgs{Limit: limit}, &r)
	return r
}
