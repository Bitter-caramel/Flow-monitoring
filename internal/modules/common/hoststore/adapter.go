// Package hoststore 把宿主桥接（plugin.Host）适配成完整的 storage.Storage。
//
// 存在意义：模块进程不直连数据库，存储访问统一走宿主桥；但既有业务代码
// （如 query / importer / packetstore）都是基于 storage.Storage 写的。
// 本适配器把两者接起来，从而**零改动复用既有存储实现代码**。
//
// 用法（模块进程内）：
//
//	rt := &plugin.Runtime{
//	    Spec: plugin.Manifest{...},
//	    MakeHandler: func(host plugin.Host) (http.Handler, error) {
//	        svc := query.New(hoststore.New(host))
//	        return svc.Handler(), nil
//	    },
//	}
package hoststore

import (
	"context"

	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/pkg/plugin"
)

// Adapter 基于宿主桥的 storage.Storage 实现。
type Adapter struct {
	host plugin.Host
}

var _ storage.Storage = (*Adapter)(nil)

// New 创建适配器。
func New(host plugin.Host) *Adapter { return &Adapter{host: host} }

// Captures 返回抓包元数据存取实现。
func (a *Adapter) Captures() storage.CaptureStore { return &captureStore{host: a.host} }

// Packets 返回数据包元数据存取实现。
func (a *Adapter) Packets() storage.PacketStore { return &packetStore{host: a.host} }

// Close 无操作（连接由宿主管理）。
func (a *Adapter) Close() error { return nil }

// —— CaptureStore ——

type captureStore struct{ host plugin.Host }

func (s *captureStore) Create(_ context.Context, rec *storage.CaptureRecord) error {
	return s.host.CaptureCreate(*rec)
}

func (s *captureStore) Get(_ context.Context, id string) (*storage.CaptureRecord, error) {
	rec, ok := s.host.CaptureGet(id)
	if !ok {
		return nil, storage.ErrNotFound
	}
	return &rec, nil
}

func (s *captureStore) List(_ context.Context, page storage.Page) (*storage.PageResult[storage.CaptureRecord], error) {
	res := s.host.CaptureList(page)
	return &storage.PageResult[storage.CaptureRecord]{Items: res.Items, Total: res.Total}, nil
}

func (s *captureStore) Delete(_ context.Context, id string) error {
	return s.host.CaptureDelete(id)
}

// —— PacketStore ——

type packetStore struct{ host plugin.Host }

func (s *packetStore) SaveBatch(_ context.Context, captureID string, packets []storage.PacketRecord) error {
	return s.host.PacketSaveBatch(captureID, packets)
}

func (s *packetStore) ListByCapture(_ context.Context, captureID string, page storage.Page) (*storage.PageResult[storage.PacketRecord], error) {
	res := s.host.PacketList(captureID, page)
	return &storage.PageResult[storage.PacketRecord]{Items: res.Items, Total: res.Total}, nil
}

func (s *packetStore) Count(_ context.Context, captureID string) (int, error) {
	return s.host.PacketCount(captureID), nil
}

func (s *packetStore) DeleteByCapture(_ context.Context, captureID string) error {
	return s.host.PacketDelete(captureID)
}
