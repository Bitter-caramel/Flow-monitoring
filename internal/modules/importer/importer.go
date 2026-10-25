package importer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/kernel/storage"
	"flow-monitoring/internal/modules/packetstore"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// Importer 流量导入器。
type Importer struct {
	store *packetstore.Store
}

// New 创建 Importer。
func New(store *packetstore.Store) *Importer {
	return &Importer{store: store}
}

// Import 导入一个 pcapng 文件。
//
// 流程：
//  1. 检查魔数（pcapng 解析器会校验）
//  2. pcapng.Parse 容器解析
//  3. decoder.Decode 逐包协议解码
//  4. 转 storage.PacketRecord
//  5. packetstore.SaveCapture 落库
//
// id 为空时按文件内容 SHA-256 生成（相同文件幂等）。
// 返回 CaptureRecord（含文件路径、sha256、包数）。
func (i *Importer) Import(ctx context.Context, id, name string, data []byte) (*storage.CaptureRecord, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("importer: empty file")
	}

	// 1. 容器解析
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		return nil, fmt.Errorf("importer: parse pcapng: %w", err)
	}

	// 2. 协议解码 + 转 PacketRecord
	packets := make([]storage.PacketRecord, 0, len(cap.Packets))
	for _, p := range cap.Packets {
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		packets = append(packets, toPacketRecord(p))
	}

	// 3. id 生成（幂等）
	if id == "" {
		id = genID(data)
	}

	// 4. 落库
	rec, err := i.store.SaveCapture(ctx, id, name, cap.LinkType, data, packets)
	if err != nil {
		return nil, fmt.Errorf("importer: save capture: %w", err)
	}
	return rec, nil
}

// toPacketRecord 把 datamodel.Packet 转 storage.PacketRecord（元数据）。
func toPacketRecord(p *datamodel.Packet) storage.PacketRecord {
	return storage.PacketRecord{
		No:      p.No,
		Time:    p.Time,
		SrcIP:   p.SrcIP,
		DstIP:   p.DstIP,
		SrcPort: p.SrcPort,
		DstPort: p.DstPort,
		Proto:   p.Proto,
		Info:    p.Info,
		CapLen:  p.CapLen,
		OrigLen: p.OrigLen,
		Offset:  p.Offset,
	}
}

// genID 按文件内容 SHA-256 生成 capture ID（取前 16 字节）。
func genID(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}
