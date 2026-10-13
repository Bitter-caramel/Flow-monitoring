package collect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/alert"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// newPkt 造一个带确定性字节模式的原始包（No/Time/Data 都设置好，便于去重与比对）。
func newPkt(no int, t time.Time, size int) *datamodel.Packet {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte((no*31 + i) % 251)
	}
	return &datamodel.Packet{No: no, Time: t, Data: data}
}

// windowPackets 返回 all 里时间落在 [from,to]（闭区间）的包，保持原顺序。
func windowPackets(all []*datamodel.Packet, from, to time.Time) []*datamodel.Packet {
	var out []*datamodel.Packet
	for _, p := range all {
		if !p.Time.Before(from) && !p.Time.After(to) {
			out = append(out, p)
		}
	}
	return out
}

// parseEvidence 用标准 pcapng.Parse 读回证据文件，返回 Capture 与原始字节。
func parseEvidence(t *testing.T, path string) (*datamodel.Capture, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence %s: %v", path, err)
	}
	cap, err := pcapng.Parse(raw, 0)
	if err != nil {
		t.Fatalf("parse evidence %s: %v", path, err)
	}
	return cap, raw
}

// loadMeta 读回证据边车 <path 去掉 .pcapng>.json。
func loadMeta(t *testing.T, pcapPath string) EvidenceMeta {
	t.Helper()
	metaPath := strings.TrimSuffix(pcapPath, ".pcapng") + ".json"
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read evidence meta %s: %v", metaPath, err)
	}
	var m EvidenceMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal evidence meta %s: %v", metaPath, err)
	}
	return m
}

// TestEvidenceDiskComplete 守的是"磁盘完整覆盖窗口时只读磁盘、零合并"：
// 产出 1 个文件、Sources==["disk"]、Incomplete==false、帧数为窗口内真实帧数、时间升序、字节正确。
func TestEvidenceDiskComplete(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{RootDir: root, CaptureID: "cap1", LinkType: 1, SegmentBytes: 200, RetentionSegments: 100})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	var all []*datamodel.Packet
	for i := 0; i < 41; i++ {
		p := newPkt(i+1, base.Add(time.Duration(i)*200*time.Millisecond), 50)
		all = append(all, p)
		if err := store.Write(p); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	alertT := base.Add(4 * time.Second)
	ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1,
		Window: time.Second, MaxBytes: 1 << 20,
	}, ring, store)

	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "r1", Name: "rule one", Time: alertT, PktNo: 21, FlowKey: "k"}})
	files, err := coll.Tick(alertT.Add(time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}

	meta := loadMeta(t, files[0])
	if !reflect.DeepEqual(meta.Sources, []string{"disk"}) {
		t.Fatalf("sources=%v, want [disk]", meta.Sources)
	}
	if meta.Incomplete {
		t.Fatalf("incomplete=%v, want false", meta.Incomplete)
	}

	from, to := alertT.Add(-time.Second), alertT.Add(time.Second)
	want := windowPackets(all, from, to)
	if len(want) == 0 {
		t.Fatal("test setup: empty window")
	}
	if meta.Packets != len(want) {
		t.Fatalf("meta.Packets=%d, want %d", meta.Packets, len(want))
	}

	cap, _ := parseEvidence(t, files[0])
	if len(cap.Packets) != len(want) {
		t.Fatalf("packet count=%d, want %d", len(cap.Packets), len(want))
	}
	for i := 1; i < len(cap.Packets); i++ {
		if cap.Packets[i].Time.Before(cap.Packets[i-1].Time) {
			t.Fatalf("packets not time-ascending at index %d", i)
		}
	}
	for i, p := range cap.Packets {
		if !bytes.Equal(p.Data, want[i].Data) {
			t.Fatalf("packet %d data mismatch", i)
		}
	}
}

// TestEvidenceRingFillsGap 是红线守卫：磁盘被轮转删除覆盖窗口的段后，
// 内存环必须把窗口内的帧补回来 —— 文件仍含完整帧、Sources 含 "ring"、Incomplete==true。
func TestEvidenceRingFillsGap(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{RootDir: root, CaptureID: "cap1", LinkType: 1, SegmentBytes: 200, RetentionSegments: 1})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ring := NewRing(RingOptions{MaxBytes: 4 << 20, Window: time.Hour})
	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	var all []*datamodel.Packet
	for i := 0; i < 41; i++ {
		p := newPkt(i+1, base.Add(time.Duration(i)*200*time.Millisecond), 50)
		all = append(all, p)
		if err := store.Write(p); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
		ring.Add(p) // 这些包同时进内存环，作为磁盘缺口的补丁
	}

	// 确认磁盘确实发生了轮转删除（否则本测试失去意义）。
	deleted := false
	for _, s := range store.Segments() {
		if s.Deleted {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("test setup: expected disk rotation to delete segments, got %+v", store.Segments())
	}

	alertT := base.Add(4 * time.Second)
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1,
		Window: 5 * time.Second, MaxBytes: 1 << 20,
	}, ring, store)
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "r1", Name: "rule one", Time: alertT, PktNo: 21}})
	files, err := coll.Tick(alertT.Add(6 * time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}

	meta := loadMeta(t, files[0])
	if !meta.Incomplete {
		t.Fatalf("incomplete=%v, want true (disk could not prove full coverage)", meta.Incomplete)
	}
	foundRing := false
	for _, s := range meta.Sources {
		if s == "ring" {
			foundRing = true
		}
	}
	if !foundRing {
		t.Fatalf("sources=%v, want contain ring", meta.Sources)
	}

	from, to := alertT.Add(-5*time.Second), alertT.Add(5*time.Second)
	want := windowPackets(all, from, to)
	cap, _ := parseEvidence(t, files[0])
	if len(cap.Packets) != len(want) {
		t.Fatalf("packet count=%d, want %d (ring must fill the disk gap)", len(cap.Packets), len(want))
	}
}

// TestEvidenceBothEmpty 守的是"两侧都没数据"时仍产出文件，且 Incomplete==true、Reason 非空。
func TestEvidenceBothEmpty(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{RootDir: root, CaptureID: "cap1", LinkType: 1})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	ring := NewRing(RingOptions{})

	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1, Window: time.Second,
	}, ring, store)
	alertT := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "r1", Time: alertT}})
	files, err := coll.Tick(alertT.Add(time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}
	if _, err := os.Stat(files[0]); err != nil {
		t.Fatalf("evidence file should exist: %v", err)
	}
	meta := loadMeta(t, files[0])
	if !meta.Incomplete {
		t.Fatalf("incomplete=%v, want true", meta.Incomplete)
	}
	if meta.Reason == "" {
		t.Fatalf("reason should explain empty data, got empty")
	}
	if meta.Packets != 0 {
		t.Fatalf("packets=%d, want 0", meta.Packets)
	}
}

// TestEvidenceMergesAlerts 守的是"窗口重叠的告警合并成一份证据"：
// 一次 Tick 只产出 1 个文件，边车 Alerts 有 2 条，文件名用第一条告警的 RuleID。
func TestEvidenceMergesAlerts(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{RootDir: root, CaptureID: "cap1", LinkType: 1, SegmentBytes: 1 << 20, RetentionSegments: 100})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	for i := 0; i < 30; i++ {
		if err := store.Write(newPkt(i+1, base.Add(time.Duration(i)*200*time.Millisecond), 40)); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}

	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1, Window: 5 * time.Second,
	}, nil, store)
	t1 := base.Add(2 * time.Second)
	t2 := base.Add(3 * time.Second)
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "alpha", Name: "a", Time: t1, PktNo: 11}})
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "beta", Name: "b", Time: t2, PktNo: 16}})

	files, err := coll.Tick(t2.Add(6 * time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("overlapping windows should yield 1 file, got %d (%v)", len(files), files)
	}
	if !strings.Contains(filepath.Base(files[0]), "alpha") {
		t.Fatalf("filename %q should contain first alert RuleID %q", filepath.Base(files[0]), "alpha")
	}
	meta := loadMeta(t, files[0])
	if len(meta.Alerts) != 2 {
		t.Fatalf("meta.Alerts=%d, want 2", len(meta.Alerts))
	}
	if meta.Alerts[0].RuleID != "alpha" {
		t.Fatalf("first alert RuleID=%q, want alpha", meta.Alerts[0].RuleID)
	}
}

// TestEvidenceWindowNotDue 守的是"窗口未到期时 Tick 不产出任何文件"。
func TestEvidenceWindowNotDue(t *testing.T) {
	root := t.TempDir()
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1, Window: 5 * time.Second,
	}, nil, nil)
	t0 := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "r1", Time: t0}})

	files, err := coll.Tick(t0) // 窗口终点是 t0+5s，此刻尚未到期
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("want 0 files before window due, got %v", files)
	}
}

// TestEvidenceFileReadable 守的是"产出文件可被标准 pcapng.Parse 读回，包数与字节完全一致"。
func TestEvidenceFileReadable(t *testing.T) {
	root := t.TempDir()
	store, err := Open(Options{RootDir: root, CaptureID: "cap1", LinkType: 1, SegmentBytes: 200, RetentionSegments: 100})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	var all []*datamodel.Packet
	for i := 0; i < 41; i++ {
		p := newPkt(i+1, base.Add(time.Duration(i)*200*time.Millisecond), 50)
		all = append(all, p)
		if err := store.Write(p); err != nil {
			t.Fatalf("write packet %d: %v", i, err)
		}
	}
	// 故意先 Close：验证"store 已 Close 过也能正常读"。
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	alertT := base.Add(4 * time.Second)
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(root, "evidence"), CaptureID: "cap1", LinkType: 1, Window: time.Second,
	}, nil, store)
	coll.OnAlert(alert.Event{Alert: detect.Alert{RuleID: "r1", Time: alertT}})
	files, err := coll.Tick(alertT.Add(time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}

	meta := loadMeta(t, files[0])
	cap, raw := parseEvidence(t, files[0])
	if int64(len(raw)) != meta.Bytes {
		t.Fatalf("meta.Bytes=%d, actual file size=%d", meta.Bytes, len(raw))
	}
	if len(cap.Packets) != meta.Packets {
		t.Fatalf("parsed packets=%d, meta.Packets=%d", len(cap.Packets), meta.Packets)
	}

	from, to := alertT.Add(-time.Second), alertT.Add(time.Second)
	want := windowPackets(all, from, to)
	wantBytes := 0
	for _, p := range want {
		wantBytes += len(p.Data)
	}
	gotBytes := 0
	for _, p := range cap.Packets {
		gotBytes += p.CapLen
	}
	if gotBytes != wantBytes {
		t.Fatalf("captured bytes=%d, want %d", gotBytes, wantBytes)
	}
}
