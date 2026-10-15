package collect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// newConnPkt 造一个带连接端点的确定性包（便于按连接键分组）。
func newConnPkt(no int, t time.Time, size int, srcIP string, srcPort uint16, dstIP string, dstPort uint16) *datamodel.Packet {
	p := newPkt(no, t, size)
	p.SrcIP, p.SrcPort, p.DstIP, p.DstPort = srcIP, srcPort, dstIP, dstPort
	return p
}

// sliceHas 判断 []string 里是否含 want。
func sliceHas(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestEvidenceRingConnWholeConnection 守的是 11-7c-1 的新语义：
// 证据在时间窗之外，还要带上告警连接的**整条连接**（环里全部帧），且不夹带其它连接。
func TestEvidenceRingConnWholeConnection(t *testing.T) {
	base := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 4 << 20, Window: time.Hour})

	keyA := datamodel.ConnKey("10.0.0.1", 1111, "10.0.0.2", 80)
	// 目标连接 A：窗口外（1s / 9s）也在环里；6s 为反向，连接键仍相同。
	aFrames := []*datamodel.Packet{
		newConnPkt(1, base.Add(1*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80),
		newConnPkt(2, base.Add(4*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80),
		newConnPkt(3, base.Add(6*time.Second), 40, "10.0.0.2", 80, "10.0.0.1", 1111),
		newConnPkt(4, base.Add(9*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80),
	}
	// 另一条连接 B：全部落在窗口 [base+3s, base+7s] 之外；只有“整条连接”逻辑才可能带入它。
	bFrames := []*datamodel.Packet{
		newConnPkt(5, base.Add(0*time.Second), 40, "10.9.9.9", 2222, "10.9.9.8", 443),
		newConnPkt(6, base.Add(10*time.Second), 40, "10.9.9.9", 2222, "10.9.9.8", 443),
	}
	for _, p := range aFrames {
		ring.Add(p)
	}
	for _, p := range bFrames {
		ring.Add(p)
	}

	alertT := base.Add(5 * time.Second)
	window := 2 * time.Second
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(t.TempDir(), "evidence"), CaptureID: "cap1", LinkType: 1,
		Window: window, MaxBytes: 1 << 20,
	}, ring, nil)
	coll.OnAlert(alert.Event{Alert: detect.Alert{
		RuleID: "r1", Name: "conn", Time: alertT, PktNo: 2,
		SrcIP: "10.0.0.1", SrcPort: 1111, DstIP: "10.0.0.2", DstPort: 80,
	}})
	files, err := coll.Tick(alertT.Add(window))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}

	meta := loadMeta(t, files[0])
	if len(meta.ConnKeys) != 1 || meta.ConnKeys[0] != keyA {
		t.Fatalf("meta.ConnKeys=%v, want [%s]", meta.ConnKeys, keyA)
	}
	if !sliceHas(meta.Sources, "ring-conn") {
		t.Fatalf("sources=%v, want contain ring-conn", meta.Sources)
	}

	cap, _ := parseEvidence(t, files[0])
	if len(cap.Packets) != len(aFrames) {
		t.Fatalf("packets=%d, want %d (whole connection A)", len(cap.Packets), len(aFrames))
	}
	// aFrames 已按时间升序；证据也应升序且逐帧字节一致。
	for i := range aFrames {
		if !bytes.Equal(cap.Packets[i].Data, aFrames[i].Data) {
			t.Fatalf("packet %d: whole-connection frame mismatch", i)
		}
	}
	// 明确断言不含连接 B 的帧。
	for _, bf := range bFrames {
		for _, gp := range cap.Packets {
			if bytes.Equal(gp.Data, bf.Data) {
				t.Fatalf("evidence must not contain connection B frame no=%d", bf.No)
			}
		}
	}
}

// TestEvidenceConnKeySymmetric 守的是边车里连接信息的正确性：
// 同一连接的两个方向得到**同一个** ConnKey；ConnKeys 只含该连接；Sources 含 ring-conn。
func TestEvidenceConnKeySymmetric(t *testing.T) {
	base := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 4 << 20, Window: time.Hour})
	ring.Add(newConnPkt(1, base.Add(4*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
	ring.Add(newConnPkt(2, base.Add(6*time.Second), 40, "10.0.0.2", 80, "10.0.0.1", 1111))

	wantKey := datamodel.ConnKey("10.0.0.1", 1111, "10.0.0.2", 80)
	coll := NewEvidence(EvidenceOptions{
		Dir: filepath.Join(t.TempDir(), "evidence"), CaptureID: "cap1", LinkType: 1,
		Window: 2 * time.Second, MaxBytes: 1 << 20,
	}, ring, nil)
	// 两个方向、同一时刻：窗口重叠 -> 合并到同一窗口。
	coll.OnAlert(alert.Event{Alert: detect.Alert{
		RuleID: "a", Name: "fwd", Time: base.Add(5 * time.Second), PktNo: 1,
		SrcIP: "10.0.0.1", SrcPort: 1111, DstIP: "10.0.0.2", DstPort: 80,
	}})
	coll.OnAlert(alert.Event{Alert: detect.Alert{
		RuleID: "b", Name: "rev", Time: base.Add(5 * time.Second), PktNo: 2,
		SrcIP: "10.0.0.2", SrcPort: 80, DstIP: "10.0.0.1", DstPort: 1111,
	}})
	files, err := coll.Tick(base.Add(7 * time.Second))
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("overlapping alerts should merge to 1 file, got %d (%v)", len(files), files)
	}
	meta := loadMeta(t, files[0])
	if len(meta.Alerts) != 2 {
		t.Fatalf("meta.Alerts=%d, want 2", len(meta.Alerts))
	}
	for i, a := range meta.Alerts {
		if a.ConnKey == "" {
			t.Fatalf("alert %d ConnKey empty", i)
		}
		if a.ConnKey != wantKey {
			t.Fatalf("alert %d ConnKey=%q, want %q", i, a.ConnKey, wantKey)
		}
	}
	if meta.Alerts[0].ConnKey != meta.Alerts[1].ConnKey {
		t.Fatalf("两个方向的 ConnKey 不一致: %q vs %q", meta.Alerts[0].ConnKey, meta.Alerts[1].ConnKey)
	}
	if len(meta.ConnKeys) != 1 || meta.ConnKeys[0] != wantKey {
		t.Fatalf("meta.ConnKeys=%v, want [%s]", meta.ConnKeys, wantKey)
	}
	if !sliceHas(meta.Sources, "ring-conn") {
		t.Fatalf("sources=%v, want contain ring-conn", meta.Sources)
	}
}

// TestEvidenceConnTruncationInference 守的是“如实标注完整性”：
// 目标连接最早帧恰是环里最老帧 -> Incomplete=true 且 Reason 含该连接键；
// 环里还有更早的其它连接帧 -> 不触发该 Reason。
func TestEvidenceConnTruncationInference(t *testing.T) {
	base := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	keyA := datamodel.ConnKey("10.0.0.1", 1111, "10.0.0.2", 80)

	run := func(t *testing.T, withEarlierOther bool) EvidenceMeta {
		t.Helper()
		ring := NewRing(RingOptions{MaxBytes: 4 << 20, Window: time.Hour})
		// A 连接：环内最早帧在 base+1s。
		ring.Add(newConnPkt(1, base.Add(1*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
		ring.Add(newConnPkt(2, base.Add(4*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
		ring.Add(newConnPkt(3, base.Add(6*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
		if withEarlierOther {
			// 另一条连接 C：更早（base+0s）=> 环里可见的最老帧不再是 A 的。
			ring.Add(newConnPkt(9, base.Add(0*time.Second), 40, "10.9.9.9", 2222, "10.9.9.8", 443))
		}
		coll := NewEvidence(EvidenceOptions{
			Dir: filepath.Join(t.TempDir(), "evidence"), CaptureID: "cap1", LinkType: 1,
			Window: 2 * time.Second, MaxBytes: 1 << 20,
		}, ring, nil)
		coll.OnAlert(alert.Event{Alert: detect.Alert{
			RuleID: "r1", Name: "conn", Time: base.Add(5 * time.Second), PktNo: 2,
			SrcIP: "10.0.0.1", SrcPort: 1111, DstIP: "10.0.0.2", DstPort: 80,
		}})
		files, err := coll.Tick(base.Add(7 * time.Second))
		if err != nil {
			t.Fatalf("tick: %v", err)
		}
		if len(files) != 1 {
			t.Fatalf("want 1 file, got %d", len(files))
		}
		return loadMeta(t, files[0])
	}

	// A. 目标连接最早帧 == 环里最老帧 => 标注可能被截断。
	metaA := run(t, false)
	if !metaA.Incomplete {
		t.Fatalf("scenario A: Incomplete=false, want true")
	}
	if !strings.Contains(metaA.Reason, keyA) {
		t.Fatalf("scenario A: Reason=%q, want contain conn key %q", metaA.Reason, keyA)
	}
	if !strings.Contains(metaA.Reason, "更早帧不在内存环") {
		t.Fatalf("scenario A: Reason=%q, want explain truncation", metaA.Reason)
	}

	// B. 环里还有更早的其它连接帧 => 不触发该 Reason。
	metaB := run(t, true)
	if strings.Contains(metaB.Reason, keyA) {
		t.Fatalf("scenario B: Reason=%q must NOT blame conn key %q", metaB.Reason, keyA)
	}
}

// ───────────────────────── 11-7c-2：库侧补齐（全部用假实现） ─────────────────────────

// fakeQuerier 假 FlowQuerier：对任何连接都返回同一批预置结果（本组测试只有一条连接）。
// total 为 0 时取 len(items)（表示"库侧没有更多"）。
type fakeQuerier struct {
	items     []ConnPacket
	total     int
	err       error
	lastLimit int
}

func (f *fakeQuerier) ListByConn(_ context.Context, _, _ Endpoint, limit int) ([]ConnPacket, int, error) {
	f.lastLimit = limit
	if f.err != nil {
		return nil, 0, f.err
	}
	total := f.total
	if total == 0 {
		total = len(f.items)
	}
	return f.items, total, nil
}

// fakeFetcher 假 FrameFetcher：按 (captureID, No) 返回预置帧；未预置的跳过。
type fakeFetcher struct {
	frames map[PacketRef]Frame
	err    error
}

func (f *fakeFetcher) FetchFrames(_ context.Context, refs []PacketRef) ([]Frame, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []Frame
	for _, r := range refs {
		if fr, ok := f.frames[r]; ok {
			out = append(out, fr)
		}
	}
	return out, nil
}

// asFrame 把测试包转成证据帧（深拷贝 Data，避免与测试用例共享底层数组）。
func asFrame(p *datamodel.Packet) Frame {
	return Frame{Time: p.Time, No: p.No, Data: append([]byte(nil), p.Data...)}
}

// dbTestEnv 造"环里只有连接 A 一帧（落在窗口内）+ 一条属于 A 的告警"的最小场景。
// 返回 collector 与"可以 Tick 的时间"（= 告警时间 + 窗口）。
func dbTestEnv(t *testing.T, base time.Time, opts EvidenceOptions, ring *Ring) (*EvidenceCollector, time.Time) {
	t.Helper()
	const window = 2 * time.Second
	alertT := base.Add(5 * time.Second)
	opts.Dir = filepath.Join(t.TempDir(), "evidence")
	opts.CaptureID = "cap1"
	opts.LinkType = 1
	opts.Window = window
	if opts.MaxBytes == 0 {
		opts.MaxBytes = 1 << 20
	}
	coll := NewEvidence(opts, ring, nil)
	coll.OnAlert(alert.Event{Alert: detect.Alert{
		RuleID: "r1", Name: "conn", Time: alertT, PktNo: 2,
		SrcIP: "10.0.0.1", SrcPort: 1111, DstIP: "10.0.0.2", DstPort: 80,
	}})
	return coll, alertT.Add(window)
}

// TestEvidenceDBBackfillAddsFrames 守的是 11-7c-2 的主路径：
// 装上 Querier/Frames 后，库里那些"已出留存窗口"的包会被取回并并入证据，且 Sources 含 "db"。
func TestEvidenceDBBackfillAddsFrames(t *testing.T) {
	base := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	ring.Add(newConnPkt(1, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))

	dbPkt := newConnPkt(100, base.Add(1*time.Second), 48, "10.0.0.1", 1111, "10.0.0.2", 80)
	q := &fakeQuerier{items: []ConnPacket{{CaptureID: "capX", No: 100, Time: dbPkt.Time}}}
	f := &fakeFetcher{frames: map[PacketRef]Frame{{CaptureID: "capX", No: 100}: asFrame(dbPkt)}}

	coll, tickAt := dbTestEnv(t, base, EvidenceOptions{Querier: q, Frames: f}, ring)
	files, err := coll.Tick(tickAt)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("want 1 evidence file, got %d (%v)", len(files), files)
	}

	meta := loadMeta(t, files[0])
	if !sliceHas(meta.Sources, "db") {
		t.Fatalf("sources=%v, want contain db", meta.Sources)
	}
	captured, _ := parseEvidence(t, files[0])
	found := false
	for _, p := range captured.Packets {
		if bytes.Equal(p.Data, dbPkt.Data) {
			found = true
		}
	}
	if !found {
		t.Fatalf("证据里没有库侧帧（No=100/48 字节）：packets=%d", len(captured.Packets))
	}
	if q.lastLimit != 1000 {
		t.Errorf("ListByConn limit = %d, want 1000（dbPageLimit）", q.lastLimit)
	}
}

// TestEvidenceDBBackfillDedupsSameFrame 守的是"库侧帧与环里帧同时间同字节时只算一次"：
// 去重复用既有的 mergeFrames（帧时间 + 帧字节哈希），库侧不得把同一帧记两遍。
func TestEvidenceDBBackfillDedupsSameFrame(t *testing.T) {
	base := time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	same := newConnPkt(7, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80)
	ring.Add(same)

	// 库里返回"同一帧"（同时间、同字节）=> 必须被去重掉。
	q := &fakeQuerier{items: []ConnPacket{{CaptureID: "capX", No: 7, Time: same.Time}}}
	f := &fakeFetcher{frames: map[PacketRef]Frame{{CaptureID: "capX", No: 7}: asFrame(same)}}

	coll, tickAt := dbTestEnv(t, base, EvidenceOptions{Querier: q, Frames: f}, ring)
	files, err := coll.Tick(tickAt)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	meta := loadMeta(t, files[0])
	if meta.Packets != 1 {
		t.Fatalf("meta.Packets = %d, want 1（同一帧被去重，不得记两遍）", meta.Packets)
	}
	captured, _ := parseEvidence(t, files[0])
	if len(captured.Packets) != 1 {
		t.Fatalf("证据里帧数 = %d, want 1", len(captured.Packets))
	}
}

// TestEvidenceDBBackfillIncomplete 守的是"库侧还有更多包未取"要**如实标注**。
func TestEvidenceDBBackfillIncomplete(t *testing.T) {
	base := time.Date(2024, 6, 3, 0, 0, 0, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	ring.Add(newConnPkt(1, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))

	dbPkt := newConnPkt(200, base.Add(1*time.Second), 32, "10.0.0.1", 1111, "10.0.0.2", 80)
	q := &fakeQuerier{items: []ConnPacket{{CaptureID: "capX", No: 200, Time: dbPkt.Time}}, total: 5}
	f := &fakeFetcher{frames: map[PacketRef]Frame{{CaptureID: "capX", No: 200}: asFrame(dbPkt)}}

	coll, tickAt := dbTestEnv(t, base, EvidenceOptions{Querier: q, Frames: f}, ring)
	files, err := coll.Tick(tickAt)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	meta := loadMeta(t, files[0])
	if !meta.Incomplete {
		t.Fatalf("Incomplete=false, want true（total=5 但只取到 1 条）")
	}
	if !strings.Contains(meta.Reason, "库里还有更多包未取") {
		t.Fatalf("Reason=%q, want mention 库里还有更多包未取", meta.Reason)
	}
}

// TestEvidenceDBBackfillErrorsDoNotFail 守的是"库侧出错不让整次取证失败"：
// 查库失败与取帧失败都只记进 Reason/Incomplete，仍要产出证据文件。
func TestEvidenceDBBackfillErrorsDoNotFail(t *testing.T) {
	base := time.Date(2024, 6, 4, 0, 0, 0, 0, time.UTC)

	t.Run("查库失败", func(t *testing.T) {
		ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
		ring.Add(newConnPkt(1, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
		coll, tickAt := dbTestEnv(t, base, EvidenceOptions{
			Querier: &fakeQuerier{err: errors.New("db down")},
			Frames:  &fakeFetcher{},
		}, ring)
		files, err := coll.Tick(tickAt)
		if err != nil {
			t.Fatalf("查库失败不应让取证失败：%v", err)
		}
		if len(files) != 1 {
			t.Fatalf("want 1 evidence file, got %d", len(files))
		}
		meta := loadMeta(t, files[0])
		if !meta.Incomplete || !strings.Contains(meta.Reason, "查库失败") {
			t.Fatalf("Incomplete=%v Reason=%q, want 标注查库失败", meta.Incomplete, meta.Reason)
		}
		if sliceHas(meta.Sources, "db") {
			t.Fatalf("sources=%v：没有取到任何库侧帧时不应出现 db", meta.Sources)
		}
	})

	t.Run("取帧失败", func(t *testing.T) {
		ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
		ring.Add(newConnPkt(1, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))
		coll, tickAt := dbTestEnv(t, base, EvidenceOptions{
			Querier: &fakeQuerier{items: []ConnPacket{{CaptureID: "capX", No: 9, Time: base.Add(1 * time.Second)}}},
			Frames:  &fakeFetcher{err: errors.New("file missing")},
		}, ring)
		files, err := coll.Tick(tickAt)
		if err != nil {
			t.Fatalf("取帧失败不应让取证失败：%v", err)
		}
		meta := loadMeta(t, files[0])
		if !meta.Incomplete || !strings.Contains(meta.Reason, "取库里的帧失败") {
			t.Fatalf("Incomplete=%v Reason=%q, want 标注取帧失败", meta.Incomplete, meta.Reason)
		}
	})
}

// TestEvidenceNoOptionalDepsUnchanged 守的是"不装可选依赖时行为完全不变"：
// 即使库里有很多包，未装 Querier/Frames 就一个都不取，Sources 里也不会出现 "db"。
func TestEvidenceNoOptionalDepsUnchanged(t *testing.T) {
	base := time.Date(2024, 6, 5, 0, 0, 0, 0, time.UTC)
	ring := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	// 另一条连接更早的一帧：避免触发 11-7c-1 的"可能被截断"推断，让断言更聚焦。
	ring.Add(newConnPkt(90, base.Add(0*time.Second), 40, "10.9.9.9", 2222, "10.9.9.8", 443))
	ring.Add(newConnPkt(1, base.Add(5*time.Second), 40, "10.0.0.1", 1111, "10.0.0.2", 80))

	coll, tickAt := dbTestEnv(t, base, EvidenceOptions{}, ring) // 不装 Querier/Frames
	files, err := coll.Tick(tickAt)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	meta := loadMeta(t, files[0])
	if sliceHas(meta.Sources, "db") {
		t.Fatalf("sources=%v：未装可选依赖时不应出现 db", meta.Sources)
	}
	captured, _ := parseEvidence(t, files[0])
	for _, p := range captured.Packets {
		if len(p.Data) == 48 {
			t.Fatalf("未装可选依赖却出现了库侧帧（48 字节）")
		}
	}
}
