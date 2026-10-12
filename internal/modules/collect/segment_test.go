package collect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// openTestStore 打开一个测试用留存库，并在测试结束时兜底关闭。
func openTestStore(t *testing.T, opts Options) *SegmentStore {
	t.Helper()
	s, err := Open(opts)
	if err != nil {
		t.Fatalf("Open(%+v): %v", opts, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// writeTestPackets 顺序写入 n 个定长包，包时间从 base 起每秒一个。
func writeTestPackets(t *testing.T, s *SegmentStore, base time.Time, n, size int) {
	t.Helper()
	for i := 0; i < n; i++ {
		data := bytes.Repeat([]byte{byte(i%251 + 1)}, size)
		p := &datamodel.Packet{
			No:   i + 1,
			Time: base.Add(time.Duration(i) * time.Second),
			Data: data,
		}
		if err := s.Write(p); err != nil {
			t.Fatalf("Write(No=%d): %v", p.No, err)
		}
	}
}

// segmentFiles 返回目录下所有 .pcapng 文件名（升序）。
func segmentFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".pcapng") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// parseSegmentFile 用 pcapng.Parse 把一个段文件读回成 Capture。
func parseSegmentFile(t *testing.T, path string) *datamodel.Capture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	cp, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("pcapng.Parse(%s): %v", path, err)
	}
	return cp
}

// readIndexLines 读 index.jsonl 并逐行解析为 SegmentInfo。
func readIndexLines(t *testing.T, dir string) []SegmentInfo {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "index.jsonl"))
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	text := strings.TrimRight(string(data), "\n")
	if text == "" {
		return nil
	}
	var out []SegmentInfo
	for i, line := range strings.Split(text, "\n") {
		var info SegmentInfo
		if err := json.Unmarshal([]byte(line), &info); err != nil {
			t.Fatalf("索引第 %d 行不是合法 JSON: %v (line=%q)", i+1, err, line)
		}
		out = append(out, info)
	}
	return out
}

// fileSize 返回文件的字节数。
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	return st.Size()
}

// TestSegmentRotation 验证定长轮转：多段、命名规则、整包不拆、段大小阈值。
func TestSegmentRotation(t *testing.T) {
	root := t.TempDir()
	opts := Options{RootDir: root, CaptureID: "run", LinkType: 1, SegmentBytes: 512}
	s := openTestStore(t, opts)

	base := time.Date(2026, 10, 12, 20, 15, 30, 0, time.UTC)
	const n = 5
	writeTestPackets(t, s, base, n, 300)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dir := filepath.Join(root, "run")
	segs := s.Segments()

	// ① 产生多段。
	if len(segs) < 2 {
		t.Fatalf("期望产生多段，实际 %d 段", len(segs))
	}

	// ② 段文件名序号连续、零填充、含起始时间；③ 每段回读都是完整包。
	var totalPkts int64
	for i, seg := range segs {
		wantNo := int64(i + 1)
		if seg.No != wantNo {
			t.Fatalf("第 %d 段 No=%d，期望 %d", i+1, seg.No, wantNo)
		}
		wantName := fmt.Sprintf("run-%06d-%s.pcapng", wantNo, seg.StartTime.Format("20060102T150405"))
		if seg.Name != wantName {
			t.Fatalf("第 %d 段名 %q，期望 %q", i+1, seg.Name, wantName)
		}

		path := filepath.Join(dir, seg.Name)
		cp := parseSegmentFile(t, path)
		if int64(len(cp.Packets)) != seg.Packets {
			t.Fatalf("段 %s 解析出 %d 包，索引记录 %d 包", seg.Name, len(cp.Packets), seg.Packets)
		}
		for _, p := range cp.Packets {
			if len(p.Data) != 300 {
				t.Fatalf("段 %s 出现半包：包长 %d，期望 300", seg.Name, len(p.Data))
			}
		}
		totalPkts += int64(len(cp.Packets))
		if got := fileSize(t, path); got != seg.Bytes {
			t.Fatalf("段 %s 实际大小 %d，索引记录 %d", seg.Name, got, seg.Bytes)
		}
	}
	if totalPkts != n {
		t.Fatalf("各段包数之和 %d，期望 %d", totalPkts, n)
	}

	// ④ 除最后一段（正在写的）外，其余都不小于阈值。
	for i := 0; i < len(segs)-1; i++ {
		if segs[i].Bytes < opts.SegmentBytes {
			t.Fatalf("第 %d 段大小 %d 小于阈值 %d", i+1, segs[i].Bytes, opts.SegmentBytes)
		}
	}

	// 首段起始时间 = 首包时间；名字符合 run-000001-20261012T201530.pcapng。
	if !segs[0].StartTime.Equal(base) {
		t.Fatalf("首段起始时间 %v，期望 %v", segs[0].StartTime, base)
	}
	if segs[0].Name != "run-000001-20261012T201530.pcapng" {
		t.Fatalf("首段名 %q，期望 run-000001-20261012T201530.pcapng", segs[0].Name)
	}
}

// TestSegmentIndex 验证 index.jsonl 每行都是合法 JSON 且各字段正确。
func TestSegmentIndex(t *testing.T) {
	root := t.TempDir()
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1, SegmentBytes: 512})

	base := time.Date(2026, 10, 12, 20, 15, 30, 0, time.UTC)
	writeTestPackets(t, s, base, 5, 300)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dir := filepath.Join(root, "run")
	segs := s.Segments()
	lines := readIndexLines(t, dir)
	if len(lines) != len(segs) {
		t.Fatalf("索引行数 %d，期望 %d", len(lines), len(segs))
	}
	for i, got := range lines {
		want := segs[i]
		if got.No != want.No || got.Name != want.Name || got.Bytes != want.Bytes ||
			got.Packets != want.Packets || got.Deleted != want.Deleted ||
			!got.StartTime.Equal(want.StartTime) || !got.EndTime.Equal(want.EndTime) {
			t.Fatalf("索引第 %d 行 = %+v，期望 %+v", i+1, got, want)
		}
	}

	// 抽查首段：2 包、字节等于文件大小、时间区间正确。
	first := lines[0]
	if first.Packets != 2 {
		t.Fatalf("首段包数 %d，期望 2", first.Packets)
	}
	if first.Name != "run-000001-20261012T201530.pcapng" {
		t.Fatalf("首段名 %q", first.Name)
	}
	if got := fileSize(t, filepath.Join(dir, first.Name)); got != first.Bytes {
		t.Fatalf("首段字节 %d，期望 %d", first.Bytes, got)
	}
	if !first.StartTime.Equal(base) {
		t.Fatalf("首段 StartTime %v，期望 %v", first.StartTime, base)
	}
	if !first.EndTime.Equal(base.Add(time.Second)) {
		t.Fatalf("首段 EndTime %v，期望 %v", first.EndTime, base.Add(time.Second))
	}
}

// TestRetentionBySegments 验证按段数保留：超限时从最老段删文件并追加 Deleted 行。
func TestRetentionBySegments(t *testing.T) {
	root := t.TempDir()
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1,
		SegmentBytes: 512, RetentionSegments: 2})

	base := time.Date(2026, 10, 12, 20, 15, 30, 0, time.UTC)
	writeTestPackets(t, s, base, 7, 300) // 2 包/段 -> 共 4 段
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dir := filepath.Join(root, "run")
	files := segmentFiles(t, dir)
	if len(files) != 2 {
		t.Fatalf("磁盘上段文件 %v，期望 2 个", files)
	}

	segs := s.Segments()
	live := 0
	deleted := map[int64]bool{}
	for _, seg := range segs {
		if seg.Deleted {
			deleted[seg.No] = true
		} else {
			live++
		}
	}
	if live != 2 {
		t.Fatalf("存活段 %d，期望 2", live)
	}
	if !deleted[1] || !deleted[2] {
		t.Fatalf("期望最老的两段(No=1,2)被删，实际删除集合 %v", deleted)
	}

	// 索引里必须有 Deleted:true 的追加行。
	mark := map[int64]bool{}
	for _, line := range readIndexLines(t, dir) {
		if line.Deleted {
			mark[line.No] = true
		}
	}
	if !mark[1] || !mark[2] {
		t.Fatalf("索引缺少 No=1/2 的 Deleted 标记：%v", mark)
	}
}

// TestRetentionByBytes 验证按总字节保留：删除后存活段总字节降到阈值内。
func TestRetentionByBytes(t *testing.T) {
	root := t.TempDir()
	const limit = int64(1500)
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1,
		SegmentBytes: 512, RetentionBytes: limit})

	base := time.Date(2026, 10, 12, 20, 15, 30, 0, time.UTC)
	writeTestPackets(t, s, base, 5, 300) // 2 包/段 -> 3 段
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var liveBytes int64
	var live, dead int
	for _, seg := range s.Segments() {
		if seg.Deleted {
			dead++
			continue
		}
		liveBytes += seg.Bytes
		live++
	}
	if liveBytes > limit {
		t.Fatalf("存活总字节 %d 超过阈值 %d", liveBytes, limit)
	}
	if dead == 0 {
		t.Fatalf("期望发生删除，但没有任何段被删")
	}
	if live == 0 {
		t.Fatalf("期望至少保留 1 段")
	}

	// 磁盘实际内容与存活的段一致，且总字节也在阈值内。
	dir := filepath.Join(root, "run")
	files := segmentFiles(t, dir)
	if len(files) != live {
		t.Fatalf("磁盘段文件 %d 个，存活段 %d 个", len(files), live)
	}
	var diskBytes int64
	for _, name := range files {
		diskBytes += fileSize(t, filepath.Join(dir, name))
	}
	if diskBytes > limit {
		t.Fatalf("磁盘段总字节 %d 超过阈值 %d", diskBytes, limit)
	}
}

// TestSegmentRoundTrip 验证写出的段读回后逐包字节与顺序完全一致。
func TestSegmentRoundTrip(t *testing.T) {
	root := t.TempDir()
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1, SegmentBytes: 512})

	base := time.Date(2026, 10, 12, 20, 15, 30, 0, time.UTC)
	lengths := []int{7, 64, 300, 1, 1000, 250}
	var expected [][]byte
	for i, ln := range lengths {
		data := make([]byte, ln)
		for j := range data {
			data[j] = byte((i*31 + j) % 251)
		}
		expected = append(expected, data)
		p := &datamodel.Packet{
			No:   i + 1,
			Time: base.Add(time.Duration(i) * time.Millisecond),
			Data: data,
		}
		if err := s.Write(p); err != nil {
			t.Fatalf("Write(No=%d): %v", p.No, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dir := filepath.Join(root, "run")
	var got [][]byte
	for _, seg := range s.Segments() {
		cp := parseSegmentFile(t, filepath.Join(dir, seg.Name))
		for _, p := range cp.Packets {
			got = append(got, p.Data)
		}
	}
	if len(got) != len(expected) {
		t.Fatalf("读回 %d 包，期望 %d 包", len(got), len(expected))
	}
	for i := range expected {
		if !bytes.Equal(got[i], expected[i]) {
			t.Fatalf("第 %d 包字节不一致：读回 %d 字节，期望 %d 字节", i, len(got[i]), len(expected[i]))
		}
	}
}

// TestWriteIgnoresEmptyPacket 验证 nil / 空 Data 包被忽略且磁盘不产生多余内容。
func TestWriteIgnoresEmptyPacket(t *testing.T) {
	root := t.TempDir()
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1})

	if err := s.Write(nil); err != nil {
		t.Fatalf("Write(nil) = %v，期望 nil", err)
	}
	if err := s.Write(&datamodel.Packet{No: 1}); err != nil {
		t.Fatalf("Write(Data=nil) = %v，期望 nil", err)
	}
	if err := s.Write(&datamodel.Packet{No: 2, Data: []byte{}}); err != nil {
		t.Fatalf("Write(Data=空切片) = %v，期望 nil", err)
	}

	if got := s.CurrentName(); got != "" {
		t.Fatalf("CurrentName() = %q，期望空串", got)
	}
	if segs := s.Segments(); len(segs) != 0 {
		t.Fatalf("Segments() = %v，期望空", segs)
	}

	dir := filepath.Join(root, "run")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	if len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("空包在磁盘上留下了内容：%v", names)
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRetentionByHours 验证按小时保留：超出保留窗口的旧段被删除。
func TestRetentionByHours(t *testing.T) {
	root := t.TempDir()
	s := openTestStore(t, Options{RootDir: root, CaptureID: "run", LinkType: 1,
		SegmentBytes: 512, RetentionHours: 1})

	now := time.Now()
	old := now.Add(-3 * time.Hour)
	// 用旧时间写 2 段（2 包/段），它们都应被删除。
	for i := 0; i < 4; i++ {
		data := bytes.Repeat([]byte{0xAB}, 300)
		p := &datamodel.Packet{No: i + 1, Time: old.Add(time.Duration(i) * time.Second), Data: data}
		if err := s.Write(p); err != nil {
			t.Fatalf("Write(old No=%d): %v", p.No, err)
		}
	}
	// 用当前时间写 1 段，它应被保留。
	for i := 0; i < 2; i++ {
		data := bytes.Repeat([]byte{0xCD}, 300)
		p := &datamodel.Packet{No: 100 + i, Time: now.Add(time.Duration(i) * time.Second), Data: data}
		if err := s.Write(p); err != nil {
			t.Fatalf("Write(now No=%d): %v", p.No, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var live, dead int
	cutoff := time.Now().Add(-time.Hour)
	for _, seg := range s.Segments() {
		if seg.Deleted {
			dead++
			continue
		}
		live++
		if seg.StartTime.Before(cutoff) {
			t.Fatalf("存活段 %d 起始时间 %v 已超出保留窗口 %v", seg.No, seg.StartTime, cutoff)
		}
	}
	if live != 1 {
		t.Fatalf("存活段 %d，期望 1", live)
	}
	if dead < 2 {
		t.Fatalf("删除段 %d，期望至少 2", dead)
	}
	if files := segmentFiles(t, filepath.Join(root, "run")); len(files) != 1 {
		t.Fatalf("磁盘段文件 %v，期望 1 个", files)
	}
}
