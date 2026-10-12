package collect

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"flow-monitoring/internal/kernel/datamodel"
)

// newRingTestPacket 构造一个测试用包（Data 由调用方提供，用于验证是否被复制）。
func newRingTestPacket(no int, ts time.Time, data []byte) *datamodel.Packet {
	return &datamodel.Packet{No: no, Time: ts, Data: data}
}

// TestRingWindowEviction 验证按"包时间"推进的时间窗淘汰。
func TestRingWindowEviction(t *testing.T) {
	r := NewRing(RingOptions{Window: time.Second, MaxBytes: 1 << 20})
	base := time.Unix(1700000000, 0)

	// 递增的包时间：base, base+500ms, base+1s, base+1500ms, base+2s。
	for i := 0; i < 5; i++ {
		ts := base.Add(time.Duration(i) * 500 * time.Millisecond)
		r.Add(newRingTestPacket(i, ts, []byte{byte(i)}))
	}

	// 最新帧时间是 base+2s，窗口 1s，因此只应保留 >= base+1s 的帧。
	got := r.Slice(base.Add(-time.Hour), base.Add(time.Hour))
	if len(got) != 3 {
		t.Fatalf("window eviction: got %d frames, want 3", len(got))
	}
	want := []time.Time{
		base.Add(time.Second),
		base.Add(1500 * time.Millisecond),
		base.Add(2 * time.Second),
	}
	for i := range want {
		if !got[i].Time.Equal(want[i]) {
			t.Fatalf("frame %d time = %v, want %v", i, got[i].Time, want[i])
		}
	}
	// 更老的帧不应再出现。
	old := r.Slice(base.Add(-time.Hour), base)
	if len(old) != 0 {
		t.Fatalf("older frames not evicted: got %d", len(old))
	}
	if r.Frames() != 3 {
		t.Fatalf("Frames() = %d, want 3", r.Frames())
	}
}

// TestRingByteCap 验证按字节上限淘汰，且至少保留最后 1 帧。
func TestRingByteCap(t *testing.T) {
	const maxBytes = 200
	r := NewRing(RingOptions{MaxBytes: maxBytes, Window: time.Hour})
	base := time.Unix(1700000000, 0)

	for i := 0; i < 5; i++ {
		data := bytes.Repeat([]byte{byte('a' + i)}, 100)
		r.Add(newRingTestPacket(i, base.Add(time.Duration(i)*time.Second), data))
		if r.Bytes() > maxBytes {
			t.Fatalf("after add %d: Bytes() = %d > %d", i, r.Bytes(), maxBytes)
		}
		if r.Frames() < 1 {
			t.Fatalf("after add %d: no frame kept", i)
		}
	}

	// 至少保留最后 1 帧，并且就是刚加入的那一帧。
	got := r.Slice(base.Add(-time.Hour), base.Add(time.Hour))
	if len(got) == 0 {
		t.Fatal("byte cap dropped every frame")
	}
	if got[len(got)-1].No != 4 {
		t.Fatalf("last frame No = %d, want 4", got[len(got)-1].No)
	}
	if r.Bytes() > maxBytes {
		t.Fatalf("Bytes() = %d > %d", r.Bytes(), maxBytes)
	}

	// 单帧就超过上限时也必须保留这最后 1 帧（允许 Bytes() > MaxBytes）。
	r2 := NewRing(RingOptions{MaxBytes: 10})
	r2.Add(newRingTestPacket(0, base, bytes.Repeat([]byte{'z'}, 100)))
	if r2.Frames() != 1 {
		t.Fatalf("oversized single frame: Frames() = %d, want 1", r2.Frames())
	}
	if r2.Bytes() != 100 {
		t.Fatalf("oversized single frame: Bytes() = %d, want 100", r2.Bytes())
	}
}

// TestRingSliceRange 验证 Slice 的闭区间语义与升序返回。
func TestRingSliceRange(t *testing.T) {
	r := NewRing(RingOptions{Window: time.Hour, MaxBytes: 1 << 20})
	base := time.Unix(1700000000, 0)

	times := []time.Time{
		base,
		base.Add(time.Second),
		base.Add(2 * time.Second),
		base.Add(3 * time.Second),
	}
	for i, ts := range times {
		r.Add(newRingTestPacket(i, ts, []byte("x")))
	}

	// 闭区间 [base+1s, base+2s] 应恰好包含第 2、3 帧（端点命中）。
	got := r.Slice(times[1], times[2])
	if len(got) != 2 {
		t.Fatalf("Slice closed interval: got %d frames, want 2", len(got))
	}
	if !got[0].Time.Equal(times[1]) || !got[1].Time.Equal(times[2]) {
		t.Fatalf("Slice returned wrong frames: %v", got)
	}
	if got[0].No != 1 || got[1].No != 2 {
		t.Fatalf("Slice returned wrong order/No: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Time.Before(got[i-1].Time) {
			t.Fatalf("Slice result not ascending: %v", got)
		}
	}

	// 全量查询也应升序。
	all := r.Slice(base.Add(-time.Hour), base.Add(time.Hour))
	for i := 1; i < len(all); i++ {
		if all[i].Time.Before(all[i-1].Time) {
			t.Fatalf("Slice result not ascending: %v", all)
		}
	}
}

// TestRingCopiesData 验证 Add 复制原始数据、Slice 返回独立副本。
func TestRingCopiesData(t *testing.T) {
	r := NewRing(RingOptions{})
	base := time.Unix(1700000000, 0)
	orig := []byte("original-frame-bytes")
	p := newRingTestPacket(7, base, orig)
	r.Add(p)

	// 原地修改调用方的底层数据，环里应保持加入时的原样。
	for i := range orig {
		orig[i] = 'Z'
	}
	p.Data[0] = 'Y'

	const want = "original-frame-bytes"
	got := r.Slice(base.Add(-time.Second), base.Add(time.Second))
	if len(got) != 1 {
		t.Fatalf("got %d frames, want 1", len(got))
	}
	if string(got[0].Data) != want {
		t.Fatalf("ring stored aliased data: got %q, want %q", got[0].Data, want)
	}

	// 修改 Slice 返回的副本，环内内容不应受影响。
	for i := range got[0].Data {
		got[0].Data[i] = 'Q'
	}
	again := r.Slice(base.Add(-time.Second), base.Add(time.Second))
	if len(again) != 1 {
		t.Fatalf("got %d frames, want 1", len(again))
	}
	if string(again[0].Data) != want {
		t.Fatalf("ring affected by caller mutation: got %q, want %q", again[0].Data, want)
	}
}

// TestRingIgnoresEmpty 验证 nil 包与空数据包被忽略（不占内存）。
func TestRingIgnoresEmpty(t *testing.T) {
	r := NewRing(RingOptions{})
	r.Add(nil)
	r.Add(&datamodel.Packet{Data: nil})
	r.Add(&datamodel.Packet{Data: []byte{}})

	if got := r.Frames(); got != 0 {
		t.Fatalf("Frames() = %d, want 0", got)
	}
	if got := r.Bytes(); got != 0 {
		t.Fatalf("Bytes() = %d, want 0", got)
	}
}

// TestRingConcurrent 验证并发 Add/Slice 不 panic（本包会由 PM 用 -race 复跑）。
func TestRingConcurrent(t *testing.T) {
	r := NewRing(RingOptions{MaxBytes: 8 << 10, Window: time.Second})
	base := time.Unix(1700000000, 0)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 个 goroutine 各加入若干帧。
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				ts := base.Add(time.Duration(g*1000+i) * time.Millisecond)
				r.Add(newRingTestPacket(i, ts, bytes.Repeat([]byte{byte(g)}, 64)))
			}
		}(g)
	}

	// 另一个 goroutine 反复调用 Slice。
	sliceDone := make(chan struct{})
	go func() {
		defer close(sliceDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = r.Slice(base.Add(-time.Hour), base.Add(time.Hour))
			}
		}
	}()

	wg.Wait()
	close(stop)
	<-sliceDone

	if r.Frames() < 1 {
		t.Fatalf("Frames() = %d, want >= 1", r.Frames())
	}
}

// TestRingSliceOutOfOrder 守住"乱序包时间也不能漏帧"：并发生产者会让包时间乱序，
// Slice 必须全量扫描窗口，而不是遇到更晚的帧就提前 break（否则会静默漏帧）。
func TestRingSliceOutOfOrder(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	// 先加入较晚的 A(100s)，再加入较早的 B(5s)，制造包时间乱序。
	r.Add(&datamodel.Packet{Time: base.Add(100 * time.Second), Data: []byte("A")})
	r.Add(&datamodel.Packet{Time: base.Add(5 * time.Second), Data: []byte("B")})

	got := r.Slice(base, base.Add(50*time.Second))
	if len(got) != 1 {
		t.Fatalf("out-of-order slice: got %d frames, want 1 (B must not be dropped)", len(got))
	}
	if !bytes.Equal(got[0].Data, []byte("B")) {
		t.Fatalf("out-of-order slice: Data = %q, want %q", got[0].Data, "B")
	}
}

// TestRingSliceSortedOutput 守住"Slice 返回按包时间升序"：乱序加入也要排好序，
// 时间相同时保持加入顺序以保证输出确定性。
func TestRingSliceSortedOutput(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := NewRing(RingOptions{MaxBytes: 1 << 20, Window: time.Hour})
	// 刻意按 30s、10s、20s 的乱序加入。
	r.Add(&datamodel.Packet{Time: base.Add(30 * time.Second), Data: []byte("t30")})
	r.Add(&datamodel.Packet{Time: base.Add(10 * time.Second), Data: []byte("t10")})
	r.Add(&datamodel.Packet{Time: base.Add(20 * time.Second), Data: []byte("t20")})

	got := r.Slice(base, base.Add(60*time.Second))
	if len(got) != 3 {
		t.Fatalf("sorted output: got %d frames, want 3", len(got))
	}
	wantTimes := []time.Duration{10 * time.Second, 20 * time.Second, 30 * time.Second}
	wantData := []string{"t10", "t20", "t30"}
	for i := range wantTimes {
		if !got[i].Time.Equal(base.Add(wantTimes[i])) {
			t.Fatalf("frame %d time = %v, want %v", i, got[i].Time, base.Add(wantTimes[i]))
		}
		if string(got[i].Data) != wantData[i] {
			t.Fatalf("frame %d Data = %q, want %q", i, got[i].Data, wantData[i])
		}
	}
}
