package alert_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"flow-monitoring/internal/hotpath"
	"flow-monitoring/internal/kernel/eventbus"
	"flow-monitoring/internal/modules/alert"
	"flow-monitoring/internal/modules/detect"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// TestE2EAlertToJSONL 验证「pcapng → 解码 → 归流 → 检测 → 事件总线 → 消费者 → JSONL」的告警端到端链路。
func TestE2EAlertToJSONL(t *testing.T) {
	// a) 加载 detect 包提供的端到端规则文件，并构建检测引擎。
	rs, err := detect.LoadFile(filepath.Join("..", "detect", "testdata", "e2e.rules"))
	if err != nil {
		t.Fatalf("加载规则文件失败: %v", err)
	}
	hp := hotpath.New(rs)
	defer hp.Close()

	// b) 读取并解析仓库根 testdata 下的真实样本。
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "test.pcapng"))
	if err != nil {
		t.Fatalf("读取样本文件失败: %v", err)
	}
	cap, err := pcapng.Parse(data, 0)
	if err != nil {
		t.Fatalf("解析 pcapng 失败: %v", err)
	}
	if len(cap.Packets) == 0 {
		t.Fatal("样本中没有数据包（可能样本文件缺失或已损坏）")
	}

	// c) 起真实事件总线 + 真实 FileSink 消费者，把告警落到测试临时目录的 jsonl。
	jsonlPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	bus := eventbus.New()
	defer bus.Close()

	sink, err := alert.NewFileSink(jsonlPath)
	if err != nil {
		t.Fatalf("打开告警落盘文件失败: %v", err)
	}
	cons := alert.NewConsumerFromBus(bus, alert.TopicAlertLifecycle, 4096, sink, alert.ConsumerOptions{})
	defer cons.Close()

	// d) 逐包执行：解码 → 归流 → 检测，并把每条命中发布到真实总线。
	hits := 0
	for _, p := range cap.Packets {
		if p == nil {
			continue
		}
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		for _, h := range hp.Process(p) {
			hits++
			if err := bus.Publish(alert.TopicAlertLifecycle, alert.Event{CaptureID: "e2e", Alert: h}); err != nil {
				t.Fatalf("发布告警失败: %v", err)
			}
		}
	}
	if hits == 0 {
		t.Fatal("命中总数为 0（期望样本至少产生一条告警）")
	}

	// e) 超时轮询等待消费端把全部命中消费完（写入 + 压制），避免死等。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cons.Written()+cons.Suppressed() >= uint64(hits) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// 显式关闭消费者：停止消费并冲刷 sink（Close 幂等，defer 再调安全）。
	if err := cons.Close(); err != nil {
		t.Fatalf("关闭消费者失败: %v", err)
	}

	written := cons.Written()
	suppressed := cons.Suppressed()
	t.Logf("命中总数=%d 写入=%d 压制=%d", hits, written, suppressed)

	// f) 最强守恒式：一条命中要么写入、要么被压制，二者之和必须等于命中总数。
	if written+suppressed != uint64(hits) {
		t.Errorf("写入+压制 != 命中：写入 %d + 压制 %d = %d，命中 %d", written, suppressed, written+suppressed, hits)
	}
	// g) 去重必须生效：样本中同一规则命中同一流的多个包应产生压制。
	if suppressed == 0 {
		t.Error("压制数为 0：期望样本中同一规则命中同一流的多个包被去重")
	}

	// h) 读回 jsonl：行数必须等于消费端 Written()，且每行都是合法 Event。
	f, err := os.Open(jsonlPath)
	if err != nil {
		t.Fatalf("打开 jsonl 失败: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // 告警行含片段，放宽单行上限。
	lines := 0
	for sc.Scan() {
		lines++
		var ev alert.Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Errorf("第 %d 行无法解析为 alert.Event: %v", lines, err)
			continue
		}
		if ev.Alert.RuleID == "" {
			t.Errorf("第 %d 行 RuleID 为空", lines)
		}
		if ev.Alert.PktNo == 0 {
			t.Errorf("第 %d 行 PktNo 非正: %d", lines, ev.Alert.PktNo)
		}
		if !strings.HasSuffix(ev.Alert.FlowKey, "/tcp") {
			t.Errorf("第 %d 行 FlowKey 不以 /tcp 结尾: %q", lines, ev.Alert.FlowKey)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("扫描 jsonl 失败: %v", err)
	}

	if uint64(lines) != written {
		t.Errorf("jsonl 行数 != Written()：行数 %d，写入 %d", lines, written)
	}
}
