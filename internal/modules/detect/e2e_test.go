package detect

import (
	"os"
	"path/filepath"
	"testing"

	"flow-monitoring/internal/modules/parse/analyzer"
	"flow-monitoring/internal/modules/parse/decoder"
	"flow-monitoring/internal/modules/parse/pcapng"
)

// TestE2ECaptureToDetect 验证「pcapng → 解码 → 归流 → 检测」的端到端链路：
// 用仓库根 testdata 下的真实样本跑通整条流水线，并断言规则命中情况符合预期
// （命中规则至少命中若干次，永不匹配/端口不匹配的规则零命中）。
func TestE2ECaptureToDetect(t *testing.T) {
	// a) 加载测试规则文件，确认三条规则全部编译成功。
	rs, err := LoadFile(filepath.Join("testdata", "e2e.rules"))
	if err != nil {
		t.Fatalf("加载规则文件失败: %v", err)
	}
	if rs == nil || rs.Report == nil {
		t.Fatal("规则导入结果为 nil（期望获得 RuleSet 及其 Report）")
	}
	if got, want := rs.Report.Compiled, 3; got != want {
		t.Errorf("编译成功规则数不符：期望 %d，实际 %d（报告：%s）", want, got, rs.Report.String())
	}
	if got, want := rs.Report.Failed, 0; got != want {
		t.Errorf("编译失败规则数不符：期望 %d，实际 %d（报告：%s）", want, got, rs.Report.String())
	}

	eng := rs.Engine()

	// b) 读取并解析 pcapng 样本。
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

	az := analyzer.New()

	// c) 逐包执行：解码 → 归流 → 检测，并累计命中统计。
	total := 0
	hitsByRule := make(map[string]int)
	decoded := false
	for _, p := range cap.Packets {
		if p == nil {
			continue
		}
		linkType := cap.LinkType
		if p.Iface >= 0 && p.Iface < len(cap.Ifaces) {
			linkType = cap.Ifaces[p.Iface].LinkType
		}
		decoder.Decode(p, linkType)
		flow := az.FeedFlow(p)
		hits := eng.Match(&Ctx{Pkt: p, Flow: flow})
		total += len(hits)
		for _, h := range hits {
			hitsByRule[h.RuleID]++
		}
		if p.Proto != "" || p.IPVersion != 0 {
			decoded = true
		}
	}

	// i) 打印排障信息：包数 / 命中总数 / 每条规则命中数。
	t.Logf("包数=%d 命中总数=%d 每条规则命中数=%v", len(cap.Packets), total, hitsByRule)

	// d) 端到端确实产生了命中。
	if total < 5 {
		t.Errorf("命中总数不足：期望 >= 5，实际 %d（每条规则命中数=%v）", total, hitsByRule)
	}

	// e) 通配规则 300001 应命中至少 5 次。
	if got := hitsByRule["suricata-300001"]; got < 5 {
		t.Errorf("规则 suricata-300001 命中次数不足：期望 >= 5，实际 %d（每条规则命中数=%v）", got, hitsByRule)
	}

	// f) 永不匹配与端口不匹配的规则必须零命中（map 取零值即可，不因缺 key 失败）。
	if got := hitsByRule["suricata-300002"]; got != 0 {
		t.Errorf("规则 suricata-300002 不应命中：期望 0，实际 %d（每条规则命中数=%v）", got, hitsByRule)
	}
	if got := hitsByRule["suricata-300003"]; got != 0 {
		t.Errorf("规则 suricata-300003 不应命中：期望 0，实际 %d（每条规则命中数=%v）", got, hitsByRule)
	}

	// g) 所有命中都只能来自 300001：命中规则集合大小必须为 1。
	if len(hitsByRule) != 1 {
		t.Errorf("命中规则数量不符：期望只有 1 条（suricata-300001），实际 %d 条（每条规则命中数=%v）", len(hitsByRule), hitsByRule)
	}

	// h) 解码确实做了事：至少有一个包被填入了协议名或 IP 版本。
	if !decoded {
		t.Error("解码无效：期望至少有一个包 Proto != \"\" 或 IPVersion != 0，实际全部为空")
	}
}
