# TCP 重组（Stream Reassembly）设计

> 版本：v1 ｜ 日期：2026-10-14 ｜ 状态：设计定稿，待实现
> 配套：《检测引擎.md》（缓冲区与匹配语义）、《告警与收集.md》（证据）、《技术决策方法.md》
> 读者：后续开发者 / AI agent

---

## 0. 一句话

**把"单包匹配"升级成"流匹配"** —— 让规则能命中**跨包**特征（如 `GET /admin` 被拆到两个 TCP 段里），
并顺带解锁"**整条连接**"级证据。★ 重组算法**复用 gopacket `reassembly`**，我们只写"存哪儿、给谁看"。

## 1. 为什么现在做

- 检测目前**只能看见完整落在单个包里的特征** ✗ —— 真实攻击（HTTP 请求、上传载荷）**普遍跨包** ⇒ 漏检；
- 9-2 起就为这一刻留好了口子：`Ctx{Pkt, Flow}` **预留 `Stream` 字段**、`Extractor` 返回 `[]byte` 且 **nil = 缓冲区不存在**
  ⇒ **引擎结构一行都不用改** ✓（只多几个缓冲区名字）；
- 有了按流字节流，"整条连接级证据"（10-4 的 P1）也随之解锁 ✓。

## 2. 复用与业界（第 0 步功课）

`github.com/gopacket/gopacket v1.7.4`（社区 fork）自带 `reassembly` 包：

- **单向**重组；调用方把 TCP 包喂给 `Assembler`；
- `StreamPool`（并发安全）持有在重组中的流；**`StreamFactory` / `Stream` 由我们实现**
  —— ★ 即"**数据怎么存、存多少，是我们的责任**"；
- 附带 `TCPSimpleFSM`（状态机）、`TCPOptionCheck`、`TCPAssemblyStats`（含 gap/跳过统计）；
- 语义对齐对象是 **Suricata**（我们的规则就是从它导入的 ✓）。

## 3. 接入点与数据流

```
收包 → 解码 → 留存/喂环 → 归流 → ★【TCP 重组】→ 检测 → 命中
```

- 新增模块 **`internal/modules/reassembly`**（职责单一，不并进 analyzer ✓）；
- 每个包：先 `analyzer.FeedFlow`（拿 `StreamID`/方向 ✓）→ 再喂重组器 → 检测时把"该流该方向已重组的字节"放进 `Ctx.Stream`。

## 4. ★ 匹配语义（本设计最关键的决定）

| 缓冲名 | 含义 |
|---|---|
| **`stream`** ★ 新增，**TCP 规则的默认粘性缓冲** | **该包所在方向**的已重组字节（"这个包往哪走，就看哪个方向"） |
| `payload` / `pkt_data` | **单个包**的载荷（语义不变） |
| http_uri / http_header / dns_query / tls_sni … | 不变（L7 层，单包） |

- **默认粘性缓冲按规则协议决定**：`alert tcp ...` → 默认 **`stream`**；
  其它协议（udp/icmp）→ 默认仍是 **`payload`** ✓（**与 Suricata 一致** ✓）。
- ★ 这条**改变了现有 TCP 规则的行为** ⇒ **必须同时补 9-6b 的引擎级 golden** 把变化锁住 ✓。
- P1 升级：等 `flow:to_server` / `flow:to_client` 落地后，再把 `stream` 拆成按方向显式指定的缓冲
  （现在用"包自身方向"是最简单且不会猜错的语义 ✓）。

## 5. `Ctx.Stream` 与新提取器

```go
// detect 侧只依赖这个小接口（由 reassembly 模块实现），不认识 gopacket。
type StreamView interface {
    // BytesToServer / BytesToClient 返回该方向**已重组**的字节（可能带截断）；
    // 数据不存在时返回 nil（= 缓冲区不存在，与既有 Extractor 约定一致）。
    BytesToServer() []byte
    BytesToClient() []byte
}
```
- `Ctx` 增加 `Stream StreamView`（9-2 预留的字段落地）；
- 新增提取器 `stream`：按 `Ctx.Pkt.StreamDir` 选 `BytesToServer/BytesToClient` ✓；
- ★ **nil 语义保持一致**：流不存在（非 TCP / 未建立 / 无数据）→ 返回 nil ⇒ 引擎按既有规则处理
  （含 §5.4 的"取反"表 ✓）。

## 6. 资源与生命周期（红线）

| 项 | 默认 | 说明 |
|---|---|---|
| `MemCap` | 64 MB | 所有流缓冲总量上限；超限按 LRU 丢最老的流并计数 |
| `FlowTimeout` | 60 s | 无新包的流回收（与 analyzer 的流老化对齐） |
| `MaxStreamBytes` | 1 MB / 方向 | 单流单方向上限；超了**停止追加并标记截断** ✓（匹配与证据都要如实体现） |
| 跳过优化 | 开 | ★ **若规则集里没有任何 `stream` 缓冲，则完全跳过重组** ✓（省 CPU） |

## 7. 乱序与丢包：如实标注，**不猜**

- gopacket 会给出 gap / 跳过统计 ✓ ⇒ 我们**记录每个方向上的洞**（`StreamStats.Gaps` / `GapBytes`）；
- 匹配：★ **2026-10-14 用真洞验证后更正** —— gopacket **不会立刻交付乱序字节**，
  而是**先按序暂存、等洞解决（补齐或流结束）才交付** ⇒
  洞会**延迟**（而不是跳过）之后的命中 ✗（实测：seq 有洞时 `Bytes` 暂为 0，直至洞补齐）。
  原写"洞之后的字节照常参与匹配"**不准确**，已按实测更正；
- **证据与统计**：把"这段有洞"写进边车/统计 ✓ —— ★ 与项目原则一致：**宁可标不确定，也不要装作完整** ✓；
- ★ **P1 待办**：给 `Gaps/GapBytes` 补一个**能可靠触发 skip** 的夹具与测试 ——
  P0 既没有 `Flush`、也没有超时触发，这条洞统计平时**很难被观测到**（代码用的是正确 API，
  但目前**零测试覆盖**，属"写了但没验证"状态）。

## 8. 顺带解锁：整条连接级证据（10-4 的 P1）

有了按流字节流后，证据可从"时间窗"升级为"**整条连接**"：命中的流 → 导出该流的**全部包**
（仍从留存/环取原始帧 ✓，而不是导出重组后的字节 —— 证据要保留**原始事实** ✓）。

## 9. 测试策略

1. ★ **自造分片夹具**：10-1 已有 pcapng 写入器 ⇒ 可程序化构造"拆包 / 乱序 / 带洞"的样本 ✓
   （不必等真实抓包 ✓），并作为**长期回归网** ✓；
2. ★ **9-6b 引擎级 golden**（本任务同批做）：固定规则集 + 固定输入 → dump 全部告警字段 → 快照；
   它正好**锁住"默认缓冲从 payload 改成 stream"这次语义变化** ✓；
3. 重组单测：跨包命中、乱序重排、带洞行为、截断（`MaxStreamBytes`）、`MemCap` 淘汰；
4. 端到端：样本 → 解码 → 归流 → 重组 → 检测 → 告警 JSONL（复用 10-6 的链路 ✓）；
5. ★ 每条新回归网都要**用"故意破坏"证明它会红一次**（坑 15 配套动作 ✓）。

## 10. 子任务拆解（v1，实际执行以逐条审批为准）

| # | 子任务 | 依赖 |
|---|---|---|
| **11-1** | `detect` 侧：`StreamView` 接口 + `Ctx.Stream` + `stream` 提取器 + 缓冲区注册 | — |
| **11-2** | 翻译器侧：默认粘性缓冲按协议决定（tcp → `stream`） | — |
| **11-3** | `reassembly` 模块：包装 gopacket Assembler/Pool + 我们的 `Stream`（memcap/截断/洞记录） | — |
| **11-4** | 把重组接进热路径（`parse-cli` 先行）+ 跳过优化 | 11-1/11-3 |
| **11-5** | **9-6b 引擎级 golden**（锁住语义变化） | 11-1/11-2 |
| **11-6** | 分片夹具生成器 + 重组行为测试 + 端到端回归 | 11-3/11-4/11-5 |
| **11-7** | 证据升级：整条连接级导出（10-4 的 P1） | 11-4 |

## 11. P0 明确不做

| 不做 | 何时 |
|---|---|
| UDP 伪流重组 | P1（视需要） |
| TLS/HTTP 解压、协议状态机 | P1（应用层识别范畴） |
| `flow:to_server` / `to_client` 真正的方向语义（现在只报"未生效"） | P1（需先定"服务端"判定） |
| 多接口乱序合并、跨流关联 | P1/P2 |
| 重组数据本身落盘（证据仍存**原始帧**） | 不做（刻意的） |

## 12. 实测发现（11-4 接线跑通后）：`stream` 在 IPv6 上完全失效 + 告警去重塌陷

### 12.1 现象（可复现）

夹具 `testdata/test.pcapng`（18 包，**只有 1 个 IPv4 包**），规则
`alert tcp any any -> any any (msg:"stream-all"; stream; pcre:"/./"; sid:940002;)`：

```
=== 检测结果：命中 1 次，涉及 1 条规则 ===     ← 只有那个 IPv4 包命中（No=16）
[命中] No=16 ... 缓冲=stream
```

对照：同一条规则把 `stream;` 写到 `pcre` **之后** → 该 `stream` 被忽略、缓冲仍是 `payload`，命中 10 次。

> ★ **粘性缓冲只作用于它之后的模式**：`stream; content:"x";` 才是对的写法（Suricata 同样如此）。
> 写反了不会报错——缓冲区静默保持 `payload`，是最容易骗过测试的那种错。

### 12.2 根因（两处，都在"流归属"上）

1. `analyzer.FeedFlow` 只处理 `IPVersion == 4`（analyzer.go:68）⇒ **IPv6 包的 `StreamID` 恒为 -1**
   （`analyzer_test.go:154` 还把这个行为锁成了断言），`Packet.StreamDir` 对 IPv6 也恒为 0。
2. `reassembly.View` 的退化路径 `keyFromPacket` 只支持 IPv4（用 `SrcIPNum/DstIPNum` 拼 4 字节）
   ⇒ IPv6 包在 `byID` 与 `byKey` 两条路上都找不到流 ⇒ 返回 `emptyStreamView{}`。

注：gopacket 侧的 IPv6 是通的（`decodeTCP` 有 `has6` 分支与 `ip6P`；`keyFrom` 用 16 字节地址比较，
IPv6 同样能进 `byKey`）——**断点只在"用 StreamID 找回流"这一步**，不是重组器不会处理 IPv6。

### 12.3 连带缺陷（比 `stream` 更紧急）

`Alert.StreamID` 取自 `pkt.StreamID`，而告警去重键 = `(RuleID, StreamID)`（alert/consumer.go:153）
⇒ **IPv6 流量的同规则告警共用 `StreamID = -1`，会被压成一条**。实测 10 次命中只写出 2 条告警
（"写入 2 条，去重压制 8 条"），其中一个"2"就是被塌陷掉的 IPv6 告警。这是**真实的漏报路径**。

### 12.4 结论与排期

- **不能先做 11-2**：在 IPv6 打通之前把 `alert tcp` 的默认粘性缓冲翻成 `stream`，会让 IPv6 上的
  所有 TCP 内容规则**静默失效**（不报错、不告警、测试还可能因为夹具偏 IPv4 而全绿）。
- 新增 **11-4b（P0）打通 IPv6 流归属**，两条路选一条或都做：
  - (a) 小改：`keyFromPacket` 支持 IPv6（`net.ParseIP` 取 16 字节）+ `Feed` 对未被 analyzer 归流的包
    回写 `StreamDir`（`keyFrom` 的归一化与 analyzer 完全一致：低地址为 A、地址相同比端口 ⇒ 无冲突）。
  - (b) 根本解（推荐排期）：`analyzer` 支持 IPv6 归流（`Flow.A/B` 现在是 uint32，需扩展表示），
    一次修好 stream + 流聚合统计 + 告警去重三处。
- 新增 **11-4c（P0）告警去重键补上 `FlowKey`/五元组**，使 `StreamID == -1` 时不会跨流塌陷。

### 12.5 11-4b 已落地（实测复核）

改动只有两处（`internal/modules/reassembly`）：① `keyFromPacket` 支持 IPv6
（`net.ParseIP` 取 16 字节、并用 `To4() == nil` 排除 v4-mapped；**IPv4 仍走 4 字节，
键逐字节不变**）；② `Feed` 在 `p.StreamID < 0`（未被 analyzer 归流）时把归一化方向
回写 `p.StreamDir`，供 `detect.extractStream` 选方向。

同一个 `stream; pcre:"/./"` 规则，实测：

| | 命中 | 命中的包 | 告警 |
|---|---|---|---|
| 修复前 | **1** | 只有 IPv4 的 No=16 | 写入 2 / 压制 11 |
| 修复后 | **13** | No=2,3,5,6,9,10,11,12,13,14,15,16,18，全部 `缓冲=stream`（含大量 IPv6 流） | 写入 2 / 压制 11 |
| 默认缓冲回归 `e2e.rules` | 10（未变） | — | 写入 2 / 压制 8 |

★ 注意最后一行：**告警数没变（仍是 2 条）** —— 因为 `StreamID` 在 IPv6 上仍是 -1，
去重键 `(RuleID, StreamID)` 依旧把 IPv6 的告警全压成一条。这正是 11-4c 要修的东西；
11-4b 只负责"让 `stream` 在 IPv6 上有数据、方向也对"。

（性能备注：`keyFromPacket` 只在 `View` 的退化路径上被调用，即只有未被归流的包（当前 = IPv6）
会走它，每包 2 次 `net.ParseIP` 分配；等 `analyzer` 支持 IPv6 归流后这条退化路径会自然退场。）

### 12.6 11-4c 已落地（告警去重不再跨流塌陷）

改法（只有 `internal/modules/alert/consumer.go` 一处）：`dedupKey` 增加 `flowKey` 字段，
**只在 `Alert.StreamID < 0` 时**用方向化五元组 `Alert.FlowKey` 兜底；`StreamID >= 0`（IPv4）
的键**完全不变**，零回归风险。`FlowKey` 为空时退化为旧行为。

| | 命中 | 写入 | 压制 |
|---|---|---|---|
| A（`stream; pcre:"/./"`）修复前 | 13 | **2** | 11 |
| A 修复后 | 13 | **4** | 9 |
| B（默认缓冲 `e2e.rules`）修复前 | 10 | **2** | 8 |
| B 修复后 | 10 | **4** | 6 |

4 条告警正好对应 4 个不同的方向化五元组（IPv6 服务端→客户端 / IPv6 客户端→服务端 /
No=16 的 IPv4 / No=18 另一条 IPv6 流），且 **写入 + 压制 = 命中** 成立。
单测层面 `TestConsumerIPv6DifferentFlowNotDeduped` 在改生产代码前是**红的**
（`等待 Written==2 超时`）—— 是红转绿的守卫，不是事后补的装饰。

★ 注意：**命中次数一次都没变**（13 / 10），所以"看命中数"永远发现不了这个 bug；
凡是有"去重/聚合"的地方，验收都要**同时看"最终写出去多少条"**。

仍待做（P1）：`StreamID` 在 IPv6 上依旧是 -1（本次只是让**去重键**不再塌陷），
要让 IPv6 真正拥有流身份（流聚合、统计、去重都靠它），仍需 `analyzer` 支持 IPv6 归流。
