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

### 7.1 11-6 用夹具把上面的行为钉成断言后，暴露出的真实风险（★ 待拍板）

11-6 建好了"洞 / 补齐 / 重传 / 乱序"的可重复夹具（`internal/modules/reassembly/holes_test.go`、
`internal/hotpath/reorder_test.go`），把 §7 那句文字描述变成了**可执行断言**：
洞未补齐前 `Bytes` 只含洞之前的部分、`Gaps/GapBytes` 恒为 0、视图里**看不到**洞之后的字节。

★ 但同一批夹具在**仓库外副本**上做的一次探针（PM 独立跑的）暴露了更严重的后果：

| 场景（同一条流） | `View` 看到的字节 | 判定 |
|---|---|---|
| 无 SYN，按序 `[A,B,C]` | `AAAABBBBCCCC` | ✓ 完整 |
| 无 SYN，乱序 **`[C,A,B]`** | **`CCCC`** | ★ 更小序号的 A、B **被静默丢弃** |
| 无 SYN，乱序 `[A,C,B]` | `AAAABBBBCCCC` | ✓ 完整 |
| 无 SYN，首段 seq 不是最小（前面少 1 字节） | **``（空）** | ★★ **该方向后续全部不可见** |

**两条结论（都会造成"静默少匹配"）**：

1. ★★ **一个丢包（洞）会让该方向后续所有数据在洞被补齐前完全不可见**，而当前**没有任何 Flush/超时**
   （`Options.FlowTimeout` 的注释写明"本步只做持有与暴露，不做后台定时器"）⇒ 洞实际上
   **永远不会被跳过**（直到 `MemCap` 把整条流淘汰），`Gaps/GapBytes` 也**恒为 0** ⇒ 问题被掩盖 ✗。
   而 **`stream` 已是 TCP 规则的默认匹配对象**（§12.9）⇒ **丢一个包就可能让该方向后续全部规则漏检**。
2. ★ **中途抓包（无 SYN 或首段不是最小序号）时，更小序号的段会被直接丢弃** —— 这是 IDS 在
   span/镜像口部署时的常见场景（抓包点从连接中途开始 + 乱序）。

**建议的下一步（11-6b，P0）**：给重组器加**周期性 Flush / 超时回收**
（`Assembler.FlushWithOptions(reassembly.FlushOptions{...})`），让未补齐的洞被**跳过交付** ——
这样既让 `Gaps/GapBytes` 如实记账（正好补上 §7 的 P1），又让洞之后的数据仍能参与检测；
同时复核 `ReassemblyComplete` 恒返回 `true` 与"中途流起始序号"策略是否符合预期。
刚建好的洞夹具可直接用作**红转绿守卫**。

### 7.2 11-6b 已落地：机会式超时 Flush（★ §7 那条 P1 已修）

改动只在 `internal/modules/reassembly`：

1. ★ **把真实 `CaptureInfo`（含 `Timestamp = p.Time`）传给 Assembler** —— 以前传的是 `asmContext{}`
   零值，gopacket 看到的包时间戳**恒为 `0001-01-01`**；不修这个，任何超时判定都会
   "看起来做了但根本没生效"（这是本次实测抓出来的隐性问题）。
2. **`flushExpired(now = p.Time)`**：超过 `FlowTimeout` 仍未补齐的洞被**跳过交付**
   （`FlushWithOptions(FlushOptions{T: now-FlowTimeout})`；`TC` 留零 ⇒ **不关闭连接、不丢已累积字节**）。
   - ★ **时间基准必须是包时间**，不是 `time.Now()`：离线回放时成千上万个包可能在亚秒内跑完，
     用真实时钟永远等不到超时，测试也会非确定。
   - ★ **机会式**（在 `Feed` 里触发 + 按包时间限频 `flushInterval = 1s`），**不起后台 goroutine**
     —— 本包不做并发保护，后台定时器会引入数据竞争。
   - 无时间戳的包（SPB 等）直接跳过 ⇒ 与以前行为一致。

实测（`TestGapFlushSkipsAndContinues`，红转绿守卫）：

| | Bytes | Gaps | GapBytes | View |
|---|---|---|---|---|
| flush 前（超时未到） | 10 | 0 | 0 | `AAAAAAAAAA` |
| flush 后（超时到点） | 20 | **1** | **10** | `AAAAAAAAAACCCCCCCCCC` |

⇒ ① 洞被**如实记账**（补上 §7 的 P1）；② 洞之后的数据**不再被无限期挡住**；
③ **没有凭空造出洞里的字节**（View 恰为 `[0,10) + [20,30)`）。
★ **变异检验**（在仓库外副本里把 `flushExpired` 变成 no-op）：该守卫立刻变红
（`flush 后 Gaps=0，want >=1`）✓ 证明它是真守卫，不是装饰。

★ **不变量**：默认 `FlowTimeout = 60s`、真实样本时间跨度约 3 秒 ⇒ **不触发 flush**；
端到端 A/B/C 三组输出与改动前**逐字节一致** ✓（说明这次修复对常规流量**行为中立**）。

★ **仍待修（11-6c）**：`Accept` 强制 `start = true` 导致**中途抓包（无 SYN / 首段不是最小序号）时
更小序号的段被直接丢弃**（探针实测 `[C,A,B]` 只剩 `CCCC`）；以及 `ReassemblyComplete` 恒返回 `true`
的策略复核。

### 7.3 11-6c 诊断结论（把缺陷钉成断言 + gopacket 源码溯源）

11-6c 只加测试、不改生产代码（`internal/modules/reassembly/midstream_test.go`，6 条），
把下面的事实钉成了可执行断言：

**根因链（gopacket v1.7.4 `reassembly/tcpassembly.go`，行号已核）**

| 行 | 代码 | 含义 |
|---|---|---|
| 662 | `a.start = half.nextSeq == invalidSequence && t.SYN` | gopacket 自己的默认：**只有看到 SYN 才起流** |
| 669 | `if !half.stream.Accept(..., &a.start, ac)` | 我们的 `Accept` **无条件 `*start = true`**，覆盖了它 |
| 693-711 | `if half.nextSeq == invalidSequence { if t.SYN {nextSeq = SYN.seq+1} else if a.start {nextSeq = 本段 seq} else {"waiting for start"} }` | ⇒ **基准（`nextSeq`）= 首个触发起流的段的 seq** |
| 712-724 | `diff := half.nextSeq.Difference(seq); if diff > 0 { "...gap in sequence numbers...storing into connection" }` | 落在基准**之前**的段被**排队**（不是立刻丢弃） |
| — | 交付/Flush 都从 `nextSeq` **向前**走 | ⇒ **基准之前排队的段永远不会被交付**（真正的"静默丢失"） |

**决定性对照（同一批段、只差有没有 SYN）**

| 场景 | `View` | 结论 |
|---|---|---|
| **有真 SYN**，之后 `[C,A,B]` | `AAAABBBBCCCC` | ★ **乱序被正确处理**（基准 = SYN.seq+1 = 真实起点，没有"基准之前的段"） |
| **无 SYN**，`[A,C,B]`（最小段先到） | `AAAABBBBCCCC` | ✓ 恰好蒙对（首个观察段就是最小段） |
| **无 SYN**，`[C,A,B]`（高序号先到） | `CCCC` | ✗ 基准被钉在 1009 ⇒ A、B 搁浅 |
| **无 SYN**，首段是高序号**空载荷**段 | ``（空） | ✗ 基准被钉在空段 seq，后续全部搁浅 |

⇒ ★★ **缺陷只影响"没抓到 SYN 的中途流"**（span/镜像口部署的常见情况）；只要看到 SYN，gopacket 的
基准就是真实起点，乱序能自愈。

**另一条独立缺陷（同批测出）**：`stream.ReassemblyComplete` **恒返回 `true`** ⇒ 双向 FIN 之后
连接被移出池，**但我们的 `byKey`/`byID` 仍持有已关闭的旧 stream**（测试日志：`池已 remove，但我们
byKey 仍持旧 stream=true`）。后果：同一四元组复用时旧缓冲会被误当成"当前流"（直到被新流替换），
且旧缓冲要等 `MemCap` 淘汰才释放。

**候选修法（待拍板，11-6c 里只诊断不实现）**

| 方案 | 做法 | 代价 / 风险 |
|---|---|---|
| **(A) 预缓冲起流** | 对无 SYN 的新连接先缓存前 K 个段（帧都还在），确定最小 seq 后**先喂最小段触发起流**、再按序回放缓冲 | ★ 最彻底，但要自己缓冲/回放，且前 K 段的 `stream` 视图会缺失；与 Flush/跳过优化有交互，复杂度最高 |
| **(B) 检测层兜底** | `stream` 为空/该包数据不在视图里时回落到 `payload` | 简单、彻底防漏；但**改变匹配语义**（同一条规则可能在两种缓冲上命中，要定义优先级） |
| **(C) 只看有 SYN 的流用 `stream`** | 重组器标记"是否见过 SYN"，`extractStream` 对**中途流回落到 `payload`** | ★ (B) 的干净变体：语义清晰（"能重组的用 stream，抓不到起点的用 payload"）；实现点在检测层，不动重组核心 |
| **(D) 修 `ReassemblyComplete` 策略** | 不再恒 `true`；FIN/超时后才允许移出，并同步清理 `byKey`/`byID` | 独立小修，治的是"陈旧指针 + 缓冲滞留"；与上面的方案正交 |

★ **PM 建议**：**先做 (C) + (D)**（防漏 + 清理陈旧引用，风险可控、语义清晰、可测），
把 **(A)** 记为 P2 备选（要做就得连带处理"预缓冲期的检测语义"），**(B)** 与 (C) 二选一即可。

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

### 12.7 热路径编排已收敛到 `internal/hotpath`（11-5a）

「归流 → 重组 → 检测」这条编排（含**顺序红线**与 11-4 的"未引用 `stream` 就不建重组器"跳过优化）
原来写在 `cmd/parse-cli/main.go` 里，而 `internal/modules/alert/e2e_test.go` **又自己抄了一遍**
（且没接重组器）⇒ 编排被改，测试不会响。

现收敛为 `internal/hotpath`（`New` / `Process` / `Analyzer` / `Engine` / `Reassembles` / `Close`），
`parse-cli` 与测试**共用同一份实现**。★ 重构后端到端输出**逐字节不变**：
A 组 23 行、B 组 20 行 stdout 完全一致（唯一差异是我自己指定的 `--alerts` 路径），
两份告警 JSONL 哈希相同；`--analyze --detect` 同时只用**一个** analyzer 实例。

★★ **一条必须记下的教训（变异检验抓到的）**：`internal/hotpath/hotpath_test.go` 的
`TestProcessFeedsReassemblyBeforeMatch` 名字与注释都声称"顺序写反就会红"，但实测**把
`Feed`/`Match` 换序后它照样通过**（命中 13 → 6，仍 > 0 ⇒ `streamHits > 0` 这条断言守不住顺序）✗。
⇒ **"≥1 / >0" 这类弱断言几乎守不住任何东西**；新的回归网必须做一次**故意破坏（变异）检验**，
否则你不知道它守的是不是空气。严格的顺序锁改由 11-5b 的 golden（逐行精确比对）承担。

### 12.8 11-5b 已落地：三组引擎级 golden（并把上面那条弱断言收紧）

`internal/hotpath/golden_test.go`：`LoadFile → hotpath.New → 逐包 Decode → Process`（**走生产真路径**），
把命中规范成一行 `No=<PktNo> sid=<RuleID> buf=<Buffer> off=<Offset> snip=<%q>`，
与 `.golden` **逐行精确比对**（不含时间/绝对路径/耗时；两侧行尾归一化；忽略末尾空行）。
`-update` 才写回，且**最低期望断言失败时拒绝写回**（防止把 bug 烤进 golden）。

| golden | 规则 | 锁定内容 |
|---|---|---|
| `explicit-payload.golden` | 显式 `payload;` | 10 命中，全部 `buf=payload` |
| `explicit-stream.golden` | 显式 `stream;` | 13 命中，全部 `buf=stream`，其中 **12 条来自 IPv6 包** |
| `default.golden` | **裸规则 `e2e.rules`** | 当前 10 命中全 `payload` —— ★ **11-2 翻默认缓冲的信号线** |

★ `default.golden` 的角色写进了测试文档注释：**11-2 落地时把旧文件改名
`default-v1-payload.golden` 永久保留、再用 `-update` 生成新的 `default.golden`（stream 语义）**，
于是"换默认缓冲前后的行为"永久留成两份可对照的可执行记录（用户 2026-10-14 拍板的"甲"）。

★ 本任务同时把 12.7 记的那条弱断言**收紧为精确计数**：`TestProcessFeedsReassemblyBeforeMatch`
现在断言 `总命中 == 13 且 stream 命中 == 13`。

**两项独立验证（PM 在仓库外副本 `D:\tmp\mut-11-5b` 上做，仓库本体一行未动）**：

1. **可复现性**：副本里重跑 `-update`，三份 golden 哈希**完全不变**，且与仓库里的**逐字节一致**；
2. **顺序变异**（把 `Feed`/`Match` 换序）：`TestGoldenHits/explicit-stream` **红**（逐行全不一致）、
   收紧后的顺序测试 **红**（`总命中 6（期望 13）`）；而 `explicit-payload` / `default` 两组**仍绿**
   —— 说明 golden 是**精确**的（只对"该变的那条"报警），不是"一改就全红"的假守卫。

★ 顺带记一个**干净的变异手法**（trae 本次自己用的，值得沿用）：
`go test -overlay <overlay.json>` —— 用 JSON 把某个 `.go` 文件映射到仓库外的一份改过的副本，
**完全不碰仓库源码**就能做变异检验（比"改完再恢复"安全得多）。

### 12.9 11-2 已落地：`alert tcp` 的默认粘性缓冲翻成 `stream`

生产改动只有一处：`internal/modules/rule/kw/frame.go` 的 `NewState` 用
`defaultStickyBuf(r.Match.Proto)` 决定 `CurBuf`（`alert tcp` → `stream`；其它协议 → `payload`）。

**语义切换的"精确改动面"（这是本次验收的核心判据）**：翻译器 golden
`internal/modules/rule/pipeline/testdata/basic.golden.json` 重生成前后：

| buffer | 改前 | 改后 |
|---|---|---|
| `payload` | 9 | **0** |
| `stream` | 0 | **9** |
| `http_uri` | 4 | **4**（不变） |
| `http_header` | 2 | **2**（不变） |
| `dns_query` | 2 | **2**（不变） |

⇒ diff 里**只出现 `payload → stream`**，显式缓冲关键字（`http_uri` / `http_header` / `dns_query`）
的计数一个都没动 ✓ —— 这正是"翻默认"应有的影响面。

**端到端三组（改前 → 改后）**：

| 组 | 规则 | 改前 | 改后 |
|---|---|---|---|
| A | 显式 `stream;` | 13 命中 / 写入 4 / 压制 9 | **13 / 4 / 9**（不变）✓ |
| B | **裸规则**（`e2e.rules`） | 10 / 4 / 6 | ★ **13 / 4 / 9**（13 条命中**全部** `缓冲=stream`）✓ |
| C | 显式 `payload;` | 10 / 4 / 6 | **10 / 4 / 6**（不变）✓ |

**三处夹具按新语义改写**（不是放宽断言，而是"裸规则"不再等于"未引用 stream"）：
`detect/ruleset_test.go: TestUsesBufferFile`、`hotpath/hotpath_test.go: TestNewSkipsReassemblyWhenUnused`、
`detect/e2e_test.go: TestE2ECaptureToDetect`（它不接重组器、`Ctx.Stream` 恒为 nil，故必须显式 `payload;`）
—— 三处的断言都**原样不动**，只把夹具从"裸 `alert tcp`"换成"显式 `payload;`"。

**"甲"方案落实**：旧 `default.golden`（10 行 payload）另存为 `default-v1-payload.golden`
（文件头加 2 行说明"11-2 前的历史对照物、不参与比对；可执行等价物见 `explicit-payload.golden`"），
新的 `default.golden` 记录 stream 语义（13 行）。换默认前后的行为因此**永久留在仓库里**。

★★ **一条流程教训（本任务暴露的）**：PM 的影响清单是**用 grep `BufPayload` 反推**出来的，
**漏掉了 `internal/modules/detect/e2e_test.go`**（它用 `LoadFile` 而不是字面量 `BufPayload`，
所以 grep 不到）—— 是 trae 跑全量测试时才发现并顺手修对的。
⇒ **改语义类任务的影响面，不能只靠关键字 grep**：正确做法是**先在仓库外副本里把改动做一遍、
跑全量测试，用"红名单"反推影响面**，再把这份名单写进 prompt（见踩坑记录 坑 25）。
