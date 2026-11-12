# 显示过滤语法

显示过滤作用于**已经抓到的包**，只决定"显示哪些"，不重新抓包。
它与捕获过滤（BPF）是两套东西：

| | 捕获过滤 | 显示过滤 |
| --- | --- | --- |
| 语法 | `tcp port 80`、`icmp` | `ip.src == 10.0.0.1 && protocol == http` |
| 生效位置 | 内核态，`pcap_compile` 下推 | 用户态，`QSortFilterProxyModel` |
| 影响 | 决定哪些包进入用户态 | 决定哪些包显示出来 |

被 BPF 丢掉的包不会因为显示过滤而回来；反过来，清空显示过滤能立刻恢复全部已抓到的包。

## 1. 文法

```ebnf
expr       := or_expr
or_expr    := and_expr ( "||" and_expr )*
and_expr   := unary ( "&&" unary )*
unary      := "!" unary | primary
primary    := "(" expr ")" | comparison
comparison := field op value
op         := "==" | "!=" | "<" | "<=" | ">" | ">="
value      := integer | "quoted string" | identifier | ip-literal
```

- 优先级由低到高：`||` < `&&` < `!` < 比较；
- `and` / `or` / `not` 与 `&&` / `||` / `!` 等价，大小写不敏感；
- 字符串可用单引号或双引号，支持 `\"`、`\\` 转义。

## 2. 字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `ip.src` / `ip.dst` | IP | 源 / 目的地址（IPv4 与 IPv6 都适用） |
| `ip.addr` | IP | 源或目的任一匹配，支持 CIDR |
| `ip.proto` | 整数 | 协议号，可写 `tcp`/`udp`/`icmp`/`icmpv6` 等名称 |
| `ip.version` | 整数 | 4 或 6 |
| `ip.len` | 整数 | IPv4 总长度 / IPv6 载荷长度 + 40 |
| `ip.ttl` | 整数 | IPv4 TTL / IPv6 Hop Limit |
| `tcp.port` | 整数 | 源或目的端口 |
| `tcp.srcport` / `tcp.dstport` | 整数 | 定向端口 |
| `tcp.flags.syn` / `tcp.flags.ack` | 整数 | 0 或 1 |
| `tcp.len` | 整数 | TCP 载荷字节数 |
| `udp.port` / `udp.srcport` / `udp.dstport` | 整数 | UDP 端口 |
| `udp.len` | 整数 | UDP 长度字段 |
| `icmp.type` / `icmp.code` | 整数 | ICMP 类型 / 代码（v4 与 v6 通用） |
| `arp.op` | 整数 | 1 请求 / 2 应答 |
| `protocol` | 字符串 | 最高层协议名（DPI 标签优先），大小写不敏感 |
| `stream_id` | 整数 | 会话编号（P3 起有值） |
| `process.pid` | 整数 | 本机进程 PID（P6，Windows） |
| `process.name` | 字符串 | 本机进程名（P6，Windows，大小写不敏感） |
| `frame.len` | 整数 | 线路长度 |
| `frame.number` | 整数 | 帧序号（过滤后不重新编号） |

## 3. 语义

1. **字段缺失不等于错误**：例如对 UDP 包求值 `tcp.port == 443`，结果恒为 `false`，不报错。
2. **多值字段**：`ip.addr`、`tcp.port`、`udp.port` 同时代表源与目的。
   - `==` 表示"任一命中"；
   - `!=` 表示"两者都不等于"，因此一个 TCP 包在 `tcp.port == 80` 与 `tcp.port != 80` 下
     不会同时为真。
3. **类型必须匹配**：数字字段与字符串比较、文本字段与数字比较都会在编译期报错，
   例如 `protocol == 80` 报"需要字符串"，`tcp.port == "80"` 报"需要整数"。
4. **IP 字段只支持 `==` 与 `!=`**，且右值可以是单个地址或 CIDR 网段。
5. **帧序号保持原值**：过滤不会重新编号，`No.` 始终是抓包时的全局序号。
6. **进程字段依赖会话归属**：`process.pid` / `process.name` 只在 Windows 上由 P6 填充；
   非 Windows、离线 PCAP 或归属失败时恒为 `false`，不报错。

## 4. 示例

```text
ip.src == 10.0.0.5
ip.addr == 192.168.0.0/16 && tcp.port == 443
tcp.flags.syn == 1 && tcp.dstport == 80
protocol == dns || udp.dstport == 53
icmp.type == 8 && ip.dst == 8.8.8.8
!(protocol == arp) && frame.len > 100
process.name == "chrome.exe"
process.pid == 1234 && tcp.port == 443
```

## 5. 错误提示

表达式出错时输入框变红，右侧显示"第 N 列：原因"，状态栏同步提示；
**上一条有效规则继续生效**，列表不会因为输入到一半的表达式而清空。

```text
第 13 列：字段 tcp.port 需要整数，得到 'x'
第 1 列：未知字段 'ip.srcc'
第 20 列：缺少右括号
```

## 6. 与 DPI 的关系

`protocol` 表示**最高层协议**：

- 会话被 DPI 命中时是 `HTTP` / `TLS` / `SSH` / `DNS` / `BitTorrent`；
- 只有端口推断时同样是应用名，但置信度为 `port`（悬停协议列可见依据）；
- 都没识别到时回落到传输层 `TCP` / `UDP` / `ICMP` / `ARP`。

因此一条 HTTP 流**不再匹配** `protocol == tcp`，要按传输层筛选请用 `ip.proto == tcp`。
识别依据可以悬停协议列查看，或在详情树最底部的应用层节点里读到「置信度 / 识别依据」。
