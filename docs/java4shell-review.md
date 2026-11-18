# Java4Shell / CVE-2026-114938 防守核验

资料核对时间：2026-11-18（Asia/Shanghai）。本项目只实现无害识别和本地主机证据采集，不包含漏洞触发器、畸形 Base64、内存破坏验证、泄露或命令执行代码。

## 已核实事实

- Oracle 是 CVE 分配方。官方记录将问题归入 Java SE `Compiler`，CVSS 3.1 为 8.1（AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H），说明攻击者可经多种协议向相关 API 提供数据；成功利用可能接管受影响产品。
- CISA ADP 将弱点标为 CWE-122，并在 2026-11-17 记录 `Exploitation: none`、`Automatable: no`、`Technical Impact: total`。这表示当时无已知利用证据，不表示以后不会变化。
- Calif 披露与 OpenJDK 修复提交将根因定位到 HotSpot x86-64 AVX-512 Base64 intrinsic 的短尾处理。修复提交 `5177a70b385c16f26ede191fdac7aaba0bed0f8b` 把短于完整 Base64 块的尾部转交标量路径。
- 公开首个修复版本为 17.0.21.1、21.0.13.1、25.0.5.1、27.0.1.1。公开研究给出的通用受影响起点为 17.0.6；18 及之后的非支持版本应升级到受支持修复线。Oracle Java SE 8u511b33-perf 是官方列出的特殊受影响构建，不能据此扩大到所有 Java 8；通用 `java -version` 输出不能可靠区分该 perf 构建，因此程序要求用 Oracle 资产/补丁库存单独核验。
- 披露路径要求 HotSpot/GraalVM 类 VM、x86-64、当前 JVM 可见相应 AVX-512/BMI2 能力、Base64 intrinsic 和 JIT 路径。OpenJ9/J9 不使用该 HotSpot intrinsic。硬件与运行参数是适用条件，不是版本补丁的替代品。

## 程序如何判断

远程扫描只复用已经取得的响应，识别 Java 产品特征并输出 `java_product_hint`。它不会为 Java4Shell 增加请求，也不会尝试寻找或调用产品接口。网页证据无法获知 JVM 和 CPU，因此永远不会直接生成“漏洞已确认”。

本地主机采集必须显式开启：

```bash
php-selfcheck collect --java-command > host-report.json
```

采集器检查最多 16 个可见 Java 程序和 128 个 JVM 进程：

1. 用每个 Java 程序自身的 `-version` 读取厂商、版本和 VM 线索。
2. 在清除采集器 Java 选项变量后用 `-XX:+PrintFlagsFinal -version` 观察该程序在当前节点的清洁默认值。
3. 读取当前命名空间可见的架构及 `avx512f`、`avx512bw`、`avx512vbmi`、`bmi2`。
4. 对正在运行的 JVM 读取命令行后只保留 Java4Shell 相关参数；其他参数被过滤且不保存，进程环境不读取。不使用 `jcmd`、agent、信号或进程附加。
5. 分别报告版本范围、VM、硬件和缓解线索。任何缺项保持未知。

清洁默认值不等于服务实际参数。实际服务还可能从环境变量、参数文件、容器编排或产品启动器获得覆盖值；主机报告明确记录 `effective_flags_complete=false`。当前节点缺少 AVX-512 只说明当前放置不适用，不能为可能迁移的镜像或工作负载永久清除风险。

## 判定状态

| 状态 | 含义 |
| --- | --- |
| `affected_candidate` | 版本、HotSpot 类 VM 和当前硬件形成候选；输入路径与可利用性未确认 |
| `affected_candidate_eol` | 非支持版本位于披露范围；应迁移到受支持修复线 |
| `candidate_hardware_unknown` | 版本/VM 可能适用，CPU 证据不足 |
| `candidate_default_mitigated` | 采集器清洁环境观察到 `UseBASE64Intrinsics=false` 或 `UseAVX<=2`；不代表服务进程 |
| `fixed_release` | 达到公开修复基线；仍需厂商构建、运行映像和重启证据 |
| `not_in_disclosed_range` | 不在通用披露版本范围；Oracle 8u511b33-perf 仍须单独查库存 |
| `not_applicable_hardware` | 当前节点缺少所需硬件条件；迁移后需重查 |
| `not_applicable_vm` | OpenJ9/J9 等不使用已披露 HotSpot intrinsic |
| `unknown` | 版本、VM、CPU 或采集权限不足 |

## 处置顺序

优先升级到产品或 JDK 厂商明确提供的固定构建，重建容器并重启全部 JVM。不能立即升级时，厂商/研究建议使用 `-XX:-UseBASE64Intrinsics`；x86-64 可用 `-XX:UseAVX=2` 作为更宽的临时缓解。参数必须在运行服务上生效并验证，不能把配置文件存在当成实际生效。ARM JVM 可能拒绝 x86 专用参数，因此跨架构共享配置前必须测试。

## 来源

- [Oracle CVE 记录](https://www.cve.org/CVERecord?id=CVE-2026-114938)，发布时间 2026-11-17。
- [Oracle November 2026 Critical Security Patch Update](https://www.oracle.com/security-alerts/cspunov2026.html)。
- [OpenJDK 修复提交 5177a70b385c](https://github.com/openjdk/jdk/commit/5177a70b385c16f26ede191fdac7aaba0bed0f8b)。
- [Calif Java4Shell 技术披露](https://calif.io/java4shell)。
- [JFrog 受影响与修复版本整理](https://research.jfrog.com/post/java4shell-vulnerability/)。
- [Semgrep 防守核验建议](https://semgrep.dev/blog/2026/java4shell-openjdk-base64-vulnerability/)。
- [ikow/java4shell-poc](https://github.com/ikow/java4shell-poc) 固定阅读提交 `15904ba6cf099e106d049162901e8a2e063bf3bf`，仅参考其分析和无害扫描判据，未运行或复制 exploit/PoC。

社区资料用于补充根因与适用条件；版本与供应商状态仍应以最新官方公告为准。
