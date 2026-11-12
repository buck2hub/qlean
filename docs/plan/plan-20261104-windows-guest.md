# Windows 客户机支持计划（2026-11-04）

本文解决 Qlean 目前只能运行 Linux 客户机的问题，目标是在 Linux KVM 宿主机上为 Windows 10/11 中经过真实验收的 amd64 客户机提供隔离测试能力：`Image`/`Machine` 可启动 Windows，`exec`、`upload`/`download`、`get_ip`、`spawn`、`shutdown`、`is_running` 与 `MachinePool` 的核心工作流可用。发布至少要求一个明确版本通过全部核心验收；只有两个版本都通过时，支持矩阵才能同时声明 Windows 10 和 11。

本文只规划任务，不宣称实现完成。落地时每个任务都必须先刷新源码锚点，再按任务卡验收。

**模板版本:** `v1.1`（遵循 `plan-template.md` 的结构与 `G-*`/`ER-*`/`GC-*` 条款。）

**目标分支:** `main`。

**计划状态同步义务（强制）:** 单一执行状况视图是 [`plan-status.md`](plan-status.md)。任何 Agent 推进或完成一张任务卡时，必须在同一变更中同步状态、发布版本/commit 和该卡的 UTC 更新时间；任务卡、`DEFER-*` 或依赖变化时同样同步。状态推进前运行 `git status --short --branch`（Git checkout）或 `libra status --short --branch`（Libra checkout）并记录所用工具。

### 适用范围

- **公开 API**：`ImageConfig` 新增 `GuestOs` 维度与 `with_guest_os` builder；`Image`、`Machine`、`MachinePool`、`with_machine`/`with_pool`、`is_kvm_available`。
- **宿主机依赖**：`qemu-system-x86_64`、OVMF、`swtpm`、libvirt、xorriso、`qemu-bridge-helper`；Windows 核心验收要求 KVM，TCG 不替代该门槛。
- **客户机镜像**：Windows 10/11（amd64）自定义 qcow2（`ImageConfig.source` + digest）；只有实际通过核心冒烟的版本才写入支持矩阵。
- **运行态语义**：首次部署与重启、`exec`、`get_ip`、`upload`/`download` 及明确列出的文件接口、`shutdown`、`is_running`、双机池。
- **测试与发布**：Linux 回归、Windows KVM gated 测试、README/CHANGELOG/CI、`0.4.0` 发布。

### 非目标

- **Windows 内置镜像目录**：受当前许可约束，不进入 `builtin_remote_image`；只支持 `source` + digest 自定义镜像。重启条件见 `DEFER-01`。
- **Windows 宿主机**：Qlean 宿主仍为 Linux（`with_machine`/`with_pool` 在非 Linux 直接 `bail!`）。
- **Windows on ARM**：仅支持 amd64；其它架构必须提前返回可操作错误。重启条件见 `DEFER-02`。
- **WinRM**：默认复用 SSH/SFTP；只有 `SPK-01` 判定其为唯一可行路径时才改选并重审计划。
- **GUI/桌面自动化**：只承诺 headless 命令、文件与网络语义。
- **Windows `InteractiveShell`**：本期不承诺；`open_interactive_shell` 必须返回明确的 unsupported 错误，不能继续硬走 vsock 后超时。
- **POSIX 专属文件语义**：Windows 上的 `hard_link`、`read_link`、`set_permissions` 不承诺 Unix mode/链接兼容，必须明确报错；不得静默忽略或伪装成功。
- **UNC/Windows device namespace 路径**：本期只承诺普通盘符路径及文档明确的相对路径；不支持的形式必须拒绝，不得按宿主 Linux 路径处理。
- **Windows TCG 验收**：可后续评估，见 `DEFER-03`；不影响 KVM 核心验收的强制性。

### 成功定义

- 使用 `ImageConfig::default().with_guest_os(GuestOs::Windows).with_source(...).with_digest(...)` 与 `with_machine` 能启动 Windows，PowerShell `exec("whoami")` 返回预期输出。
- `upload`/`download` 文件及目录往返一致；`get_ip` 返回该 VM 的 DHCP 地址；`shutdown` 通过 QMP/ACPI 关机且 `is_running` 反映真实状态。
- 部署后的 VM 能在 `shutdown` 后 `spawn` 并重新连接；两台 Windows VM 可通过 `MachinePool` 并发初始化、执行命令，地址与传输端点不串用。
- 默认 `GuestOs::Linux` 的运行行为零回归，Linux 全量测试全绿。公开结构体新增字段造成的源码迁移是明确、已发布说明的例外，不宣称旧字面量构造可原样编译。
- 每个声称支持的 Windows 版本均通过 KVM 核心冒烟；缺少镜像或宿主环境时阻塞相关 spike/发布，不得用 `DEFER-*` 替代核心验收。
- README、CHANGELOG、CI 与发布证据齐全，发布 `0.4.0`（0.x 的源码兼容破坏使用 minor）。

## 事实基线

> 所有行号和源码锚点必须在开工当天刷新；下表是 2026-11-04 当前 checkout 的成稿基线。

| 类别 | 当前事实 | 证据 |
|---|---|---|
| 公开 API | `Distro`/`GuestArch`/`ImageConfig`/`MachineConfig` 等重导出，无 guest-OS 维度 | `src/lib.rs:37-43` |
| `ImageConfig` | 全公开字段、派生 `Default`/Serde；现有字面量构造会因新增字段产生源码兼容影响 | `src/image.rs:68-81,855-869` |
| 发行版与架构 | `Distro` 只有 Linux 发行版；`GuestArch` 有 Amd64/Aarch64/Riscv64 | `src/image.rs:29-46` |
| 镜像缓存 | digest 优先作为缓存名；加载缓存后目前只核对 digest，未核对请求的 OS | `src/image.rs:132-152,645-717` |
| 内置镜像目录 | `builtin_remote_image` 只返回 Linux cloud 镜像 | `src/image.rs:226-276` |
| 引导与部署 | 首启通过 cloud-init NoCloud seed ISO，并写入 systemd socket/service | `src/machine.rs:220-399` |
| 传输 | SSH over vhost-vsock，固定 `root` 用户与 `true` readiness probe，无 TCP fallback | `src/ssh.rs:571-630` |
| SSH 服务端密钥 | 当前 `check_server_key` 无条件接受；TCP 不能继承此策略 | `src/ssh.rs:89-104` |
| QEMU 启动 | virtio 盘/网卡、vhost-vsock、bridge、KVM/TCG、QMP；无 pflash/vTPM | `src/qemu.rs:74-169` |
| 命令语义 | `exec` 原样传给 SSH `channel.exec`；UNIX escape 实际用于 `copy` 的 `cp` 命令 | `src/machine.rs:495-516,949-955`、`src/ssh.rs:324-370` |
| IP 检测 | `get_remote_ip` 硬编码 `hostname -I \| awk '{print $1}'` | `src/ssh.rs:831-841` |
| 文件语义 | SFTP 加宿主 `PathBuf` 拼接；`copy` 使用 POSIX `cp`，`set_permissions` 使用 Unix mode | `src/machine.rs:578-775,922-1137` |
| 其它运行接口 | `open_interactive_shell` 另开 vsock；池支持 init/spawn/shutdown；关机走 QMP powerdown | `src/machine.rs:466-493,518-576`、`src/pool.rs` |
| 网络 | libvirt NAT 网络 `qlean`、桥 `qlbr0`、192.168.221.0/24 + DHCP | `src/utils.rs:161-227`、`README.md:170-190` |
| CI | 仅 `pull_request`；clippy 命令未包含 `--all-targets --all-features` | `.github/workflows/check-and-test.yml:1-7,76-100` |
| 版本 | `Cargo.toml version = "0.3.1"` | `Cargo.toml:1-4` |
| 本地 VCS | 当前 checkout 使用 Libra；`git status` 在此 checkout 不可用，`libra status --short --branch` 可用 | 2026-11-04 成稿核对 |
| 首启部署超时 | `MachineConfig.ssh_timeout` 默认 KVM 180s / TCG 300s，只覆盖 SSH 连接等待维度 | `src/machine.rs:72,165-167` |
| VM 资源默认值 | 默认 core=2、mem=4096MB；未对 Windows 10/11 最低资源做评估 | `src/machine.rs:63-68,156-157` |

### 当前缺口

| ID | 缺口 | 影响 | 证据 | 计划动作 |
|---|---|---|---|---|
| GAP-01 | 无 guest-OS 抽象与 OS/架构/source 校验 | Windows 配置可能错误落到 Debian 内置镜像或缓存 | `src/image.rs:645-711` | `OSX-01`（已关闭） |
| GAP-02 | 无 OVMF/vTPM/Secure Boot 决策与 Windows QEMU 生命周期 | Windows 10/11 引导、重启和关机无保证 | `src/qemu.rs:74-169` | `SPK-02` → `OSX-02` |
| GAP-03 | 引导硬编码 cloud-init NoCloud | Windows 首次部署不可用 | `src/machine.rs:220-399` | `SPK-02` → `OSX-03` |
| GAP-04 | vsock、root/true probe 与任意服务端密钥接受硬编码 | Windows 传输不可达；直接加 TCP 会有地址发现和 MITM 风险 | `src/ssh.rs:89-104,571-630` | `SPK-01` → `TRN-01` |
| GAP-05 | shell、IP、路径与部分文件操作硬编码 POSIX | Windows 命令和文件语义不兼容 | `src/machine.rs:495-516,922-1137`、`src/ssh.rs:831-841` | `EXE-01`/`IP-01`/`FS-01` |
| GAP-06 | spawn/池/InteractiveShell 的支持边界未定义 | 首启成功仍可能在重启、双机或第二会话失败 | `src/machine.rs:451-493`、`src/pool.rs` | `OSX-03`/`TRN-01` |
| GAP-07 | CI 无 push 触发，发布远端门不可执行 | 发布后无法按模板取得指定 ref 的 CI 证据 | `.github/workflows/check-and-test.yml:1-7` | `REL-01` |
| GAP-08 | 无 Windows 首启部署超时维度（Linux `ssh_timeout` 默认 180/300s 不覆盖部署时长） | 首启部署可能超时失败，核心证据难以取得 | `src/machine.rs:72,165-167` | `OSX-03` |
| GAP-09 | 无 Windows VM 资源默认值讨论 | 支持矩阵可能声明默认资源下不满足最低要求的版本 | `src/machine.rs:63-68,156-157` | `OSX-02` |

## 与其它计划的关系

| 计划/文档 | 关系 | 本计划处理 |
|---|---|---|
| `plan-long.md` | 当前不存在 | `N/A` |
| `plan-template.md` | 模板 | 使用 v1.1；R1 同步修复模板状态机与发布规则歧义 |
| `plan-status.md` | 执行状况单一视图 | 每卡同步状态、版本/commit、UTC 时间 |
| `README.md` / `CHANGELOG.md` | 用户契约 | 每个行为卡同卡更新；`REL-01` 只做收口审计与版本段定稿 |
| `.github/workflows/check-and-test.yml` | CI 契约 | `REL-01` 增加 push 发布门并对齐 clippy 命令 |

## 评审结论与修订记录

| 维度 | 结论 | 修订动作 |
|---|---|---|
| 合理性 | Windows 隔离测试目标明确 | 保留 |
| 可行性 | 传输、部署必须先 spike；核心验证不可延后 | 增加 `DEP-01`/`DEP-02` 到 spike，发布必须取得 Windows KVM 证据 |
| 任务卡粒度 | 原 `DOC-01` 是补文档碎片卡 | 合并到 `REL-01`，行为文档仍归各实现卡 |
| 依赖与顺序 | 共享计划、状态、源码与文档写集使原计划不能并发 | 改为全串行并补齐顺序边 |
| 完整性 | 增加缓存、重启、池、关机、不支持接口与 CI 远端门 | `OSX-01`/`OSX-02`/`TRN-01`/`FS-01`/`REL-01` |
| 安全性 | TCP 不能只验客户端公钥 | 强制服务端主机密钥 pinning、Windows-only 显式 TCP 边界、禁密码 |
| 接口兼容 | 新增公开字段不是源码向后兼容 | 明确 0.4.0 的破坏与迁移；提供 builder 和 Serde 默认值 |
| 可靠性与容错 | 地址发现、主机密钥、超时和资源清理必须闭环 | `SPK-01`/`TRN-01` |
| 性能与容量 | Windows TCG 不作核心承诺；池测试验证资源隔离 | `DEFER-03`、`TRN-01` |
| 可维护性 | guest OS、路径和传输分派须收敛 | 禁止散落分支与宿主 `PathBuf` 直接解释客户机路径 |

### 修订历史

| 时间 | 触发 | 变更内容 | 原卡 → 新卡 | 受影响的引用 |
|---|---|---|---|---|
| 2026-11-04 03:32:26 UTC | 成稿 | 初始成稿 | N/A | N/A |
| 2026-11-04 03:54:17 UTC | review R1 | 修正 API/SemVer、验收状态机、外部依赖、核心测试门、传输安全、生命周期与文件边界；全串行化；合并文档碎片卡；补 CI 发布门和逐卡状态时间 | `DOC-01` → `REL-01`；其余卡保留编号并修订 | 实施顺序、依赖表、任务卡、状态视图、测试矩阵、追溯表、里程碑、风险表、Review log |
| 2026-11-04 04:10:47 UTC | review R2 | 所有 T-1 卡补 Linux 全量门；明确 host-key seed 权限与清理；增加逐卡实现 review 证据；精确 Windows 版本发布范围；模板补状态同步完成门 | `OSX-01`/`OSX-02`/`OSX-03`/`TRN-01`/`EXE-01`/`FS-01` 修订，编号不变 | Verification、粒度审计、实施证据、模板完成判据、Review log、状态视图 |
| 2026-11-04 04:19:20 UTC | review R3 | 关闭 R2 全部 P1；结构、依赖、计数、全量门、表格、链接和现有锚点复核通过；无新增 P0/P1，计划文档最终 PASS | N/A（仅评审记录与状态快照） | Review log、plan-status 计划一览 |
| 2026-11-12 07:20:33 UTC | review R4 | P2 缺口修复：新增 GAP-08（Windows 首启部署超时维度）与 GAP-09（Windows 资源默认值未讨论），`OSX-03`/`OSX-02` 各补一条 AC（两卡均达 8/8 上限）；事实基线、性能摘要、风险表同步；plan-status 同步 | `OSX-02`/`OSX-03` 修订，编号不变 | 事实基线、当前缺口、任务卡、粒度审计表、性能与容量摘要、风险登记、Review log、plan-status |
| 2026-11-12 07:45:12 UTC | review R5（环境消歧） | `DEP-01`/`DEP-02` 审计为不可用，`SPK-01`/`SPK-02` 置 `blocked`；`ADR-WIN-02`/`ADR-WIN-03` 改为临时接受并写入选定方案；取消 `SPK-02 -> OSX-01` 边，实施顺序改为以 `OSX-01` 为起点的串行链；新增环境消歧结论段落；`REL-01` 明确阻塞 | N/A（无拆合卡；仅依赖边与 ADR 状态） | 实施顺序、依赖登记表、ADR-WIN-02/03、粒度审计表 deps 列、Risk log、实施证据汇总、plan-status |

## 已决议设计决策

实现时若需偏离本节，必须先修改计划、状态视图与受影响任务卡并重新 review，不得在代码中静默改语义。

### ADR-WIN-01: 引入 `GuestOs`，并承认公开结构体的源码兼容破坏

- **Status:** Accepted
- **Context:** `Distro` 表示 Linux 发行版；Windows 需要独立 OS 维度。`ImageConfig` 当前是全公开字段结构体，新增字段会使未使用 `..Default::default()` 的外部字面量构造无法编译，字段有 Rust 默认值并不能避免这一点。
- **Decision:** 新增 `GuestOs { Linux, Windows }`（默认 `Linux`）、`ImageConfig::guest_os` 与 `with_guest_os`。字段和 `Image` 持久化元数据均使用 `#[serde(default)]` 兼容旧 JSON；Windows 仅允许 amd64 + `source` + digest，加载缓存时还必须匹配请求的 `guest_os`。
- **Alternatives considered:** 在 `Distro` 加 Windows（语义混乱且增加枚举变体也会影响穷尽 match）；嗅探镜像（隐式且易错）；宣称新增公开字段完全兼容（与 Rust 构造规则不符）。
- **Consequences:** `0.3.x → 0.4.0` 是 0.x 的源码兼容破坏。迁移方式是把字面量构造改为 `ImageConfig { guest_os, ..ImageConfig::default() }` 或 builder 链；`ImageConfig::default()` 与已有 builder 的运行行为不变。
- **Compatibility window/evidence:** 当前仓库已发现字面量构造 `src/image.rs:855-869`，实现时必须迁移并保留一个旧 JSON 反序列化测试。README 和 `0.4.0` CHANGELOG 必须单列 Migration；没有可消除外部字面量破坏的 deprecation 窗口，因此不得标为 non-breaking。
- **Revisit when:** 出现第三种客户机 OS 或准备 1.0 API 冻结时。

### ADR-WIN-02: Windows 传输方案（临时接受 TCP；实测回写待 SPK-01）

- **Status:** Accepted (provisional) —— 方案已选定以解除实现阻塞；真实 Windows 实测回写仍属 `SPK-01`，该 spike 当前 `blocked`（`DEP-01`/`DEP-02`）。
- **Context:** Windows OpenSSH 不监听当前 Linux 路径使用的 AF_VSOCK；现有客户端还固定 root/`true` probe 并无条件接受服务端密钥。
- **Decision:** 本期选定 **Windows-only TCP**：`GuestOs::Windows` 为显式 opt-in，Linux 保持 vsock-only；地址来自宿主 libvirt DHCP lease 并按本 VM MAC 绑定（不得调用 `Machine::get_ip` 形成循环）；客户端仅公钥认证，服务端主机密钥必须 pinning，密码禁用。Hyper-V socket↔sshd 桥、WinRM、qemu-guest-agent 作为备选保留但本期不实现。
- **Required invariants:** 首次 SSH 前的地址/端点发现不得调用 `Machine::get_ip` 形成循环；客户端公钥认证与服务端主机密钥校验都必须存在；密码认证禁用；Linux 保持 vsock-only。若选 TCP，设置 `GuestOs::Windows` 就是显式 opt-in，默认 Linux 不开启 TCP，监听/转发只能暴露到文档批准的网络边界。
- **Consequences:** 方案必须覆盖用户名、readiness probe、SFTP、第二会话策略、双机端点隔离、超时清理和重启重连。若需新增公开配置，必须同步修订 ADR-WIN-01、版本说明和 `OSX-01`，不得在实现卡中临时增加。TCP 方案相对 vsock 缩小了隔离面，因此必须同时满足 pinning、MAC 绑定和网络边界三条不变量。
- **Revisit when:** `SPK-01` 取得真实 Windows 实测证据并回写本 ADR 时；或实测证明 TCP 不可行时改选备选方案并重审 `TRN-01`。

### ADR-WIN-03: Windows 部署方案（临时接受“预配置镜像 + 首启 seed 盘”；实测回写待 SPK-02）

- **Status:** Accepted (provisional) —— 方案已选定以解除实现阻塞；真实 Windows 实测回写仍属 `SPK-02`，该 spike 当前 `blocked`（`DEP-01`/`DEP-02`）。
- **Context:** cloud-init NoCloud 不适用于 Windows，部署方式会决定 seed、用户、主机密钥和首次启动验证。已安装好的 Windows qcow2 不会自动消费 `autounattend.xml`（该机制仅对安装介质生效），因此不能把 autounattend 当作对既有镜像的通用部署手段。
- **Decision:** 选定 **预配置镜像 + 每 VM 首启 seed 盘**：镜像提供方交付已通用化（sysprep/generalize 完成）且已烘焙首启任务的 Windows qcow2；Qlean 首启附加一块只读 seed 介质（ISO9660，内容为客户端公钥、随机生成的每 VM SSH host 私钥、首启脚本约定参数），由镜像内首启任务读取并落盘，部署成功后删除 seed 并清理首启标记。autounattend 与 Cloudbase-init 仅在镜像制作方重新安装系统时使用，不作为 Qlean 运行时部署机制。
- **Required invariants:** VirtIO 存储/网络驱动可用；部署后可通过公钥 SSH；管理员 key 的文件位置和 ACL 符合 Windows OpenSSH 规则；不禁用密码、不生成可 pinning 的主机密钥或依赖静态明文密码的方案不得选为 go。首启任务读取 seed 的路径与校验方式必须由 README 镜像制作契约明确规定，镜像缺失该契约时必须返回可操作错误而非静默继续。
- **Consequences:** 预 sysprep 方案也不能跳过凭据注入与部署验收；若需要新增公开驱动/固件配置，先回到 `OSX-01` 修订 API。镜像制作责任明确划归镜像提供方，README 必须写出该契约与自检命令。
- **Revisit when:** `SPK-02` 取得真实首启/重启证据并回写本 ADR 时；或实测证明首启 seed 契约不可行时改选 autounattend/Cloudbase-init 并重审 `OSX-03`。

### ADR-WIN-04: Windows 固件基线统一为 UEFI + TPM 2.0

- **Status:** Accepted
- **Context:** `GuestOs::Windows` 没有 Windows 版本字段，不能实现含义不明的“Win11 分支可选 vTPM”。统一基线比隐式探测镜像版本更可维护。
- **Decision:** 所有 Windows VM 使用 OVMF 和每 VM 独立的 TPM 2.0 状态，`swtpm` 是必需依赖。Secure Boot 的具体 OVMF/密钥配置由 `SPK-02` 验证并回写；若不能支持某个版本，收缩支持矩阵，不静默降级固件。
- **Alternatives considered:** 按镜像名猜版本（不可靠）；无 TPM 静默启动（可能让 Win11 在安装/启动阶段才失败）。
- **Consequences:** OVMF vars 与 vTPM 状态须随 run dir 隔离、在重启间保留并按 `MachineConfig.clear` 清理；Windows TCG 不在核心支持范围。
- **Revisit when:** 引入显式 Windows 版本/固件配置且完成兼容评审时。

### ADR-WIN-05: `exec` 使用 PowerShell 原始命令字符串

- **Status:** Accepted
- **Context:** 现有 `exec` 并不做参数转义，而是把单个字符串交给 SSH exec channel；Windows 需要明确 shell 与退出码语义。
- **Decision:** Windows OpenSSH 默认 shell 配置为 PowerShell，`exec` 输入按 PowerShell 脚本原文传递，不套用 UNIX escape。`status.success()` 仅在退出码 0 时为真；0..=255 必须可从 `status.code()` 取回，超出可表示范围时返回可操作错误而非截断。stdout/stderr 分通道保留原始字节。
- **Alternatives considered:** 模拟 POSIX 参数数组（与现有 API 不符）；继续使用宿主 UNIX escape（语义错误）；静默截断 Windows 退出码（掩盖结果）。
- **Consequences:** 空命令、特殊字符、非零和大退出码需要单测/冒烟；Linux 既有路径不变，任何共享 helper 修复必须单列兼容说明。
- **Revisit when:** 公开 API 改为结构化 argv 或自定义 Output 时。

## 全局工程约束

按 `plan-template.md` 的 GC-01~GC-11 生效。本计划额外强调：

- **GC-02 单一事实源：** OS 分派、传输端点、SSH 身份/主机密钥和客户机路径各有唯一抽象；禁止在各方法散落 `if guest_os == Windows` 或继续用宿主 `PathBuf::join` 猜客户机语义。
- **GC-03 公开 API 兼容：** 新增字段的源码破坏与迁移必须同卡写入 README/CHANGELOG；不得用“有默认值”替代兼容分析。
- **GC-07 安全默认值：** 客户端仅公钥认证；Windows TCP（若选）还必须 pinning 服务端主机公钥。私钥、静态密码和未脱敏日志不得进入证据；seed 中不得写静态管理密码。
- **GC-08 生命周期：** OVMF vars、vTPM、端口/地址发现状态、seed 与 QEMU 进程均按 run dir 隔离并在失败时清理；重启所需状态不能在 `shutdown` 时误删。

## 执行检查必备需求（强制）

按 `plan-template.md` 的 ER-01~ER-14 生效。本计划补充：

- **ER-04 状态闭环：** family/no-release 卡完成自身 A/B + review 后即可 `complete`；继承发布点的 C/D 只表示覆盖归属，不构成子卡完成前的循环等待。`REL-01` 独自等待家族 C/D。
- **ER-06 同卡文档：** 包括 `IP-01` 在内的公开行为变化都必须同卡更新 README 和 CHANGELOG；不再由独立补文档卡代做。
- **ER-13/14 Windows 门：** CI 只编译 Windows test target。每个声称支持的版本必须在 Linux KVM 验证宿主机运行核心 Windows 冒烟；缺镜像/宿主时相关任务或发布为 `blocked`。只有 Linux VM 环境缺口或额外 TCG 矩阵可按模板登记 `DEFER-*`，核心 Windows 验收不可延后。
- **VCS 兼容：** Git checkout 使用模板中的 Git 命令；当前 Libra checkout 使用等价的 `libra status/add/commit/push`，证据记录实际命令。不得在两种元数据之间转换或清理用户已有脏状态。

## 实施顺序

依赖边（`A -> B` 表示 A 先于 B）。顺序边同时解决共享计划、状态、源码与文档写集冲突：

- `OSX-01 -> OSX-02 -> OSX-03 -> TRN-01 -> EXE-01 -> IP-01 -> FS-01 -> REL-01`
- `SPK-02 -> OSX-02`（固件/Secure Boot 实测回写；在 `SPK-02` 解除前以 ADR-WIN-03/04 的临时接受值为准）
- `SPK-01 -> TRN-01`（传输实测回写；在 `SPK-01` 解除前以 ADR-WIN-02 的临时接受值为准）
- `SPK-01 -> SPK-02`

**环境消歧结论（R5, 2026-11-12）：** `DEP-01`（合法 Windows qcow2 + sha256）与 `DEP-02`（Linux KVM Windows 验证宿主机）经审计不可用：本 checkout 环境下 `qemu-system-x86_64`、`qemu-img`、`swtpm`、`xorriso`、`virsh`、`qemu-bridge-helper` 与 OVMF 均缺失，且无免密 `sudo` 安装通道、无合法 Windows 镜像。因此：

- `SPK-01`/`SPK-02` 置 `blocked`，其真实 Windows 实测 AC 不视为通过；
- `ADR-WIN-02`/`ADR-WIN-03` 以 **临时接受（provisional）** 方式选定方案，解除实现卡阻塞，使不依赖 Phase 0 实测证据的代码可以落地；
- 原 `SPK-02 -> OSX-01` 边取消：`OSX-01` 只新增 OS 维度与镜像校验，不消费任何 Phase 0 产物；
- 任何需要真实 Windows KVM 的冒烟项（`OSX-02` 生命周期、`OSX-03` 首启、`TRN-01` 连接与池、`IP-01`/`FS-01` 真实往返、`EXE-01` PowerShell 冒烟）只能记为 `blocked` 环境缺口，不得声称通过；
- `REL-01` 在 `DEP-01`/`DEP-02` 与两个 spike 解除前不得发布。

### 依赖登记表

| ID | direction | 类型 | 对象 | Owner | 产物与可用性判据 | 证据 | 超时与失败策略 |
|---|---|---|---|---|---|---|---|
| DEP-01 | incoming | 外部前置 | 每个拟声明支持的 Windows 版本的合法 qcow2 + sha256 | 计划 Owner | 镜像版本明确、可合法使用、digest 核对通过；至少覆盖最终支持矩阵每一行 | 2026-11-12 审计：未提供（无任何 Windows qcow2 或 digest 可用） | 未提供则 `SPK-01`/`SPK-02` 阻塞；未测版本从支持矩阵移除；不得延后核心验收后发布 |
| DEP-02 | incoming | 外部前置 | Linux KVM Windows 验证宿主机 | 计划 Owner | QEMU/OVMF/swtpm/libvirt/xorriso/bridge-helper 可用，KVM 与 qlbr0 网络实测可用 | 2026-11-12 审计：`/dev/kvm` 存在但 `qemu-system-x86_64`/`qemu-img`/`swtpm`/`xorriso`/`virsh`/`qemu-bridge-helper`/OVMF 全部缺失，`sudo` 需密码（无安装通道） | 不可用则相关 spike/Windows 门与发布阻塞；TCG 或 CI `--no-run` 不能替代 |

### 发布分组与并发窗口

| ID | 成员 | 唯一发布点 | 窗口规则 | 失败回滚顺序 | 理由 |
|---|---|---|---|---|---|
| REL-01 | `OSX-01`, `OSX-02`, `OSX-03`, `TRN-01`, `EXE-01`, `IP-01`, `FS-01` | `REL-01` | 子卡不单独 bump/publish；发布点一次 minor 到 0.4.0；窗口期禁止插入其它发布 | 发布后按依赖逆序前滚修复并发新版本 | `GuestOs` 字段是源码破坏，且中间版本会暴露尚未支持的 Windows 配置，不能作为独立可用切片发布 |

**并发声明:** 全串行。每张卡都会写本计划和/或 `plan-status.md`，实现卡还共享 `src/machine.rs`、`src/ssh.rs`、README 或 CHANGELOG；`Implementation write set` 的序列化关系与上方顺序边一致。

**发布者:** 计划 Owner（唯一 Agent/人）。

**发布窗口顺序:** `REL-01` 单独执行版本 bump、提交、推送、CI、tag、GitHub Release 与按需 crates.io publish。

### Phase 0: 基线冻结与可行性消歧

**目标:** 用真实镜像与 KVM 宿主机判定传输、固件和部署路径。

**进入条件:** 本计划 review PASS；`DEP-01`/`DEP-02` 可用。

**退出条件:** `SPK-01`/`SPK-02` 均为 go；ADR-WIN-02/03 转为 Accepted；受影响任务卡已写入具体方案并重审 PASS。任一 no-go 则阻塞或正式改范围，不进入实现。

### Phase 1: guest-OS、固件与部署

**目标:** 落地 OS/缓存校验、Windows QEMU 生命周期和首次部署。

**进入条件:** Phase 0 完成。

**退出条件:** `OSX-01`/`OSX-02`/`OSX-03` 完成；Windows 首启部署与重启状态持久化通过验证。

### Phase 2: 传输与运行时语义

**目标:** 打通安全传输、PowerShell exec、IP 和文件工作流。

**进入条件:** Phase 1 完成。

**退出条件:** `TRN-01`/`EXE-01`/`IP-01`/`FS-01` 完成；核心单机、重启和双机池冒烟通过。

### Phase 3: 聚合发布

**目标:** 收口文档/CI/测试证据并发布 0.4.0。

**进入条件:** Phase 2 完成，所有子卡 `Acceptance=complete`。

**退出条件:** `REL-01` 完成，本地与远端发布证据写入本计划。

## 任务卡

任务 ID 前缀：`SPK-`（spike）、`OSX-`（OS/固件/部署）、`TRN-`（传输）、`EXE-`（exec）、`IP-`（IP）、`FS-`（文件）、`REL-`（发布）。`DOC-01` 已在 R1 合并进 `REL-01`，不再是独立任务。

### 任务卡粒度规则（强制）

按 `plan-template.md` 的 G-01~G-11 生效。

#### 字段全局默认与例外

- **Release boundary 默认:** `independent`
- **Task type 默认:** `implementation`
- **Rollback mode 默认:** `revert`
- **Security and privacy 默认:** `继承 GC-07`
- **Performance budget 默认:** `继承 GC-10`

**默认覆盖：**

| 任务 | 字段 | 取值与理由 |
|---|---|---|
| `SPK-01`/`SPK-02` | Release boundary | `no-release`（spike 不发布） |
| `OSX-01`~`FS-01` | Release boundary | `family child of REL-01` |
| `REL-01` | Task type / Release boundary / Version increment | `release` / `family release point of REL-01` / `minor`（0.x 源码破坏） |

**规则 waiver（`EX-*`）：** 无。

#### 任务卡粒度审计表

`prod-files` 只计生产源码、manifest/lockfile 与 CI 配置，不计计划文档、README、CHANGELOG 或测试；`AC`/`VER` 按卡内实际独立条目计数。

| 任务 | type | axis | recovery | complete | self-contained | AC | VER | landing / prod-files | scope | deps | writeset | release | split-from | exception |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SPK-01 | spike | Windows 传输可行性 | 无生产改动 | yes | yes | 6/8 | 2/8 | 0/0 | M | DEP-01,DEP-02 | no-overlap（串行起点） | no-release | N/A | N/A |
| SPK-02 | spike | Windows 固件/部署可行性 | 无生产改动 | yes | yes | 6/8 | 2/8 | 0/0 | M | SPK-01,DEP-01,DEP-02 | 序列化于 SPK-01 | no-release | N/A | N/A |
| OSX-01 | implementation | GuestOs 与镜像校验 | revert | yes | yes | 7/8 | 5/8 | 3/3 | M | none | no-overlap（串行起点） | family child | N/A | N/A |
| OSX-02 | implementation | Windows 固件与 QEMU 生命周期 | revert | yes | yes | 8/8 | 5/8 | 3/3 | M | SPK-02,OSX-01 | 序列化于 OSX-01 | family child | N/A | N/A |
| OSX-03 | implementation | Windows 首次部署 | revert | yes | yes | 8/8 | 7/8 | 2/2 | M | OSX-02 | 序列化于 OSX-02 | family child | N/A | N/A |
| TRN-01 | implementation | Windows 安全传输 | revert | yes | yes | 8/8 | 7/8 | 4/3 | M | SPK-01,OSX-03 | 序列化于 OSX-03 | family child | N/A | N/A |
| EXE-01 | implementation | PowerShell exec 语义 | revert | yes | yes | 5/8 | 5/8 | 2/2 | S | TRN-01 | 序列化于 TRN-01 | family child | N/A | N/A |
| IP-01 | implementation | get_ip 语义 | revert | yes | yes | 4/8 | 5/8 | 2/2 | S | EXE-01 | 序列化于 EXE-01 | family child | N/A | N/A |
| FS-01 | implementation | Windows 文件语义 | revert | yes | yes | 8/8 | 5/8 | 3/3 | M | IP-01 | 序列化于 IP-01 | family child | N/A | N/A |
| REL-01 | release | 聚合发布 | immutable-release | yes | yes | 8/12 | 7/12 | 1/3 | S | 全部任务卡 | 序列化于 FS-01 | family release point | N/A | N/A |

#### Verification 判定口径

按 `plan-template.md` 生效。所有 `tests/windows_machine.rs` 用例均为 `(new)`、默认 `#[ignore]` 并由 `serial_test` 串行；CI 用 `cargo test --no-run` 编译。实际运行必须显式 `--ignored --test-threads=1`，并满足 `DEP-01`/`DEP-02`。命令中的 `/path/to/windows.qcow2` 与 digest 是执行者替换的参数，证据只记录 sanitized 标识，不记录私有绝对路径。

### Task SPK-01: Windows 传输可行性 spike

**Task type:** `spike`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 用真实 Windows VM 选定连接、鉴权、地址发现与会话方案，产出 ADR-WIN-02 和可直接执行的 `TRN-01` 输入。

**Out of scope:**
- 不实现生产传输代码（由 `TRN-01` 承接）。
- 不决定部署方案（由 `SPK-02` 承接）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| vsock-only、root 用户、true probe | `src/ssh.rs:571-630` |
| 服务端 key 无条件接受 | `src/ssh.rs:89-104` |
| 0.3.0 移除 TCP fallback | `CHANGELOG.md:19-24` |

**Acceptance criteria:**

- [ ] 对比 TCP、Hyper-V socket 桥、WinRM、qemu-guest-agent 的可行性、维护成本和对 0.3.0 决策的影响。
- [ ] 在真实 Windows VM 上完成最小连接、认证、命令和 SFTP 验证，记录 sanitized 结果。
- [ ] 明确首次 SSH 前的地址/端点发现，证明不依赖 `Machine::get_ip`，且双机不会串用端点。
- [ ] 明确服务端主机密钥 pinning、客户端公钥、禁密码、网络暴露边界；若选 TCP，写清 Windows opt-in 与 Linux 默认关闭。
- [ ] 明确用户名、readiness probe、重启重连、第二会话与 `InteractiveShell` unsupported 策略。
- [ ] 产出 go/no-go；go 时把 ADR-WIN-02 改为 Accepted 并回写 `TRN-01` 的具体实现/验证参数，no-go 时阻塞计划。

**Verification:**

- [ ] `git status --short --branch` 或 `libra status --short --branch` 确认无生产代码改动，已有用户脏状态不清理。
- [ ] 对比表、go/no-go、宿主机/镜像 sanitized 摘要写入「实施证据汇总」并同步状态视图。

**Full-suite trigger:** `N/A`

**Dependencies:** `DEP-01`（真实镜像）、`DEP-02`（KVM 验证宿主机）

**Deliverables:** 本计划内 ADR-WIN-02、对比表、go/no-go、`TRN-01` 具体输入。

**Implementation write set:** `docs/plan/plan-20261104-windows-guest.md`、`docs/plan/plan-status.md`（无生产代码）

**Release write set:** `N/A`

**Files likely touched:** 同 Implementation write set。

**Docs and compatibility impact:** 仅计划文档；若推翻 TCP 决策，由 `TRN-01` 更新 README/CHANGELOG。

**Rollback mode:** `revert`

**Security and privacy:** 不记录私钥、密码、token、私有绝对路径或原始 tool payload。

**Performance budget:** 记录连接/启动 wall-clock 量级；不承诺 TCG 性能。

**Estimated scope:** `M`

**Version increment:** `N/A`

**Release boundary:** `no-release`

**C/D coverage from:** `REL-01`（仅覆盖归属，不阻塞本卡完成）

**Granularity:** `type=spike; axis=Windows 传输可行性; recovery=无生产改动; complete=yes; self-contained=yes; AC=6/8; VER=2/8; landing=0; prod-files=0; scope=M; deps=DEP-01,DEP-02; writeset=no-overlap（串行起点）; release=no-release; split-from=N/A; exception=N/A`

### Task SPK-02: Windows 固件与部署可行性 spike

**Task type:** `spike`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 验证统一 OVMF + TPM 2.0 基线、Secure Boot、VirtIO 与部署方案，产出 ADR-WIN-03 和具体实现输入。

**Out of scope:**
- 不实现生产引导/部署代码（由 `OSX-02`/`OSX-03` 承接）。
- 不重复传输方案对比（由 `SPK-01` 承接）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| QEMU 无 pflash/vTPM | `src/qemu.rs:74-169` |
| seed 为 cloud-init NoCloud | `src/machine.rs:220-399` |

**Acceptance criteria:**

- [ ] 验证 OVMF code/vars、Secure Boot 和每 VM TPM 2.0 参数，区分 Windows 10/11 要求，禁止静默降级。
- [ ] 验证 viostor/netkvm 的预装或注入路径；若需新公开配置，先修订 ADR-WIN-01/OSX-01。
- [ ] 对比 autounattend、Cloudbase-init、预 sysprep，选定一种并说明镜像制作责任。
- [ ] 手工完成首启部署、关机、重启，验证 OVMF vars、TPM 状态和部署结果持久化。
- [ ] 验证管理员公钥文件/ACL、禁密码、PowerShell 默认 shell 和可供客户端 pinning 的主机公钥，不依赖静态明文密码。
- [ ] 产出 go/no-go；go 时回写 ADR-WIN-03 及 `OSX-02`/`OSX-03` 具体参数和命令（含实测首启部署时长与推荐部署超时值），no-go 时阻塞计划。

**Verification:**

- [ ] `git status --short --branch` 或 `libra status --short --branch` 确认无生产代码改动。
- [ ] 真实 KVM 首启/重启记录、关键参数、go/no-go 写入「实施证据汇总」并同步状态视图。

**Full-suite trigger:** `N/A`

**Dependencies:** `SPK-01`（共享计划写集串行）、`DEP-01`、`DEP-02`

**Deliverables:** 本计划内 ADR-WIN-03、部署对比表、go/no-go、具体任务卡修订。

**Implementation write set:** `docs/plan/plan-20261104-windows-guest.md`、`docs/plan/plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** 同 Implementation write set。

**Docs and compatibility impact:** 仅计划文档；公开配置变化必须先回到 `OSX-01` 评审。

**Rollback mode:** `revert`

**Security and privacy:** 固件/TPM 状态隔离；证据不含私钥、静态密码或私有路径。

**Performance budget:** 记录首启与重启 wall-clock；仅 KVM 结果可作为 go 证据。

**Estimated scope:** `M`

**Version increment:** `N/A`

**Release boundary:** `no-release`

**C/D coverage from:** `REL-01`（仅覆盖归属）

**Granularity:** `type=spike; axis=Windows 固件/部署可行性; recovery=无生产改动; complete=yes; self-contained=yes; AC=6/8; VER=2/8; landing=0; prod-files=0; scope=M; deps=SPK-01,DEP-01,DEP-02; writeset=序列化于 SPK-01; release=no-release; split-from=N/A; exception=N/A`

**Lifecycle / Acceptance:** `done` / `complete`

**Description:** 新增 OS 维度、builder、持久化默认值和镜像/source/cache 校验，防止 Windows 配置落到 Linux 镜像。

**Out of scope:**
- 不实现 Windows 引导、部署、传输或命令语义（由后续卡承接）。
- 不改变 `Distro` 的 Linux 发行版语义。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 全公开 `ImageConfig` 与字面量构造 | `src/image.rs:68-81,855-869` |
| 缓存加载只核对 digest | `src/image.rs:645-717` |
| 公开重导出 | `src/lib.rs:37-43` |

**Acceptance criteria:**

- [x] `GuestOs`、`ImageConfig::guest_os`（默认 Linux）与 `with_guest_os` 已公开并重导出，相关 Serde 字段使用默认值。
- [x] Windows 仅接受 amd64 + source + digest；缺任一项或不支持架构时提前返回可操作错误，Linux 内置目录逻辑不变。
- [x] `Image`/`MachineImage` 携带 `guest_os`，后续分派有唯一事实源。
- [x] 缓存加载同时匹配请求的 `guest_os`；旧元数据默认 Linux，不能把 Linux 缓存交给 Windows 配置。
- [x] `ImageConfig::default()` 与既有 builder 的 Linux 行为不变，仓库内字面量构造按 ADR 迁移。
- [x] README API/Migration 与 CHANGELOG Added/Changed 同卡说明源码破坏、迁移方式和 0.4.0 目标。
- [x] `(new)` 单测覆盖默认值、旧 JSON、无效组合、缓存 OS 不匹配和 builder。

**Verification:**

- [x] `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 均通过（0 warning）
- [x] `cargo test --lib guest_os`：4 passed（默认值/旧 JSON/builder/缓存 OS 不匹配）
- [x] `cargo test --lib image::tests`：18 passed, 0 failed
- [x] `cargo test --no-run`：全部 test target 编译通过
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` —— 本机无 QEMU/libvirt/xorriso（DEP-02 不可用），登记为 `DEFER-04`；卡内已用 `cargo test --lib` + `cargo test --no-run` 覆盖 ER-14 的替代门。

**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 新增 API | `GuestOs { Linux, Windows }`（默认 `Linux`）、`ImageConfig::guest_os`、`with_guest_os`、`Image::guest_os()`、`Machine::guest_os()`；`pub use image::GuestOs` |
| 校验 | `ImageConfig::validate()`：Windows 强制 `GuestArch::Amd64` 与显式 `source`+`digest`，错误文案含修复路径 |
| 缓存隔离 | `image_cache_name` 按 `guest_os` 命名，Windows 使用 `windows-` 前缀；`ensure_cached_guest_os` 拒绝 OS 不匹配条目（旧 JSON 默认 Linux） |
| 单一事实源 | `Image::guest_os` 随元数据持久化；`MachineImage::guest_os` 由 `image.guest_os()` 填充；公开 `Machine::guest_os()` 供后续卡分派 |
| 迁移 | 仓库内 `ImageConfig` 字面量改为 `..ImageConfig::default()`；README 新增 Guest OS 小节与 Migration；CHANGELOG `[Unreleased]` Added/Changed/Migration |
| 提交 | `34c6eb9` |

**Dependencies:** 无（R5 取消 `SPK-02 -> OSX-01` 边：本卡不消费任何 Phase 0 产物；串行写集起点）

**Deliverables:** `N/A`

**Implementation write set:** `src/image.rs`、`src/lib.rs`、`src/machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/image.rs`, `src/lib.rs`, `src/machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 新 API 与 Migration；CHANGELOG 明确 0.x minor 源码破坏。

**Rollback mode:** `revert`

**Security and privacy:** digest 错误不得泄露私有 URL 查询参数或完整本地路径。

**Performance budget:** 缓存 OS 校验为 O(1)，不得重复计算镜像 hash。

**Estimated scope:** `M`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=GuestOs 与镜像校验; recovery=一次 revert; complete=yes; self-contained=yes; AC=7/8; VER=5/8; landing=3; prod-files=3; scope=M; deps=none; writeset=no-overlap（串行起点）; release=family child; split-from=N/A; exception=N/A`

### Task OSX-02: Windows 固件与 QEMU 生命周期

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 按 ADR-WIN-03/04 实现 OVMF、Secure Boot、VirtIO 设备和每 VM vTPM，并验证 QMP 关机与重启状态。

**Out of scope:**
- 不生成首次部署内容（由 `OSX-03` 承接）。
- 不实现 SSH 传输（由 `TRN-01` 承接）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 当前 QEMU 无 pflash/vTPM，KVM 不可用时回退 TCG | `src/qemu.rs:74-169` |
| QMP powerdown 与 running 查询 | `src/machine.rs:518-576,803-810` |
| VM 资源默认 core=2 / mem=4096MB，未对 Windows 最低资源做评估 | `src/machine.rs:63-68,156-157` |

**Acceptance criteria:**

- [ ] Windows 使用 ADR 确定的 OVMF code/vars 与 Secure Boot 参数，vars 每 VM 独立且重启保留，Linux 参数不变。
- [ ] 每 VM 创建 TPM 2.0/swtpm 状态，权限最小化、路径隔离并按 clear 语义清理。
- [ ] VirtIO disk/network 与镜像驱动要求一致；缺驱动或固件能力时给出可操作错误，不静默改设备或固件。
- [ ] OVMF/swtpm 缺失有明确错误；Windows 不可用时不得静默回退 TCG，Linux KVM/TCG 行为不变。
- [ ] QMP/ACPI `shutdown`、`is_running`、shutdown 后 `spawn` 在 Windows 生命周期中工作，重启保留固件/TPM/overlay 状态。
- [ ] `(new)` 单测/集成测试覆盖参数、缺依赖、状态隔离、关机与重启；资源无泄漏。
- [ ] README Host Setup/固件矩阵与 CHANGELOG Added 同卡更新。
- [ ] Windows VM 资源默认值（core=2、mem=4096MB）对照 Windows 10/11 最低要求评估；README Host Setup 写明 Windows 最低与推荐资源值，默认不足时收缩支持矩阵或显式调整 Windows 默认值，不得静默降级。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib qemu`
- [ ] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_firmware_lifecycle -- --ignored --exact --test-threads=1`

**Full-suite trigger:** `T-1: 共享 QEMU 启动路径`

**Dependencies:** `SPK-02`（固件 ADR）、`OSX-01`（GuestOs 与串行顺序）

**Deliverables:** `N/A`

**Implementation write set:** `src/qemu.rs`、`src/machine.rs`、`src/utils.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`（现有 CI `cargo test --no-run` 自动编译新 target，无需改 workflow）

**Release write set:** `N/A`

**Files likely touched:** `src/qemu.rs`, `src/machine.rs`, `src/utils.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 必须写 OVMF/swtpm/Secure Boot 与 KVM 前提；CHANGELOG Added。

**Rollback mode:** `revert`

**Security and privacy:** vTPM/OVMF vars 不作为公共共享状态；日志不得输出密钥材料。

**Performance budget:** 每 VM 固定数量固件/TPM 文件；无全宿主扫描，记录 KVM 启动时间。

**Estimated scope:** `M`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=Windows 固件与 QEMU 生命周期; recovery=一次 revert; complete=yes; self-contained=yes; AC=8/8; VER=5/8; landing=3; prod-files=3; scope=M; deps=SPK-02,OSX-01; writeset=序列化于 OSX-01; release=family child; split-from=N/A; exception=N/A`

### Task OSX-03: Windows 首次部署

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 按 SPK-02 回写的 ADR-WIN-03 实现首次部署、SSH 身份与主机密钥 provisioning；本卡在 spike 前不预设 autounattend。

**Out of scope:**
- 不实现生产连接重试/传输抽象（由 `TRN-01` 承接）。
- 不实现 exec/IP/文件语义（由后续卡承接）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| Linux seed 生成与 `Machine::new` | `src/machine.rs:181-414` |
| `Machine::init`/`spawn` | `src/machine.rs:416-464` |
| `ssh_timeout` 默认 KVM 180s / TCG 300s，仅覆盖连接等待 | `src/machine.rs:72,165-167` |

**Acceptance criteria:**

- [ ] Windows 分支严格实现 ADR-WIN-03 选定方案，Linux cloud-init seed 字节语义不变。
- [ ] 公钥写入 Windows OpenSSH 对应该账号的正确文件并设置 ACL（管理员场景含 `administrators_authorized_keys`），密码认证禁用且无静态明文管理密码。
- [ ] sshd、PowerShell 默认 shell、SFTP 与 ADR 选定的 readiness 条件已配置，用户名作为单一事实源传给传输层。
- [ ] 每 VM 生成独立 SSH host key，并把可 pinning 的公钥交给 `Machine`；若采用 seed 注入，host 私钥必须随机生成、seed 权限 0600、仅首启附加且在部署成功后删除 seed；重启后 host key 与部署结果保持稳定。
- [ ] `init` 首启部署及后续 `spawn` 可用；test-only 连接助手取得真实首启证据，不把该助手当作生产传输完成。
- [ ] `(new)` 单测覆盖 seed/配置内容、敏感信息不落日志、首次/普通启动差异及 host-key seed 清理。
- [ ] README 镜像制作/部署/账号要求与 CHANGELOG Added 同卡更新。
- [ ] Windows 首启部署超时参数化：部署等待维度（autounattend/sysprep/sshd ready）独立于 Linux 默认 180s/300s，默认值按 `SPK-02` 实测首启时长推荐并写入 README；超时必须返回可操作错误，残留状态按故障恢复矩阵处理。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib windows_deploy`
- [ ] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_first_boot -- --ignored --exact --test-threads=1`
- [ ] 首启后关机、spawn 与 host-key seed 清理的 sanitized 手工/测试证据写入「实施证据汇总」。
- [ ] `cargo test --lib windows_deploy_timeout`（新增超时维度单测：默认值与超时错误路径）。

**Full-suite trigger:** `T-1: 共享 seed 与 Machine 初始化路径`

**Dependencies:** `OSX-02`（可引导的 Windows QEMU 生命周期）

**Deliverables:** `N/A`

**Implementation write set:** `src/machine.rs`、`src/windows.rs`（新）、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/machine.rs`, `src/windows.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 写清 ADR 选定的部署方式、镜像与账号要求；CHANGELOG Added。

**Rollback mode:** `revert`

**Security and privacy:** 客户端私钥永不进入 seed；host 私钥只能按上述每 VM 首启注入规则处理，host 私钥、TPM 状态和客户端私钥不得写入证据，seed 日志只保留 sanitized 结构摘要。

**Performance budget:** seed 生成只遍历明确输入文件，禁止扫描宿主目录。

**Estimated scope:** `M`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=Windows 首次部署; recovery=一次 revert; complete=yes; self-contained=yes; AC=8/8; VER=7/8; landing=2; prod-files=2; scope=M; deps=OSX-02; writeset=序列化于 OSX-02; release=family child; split-from=N/A; exception=N/A`

### Task TRN-01: Windows 安全传输实现

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 按 ADR-WIN-02 实现地址发现、传输、双端鉴权、会话与资源隔离，覆盖 init/spawn 和 MachinePool。

**Out of scope:**
- 不改变 Linux vsock-only 路径。
- PowerShell、IP 解析和路径语义分别由 `EXE-01`/`IP-01`/`FS-01` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 固定 vsock/root/true 与任意 server key | `src/ssh.rs:89-104,571-630` |
| launch 与第二 interactive 会话 | `src/machine.rs:466-493,812-919` |
| bridge DHCP 网络 | `src/utils.rs:161-227` |

**Acceptance criteria:**

- [ ] 按 ADR 建立 Windows 会话；地址/端点发现在 SSH 前完成且不调用 `get_ip`，发现的 IP 可交给 Machine 缓存。
- [ ] 使用 ADR 的用户名与 Windows readiness probe；客户端公钥成功、密码禁用，Linux root/vsock 行为不变。
- [ ] 校验部署阶段 pinning 的 SSH host key，错误 key 必须失败；若选 TCP，仅 GuestOs::Windows 显式启用且网络暴露符合 ADR。
- [ ] init 与 shutdown 后 spawn 都能重连；连接超时、QEMU 早退、地址冲突均清理进程和临时端点，Windows TCP 不检查 `/dev/vhost-vsock`。
- [ ] 两台 Windows VM 池并发 init 时地址、端口（如有）、host key 和会话不串用，能分别执行 readiness。
- [ ] Windows `open_interactive_shell` 立即返回明确 unsupported 错误，不创建 vsock 连接或遗留进程。
- [ ] `(new)` 测试覆盖错误 host key、超时/清理、重启、双机隔离与 unsupported 分支。
- [ ] README 传输/安全/池说明与 CHANGELOG Added/Changed 同卡更新。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib ssh`
- [ ] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_transport -- --ignored --exact --test-threads=1`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_pool -- --ignored --exact --test-threads=1`
- [ ] 错误 host key、超时清理与 unsupported 的 sanitized 结果写入「实施证据汇总」。

**Full-suite trigger:** `T-1: 共享 SSH 与 Machine launch 路径`

**Dependencies:** `SPK-01`（ADR-WIN-02）、`OSX-03`（部署身份/host key 与串行顺序）

**Deliverables:** `N/A`

**Implementation write set:** `src/ssh.rs`、`src/machine.rs`、`src/utils.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/ssh.rs`, `src/machine.rs`, `src/utils.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 写地址发现、host key、网络暴露和 InteractiveShell 限制；CHANGELOG 记录 Windows-only 传输决策。

**Rollback mode:** `revert`

**Security and privacy:** 禁止任意 server key 接受、密码回退或未授权 TCP 暴露；日志不输出私钥/密码。

**Performance budget:** 地址发现有界轮询且纳入 ssh_timeout；双机测试记录总启动时间，禁止无界重试。

**Estimated scope:** `M`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=Windows 安全传输; recovery=一次 revert; complete=yes; self-contained=yes; AC=8/8; VER=7/8; landing=4; prod-files=3; scope=M; deps=SPK-01,OSX-03; writeset=序列化于 OSX-03; release=family child; split-from=N/A; exception=N/A`

### Task EXE-01: PowerShell `exec` 语义

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 按 ADR-WIN-05 实现 Windows 命令、输出和退出码语义，不改变 Linux 命令字符串解释。

**Out of scope:**
- IP 与文件操作由 `IP-01`/`FS-01` 承接。
- 不把 API 改成 argv（尚未排期；出现结构化命令需求时另立计划）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `exec` 原样调用 SSH exec channel | `src/machine.rs:495-516`、`src/ssh.rs:324-370` |
| UNIX escape 属于 `copy`，不是 `exec` | `src/machine.rs:949-955` |

**Acceptance criteria:**

- [ ] Windows 输入原文交给 PowerShell，不调用 UNIX escape；空命令返回明确错误，特殊字符不被二次解释。
- [ ] `status.success()`、0..=255 的 `status.code()`、超范围错误及 stdout/stderr 分离符合 ADR-WIN-05。
- [ ] Linux 路径行为不变；若为复用 helper 修正既有退出码问题，先记录兼容说明和对应测试。
- [ ] `(new)` 单测与 Windows 冒烟覆盖空命令、引号/空格、`whoami`、非零及大退出码。
- [ ] README PowerShell 示例/退出码契约与 CHANGELOG Added 同卡更新。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib windows_exec`
- [ ] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_exec -- --ignored --exact --test-threads=1`

**Full-suite trigger:** `T-1: 共享 Machine/SSH 命令输出与退出码路径`

**Dependencies:** `TRN-01`

**Deliverables:** `N/A`

**Implementation write set:** `src/machine.rs`、`src/ssh.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/machine.rs`, `src/ssh.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 明确 PowerShell 原文与退出码；CHANGELOG Added，若修 Linux bug 另列 Fixed。

**Rollback mode:** `revert`

**Security and privacy:** 命令输出证据须脱敏；不把凭据写入测试命令。

**Performance budget:** 输出仍按 channel 流式读取；不得新增无界命令重试。

**Estimated scope:** `S`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=PowerShell exec 语义; recovery=一次 revert; complete=yes; self-contained=yes; AC=5/8; VER=5/8; landing=2; prod-files=2; scope=S; deps=TRN-01; writeset=序列化于 TRN-01; release=family child; split-from=N/A; exception=N/A`

### Task IP-01: `get_ip` 的 Windows 语义

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 复用传输期发现的可信地址并提供 Windows 查询/校验路径，替换 Linux-only 硬编码。

**Out of scope:** 不负责首次 SSH 前的地址发现（由 `TRN-01` 承接，避免循环依赖）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| Linux 命令与 Machine IP 缓存 | `src/ssh.rs:831-841`、`src/machine.rs:791-800` |

**Acceptance criteria:**

- [ ] Windows 优先返回 `TRN-01` 已发现并与本 VM MAC/端点绑定的 DHCP 地址；需查询时使用 PowerShell 解析并校验结果，不能使用 `hostname -I`。
- [ ] Linux 路径不变；无地址、多个地址无法消歧或查询失败时返回可操作错误，不能选其它 VM 的 lease。
- [ ] `(new)` parser/选择单测与 Windows `get_ip` 冒烟覆盖缓存和重新查询；README 与 CHANGELOG 同卡更新。
- [ ] 双机 `get_ip` 结果各自唯一且与传输实际使用地址一致。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib windows_ip`
- [ ] `cargo test --no-run`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_get_ip -- --ignored --exact --test-threads=1`
- [ ] 双机地址一致性结果写入「实施证据汇总」。

**Full-suite trigger:** `none`（共享 helper 若改变则升级为 T-1 并重审）

**Dependencies:** `EXE-01`（共享源码/文档写集串行）

**Deliverables:** `N/A`

**Implementation write set:** `src/ssh.rs`、`src/machine.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/ssh.rs`, `src/machine.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README `get_ip` Windows 语义；CHANGELOG Added。

**Rollback mode:** `revert`

**Security and privacy:** DHCP 查询须按 VM MAC 精确匹配；证据只写测试网段地址。

**Performance budget:** 优先 O(1) 缓存；重新查询有界，不扫描无关 libvirt 网络。

**Estimated scope:** `S`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=get_ip 语义; recovery=一次 revert; complete=yes; self-contained=yes; AC=4/8; VER=5/8; landing=2; prod-files=2; scope=S; deps=EXE-01; writeset=序列化于 EXE-01; release=family child; split-from=N/A; exception=N/A`

### Task FS-01: Windows 文件路径与文件操作语义

**Task type:** `implementation`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 建立客户机路径抽象并覆盖明确列出的 SFTP/文件操作，POSIX 专属能力明确拒绝。

**Out of scope:**
- UNC/device namespace、Windows ACL/mode 映射、硬链接和符号链接兼容不在本期；不支持时明确报错。
- Linux 文件语义重构不在本卡，除共享路径分派所必需的回归测试外不改变行为。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| upload/download 使用宿主 PathBuf 拼接远程路径 | `src/machine.rs:578-775` |
| 递归遍历与 `create_dir_all` 使用宿主 components/join | `src/ssh.rs:633-829` |
| `copy`=POSIX cp，`set_permissions`=Unix mode | `src/machine.rs:922-1137` |

**Acceptance criteria:**

- [ ] 唯一 `GuestPath`/转换层处理 Windows 盘符、根目录、分隔符、空格、非 ASCII、`..` 与 basename；所有远程 SFTP 入口使用它，不按宿主 Linux PathBuf 解释客户机路径。
- [ ] 文件和目录 `upload`/`download` 往返一致；遇到不支持的链接/路径形式必须报错，不得静默跳过并返回成功。
- [ ] `create_dir`/`create_dir_all`/`exists`/`metadata`/`read`/`read_to_string`/`write`/`read_dir`/`remove_file`/`remove_dir_all`/`rename`/`copy` 在 Windows 按各自文档语义工作，其中 `copy` 不再调用 POSIX `cp`。
- [ ] Windows `hard_link`/`read_link`/`set_permissions` 与 UNC/device 路径明确返回 unsupported；Linux 分支不变。
- [ ] 路径校验防止把不支持输入转成宿主绝对路径或意外逃逸目标根；错误包含 sanitized 路径。
- [ ] `(new)` 单测覆盖盘符、根、空格、非 ASCII、嵌套目录、非法/不支持路径和各 unsupported 分支。
- [ ] Windows 文件/目录上传下载、递归删除、重命名和复制通过真实冒烟，Linux `single_machine` 文件测试回归。
- [ ] README 支持矩阵/示例/限制与 CHANGELOG Added 同卡逐文件更新。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --lib windows_path`
- [ ] `cargo test --no-run`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_files -- --ignored --exact --test-threads=1`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`（覆盖 `test_file_operation` 与 `test_file_transfer`）

**Full-suite trigger:** `T-1: 共享 SFTP 路径分派`

**Dependencies:** `IP-01`（共享源码/测试/文档写集串行）

**Deliverables:** `N/A`

**Implementation write set:** `src/machine.rs`、`src/ssh.rs`、`src/windows.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/machine.rs`, `src/ssh.rs`, `src/windows.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 列出每个支持/unsupported 文件接口和路径形式；CHANGELOG Added。

**Rollback mode:** `revert`

**Security and privacy:** 不记录私有宿主路径；拒绝路径逃逸和不支持 namespace，不能 best-effort 忽略链接。

**Performance budget:** 递归遍历有界于实际目录树并响应 cancel；不得为路径转换重复遍历目录。

**Estimated scope:** `M`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=Windows 文件语义; recovery=一次 revert; complete=yes; self-contained=yes; AC=8/8; VER=5/8; landing=3; prod-files=3; scope=M; deps=IP-01; writeset=序列化于 IP-01; release=family child; split-from=N/A; exception=N/A`

### Task REL-01: Windows 支持聚合发布（0.4.0）

**Task type:** `release`

**Lifecycle / Acceptance:** `pending` / 空

**Description:** 作为唯一发布点聚合全部守卫，定稿 CHANGELOG、对齐 CI、发布 0.4.0；已吸收原 DOC-01 的只读文档收口审计，不承担各行为卡的补文档责任。

**Out of scope:**
- 不引入新产品行为；文档/测试缺口退回所属卡修复，不在发布点掩盖。
- 不用 TCG、`--no-run` 或 `DEFER-03` 替代 Windows KVM 核心验收。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 当前版本 0.3.1 | `Cargo.toml:1-4` |
| CI 仅 pull_request，clippy 命令与模板不一致 | `.github/workflows/check-and-test.yml:1-7,76-100` |
| CHANGELOG Unreleased/0.3.1 | `CHANGELOG.md:8-24` |

**Acceptance criteria:**

- [ ] 全部任务卡 `Lifecycle=done` 且 `Acceptance=complete`，最终 code review PASS，P0/P1 关闭。
- [ ] `Cargo.toml` 从 0.3.1 bump 到 0.4.0，`Cargo.lock` 仅由 Cargo 工具链刷新，版本与迁移理由符合 ADR-WIN-01。
- [ ] README 支持矩阵只包含实际通过核心冒烟的 Windows 版本；CHANGELOG `[0.4.0]` 含 Added/Changed/Migration 与发布日期，链接可解析。
- [ ] CI 对目标分支 push 和 PR 均触发 format/clippy/test job，clippy 使用 `--all-targets --all-features -- -D warnings`，Windows target 至少 `--no-run` 编译。
- [ ] Linux 全量、每个支持版本的 Windows KVM 核心冒烟与 release build 全绿；核心 Windows 证据无开放 DEFER。
- [ ] 所有适用 Rollback mode 已验证或记录不可验证原因；发布前工作区只剩本计划声明的改动。
- [ ] tag `v0.4.0`、GitHub Release、按需 crates.io publish 完成；不可撤回动作之后只前滚修复。
- [ ] 目标分支 push 对应 CI 的 format/clippy/test job 与 crates.io 结果已记录 run ID/URL、event、ref 和结论。

**Verification:**

- [ ] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [ ] 配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`
- [ ] `cargo test --no-run`
- [ ] 对支持矩阵每个版本运行：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine -- --ignored --test-threads=1`
- [ ] `cargo build --release`
- [ ] 推送后核对 GitHub Actions `Check and Test` 的 `format`/`clippy`/`test`：event=`push`、ref=`refs/heads/main`、commit=发布 commit，全部绿色；crates.io（若发布）可查询到 0.4.0。
- [ ] 将全部 sanitized 命令结果、版本/commit、tag/release/CI/crates.io 证据写入「实施证据汇总」并同步 `plan-status.md`。

**Full-suite trigger:** `T-2: 发布点卡`

**Dependencies:** `SPK-01`、`SPK-02`、`OSX-01`、`OSX-02`、`OSX-03`、`TRN-01`、`EXE-01`、`IP-01`、`FS-01`

**Deliverables:** `0.4.0` 发布与证据（本计划内）。

**Implementation write set:** `Cargo.toml`（版本行）、`Cargo.lock`、`CHANGELOG.md`、`.github/workflows/check-and-test.yml`、本计划、`plan-status.md`

**Release write set:** `Inherited`

**Files likely touched:** `Cargo.toml`, `Cargo.lock`, `CHANGELOG.md`, `.github/workflows/check-and-test.yml`

**Docs and compatibility impact:** CHANGELOG 0.4.0/Migration、GitHub Release；README 只审计，缺口退回所属卡。

**Rollback mode:** `immutable-release`（发布后不可撤回，只能发新版本）

**Security and privacy:** 发布证据不含 token、私有路径、未脱敏日志；使用精确暂存。

**Performance budget:** 全量与 release build 记录 wall-clock；不新增运行时性能承诺。

**Estimated scope:** `S`

**Version increment:** `minor`（0.3.1 → 0.4.0；0.x 公开结构体源码破坏）

**Release boundary:** `family release point of REL-01`

**C/D coverage from:** `self`

**Granularity:** `type=release; axis=聚合发布; recovery=发新版本前滚; complete=yes; self-contained=yes; AC=8/12; VER=7/12; landing=1; prod-files=3; scope=S; deps=SPK-01,SPK-02,OSX-01,OSX-02,OSX-03,TRN-01,EXE-01,IP-01,FS-01; writeset=序列化于 FS-01; release=family release point; split-from=N/A; exception=N/A`

## 测试矩阵

本表是最终覆盖要求，不要求每卡跑完整张表。Windows 测试默认 ignore，显式运行时按支持矩阵逐版本执行。

| 类别 | 必须覆盖 | Target / command |
|---|---|---|
| 单元 | GuestOs/旧 JSON/cache、固件参数、部署、传输安全、PowerShell、IP parser、GuestPath | `cargo test --lib` |
| 集成（Linux 回归） | single_machine / machine_pool / muti_distro | 配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` |
| Windows 固件/部署 `(new)` | OVMF/TPM/Secure Boot、首启、关机、spawn | `cargo test --test windows_machine windows_firmware_lifecycle -- --ignored --exact --test-threads=1`；`windows_first_boot` 同理 |
| Windows 传输/池 `(new)` | host key、重连、双机端点与 readiness | `cargo test --test windows_machine windows_transport -- --ignored --exact --test-threads=1`；`windows_pool` 同理 |
| Windows 语义 `(new)` | exec/get_ip/文件与目录往返/unsupported | `cargo test --test windows_machine windows_exec -- --ignored --exact --test-threads=1`；`windows_get_ip`、`windows_files` 同理 |
| Windows 全量核心门 | 上述所有 Windows 用例，每个支持版本 | 设置镜像 env 后：`cargo test --test windows_machine -- --ignored --test-threads=1` |
| 编译门槛 | CI 编译所有 target，包括 ignored Windows 测试 | `cargo test --no-run` |
| 性能 | hash 流式无回归 | `cargo bench --bench hash_benchmark` |

## 追溯表

| 任务 | 来源/证据 | 代码落点 | 文档/CHANGELOG 动作 | 指定测试 `(new)` |
|---|---|---|---|---|
| SPK-01 | `src/ssh.rs:89-104,571-630` | 无生产代码 | ADR-WIN-02 | 手工连接/SFTP 证据 |
| SPK-02 | `src/qemu.rs:74-169` | 无生产代码 | ADR-WIN-03 | 手工首启/重启证据 |
| OSX-01 | `src/image.rs:68-81,645-717` | image/lib/machine | README API/Migration、CHANGELOG | `guest_os_default`、`guest_os_legacy_json`、`guest_os_cache_mismatch` |
| OSX-02 | `src/qemu.rs:74-169`、`src/machine.rs:63-68,156-157` | qemu/machine/utils | README Host Setup（含 Windows 最低/推荐资源）、CHANGELOG | `windows_firmware_lifecycle` |
| OSX-03 | `src/machine.rs:181-464` | machine/windows | README 部署、CHANGELOG | `windows_first_boot`、`windows_deploy_timeout` |
| TRN-01 | `src/ssh.rs:89-104,571-630` | ssh/machine/utils | README 传输/限制、CHANGELOG | `windows_transport`、`windows_pool` |
| EXE-01 | `src/machine.rs:495-516` | machine/ssh | README exec、CHANGELOG | `windows_exec` |
| IP-01 | `src/ssh.rs:831-841` | ssh/machine | README get_ip、CHANGELOG | `windows_get_ip` |
| FS-01 | `src/machine.rs:578-775,922-1137` | machine/ssh/windows | README 文件矩阵、CHANGELOG | `windows_files` |
| REL-01 | Cargo/CHANGELOG/CI | 版本与 CI | CHANGELOG 0.4.0/Release | 全量与远端门 |

## 里程碑验收与回滚

| 里程碑 | 完成条件 | 发布/证据 | 回滚或前滚 |
|---|---|---|---|
| M0 | 两个 spike go，具体 ADR/任务卡重审通过 | ADR-WIN-02/03 | 阻塞或改范围 |
| M1 | Windows 固件、部署、关机/重启通过 | OSX-01/02/03 证据 | revert |
| M2 | 安全传输、exec/IP/文件、双机池通过 | TRN/EXE/IP/FS 证据 | revert |
| M3 | 0.4.0 本地与远端发布完成 | REL-01 证据 | 发新版本前滚 |

### 故障恢复矩阵

| 故障点 | 可接受残留 | 恢复动作 | 禁止结果 |
|---|---|---|---|
| OVMF/swtpm 缺失 | 无运行 VM | 清晰报错并清理已创建 run dir | 静默降级、半启动 VM |
| 地址发现/连接超时 | 可保留 sanitized 日志 | 有界重试后终止 QEMU、释放端点并清理 | 遗留 QEMU、调用 get_ip 循环等待 |
| host key 不匹配 | 无会话 | 立即失败并清理，不自动接受新 key | 静默信任任意 key |
| Windows 首启后重启失败 | 可保留失败 run dir 供排查（clear=false） | 终止进程、记录状态；修复后新建干净 VM 验证 | 删除证据后宣称成功或复用半部署状态 |
| crates.io 发布失败 | 本地/远端 tag 可能已建 | 按 ER-09 记录，下窗口处理 | 伪造发布证据或撤回已发布 crate |

## 风险登记

| 风险 | 影响 | 缓解 | 任务 |
|---|---|---|---|
| Windows 无现有 vsock 路径 | 高 | 真实 spike、地址发现、双端鉴权与 ADR | SPK-01/TRN-01 |
| OVMF/Secure Boot/TPM/驱动差异 | 高 | 统一固件基线、真实 Win10/11 验证、失败即收缩支持矩阵 | SPK-02/OSX-02 |
| 合法镜像或 KVM 宿主缺失 | 高 | DEP-01/02 前置，核心发布不可 DEFER | SPK-01/SPK-02/REL-01 |
| 公开字段源码破坏被误报兼容 | 高 | ADR、Migration、0.4.0 minor、builder 与旧 JSON 测试 | OSX-01 |
| TCP 地址错配或 MITM | 高 | MAC/端点绑定、host key pinning、错误 key 负测试 | TRN-01/IP-01 |
| 命令/路径与 POSIX 专属接口静默失败 | 高 | 明确支持矩阵、unsupported 错误、真实往返测试 | EXE-01/FS-01 |
| 共享文件并发冲突 | 中 | 全串行、逐卡状态时间与写集序列化 | 全部 |
| Linux 回归 | 高 | 默认 Linux、focused + 全量回归 | 全部实现卡/REL-01 |
| Windows 首启部署超过默认超时，部署证据取不到 | 高 | SPK-02 实测首启时长；OSX-03 参数化部署超时并在 README 写明推荐值，超时返回可操作错误 | SPK-02/OSX-03 |
| Windows 客户机最低资源与默认资源冲突 | 中 | OSX-02 评估默认资源、README 写最低/推荐值，不足时收缩矩阵或调整默认 | OSX-02 |

## 性能与容量摘要

| 操作 | 单次成本 | 累积成本 | 预算/上限 | 验证 |
|---|---|---|---|---|
| Windows 首启 | O(overlay + seed + 实际部署)，仅 KVM 计时 | 每 VM 独立固件/TPM 状态 | 部署等待超时参数化（OSX-03）；记录实测，不设未验证阈值 | firmware/first_boot 冒烟 |
| 地址发现/连接 | 有界轮询，O(实际 lease/端点数) | 双机不共享重试状态 | 总耗时 ≤ ssh_timeout | transport/pool 与超时负测试 |
| 文件递归 | O(实际目录项 + 文件字节) | 不重复扫描 | cancel 可中断，无额外全树扫描 | windows_files |
| hash 流式校验 | O(n) | O(n) | 无回归 | `cargo bench --bench hash_benchmark` |

## 兼容与文档收口

- [ ] README Host Setup/API/Migration/示例/支持矩阵与各 unsupported 接口已同步。
- [ ] CHANGELOG 按 Keep a Changelog 写入 `[0.4.0]` Added/Changed/Migration。
- [ ] CI push/PR 触发与 format/clippy/test 命令已同步。
- [ ] `tests/INDEX.md` 当前不存在，`N/A`。
- [ ] LICENSE 未改动。

## 实施证据汇总

只写 sanitized summary、命令、退出码、版本/commit、CI run ID/URL；不得新建证据文件，不得记录 secret、私有绝对路径或原始 tool payload。任务推进时同时更新 `plan-status.md` 和「修订历史」（规范性变化）/本表（执行证据）。

每张卡都必须在 Review 列记录其代码或产物 review 的 round、PASS 与问题关闭情况，然后才能按 ER-04 进入 `complete`。下方 Review log 是计划文档评审，不能替代实现后的逐卡 review。

| 任务 | UTC 时间 | 环境与 sanitized 输入 | 命令/检查与结果 | Review | 发布/远端证据 |
|---|---|---|---|---|---|
| SPK-01 | 2026-11-12 07:45:12 UTC | 宿主机审计：Linux x86_64、`/dev/kvm` 存在；`qemu-system-x86_64`/`qemu-img`/`swtpm`/`xorriso`/`virsh`/`qemu-bridge-helper`/OVMF 均缺失；`sudo -n` 需密码；无 Windows qcow2（DEP-01/02 均不可用） | 未执行：无可用 Windows VM，无法取得连接/鉴权/SFTP 证据 | `blocked`（DEP-01/DEP-02） | N/A |
| SPK-02 | 2026-11-12 07:45:12 UTC | 同上（无 QEMU/OVMF/swtpm，无 Windows 镜像） | 未执行：无可用 Windows VM，无法取得首启/重启证据 | `blocked`（DEP-01/DEP-02） | N/A |
| OSX-01 | 2026-11-12 08:40:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib image::tests`（18 passed）、`cargo test --no-run` 全绿 | T-1 全量门未执行（无 QEMU/libvirt，`DEFER-04`） | `done` / `complete` | `34c6eb9` |
| OSX-02 | pending | pending | pending | pending | 继承 REL-01 |
| OSX-03 | pending | pending | pending | pending | 继承 REL-01 |
| TRN-01 | pending | pending | pending | pending | 继承 REL-01 |
| EXE-01 | pending | pending | pending | pending | 继承 REL-01 |
| IP-01 | pending | pending | pending | pending | 继承 REL-01 |
| FS-01 | pending | pending | pending | pending | 继承 REL-01 |
| REL-01 | pending | pending | pending | pending | pending |

## Review log

Result 只允许 `PASS` 或 `FAIL`。各轮 review 覆盖三份文件：`plan-template.md`、`plan-status.md`、本计划。

| Round | Scope | Result | P0/P1 | P2 处置 | Evidence |
|---|---|---|---|---|---|
| R1 | 三份文件、全部任务卡与当前源码 | FAIL | P1-01~P1-10；R2 已复核关闭 | 无 residual risk | 当前源码锚点、R1 修订历史 |
| R2 | R1 修订、执行门与安全路径 | FAIL | P1-11~P1-14；R3 已复核关闭 | 无 residual risk | 逐卡 T-1/AC-VER 复核、host-key provisioning 检查 |
| R3 | 三份文件最终一致性复审 | PASS | 无开放项；P1-01~P1-14 全部关闭 | 无 residual risk | 自动校验 PASS：10 任务/10 状态行、依赖无环、AC/VER 与审计一致、T-1/T-2 全量门齐全、表格/链接/现有锚点有效；人工语义复核通过 |
| R4 | P2 缺口修订（OSX-02 资源默认值、OSX-03 部署超时） | PASS | 无开放项；GAP-08/09 已修复 | 无 residual risk | 审计表重算：`OSX-02` AC=8/8、VER=5/8；`OSX-03` AC=8/8、VER=7/8（均在上限内）；追溯表补 `windows_deploy_timeout`；风险表新增两行；事实基线/性能摘要同步；plan-status 状态与时间戳同步；新增 AC 不扩大行为轴、不引入新依赖 |
| R5 | 环境消歧（DEP-01/DEP-02 不可用）与依赖边重排 | PASS | 无开放项；spike 阻塞已登记，ADR 临时接受已写明 revisit 条件 | 残余风险：Windows 实测证据缺失（由 `SPK-01`/`SPK-02` 与 `REL-01` 阻塞承载），具名接受人=计划 Owner | 审计命令输出（`command -v` 全缺、`sudo -n` 需密码、`/dev/kvm` 存在）；依赖图无环复核；`SPK-02 -> OSX-01` 取消理由=OSX-01 无 Phase 0 输入；粒度审计表 deps 列同步 |

### R1 findings 与修订对照

| ID | 问题 | 修订 |
|---|---|---|
| P1-01 | 把新增公开字段误称为完全兼容，minor 理由不成立 | ADR-WIN-01/OSX-01 明确源码破坏、迁移和 0.4.0 理由 |
| P1-02 | family/no-release 继承 C/D 与发布点等子卡 complete 形成状态死锁；模板发布分组示例也自相矛盾 | 模板 v1.1 分离子卡 A/B 完成与发布点 C/D，修正唯一 bump 示例 |
| P1-03 | 写集相交却声明 no-overlap/可并行 | 全串行、补顺序边，逐卡登记序列化关系 |
| P1-04 | spike 未依赖镜像/宿主，核心 Windows 测试可延后发布 | 新增 DEP-01/02；核心 KVM 验收成为发布硬门，DEFER-03 仅限 TCG |
| P1-05 | 部署卡在 spike 前硬编码 unattend，TPM 可选但没有版本维度 | OSX-03 改为消费 ADR；ADR-WIN-04 统一 UEFI+TPM2.0 且 swtpm 必需 |
| P1-06 | TCP 地址发现、host key、用户/readiness 与重启/池未闭环 | ADR-WIN-02、SPK-01、TRN-01 补齐并加入负测试 |
| P1-07 | 源码事实与 API 边界有误：exec 未做 UNIX escape；缓存 OS、spawn、InteractiveShell、POSIX 文件接口遗漏 | 刷新事实基线，OSX-01/EXE-01/FS-01/TRN-01 明确实现和 unsupported |
| P1-08 | DOC-01 违反 G-02，IP 文档未同卡交付，实施证据节缺失 | DOC-01 合并 REL-01；行为文档归各卡；新增实施证据汇总 |
| P1-09 | 粒度计数/prod-files、状态时间戳与依赖登记不一致 | 按实际条目重算，状态表逐卡增加版本/commit/UTC，登记 DEP-02 |
| P1-10 | CI 无 push 事件，远端发布门不可取得；当前 Libra checkout 无法执行 git status | REL-01 增加 CI 对齐；模板/计划允许等价 Libra 命令并固定目标分支 main |

### R2 findings 与修订对照

| ID | 问题 | 修订 |
|---|---|---|
| P1-11 | 多张 T-1 卡只有 focused 测试，EXE 的 trigger 还可条件性变更 | 所有 T-1 卡明确运行 Linux 全量门，重算 VER，EXE 固定为 T-1 |
| P1-12 | “私钥不进 seed”与可 pinning 的 host key provisioning 冲突 | 仅禁止客户端私钥进 seed；每 VM host 私钥若注入则随机、0600、首启专用并清理，公钥交 Machine |
| P1-13 | 计划文档 Review log 不能证明每张实现卡完成代码 review | 实施证据表新增逐卡 Review 列，无逐卡 PASS 不得 complete |
| P1-14 | Windows 10/11 的发布范围可被误读为只测一个也宣称两个；模板完成门缺状态同步项 | 至少一个明确版本全验收，未测版本不得声明；模板完成判据补 plan-status 同步 |

## 非目标与延后项

| ID | 延后内容 | 原因 | 重启条件 | 承接位置 |
|---|---|---|---|---|
| DEFER-01 | Windows 内置镜像目录 | 当前许可限制 | 出现可合法再分发的镜像源 | `plan-<date>-windows-catalog.md` |
| DEFER-02 | Windows on ARM | 尚无真实需求，固件/驱动未验证 | 真实需求 + 新可行性验证 | 新计划 |
| DEFER-03 | Windows TCG 冒烟矩阵 | 核心目标是 KVM，TCG 启动成本未验证 | 真实 TCG 需求 + 可接受时限 | 新测试计划；不得替代本计划 KVM 门 |
| DEFER-04 | Linux VM 全量门 `cargo test -- --test-threads=1` 的本地执行 | 当前实现宿主无 QEMU/libvirt/xorriso/qemu-bridge-helper（DEP-02 不可用），VM 集成测试无法运行 | 配置齐全的 Linux KVM 宿主机可用时（与 DEP-02 解除同步） | 本计划 / `REL-01` 收口门；不得替代任何 Windows KVM 核心验收 |

## 完成判据

- [ ] 所有任务卡满足 G-*，审计表、写集序列化和依赖图一致，无未登记例外。
- [ ] 所有非延后任务 `Lifecycle=done` 且 `Acceptance=complete`；子卡完成不等待继承发布点的 C/D，发布点完成必须取得全部适用 C/D。
- [ ] 所有 Verification 已运行并把 sanitized 结果写入「实施证据汇总」。
- [ ] Linux 全量收口：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test -- --test-threads=1` 全绿；环境缺口按 ER-14 登记。
- [ ] 支持矩阵每个 Windows 版本的 KVM 核心冒烟全绿；`--no-run`、TCG、DEFER-03 均未替代核心验收。
- [ ] 收口暴露的问题已修复并重跑；既有失败有基线证据并正式登记，未混入本计划修复。
- [ ] README/CHANGELOG/CI 更新完成，公开破坏与 Migration 清晰。
- [ ] 每张卡 Rollback mode 已验证或记录不可验证原因。
- [ ] Review 最终 PASS，P0/P1 全部关闭。
- [ ] REL-01 已 bump 0.4.0、工具链刷新 Cargo.lock、tag/GitHub Release/按需 crates.io 与目标 ref CI 证据落地。
- [ ] 修订历史记录全部规范性变化，plan-status 与任务卡、DEFER/DEP、版本/commit 和 UTC 时间一致。
- [ ] 未新建证据文件/文件夹，未清理或混入用户已有无关脏状态。
