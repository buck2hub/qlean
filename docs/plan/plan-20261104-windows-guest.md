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
| CI | `push`（`main`）与 `pull_request` 均触发；clippy 带 `--all-targets --all-features`，另跑 `cargo test --lib`、`cargo test --no-run --all-targets` 与 `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`（R22 实测 run 全绿） | `.github/workflows/check-and-test.yml:1-8,78-83,106-112` |
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
| GAP-07 | CI 无 push 触发，发布远端门不可执行（R22 已关闭：`push`(main)+PR 双触发，run `43197579979` 取得指定 ref 的 CI 证据） | 发布后无法按模板取得指定 ref 的 CI 证据 | `.github/workflows/check-and-test.yml:1-8` | `REL-01`（已关闭，R22 `4d4d1e9`） |
| GAP-08 | 无 Windows 首启部署超时维度（Linux `ssh_timeout` 默认 180/300s 不覆盖部署时长） | 首启部署可能超时失败，核心证据难以取得 | `src/machine.rs:72,165-167` | `OSX-03` |
| GAP-09 | 无 Windows VM 资源默认值讨论 | 支持矩阵可能声明默认资源下不满足最低要求的版本 | `src/machine.rs:63-68,156-157` | `OSX-02` |

## 与其它计划的关系

| 计划/文档 | 关系 | 本计划处理 |
|---|---|---|
| `plan-long.md` | 当前不存在 | `N/A` |
| `plan-template.md` | 模板 | 使用 v1.1；R1 同步修复模板状态机与发布规则歧义 |
| `plan-status.md` | 执行状况单一视图 | 每卡同步状态、版本/commit、UTC 时间 |
| `README.md` / `CHANGELOG.md` | 用户契约 | 每个行为卡同卡更新；`REL-01` 只做收口审计与版本段定稿 |
| `.github/workflows/check-and-test.yml` | CI 契约 | `REL-01`：push 发布门与 clippy 对齐已由 R22 落地（`4d4d1e9`，run `43197579979`）|

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
| 2026-11-12 13:45:00 UTC | review R6（实施后逐卡 review；修订提交 `496b471`） | 逐卡核对 `OSX-01`~`FS-01` 实现与门禁；F1~F4 修复（`Drop`/`swtpm` 顺序、证据表 Review 列语义、`GuestPath::join` 不可达分支、`TRN-01` 提交号更正）；`REL-01` 维持 `blocked` | N/A（无拆合卡、无 AC 变更） | 实施证据汇总、Review log、`src/machine.rs`、`src/firmware.rs`、`src/guest_path.rs`、plan-status |
| 2026-11-12 14:20:00 UTC | review R7（结构复核） | 修复文档结构：恢复丢失的 `OSX-01` 标题与 `Task type` 行；`SPK-01`/`SPK-02` 卡片状态由 `pending` 更正为 `blocked` 并写入阻塞审计证据；删除 `OSX-03` 重复的第二个 `Verification` 块（与首个块矛盾且把已跑通的本地门标为未做）；补回 `TRN-01`/`EXE-01`/`IP-01`/`FS-01` 卡内 `Implementation evidence` 标签（原为无标题孤表）并消除修订历史表内空行；修复 `Machine::exec` 空命令错误文案的多余空格（`c14b915`），三处状态视图一致 | N/A（无拆合卡、无 AC 变更） | 任务卡、Review log、plan-status |
| 2026-11-12 14:55:00 UTC | review R8（首启生命周期） | F5~F8 修复：`init` 用部署预算等待 `sshd`（`0e72b45`）；部署确认失败即拆除 VM 并清理 seed（`f9cc1ee`）；`read_pid` 失败路径有界等待并停 `swtpm`（`83a8b0c`）；已部署机器再次 `init` 明确拒绝（`178ac03`）；README/CHANGELOG 同步 | N/A（均为让实现符合 `OSX-03` 既有 AC 与故障恢复矩阵，无卡拆合） | `OSX-03` 实现证据、Verification、实施证据汇总、Review log、故障恢复矩阵、README、CHANGELOG |
| 2026-11-12 15:20:00 UTC | review R9（硬件对接面） | F9~F11 修复：vsock 设备仅为 Linux 添加（`f42a942`）；OVMF code/vars 等长校验改为「vars 不得大于 code」（`8ae13ec`）；swtpm 控制 socket 改 `mode=0600`（`3e7ebd0`） | N/A（`OSX-01`/`OSX-02` 既有 AC，无卡拆合） | `OSX-01`/`OSX-02` 实现证据、Review log、`src/qemu.rs`、`src/firmware.rs`、CHANGELOG |
| 2026-11-12 15:50:00 UTC | review R9 补记（Secure Boot vars 与首启介质前置） | F12 修复：`OVMF_CANDIDATES` 为每个 code 镜像列出多个 vars 模板，secboot 优先 Microsoft 已注册的 `.ms`/`.secboot` 模板，普通模板仅作 fallback（setup mode）；F13 修复：`ensure_host_support` 增加 `xorriso`（首启 seed 介质的必需构建器），与其他缺口一次性报出（`7ddc686`） | N/A（细化 ADR-WIN-02 的 Secure Boot 判定与 `OSX-02` 前置检查，不改变既有决策） | `OSX-02` 实现证据、Review log、ADR-WIN-02、`src/firmware.rs`、README、CHANGELOG |
| 2026-11-12 16:10:00 UTC | review R10（Windows 命令构造） | F14 修复：`Machine::copy` 的 Windows 分支改为直接执行 `Copy-Item`（`windows::copy_file_command`），不再套 `powershell -Command "..."`，避免外层 PowerShell 二次解析把路径中的 `$` 展开成空 | N/A（`FS-01` 既有 AC「Windows 文件语义」，无卡拆合） | `FS-01` 实现证据、Review log、`src/windows.rs`、`src/machine.rs`、CHANGELOG |
| 2026-11-12 16:30:00 UTC | review R11（失败启动的可恢复性） | F15 修复：`init`/`spawn` 把 cancel token 当「已启动」标记，启动失败后 token 残留，之后每次尝试都报 `Machine already initialized`/`already spawned`，且残留的连接任务不会被取消；现在只在机器确实在运行时拒绝重复启动，失败时取消并清除 token（`bf0710c`） | N/A（`OSX-03`/`TRN-01` 既有「有界重试后清理」AC 与故障恢复矩阵，无卡拆合） | `OSX-03` 实现证据、故障恢复矩阵、Review log、`src/machine.rs`、README（Windows 状态说明改为「已实现但未发布/未支持」）、CHANGELOG |
| 2026-11-12 17:00:00 UTC | review R12（首启地址发现与目录创建） | F16 修复：Windows 首启的 DHCP lease 轮询在 `select!` 之前执行且不可取消，QEMU 启动即死时要等满 900s 并误报「无 lease」（`d2a85ab`）；F17 修复：`create_dir_all` 会尝试 mkdir/stat Windows 盘根 `C:`（drive-relative，部分服务器会失败），改为对两种 OS 的根一律跳过（`1e1af91`） | N/A（`TRN-01`/`FS-01` 既有 AC：有界重试后清理、Windows 目录创建，无卡拆合） | `TRN-01`/`FS-01` 实现证据、故障恢复矩阵、Review log、`src/machine.rs`、`src/ssh.rs`、CHANGELOG |
| 2026-11-12 17:40:00 UTC | review R13（地址选择与路径拼接） | F18 修复：lease 查找取首个匹配行，双栈网络下可能选中链路本地 IPv6（无 scope id，必然连不上），且解析成功导致不再重试，现仅接受 IPv4 并在超时错误中说明（`ed09b5b`）；F19 修复：`GuestPath::join` 会静默吞掉前导分隔符（Linux 上把 `/etc/passwd` 变成相对路径），现显式拒绝绝对子路径；`\\?\C:` 设备路径此前被误报为 UNC（`33567ed`） | N/A（`TRN-01`/`FS-01` 既有 AC：按本 VM MAC 解析且不回退到别机、路径校验，无卡拆合） | `TRN-01`/`FS-01` 实现证据、Review log、`src/utils.rs`、`src/guest_path.rs`、CHANGELOG |
| 2026-11-12 18:20:00 UTC | review R14（启动失败时的资源收尾） | F20 修复：QEMU 在 SSH 阶段退出时 `launch` 直接返回，`self.pid` 与 `swtpm` 句柄残留（TPM 进程活到 Machine 被 drop，且仍报告有 pid）；SSH 任务 panic 更严重，`?` 直接把 `qemu_handle` 分离（QEMU 继续运行），现统一走终止 QEMU + 停 swtpm + 清 pid 的失败分支（`e412251`、`77cc1fc`） | N/A（`OSX-03` 既有 AC：启动失败不遗留进程与句柄，无卡拆合） | `OSX-03` 实现证据、故障恢复矩阵、Review log、`src/machine.rs` |
| 2026-11-12 19:10:00 UTC | review R15（部署标记探测与池化启停） | F21 修复：`deploy_marker_present` 把传输错误当成「标记不存在」，guest 首启末尾重启时会在 900s 后误报「部署未完成」；现区分「guest 已应答」与「问不到」，连续 3 次传输失败即报「会话丢失，可 spawn 重试」（`9cc7eb0`）；F22 修复：`init_all` 一律 `init`（部署过的 Windows 会被拒绝），`spawn_all` 一律 `spawn`（从未部署的 Windows 会启动到不可达状态），现按部署状态分流（`2d8b772`） | N/A（`OSX-03`/`TRN-01` 既有 AC：首启失败可诊断、池内各 VM 独立，无卡拆合） | `OSX-03`/`TRN-01` 实现证据、故障恢复矩阵、Review log、`src/machine.rs`、`src/pool.rs` |
| 2026-11-12 19:50:00 UTC | review R16（公开文档与门禁补强） | F23 修复：`upload`/`download` 的公开文档用 intra-doc 链接指向 `pub(crate) GuestPath`，`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` 直接失败（`rustdoc::private_intra_doc_links`），改为代码字面量（`9297994`）；同轮把 rustdoc 与 benches 编译纳入每卡门禁 | N/A（无卡拆合） | Review log、Verification 判定口径、`src/machine.rs` |
| 2026-11-12 20:20:00 UTC | review R17（宿主前置聚合的测试有效性） | F24：`ensure_host_support` 的「一次性报告全部缺失前置」AC 只有一个自证式测试——它用字面量拼出期望消息再断言自己的文本，`ensure_host_support` 改成只报第一条也不会失败；现抽出 `host_support_problems(kvm, ovmf, swtpm, swtpm_available, xorriso_available)` 纯函数，用真实调用结果断言 | N/A（`OSX-02` AC-A3 的可测部分现已真正覆盖） | `OSX-02` 实现证据、Review log、`src/firmware.rs` |
| 2026-11-12 20:50:00 UTC | review R18（CI 覆盖面审计，findings-only） | 无代码缺陷；记录一条需要 `REL-01` 修的执行缺口：`.github/workflows/check-and-test.yml` 的 test job 只有 `cargo test --no-run`（只编译不运行），而唯一能在任意宿主运行的验证面（85 个 `cargo test --lib` 单测）因此从未在 CI 上被检查；同时 CI 的 clippy 为 `cargo clippy -- -D warnings`，未带 `--all-targets --all-features`，测试与 bench 代码不被 lint。两处修复均属 `REL-01` 的 write set（该卡 AC 已写明对齐 clippy 命令），故只登记不改动 | N/A（不新增卡；缺口归属 `REL-01` AC-04） | `REL-01` Current evidence、Review log、`.github/workflows/check-and-test.yml` |
| 2026-11-12 21:20:00 UTC | review R19（验收项到断言的追溯） | F25：`windows_files` 只断言 `read_link` 报错，而 FS-01 的 AC 要求 `hard_link`/`read_link`/`set_permissions` 三个 POSIX-only 入口都明确报错；单测覆盖了 `ensure_supported` 层，但一次昂贵的硬件冒烟跑完仍不能证明后两个入口的接线正确。补两条断言（`daa6f19`） | N/A（不新增卡；补齐 `FS-01` 既有 AC 的硬件证据面） | `FS-01` 实现证据、Review log、`tests/windows_machine.rs` |
| 2026-11-12 21:45:00 UTC | review R20（一次性部署的可观测性） | F26：`windows_transport` 只断言 `spawn` 后能执行命令，未验证「部署后 seed 介质已删除」「host key 跨重启不变」「二次 `init` 被拒绝」这三条 OSX-03 AC；其中「seed 已删除」此前只有宿主私有路径可查、无公开可观测面。利用 `init` 对已部署 Windows 的拒绝（`deploy_seed.is_none()` 即 seed 已被 take+remove）作为公开观测量，补 3 条断言（`aa7fc0e`） | N/A（不新增卡、不加公开 API） | `OSX-03`/`TRN-01` 实现证据、Review log、`tests/windows_machine.rs` |
| 2026-11-12 22:15:00 UTC | review R21（迁移说明与 CHANGELOG 一致性） | F27：README「0.3.x → 0.4.0」写着「Linux runtime behavior are unchanged」，但 CHANGELOG `Fixed` 已记录两处 Linux 运行时行为变化（`exec` 退出码换算修复、空命令拒绝），迁移说明与事实矛盾。改为「破坏仅源码级」并新增「两处 Linux 运行时行为变化」小节，写明需要调用方适配的内容（`943daa0`）；随后自查发现初稿多写了一条第 `upload`/`download` 绝对目的地的断言，但该路径走 `guest_path_from` 而非 `join`，不是错误，已撤回该句（`8365972`） | N/A（不新增卡） | `REL-01` Current evidence、Review log、`README.md`、`CHANGELOG.md` |
| 2026-11-12 10:20:00 UTC | review R22（CI 门实际执行与远端证据） | F28（R18 登记项落地）：`.github/workflows/check-and-test.yml` 的 test job 只有 `cargo test --no-run`（单测从未在 CI 执行）、clippy 缺 `--all-targets --all-features`（测试与 bench 不被 lint）、workflow 只在 `pull_request` 触发且 `paths-ignore` 忽略自身，故直推 `main` 的 57 个提交一次 CI 都没有。改为 `push`（`main`）+ `pull_request` 双触发、clippy 全 target/all features、新增 `cargo test --lib` 与 rustdoc 门、不再忽略 `.github/**`（`4d4d1e9`）；推后取得真实远端运行证据：run `43197579979`、event=`push`、ref=`refs/heads/main`、commit=`4d4d1e9`，4 个 job 全绿，CI 日志中 `running 85 tests` / `test result: ok. 85 passed` 证明单测确实被执行 | N/A（不新增卡；落地 `REL-01` AC-04 的 CI 部分，发布动作仍阻塞） | 事实基线 CI 行、门禁说明、`REL-01` Current evidence/AC-04、Review log、实施证据汇总、`.github/workflows/check-and-test.yml`、plan-status |
| 2026-11-12 10:35:00 UTC | review R23（发布打包前置检查） | F29：`cargo package --allow-dirty --no-verify` 打包成功但警告 `crypto-bigint v0.7.5`（经 russh→rsa→crypto-primes 间接依赖）在 crates.io 已 yanked；发布点留下的锁文件会带着被撤回的依赖，接手者安装时只能看到警告。patch 级更新锁文件 `crypto-bigint 0.7.5 → 0.7.11`（连带 `ctutils 0.4.2 → 0.4.8`），无 manifest/API 变更（`bf83b3c`）；CI run `43198568379`（push/`main`）四 job 全绿；`cargo package` 现打包 27 个文件、598.4KiB，无 yanked 警告。同时勾选「兼容与文档收口」的 CI 项（R22 已落地） | N/A（不新增卡；`Cargo.lock` 属 `REL-01` write set，但为发布前置的依赖卫生，非发布动作） | `REL-01` Current evidence、Review log、实施证据汇总、兼容与文档收口、`Cargo.lock`、plan-status |
| 2026-11-12 10:55:00 UTC | review R24（打包全验证与治理性发现，findings-only） | `cargo publish --dry-run --allow-dirty` 全验证通过（从 `target/package/qlean-0.3.1` 重新编译整个 crate），7 个 ignored 硬件测试实测全部快速失败于 DEP-01 守卫（无静默跳过、无挂起）。两条治理性发现，均属 `REL-01` 发布面、本轮不改：① 远端仅存在 tag `v0.1.0`/`v0.2.0`/`v0.3.0`，而 CHANGELOG 历史段落引用的 `v0.2.1`/`v0.2.2`/`v0.2.3`/`v0.3.1` 从未打过 tag，其 compare/release 链接 404；② 本机 DNS 把 `buck2hub.com` 解析到保留网段 `198.18.1.149`，外链可用性在本环境不可判定（`buck2hub.com` 与 crates.io API 探针均为代理伪影），因此不依据本轮探测改动任何外链 | N/A（不新增卡；两条发现登记给 `REL-01`） | `REL-01` Current evidence、Review log、兼容与文档收口（CHANGELOG 链接判据） |
| 2026-11-12 11:10:00 UTC | review R25（文档滞后项对齐 R22/R24 事实） | F30：三处文档滞后——「当前缺口」表 GAP-07 仍写「CI 无 push 触发」（R22 已修并取得 run 证据）、「与其它计划的关系」表仍把 push 门列为待办、测试矩阵「编译门槛」写成 `cargo test --no-run`（CI 实为 `--all-targets`）。三处均按实测事实更新 | N/A（不新增卡；不改代码） | 当前缺口表、与其它计划的关系表、测试矩阵、Review log、plan-status |
| 2026-11-12 11:30:00 UTC | review R26（路径层不变量与诊断准确性） | F31：`validate_windows_components` 对 `..` 命中的是「结尾空格或点」规则，报错为 `` `..` ends with a space or dot, which Windows strips ``——拒绝行为正确但诊断误导（Windows 会剥掉结尾点，`..` 是遍历语义，两者成因不同，调用方会按错误方向排查）。由新增的组合式不变量测试（768 种拼写 × 结构不变量）与「拒绝原因分类」测试发现。修：`..` 组件优先显式拒绝并给出 `` `..` is not allowed in a Windows guest path ``（`70a3155`）；同时把 28 个非法形态的断言从「有错即可」收紧为「必须命中对应检查」，NUL 与纯控制字符分列，新增纯控制字符用例。`cargo test --lib windows_path` 9 → 11，`cargo test --lib` 85 → 87 | N/A（`FS-01` 既有 AC：路径规范化与非法形式拒绝；无卡拆合） | `FS-01` 实现证据与门禁行、Review log、`src/guest_path.rs`、plan-status |
| 2026-11-12 12:00:00 UTC | review R27（QEMU 选项编码注入面） | F32：宿主路径被原样插进逗号分隔的 QEMU 选项值——`-drive file={overlay}`、`-drive file={seed}`、`-chardev socket,path={qmp}`、`-chardev stdio,…,logfile={serial}`，以及 Windows 分支的 `-drive …file={OVMF code/vars}` 与 `-chardev …path={swtpm socket}`。路径里出现逗号时 QEMU 会把它读成额外 key=value 对：轻则报出难懂的启动失败，重则被当作注入属性（如 `cache=unsafe`）。修：新增 `qemu_option_path(kind, path) -> Result<String>` 统一校验（空、含逗号、控制字符均报可操作错误），五类路径全部改走它，`windows_firmware_args` 改为返回 `Result<Vec<String>>`（`85bc525`）；空格仍允许（单 argv 元素）。新增单测覆盖三类路径的逗号拒绝与含空格路径的正向对照，`cargo test --lib` 87 → 88 | N/A（`OSX-02` 既有 AC：Windows QEMU 生命周期与参数正确；无卡拆合） | `OSX-02` 实现证据、Review log、`src/qemu.rs`、CHANGELOG、plan-status |
| 2026-11-12 12:25:00 UTC | review R28（拒绝路径的诊断质量：钉住的主机密钥） | F33：`check_server_key` 返回 `false` 时 russh 抛 `Error::UnknownKey`，而 `connect_over` 只有 IO/Disconnect/通配三个分支，于是钉住密钥不匹配被归为 `SSH client error: UnknownKey`——既没说明是哪项校验失败，也没说明该怎么办；该场景恰恰是安全相关的（同网段另一台 VM 抢到同一地址、或 VM 被重新部署换了密钥），而且 Windows 是唯一钉住密钥的传输。修：新增 `host_key_rejection_message(transport, pinned)`，在握手匹配里显式拦截 `UnknownKey`，钉住场景给出「不是本 VM 部署时的那把密钥 / DHCP 租约可能已移动 / 用 `get_ip` 核对地址」的可操作说明，未钉住的 vsock 保持中性措辞（`5578f52`）；新增单测断言消息含两项成因与 `get_ip` 指引、且不含裸 `UnknownKey`。`cargo test --lib` 88 → 89 | N/A（`TRN-01` 既有 AC：host key pinning 与拒绝行为；无卡拆合） | `TRN-01` 实现证据、Review log、`src/ssh.rs`、plan-status |
| 2026-11-12 12:50:00 UTC | review R29（Secure Boot 配对的静默降级） | F34：R9 只修了**候选表内的排序**（优先 `.ms` 模板），但 `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS` 覆盖路径只按 code 文件名推断 `secure_boot`，从不检查 vars 模板是否真的带 Microsoft 密钥；用户把 `OVMF_CODE_4M.secboot.fd` 与普通 `OVMF_VARS_4M.fd` 配对时，Qlean 会用 `smm=on` + secure pflash 启动，固件却停在 **setup mode**——Windows 11 会以一个与固件无关的报错拒绝安装。README 当时还把这当成「可接受的 fallback」写进文档，属实现与文档同向错误。修：新增 `vars_template_enrolls_microsoft_keys`（在 vars 模板里按 UTF-16LE 找已登记的 `Microsoft Corporation` 主体）与 `ensure_secure_boot_pair`，覆盖路径与候选路径都先校验（`dedaacd`）；配对不成立时给出可操作错误（说明 setup mode 后果、指向同包的 `.ms` 模板、或改用非 `secboot` 镜像）。README 段落与 CHANGELOG 同步改为「拒绝而非降级」。`cargo test --lib` 89 → 90 | N/A（`OSX-02` 既有 AC：Secure Boot 仅在真 enrolled 时启用，不得静默降级固件） | `OSX-02` 实现证据、Review log、`src/firmware.rs`、README、CHANGELOG、plan-status |
| 2026-11-12 13:20:00 UTC | review R30（不完整状态下的报错质量：进程内 panic） | F35：`Machine::get_ssh` 用 `.expect("Machine not initialized or spawned")` 取会话，因此**所有**会话级操作（`upload`、`download`、`copy`、`read`/`write`/`metadata`/`rename`/`remove_*` 等 19 个入口）在机器未运行时会 **panic**，直接把库使用者的进程打挂；唯一例外的 `exec` 返回 `SSH session not established`——既没说是哪台机器、也没说怎么启动。`remove_dir_all` 与 `open_interactive_shell` 各自还留着同一条 `expect`。这属于计划要求的「不完整状态下必须给出可操作错误」覆盖面缺口，且 panic 在库中比错误严重得多。修：新增 `session_or_operation_error`/`not_running_error`（`Result` 而非 `expect`），`get_ssh(operation)` 统一走它，19 个调用点各自传入操作名（upload/download/copy/read/rename/…），`exec` 也改走同一入口，`remove_dir_all`/`open_interactive_shell` 的 `expect` 一并去掉（`940dbe6`）；新增 2 个单测：错误文案含机器 id、操作名、`init`/`spawn` 指引，且「有 token 无会话」（`spawn` 失败后的可重试状态）与「两者皆无」两种不完整状态都返回错误而非 panic。`cargo test --lib` 90 → 92 | N/A（`OSX-03`/`TRN-01` 既有 AC：错误必须可操作；无卡拆合） | `OSX-03` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 13:50:00 UTC | review R31（DHCP 租约行的时效性） | F36：`lease_address_for` 取「首个 MAC 匹配且为 IPv4」的行。libvirt 对同一 MAC 会同时保留多行租约（临到期的一行 + 续租后的新行），行序不保证新行在前，于是续租后可能拿到 Guest **已经放弃**的旧地址——后续连接在无人应答的地址上耗尽整个预算，最终报「连接超时」，与真实原因（租约选择）完全无关。R13 修了双栈的 IPv6 干扰，但同协议多行的时效问题没覆盖。修：`DhcpLease` 增加 `expiry`（按 libvirt 打印的 `YYYY-MM-DD HH:MM:SS` 原样保存，该格式字典序即时间序，无需引入时间库），`lease_address_for` 改为在同 MAC 的 IPv4 行里取**最新到期**的一行（`3cdf5a3`）；超时错误逐行附上到期时间，便于判断是否拿到了过期租约。新增 2 个单测：同 MAC 两行（旧行在前）取新地址；无时间戳行的解析退化。README「Windows transport」同步说明「仅 IPv4 + 最新租约优先」。`cargo test --lib` 92 → 94 | N/A（`IP-01` 既有 AC：地址必须属于本 VM 且可拨号；无卡拆合） | `IP-01` 实现证据、Review log、`src/utils.rs`、README、CHANGELOG、plan-status |
| 2026-11-12 14:20:00 UTC | review R32（部署物料与目录权限） | F37：R11 只给 seed 目录里的两个**文件**加了 `0600`（`authorized_keys`、`ssh_host_ed25519_key`），但 (1) `xorriso` 生成的 `seed.iso` 用进程 umask（通常 `0644`），而该镜像里就有**每 VM 的主机私钥**——同机其他用户可读出来后冒充 guest 的 sshd，而客户端恰恰钉住这把密钥，冒充不会被发现；(2) `seed/`、`seed/QLEANSEED/`、`~/.local/share/qlean/{secrets,runs}`、每 VM 的 run 目录全部用默认 umask 创建，`secrets/` 里是**客户端私钥**。安全边界只靠「用户家目录通常是 0700」这一外部假设。修：新增 `utils::restrict_dir`（`0700`），`create_dir` 对 data/images/secrets/runs 与已存在目录统一收紧，`Machine::new` 对 run 目录、`DeploySeed::stage` 对 seed 两级目录同样处理；`build()` 成功后调用新的 `seal_seed_medium`（`0600`）封住镜像（`80a57f7`）。新增 2 个单测：`create_dir` 在宽松 umask 与已存在 `0755` 目录两种情况下都得到 `0700`；`seal_seed_medium` 把 `0644` 文件变为 `0600`。seed 文件用例扩展为同时断言两级目录为 `0700`。README「Windows transport and security」与 CHANGELOG 同步。`cargo test --lib` 94 → 96 | N/A（`OSX-03` 既有 AC：seed 物料仅在部署期存在且不可被他人读取；无卡拆合） | `OSX-03` 实现证据、Review log、`src/utils.rs`、`src/windows.rs`、`src/machine.rs`、README、CHANGELOG、plan-status |
| 2026-11-12 14:50:00 UTC | review R33（pid 复用与信号对象） | F38：`Drop`、`shutdown` 的超时兜底、`launch` 失败清理里的 `terminate_qemu` 都直接 `kill -9 <pid>`，pid 来自 `qemu.pid`/`self.pid`。若 QEMU 已自行退出、内核把同一 pid 分给了别的进程，`Drop` 会**无条件 SIGKILL 一个无关进程**——库使用者可能在毫无察觉的情况下丢失他人数据。`/proc/<pid>` 是否存在并不能证明它是 QEMU。修：新增 `cmdline_is_qemu`/`process_is_qemu`/`kill_if_qemu`，只在 `/proc/<pid>/cmdline` 的 **argv[0]** 是 `qemu-system*`/`qemu-kvm` 时才发信号，否则 `warn!` 说明 pid 疑似被复用；三处调用点全部改走（`23f387c`）。新增 2 个单测：`cmdline_is_qemu` 的 8 种形态（包含「后续参数提到 qemu 的 `tee`」「`qemu-img`」两类假阳性）；`process_is_qemu` 对测试进程与不存在 pid 均返回 `false`。`cargo test --lib` 96 → 98 | N/A（`FS-01`/`OSX-03` 既有 AC：清理不得影响宿主其他进程；无卡拆合） | `OSX-03` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 15:20:00 UTC | review R34（宿主前置程序的聚合报告） | F39：`ensure_host_prerequisites` 对 `qemu-system-x86_64`/`qemu-img`/`xorriso`/`virsh` 逐个 `?`，于是「一次运行报出全部缺口」这条设计只对 `firmware::host_support_problems` 生效——而那组检查反而**排在后面**。新宿主实际要经历「装一个包→再跑→再装一个」多轮；且 `let _ = cmd.output()` 丢掉退出状态，装了个坏的可执行文件也会被判为「存在」。修：新增 `ProgramProbe`/`program_problems` 把四个程序一次探测完并合并成一条错误，`--version` 非零退出单独归类为「安装疑似损坏」而不是「未安装」（`ca4996c`）。新增 3 个单测：多缺口同时报告且「未安装」/「损坏」不互相串味、全可用时为空、缺失程序名出现在错误里。`cargo test --lib` 98 → 101 | N/A（`OSX-02` 既有 AC：宿主前置缺口一次性报全；无卡拆合） | `OSX-02` 实现证据、Review log、`src/utils.rs`、CHANGELOG、plan-status |
| 2026-11-12 15:50:00 UTC | review R35（镜像下载的完整性判据） | F40：`download_with_hash` 用 `.part` + rename 是好的，但 (1) 全程没有比较 `content_length` 与实际收字节数——代理/服务端提前关流时循环以「干净 EOF」结束，文件被 **rename 到最终路径**，随后 `fetch_from_source` 报的是「hash mismatch」。用户看到的结论是「校验和不符」（会怀疑源站或中间人），真因却是传输被截断；Windows qcow2 动辄 20+ GiB，这种误判代价极高。(2) 校验失败的文件**留在缓存目录**里，占满磁盘，且留下一个「看起来合法」的产物。修：新增 `truncation_problem(expected, downloaded)`，在 rename **之前**比对字节数，短传/多传分别给出缺多少字节/「响应已损坏」并删除 `.part`；新增 `verify_fetched`，校验失败时删除文件并在错误里说明已删除（两处 `fetch_from_source` 分支共用）（`4efb45c`）。新增 3 个单测：长度未知与相等时不报、短传/多传两种措辞、拒绝后文件不存在且大小写不敏感匹配保留文件。`cargo test --lib` 101 → 104 | N/A（`OSX-02`/`IP-01` 既有 AC：镜像获取失败必须归因准确且不留下不可用产物；无卡拆合） | `OSX-02` 实现证据、Review log、`src/image.rs`、CHANGELOG、plan-status |
| 2026-11-12 16:20:00 UTC | review R36（xorriso 参数里的宿主路径） | F41：R27 已把 QEMU 参数里的路径统一走 `qemu_option_path`，但**同一类问题在 seed 构建处没修**：Linux 路径用 `seed_iso_path.to_str().unwrap()`（家目录非 UTF-8 直接 **panic**）与 `to_string_lossy()`（把非 UTF-8 字节换成 `U+FFFD`，于是 xorriso 拿到一个**不存在但看起来正常**的路径），Windows 的 `-graft-points` 用 `.display()` 有同样的损失。这类宿主（老 locale、非 UTF-8 家目录）上，seed 构建会以「xorriso: file not found」或 panic 告终，而错误完全指不到真因。修：新增 `utils::path_argument(prefix, path)`，用 `OsString` 拼接 `key=path`，字节原样保留；Linux 的 `-o` 改为独立 `arg`（不再需要任何字符串转换），`user-data=`/`meta-data=`/`qlean=` 三处全部走新函数（`450a647`）。新增 2 个单测：非 UTF-8 路径（`/home/l\xffgacy/...`）的字节逐一相等且断言 `to_string_lossy()` 确实会损坏它、前缀为空与前缀非空两种拼法。`cargo test --lib` 104 → 106 | N/A（`OSX-03` 既有 AC：seed 构建在任意宿主路径下都必须成功或给出准确原因；无卡拆合） | `OSX-03` 实现证据、Review log、`src/utils.rs`、`src/machine.rs`、`src/windows.rs`、CHANGELOG、plan-status |
| 2026-11-12 16:50:00 UTC | review R37（构造失败时的残留） | F42：`Machine::new` 会先建 run 目录、`qemu-img` overlay、SSH keypair，Windows 分支还会生成 host key 并跑 `xorriso` 建 ISO；**最后**才在 `launch` 里调 `firmware::ensure_host_support()`。任何一步失败时返回 `Err` 且没有 `Machine` 对象，于是 `Drop` 不执行，`runs/<id>/`（含 overlay、seed 目录、host 私钥）永久残留，`get_free_cid` 还会把它算进占用。缺 `swtpm`/OVMF 的宿主上，用户先白跑一次 `xorriso`，再得到一个残骸目录。修：新增 `RunDirGuard`（armed 时 `Drop` 递归删除 run 目录并 `warn!`），在目录建立后立即武装，两处成功返回前 `disarm()`；Windows 分支把 `firmware::ensure_host_support()` 提到任何密钥/seed 生成**之前**（`a6722f7`）。新增 2 个单测：构造中断（已写入 overlay 与 seed 子目录）后目录不存在；`disarm()` 后目录与内容保留。`cargo test --lib` 106 → 108 | N/A（`OSX-02`/`OSX-03` 既有 AC：构造失败不得留下残留物料；无卡拆合） | `OSX-02`/`OSX-03` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 17:20:00 UTC | review R38（库入口的 panic 面） | F43：R30 只清掉了 `get_ssh` 那条 `expect`，其余还在——(1) `QleanDirs::new` 开头 `ProjectDirs::from(...).expect("Couldn't get project dir")`：`XDG_DATA_HOME`/`HOME` 不可用（容器、`env -i`、systemd 单元未设 `HOME`）时，**每个**公开入口都直接 panic；(2) 更糟的是 `Drop for Machine` 里 `QleanDirs::new().expect(...)`——在**析构**中 panic，若此时正在展开别的 panic 就变成进程 **abort**；(3) `create_dir` 对建不出来的目录 `expect("Failed to create directory")`，而签名本来就返回 `Result`；(4) `launch` 里仍有 `ssh_cancel_token.expect("Machine not initialized or spawned")` 与 `swtpm.expect("swtpm was just started")`；(5) `ssh::get_sftp` 的 `expect("SFTP session must exist")`。修：新增 `project_dir_or_explain` 返回可执行的错误（指明 `XDG_DATA_HOME`/`HOME`），`create_dir` 用 `with_context` 返回错误，`Drop` 改为匹配 `Ok/Err` 并 `warn!`（**绝不在析构中 panic**），`launch` 两处与 `get_sftp`、`strip_prefix` 全部改为带上下文的错误（`4de03cc`）。新增 2 个单测：`project_dir_or_explain(None)` 的错误含两个环境变量名、父路径是普通文件时 `create_dir` 返回错误而非 panic。`cargo test --lib` 108 → 110；`rg '\.expect\('` 复查后生产代码只剩 `qemu.rs` 的 spawn 后取值不变量 | N/A（全线卡既有 AC：库入口不得 panic；无卡拆合） | `OSX-01`/`OSX-02` 实现证据、Review log、`src/utils.rs`、`src/machine.rs`、`src/ssh.rs`、CHANGELOG、plan-status |
| 2026-11-12 17:50:00 UTC | review R39（每 VM 的 OVMF vars 镜像） | F44：`prepare_vars` 对 per-VM 的 `ovmf_vars.fd` 有两处盲信——(1) 首次创建走 `std::fs::copy`，而 Unix 的 `copy` **连权限位一起复制**：发行版把 vars 模板打成 `0444` 时，per-VM 镜像也是 `0444`，QEMU 的 pflash unit=1 变成只读，固件写不回变量（Secure Boot 密钥、启动项全部存不上），Windows 安装在毫无线索的地方失败；(2) 复用时只判 `is_file()` 就直接拿来启动，若 OVMF 已随发行版升级（模板 528 KiB → 另一个尺寸）或上次写完被截断，这块 NVRAM 与当前 code 镜像不配套，后果是固件内部报错或变量区损坏。修：新增 `utils::restrict_file`（`0600`，兼作「可写」），创建后与复用前都施加；复用前比对 per-VM 镜像与模板的字节数，不一致则**拒绝启动**并给出可执行的恢复步骤（删除该文件会丢 Secure Boot/TPM NVRAM，必须由用户决定），绝不静默覆盖用户的 NVRAM；`windows::set_owner_only` 收敛到同一实现（`c6c84f5`）。新增 2 个单测：`0444` 模板产出的镜像模式为 `0600` 且**真的能写**、陈旧镜像被拒且原内容未被覆盖。`cargo test --lib` 110 → 112 | N/A（`OSX-02`/`OSX-03` 既有 AC：固件状态必须可用且不得静默损坏；无卡拆合） | `OSX-02` 实现证据、Review log、`src/firmware.rs`、`src/utils.rs`、`src/windows.rs`、CHANGELOG、plan-status |
| 2026-11-12 18:20:00 UTC | review R40（swtpm 的停止路径） | F45：`Swtpm::stop`/`stop_now` 都直接 `start_kill()`，也就是 **`SIGKILL`**。但 swtpm 是在**关闭过程中**把 TPM 状态写盘的（permall 等），被强杀就可能留下半写状态文件；下次启动要么报状态损坏，要么 TPM 身份丢失——而 Windows 把 BitLocker 密钥封在 TPM 里，后果是恢复密钥提示。`stop_now` 还叠加一层：它只发信号就返回，随后 `Child` 被丢弃，`kill_on_drop(true)` 立刻补一发 `SIGKILL`，等于**优雅停止根本没机会发生**。我们的 `Drop for Machine` 走的正是这条路径，所以每次 Ctrl-C 或结束程序都在赌状态文件完好。修：新增 `signal_terminate`（Unix 上 `libc::kill(pid, SIGTERM)`，其它平台退回原行为），`stop()` 改为 SIGTERM → `SHUTDOWN_GRACE`（2s）→ 仍未退出才 kill；`stop_now()` 在 `Drop` 里**同步**进行同样的等待（否则 `kill_on_drop` 会立刻强杀），超时才 kill（`c688ce3`）。新增 2 个单测：`sleep` 走优雅路径且**用时短于**宽限期（证明没有落到强杀）、带 `trap '' TERM` 且用标记文件确认陷阱已装好的 `sh` **必须等满宽限期才被杀**（证明兜底真的执行）。`cargo test --lib` 112 → 114（其中 1 条耗时 ~2s） | N/A（`OSX-02` 既有 AC：TPM 状态跨重启必须可信；无卡拆合） | `OSX-02` 实现证据、Review log、`src/firmware.rs`、`Cargo.toml`/`Cargo.lock`（新增 `libc`）、CHANGELOG、plan-status |
| 2026-11-12 18:50:00 UTC | review R41（「问不到」被当成「没有」） | F46：两处把**未知**折叠成**否定**——(1) `deploy_marker_present` 在没有 SSH 会话时返回 `Ok(false)`，而它自己的文档写的是「`Ok(false)` 表示 guest 回答了、标记不存在；`Err` 表示问不到」。丢失会话于是被当成「还没部署完」，`confirm_deployment` 会**空转满 900 秒**，最后给出「部署超时」这条与真因（宿主侧会话没了）无关的结论；(2) `is_running` 用 `qmp::query_running(...).unwrap_or(false)`，QMP 查询失败（socket 存在但不应答）被报成「没在运行」——而 `MachinePool::init_all`/`spawn_all` 正是拿 `false` 当「可以启动」的判据，于是可能在**活着的** domain 的磁盘上再起一个 QEMU，即镜像损坏路径。修：新增 `marker_probe_guard`，无会话时返回 `not_running_error`（与 R30 同一条诊断），`deploy_marker_present` 内部的两处 `Ok(false)` 改为「不可能发生」的显式错误；新增 `running_check`，只有「有 pid 但 socket 没了」与「没有 pid」才算「没在运行」，两者齐全时 QMP 失败**如实报错**并提示先确认进程是否还在（`3505750`）。新增 2 个单测：无会话必须是错误且含 `VM-<id>`、`running_check` 的四种输入组合逐一断言。`cargo test --lib` 114 → 116 | N/A（`OSX-02`/`EXE-01` 既有 AC：会话类操作必须给出可执行诊断；无卡拆合） | `OSX-02` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 19:15:00 UTC | review R42（`spawn` 前必须已部署） | F47：`MachinePool` 有 `wants_init()`/`needs_first_boot()` 来把「部署还没跑过」的 Windows 机器路由到 `init`，但**库的公开入口** `Machine::spawn` 没有同样的判断。`spawn` 走 `launch(false)`，不挂载 seed 介质 → guest 永远拿不到 `authorized_keys` → 唯一的症状是 `confirm_deployment` 空转满 900 秒后报「部署未完成」。也就是说：一个可以从公开 API 构造出来的状态，其失败只能在 15 分钟后以与真因无关的信息暴露。修：新增 `spawn_guard`，`spawn` 在「已启动」判定之后立即检查 `needs_first_boot()` 并给出「首次启动用 `init`、之后用 `spawn`」的处置（`692c456`）。新增 1 个单测：错误里必须出现 `VM-<id>` 与 `init`，且非首启场景必须放行。`cargo test --lib` 116 → 117 | N/A（`OSX-02`/`EXE-01` 既有 AC：Windows 首启与再启动路径必须可区分；无卡拆合） | `OSX-02` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 19:40:00 UTC | review R43（被拒绝的固定主机密钥不得重试） | F48：`connect_ssh`/`connect_ssh_windows` 对**任何**错误都走同一条重试路径，于是「固定主机密钥不匹配」——一个**安全判定**，重试永远不可能成功——被当成「guest 的 sshd 还没起来」这类瞬时故障，反复重试直到把整个连接预算耗尽，最后用「仍然不可达」覆盖掉真正的原因。这正是 `host_key_rejection_message` 存在的理由被调用方抵消：诊断写得很清楚，却从未到达用户。顺带修掉三处用户可见消息里**句中出现的一串空格**（`\` 续行被误删的残留：`is_running` 的上下文、`spawn_guard`、`connect_ssh_windows` 的超时兜底），并把 `host_key_rejection_message` 里那 13 个空格一并清掉。修：抽出 `PINNED_KEY_REJECTED` 作为**唯一**定义，既用于构造消息、也用于 `is_fatal_connect_error` 沿 `anyhow` 错误链识别（构造与识别不可能漂移）；两个重试循环遇到致命错误立即返回（`f3296fc`）。新增 3 个单测：致命判定（含跨 context 层）必须为真、连接被拒/未固定场景必须为假；两组消息逐行断言不含连续两个空格。`cargo test --lib` 117 → 120 | N/A（`TRN-01`/`OSX-02` 既有 AC：固定主机密钥必须拒绝，且用户要能看懂为什么；无卡拆合） | `TRN-01` 实现证据、Review log、`src/ssh.rs`、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 20:05:00 UTC | review R44（QEMU 进程如何结束必须说清楚） | F49：`map_qemu_exit_status` 两个方向都错。(1) 它只看 `status.success()`，`expected_to_exit` 仅在成功分支被读——而 Windows guest 忽略 ACPI powerdown 时，teardown 会先 SIGTERM 再 SIGKILL，于是**我们自己发起的停止**被报成「QEMU 启动失败」，把调用方自己造成的后果算在它头上；(2) 信号死亡时 `ExitStatus::code()` 是 `None`，消息逐字变成「QEMU exited with error code: None」——一条不含任何信息的诊断。修：`describe_exit` 统一描述死因（`exited with status 3` / `was killed by signal 9 (SIGKILL)`），`signal_name` 覆盖 SIGHUP/INT/ILL/ABRT/BUS/FPE/KILL/SEGV/PIPE/TERM；已请求停止时非零或信号死亡只 `warn!` 不报错，未请求时给出「在未被要求停止前死亡，请查日志」（`1bb1af1`）。新增 4 个单测：teardown 被杀不算失败（SIGTERM/SIGKILL/退出码 1）、未请求的死亡必须点名信号且**不能**出现 `None`、非零退出码必须点名、已请求的正常退出仍为 `Ok`。`cargo test --lib` 120 → 124 | N/A（`OSX-02` 既有 AC：停止路径必须可诊断；无卡拆合） | `OSX-02` 实现证据、Review log、`src/qemu.rs`、CHANGELOG、plan-status |
| 2026-11-12 20:30:00 UTC | review R45（固件解析要取第一个**可用**的候选） | F50：`resolve_ovmf_with` 用 `find_map` 取第一个**物理存在**的候选，`ensure_secure_boot_pair` 的检查在它**之后**才跑。于是发行版把 `OVMF_CODE.secboot.4m.fd` 和**普通** `OVMF_VARS.4m.fd` 摆在一起（Arch/Fedora 的常见布局）时：解析器先选中这个不可用的组合 → 校验失败 → **整机拒绝**，而紧邻的 `OVMF_CODE.4m.fd`（关 Secure Boot）本来完全可用。R39 之前这里会静默进 setup mode（真 bug），R39 之后变成硬失败（另一种 bug）——两次都是「检查放错了层」：判据应当在**候选筛选**里，而不是在**选定之后**。修：`resolve_ovmf_with` 增加 `enrolls_microsoft_keys` 探针，返回 `ResolvedFirmware { paths, skipped }`——不可用的 pair 只记原因并继续下一个候选；vars 不可读也按「不可用」处理但原因里保留 I/O 错误；全部不可用时 `no_usable_firmware_message` 逐条列出被跳过的 pair 并给出 `QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS` 覆盖方式与「换非 secboot code 关掉 Secure Boot」两条出路（`3c0ad9f`）。新增 3 个单测（共 6 个覆盖解析器）：secboot 无密钥**不得**遮蔽普通候选（断言落到 `OVMF_CODE.4m.fd` 且 `secure_boot=false`、`skipped` 恰一条且提到 setup mode）、全部不可用时错误必须点名 setup mode 与覆盖变量、vars 不可读时必须报出 I/O 原因。`cargo test --lib` 124 → 127 | N/A（`OSX-01` 既有 AC：宿主缺少固件时必须在启动前给出可执行诊断；无卡拆合） | `OSX-01` 实现证据、Review log、`src/firmware.rs`、CHANGELOG、plan-status |
| 2026-11-12 20:55:00 UTC | review R46（池子不得取消其他机器的启动） | F51：`init_all`/`spawn_all` 用 `try_join_all`，**任一**机器失败就短路——被丢弃的是其他机器的启动 future。`Machine::init` 的 future 被 drop 时，已经 spawn 出来的 QEMU 进程会继续跑，而 `self.pid` 可能还没写入：下一次 `init_all` 判 `is_running()==false`，于是重新 `qemu-img create` 覆写 overlay——正是在**活着的 guest 磁盘上重建 overlay** 的数据损坏路径（与 F46 同源：把「不知道」当「没有」，这里是把自己的取消当成「没在跑」）。修：新增 `run_all`（`join_all` + 逐台标注机器名后聚合错误），`init_all`/`spawn_all`/`shutdown_all` 三处统一走它——单台失败只影响自己，错误一次性带名字汇报；同时保留「绝不取消启动 future」的理由写在函数文档里（`f2426cd`）。新增 3 个单测：两台失败必须都点名且不误报健康机器、全部成功时静默、有失败时**其余任务仍必须被驱动完成**（用计数器断言，短路实现会挂）。`cargo test --lib` 127 → 130 | N/A（`OSX-02` 既有 AC：多机场景中的失败必须可定位且不互相破坏；无卡拆合） | `OSX-02` 实现证据、Review log、`src/pool.rs`、CHANGELOG、plan-status |
| 2026-11-12 21:20:00 UTC | review R47（`qemu-bridge-helper` 属于宿主前置检查） | F52：DEP-02 明确把 `qemu-bridge-helper` 列为 Windows 宿主依赖，而 `ensure_host_prerequisites` 的 `REQUIRED_PROGRAMS` 只有 `qemu-system-x86_64`/`qemu-img`/`xorriso`/`virsh`——缺 helper 或 `/etc/qemu/bridge.conf` 没有 `allow qlbr0` 时，前检查静默通过，QEMU 在 `-netdev bridge,br=qlbr0` 处才失败，报的是 QEMU 自己的内部错误。Windows 传输**没有 vsock 兜底**，桥接是唯一通路，所以这是核心通路的静默缺口；且 helper 装在 `libexec` 而不在 `PATH`，`--version` 式探测根本看不到它。修：新增 `BRIDGE_HELPER_PROGRAM`/`BRIDGE_HELPER_CANDIDATES`、`bridge_helper_path(exists, on_path)`（先已知安装路径再 `PATH` 兜底）、`bridge_helper_problem(found)`（缺失时把「装包」与「`allow qlbr0`」两件事一并说清），`check_commands_available` 改为返回 `Vec<String>` 与 helper 问题**合并**后统一报错（一次列全，延续 R34 的聚合原则）。新增 3 个单测（路径优先/`PATH` 兜底、缺失消息必须同时点名 `bridge.conf` 与 `allow qlbr0`、消息不含双空格——R43 教训的回归守卫），并把既有 `check_commands_available` 测试改到新签名。`cargo test --lib` 130 → 133 | N/A（`OSX-02` 既有 AC：宿主前置条件必须一次性报全；无卡拆合） | `OSX-02` 实现证据、Review log、`src/utils.rs`、CHANGELOG、plan-status |
| 2026-11-12 21:45:00 UTC | review R48（teardown 不得报告没有发生的关停） | F53：`shutdown` 的关停等待循环在 `kill_if_qemu(pid)` 之后**无条件 `break` 并返回 `Ok(())`**——SIGKILL 若没送到（EPERM、容器里 `kill` 程序不可用、pid 被复用但 cmdline 仍像 QEMU），QEMU 还在跑，调用者却拿到「成功」，下一次启动就会在活着的 guest 磁盘上重建 overlay（与 F46/F51 同一条数据损坏路径的第三个入口）。`kill_if_qemu` 的文档说「返回信号是否已发送」，实现却只用外部 `kill` 命令、**丢弃其退出码**，只要前置检查通过就返回 `true`。另外 `qmp::powerdown` 失败只 `debug!`：优雅关停压根没请求出去时，用户唯一看到的是「超时，强杀」，死因不可见（F49 的同类）。修：新增纯函数 `teardown_step(alive, elapsed, grace, kill_sent) -> TeardownStep`（`StillGone`/`KeepWaiting`/`ForceKill`/`Unkillable`），`shutdown` 改为按它决策，`Unkillable` 时 **`bail!` 并保留 `self.pid`**（`Drop` 会再试一次 SIGKILL，`is_running` 也不再谎报），错误里带 pid 与人工清理指引；`signal_kill` 改用 `libc::kill`（与 R40 的 `signal_terminate` 一致），`kill_if_qemu` 改为如实反映是否送达（进程已消失不算失败）；powerdown 失败改 `warn!` 并说明「可能被强杀」。新增 3 个单测覆盖四种出口（含「宽限期内已发信号仍在等」与「宽限期外未发信号才强杀」）。`cargo test --lib` 133 → 136 | N/A（`OSX-02` 既有 AC：关停必须可验证，不得留下活着的 QEMU；无卡拆合） | `OSX-02` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 22:10:00 UTC | review R49（启动失败路径不得无限挂起） | F54：`launch` 的两条失败清理路径都是「`terminate_qemu(pid)` 之后 `let _ = qemu_handle.await;`」——**无限等待**。若 QEMU 杀不掉（EPERM、被 ptrace 暂停、pid 已不是 QEMU），`qemu_handle` 永远不会结束（它还在读 QEMU 的 stdout/stderr 管道），于是 `launch` 永不返回，**原始失败原因永不呈现**——而 Windows 首启失败的诊断（固件/TPM/部署日志）恰恰全在这条路径上，等于把最有价值的证据锁死。`terminate_qemu` 本身也用的是外部 `kill` 程序并丢弃退出码，杀掉失败会被当成杀掉成功。修：新增 `signal_term`（`libc::kill`，与 R48 的 `signal_kill` 一对，拒绝时 `warn!`）与泛型 `reap_launch_task(task, grace)`——有界等待（5s）后 `abort()` 并记录，两条失败路径都改用它，保证 `return Err(e)`/`bail!(e)` 一定能到达。新增 2 个单测：已结束的任务不被 abort；拒绝结束的任务在 50ms 内放弃而不是挂住（断言耗时上限）。`cargo test --lib` 136 → 138 | N/A（`OSX-02` 既有 AC：启动失败必须给出可诊断原因；无卡拆合） | `OSX-02` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 22:35:00 UTC | review R50（已部署的 guest 不因清理失败被判失败） | F55：`DeploySeed::remove` 只对 **ISO** 的 `NotFound` 宽容，对**目录**的 `remove_dir_all` 不宽容——而这个函数跑在「guest 侧已经重启」之后，半途清理是正常情形，于是**首启成功**却被报成 `failed to delete the deployed seed medium`（正中 `windows_first_boot` 的核心验收）。更糟的是文档与调用点自相矛盾：`remove` 的注释写「清理失败不致命，返回错误只为让调用者记录」，而 `confirm_deployment` 直接 `?`——把一个**已经可用**的 VM 判成失败。修：`remove` 两条路径都容忍 `NotFound`（其余错误仍逐条保留第一条并继续清理另一半），`confirm_deployment` 改为 `warn!` 并带上 seed 路径（它就落在 0700 的运行目录里，不是泄漏）。新增 1 个单测：目录已被清掉（模拟两次尝试之间 guest 重启）时 `remove` 必须成功且 ISO 仍被删除。`cargo test --lib` 138 → 139 | N/A（`EXE-01` 既有 AC：部署成功后 VM 必须立即可用；无卡拆合） | `EXE-01` 实现证据、Review log、`src/windows.rs`、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 23:00:00 UTC | review R51（guest 地址只在 IPv4 里选） | F56：`select_guest_address` 不筛地址族，只按 MAC 匹配——「只用 IPv4」这条判据被放在**生产者**（`GUEST_IP_QUERY` 里的 `-AddressFamily IPv4`）而不是**选择点**。双栈适配器同时报出 `192.168.221.42` 与 `fe80::…` 时，会因「同 MAC 多个地址」被判为 ambiguous 而**拒绝一个完全可用的地址**；若哪天查询里丢了过滤，则会直接把无 scope id 的链路本地 IPv6 交给传输层。旁边的 `lease_address_for` 恰恰是在选择点过滤的（注释还专门解释了原因），同一份代码里两种做法，说明这不是疏漏而是没统一。修：`parse_adapter_addresses` 丢弃非 IPv4 行，`select_guest_address` 的匹配与「多地址」诊断**都**加 `ip.is_ipv4()`（纵深防御：选择点自己守规矩，不依赖调用者），文档口径改为「恰好一个 IPv4 地址」。新增 3 个单测：双栈只取 IPv4、仅 IPv6 时报错且消息提到 IPv4、绕过解析器直接传 IPv6 也不会被选中。`cargo test --lib` 139 → 142 | N/A（`IP-01` 既有 AC：地址必须来自本 VM 且可用；无卡拆合） | `IP-01` 实现证据、Review log、`src/windows.rs`、CHANGELOG、plan-status |
| 2026-11-12 23:25:00 UTC | review R52（Qlean 自己的探测要有预算，用户命令不要） | F57：`Session::call_with_output` **没有超时**，只靠 cancel token——而 cancel token 只在 `Drop`/`shutdown` 时才被取消。于是 Windows 的部署标记探测、`get_ip`、`copy` 一旦遇到「通道接受命令但 guest 侧永不返回」，就**永久挂住**。尤其致命的是 `confirm_deployment`：它的 15 分钟预算只在**两次探测之间**检查，单次探测挂住就等于预算形同虚设——`windows_first_boot` 的失败会表现为「qlean 卡住不动」，而不是任何一条可诊断的信息（R49 是启动路径的同一形状，这里是传输层）。修：新增 `bounded(budget, command, operation)` 与 `Session::call_probe`（`PROBE_TIMEOUT = 120s`），把 Qlean **自己**的三处探测（部署标记、`GUEST_IP_QUERY`、文件复制）切到有界版本；用户 `exec` 保持无界——`sleep 600` 是合法的静默命令，给传输层加全局空闲超时会把正常的用户命令杀掉（**这条边界是修复的重点，不是副产品**）。错误文案明确写「这是 Qlean 自己的探测上限，不是 guest 内的超时，命令可能仍在 guest 里跑」，不撒一个自己不知道的谎。新增 3 个单测：快速操作原样通过、原错误原样上抛、超预算时快速失败且文案含命令名与「Qlean 自己的上限」。`cargo test --lib` 142 → 145 | N/A（`EXE-01` 既有 AC：首启失败必须可诊断；无卡拆合） | `EXE-01` 实现证据、Review log、`src/ssh.rs`、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-12 23:50:00 UTC | review R53（先确认 `qlean` 网络真的提供 `qlbr0`） | F58：`ensure_network` 只看「`qlean` 网络存在不存在、active 不 active」，**从不检查它的桥名**，而 `launch_qemu` 里硬编码 `-netdev bridge,br=qlbr0`。若机器上已有一个**别的** `qlean` 网络（旧版本、别的工具、手工改过），检查全过 → QEMU 挂网卡失败或 guest 永远拿不到租约，用户看到的是一串 QEMU bridge 报错，而根因（存量网络定义过时）一个字都没提。Windows 只有桥接这一条路，这个缺口对 `windows_transport`/`windows_get_ip` 是**必然致命**的。修：`net_exists` 时先 `virsh net-dumpxml qlean` 取真实桥名（`network_bridge_name` 只认 `<bridge …/>` 元素，不被前面的 `<name>`/`<uuid>` 属性带偏；单双引号都认；读不出就 `warn!` 而不是猜），桥名不是 `qlbr0` 就 `bail!` 并给出**可直接粘贴**的 `net-destroy`/`net-undefine` 恢复命令——且这一步在 `net-autostart`/`net-start` **之前**，不留下改到一半的网络状态。新增 3 个单测：真实 dumpxml 解析、无 `<bridge>` 时不瞎猜、错误消息同时点名两个桥名与恢复命令。`cargo test --lib` 145 → 148 | N/A（`TRN-01`/`IP-01` 既有 AC：guest 必须拿到本 VM 的租约；无卡拆合） | `TRN-01`/`IP-01` 实现证据、Review log、`src/utils.rs`、CHANGELOG、plan-status |
| 2026-11-13 00:15:00 UTC | review R54（首启窗口里换 host key 是预期的，不是攻击） | F59：R43 的「pinned key 不符 → 立即致命」被放到了**所有**连接尝试上。可首启恰恰是 sshd 状态**预期在变**的阶段：首启任务要写 Qlean 的 host key 并重启 sshd，而且计划里明说 guest 可能重启多次。在这段窗口里只要有一次连接撞上「sshd 还带着镜像自带的 host key」，**整个 15 分钟部署预算当场作废**，报出来的还是一句 R43 的通用错——一个正确的修复被套在了错误的阶段上（与 F46/F47/F48 同族，这次是**时间维度**放错层）。修：`pinned_key_mismatch_is_fatal(deployment_in_progress)` 区分阶段——种子介质在 = 首启未完成 = 不符就**继续等**（记录最后一次不符），部署确认后不符仍然**立即致命**（R43 的保护一点没退）；预算耗尽时若最后原因是 key 不符，就用 `host_key_pending_message` 报告真实死因：点名地址、预算秒数、`ssh_host_ed25519_key`、种子卷名、README 的 image contract，并提示 `spawn`。`connect_ssh_windows` 新增 `deployment_in_progress` 参数，由 `deploy_seed.is_some()` 提供——种子的生命周期**本身**就是「部署未完成」的判据，不额外造状态位。新增 2 个单测（两阶段的致命性、消息内容）。`cargo test --lib` 148 → 150 | N/A（`EXE-01`/`TRN-01` 既有 AC：首启可跨重启且失败必须可诊断；无卡拆合） | `EXE-01`/`TRN-01` 实现证据、Review log、`src/ssh.rs`、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-13 00:40:00 UTC | review R55（guest 拒了钥匙就说拒了钥匙） | F60：传输层只把「host key 不符」当死因记下来，**握手成功但公钥被拒**的尝试被丢进泛型分支——预算耗尽后用户看到的是 `Timeout establishing SSH over tcp … check that sshd accepts the deployed client key`，等于什么都没说。而真实死因几乎总是 guest 侧的**契约细节**：authorized_keys 装错位置（管理员要走 `administrators_authorized_keys`）、ACL 没收敛、`PubkeyAuthentication` 关了，或者——最阴的一条——账号是**空密码**，Windows 的 `LimitBlankPasswordUse` 直接拒绝一切网络登录，公钥装对了也照样失败。README 原文还写着「Give it no static password」，等于把人往这个坑里带。修：抽出 `AUTH_REJECTED` 常量与 `is_auth_rejection`（只认握手之后的拒绝，不吞 host key 不符，也不吞连不上），循环里记下最后一次被拒；预算耗尽时按「host key 不符 → 公钥被拒 → 泛型」的优先级报真实死因，`auth_rejected_message` 点名安装位置、ACL、`PubkeyAuthentication yes`、空密码陷阱与 README 契约。README 第 2 步改成「给一个没人会输入的口令，但**不能是空口令**」并写明原因。新增 2 个单测（三类错误分类不串味、消息内容）。`cargo test --lib` 150 → 152 | N/A（`TRN-01` 既有 AC：连接失败必须可诊断；无卡拆合） | `TRN-01` 实现证据、Review log、`src/ssh.rs`、README、CHANGELOG、plan-status |
| 2026-11-13 01:10:00 UTC | review R56（一个预算管整段首启，不是每段各发一份） | F61：计划与 README 都写「部署预算 900s **约束首启的两半**：等 sshd 应答 + 等部署标记」，代码却是**三段各发一份**：`find_lease_address` 拿满 900s，`connect_ssh_windows` 再拿满 900s，`confirm_deployment` 又新开一个 900s。于是一个卡住的首启可以烧掉 45 分钟，而文档承诺的是 15 分钟——**用户按文档设的 `ssh_timeout` 完全不成立**，排障时也无法解释「为什么它等了一个多小时」。这类「文档承诺与实现不一致」比崩溃更耗人：它让所有时间判断都失去参考价值。修：首启引入**一个共享 deadline**（`Machine::first_boot_deadline`，仅 `init` + Windows 时设置），DHCP 发现、`sshd` 连接、部署标记三段都从它扣减；`remaining_budget` 是纯函数（到点即 `None`，不会把已耗尽的 deadline 变成新的等待），耗尽的报错用 `spent_first_boot_budget` 点名**没轮到的阶段**并说明「预算覆盖整段首启、后段不会重新发一份」，给出 `ssh_timeout` 这条唯一旋钮。README 同段改写为「一个 deadline 管整段首启」。`spawn`/Linux 路径不带 deadline，语义不变。新增 2 个单测（deadline 耗尽不复用、消息点名阶段与整段语义）。`cargo test --lib` 152 → 154 | N/A（`EXE-01` 既有 AC：首启时间盒与失败可诊断；无卡拆合） | `EXE-01` 实现证据、Review log、`src/machine.rs`、README、CHANGELOG、plan-status |
| 2026-11-13 01:35:00 UTC | review R57（非 UTF-8 镜像名不再共用一个缓存槽） | F62：`image::cache_name_from_source` 对**非 UTF-8** 的本地文件名回退成字面量 `custom-image`，于是**所有**这类镜像共用一个缓存文件。两个不同的 Windows qcow2（数 GB）会互相顶掉：`Image::load` 命中后重算哈希发现不符，转而重新下载，**每次在两者之间切换都要重下一遍**。调试时表现为「明明缓存过，怎么又在下」，几乎不可能指向真正原因（文件名编码）。修：新增 `local_cache_stem`——文件名是合法 UTF-8 时行为不变（仍取 stem），否则回退名带上**原始字节的 FNV-1a 哈希**（`custom-image-<16 hex>`），稳定且互不相同；URL 分支不动。新增 2 个单测（两个不同非 UTF-8 名必须得到不同缓存名且可重复、UTF-8 名保持原 stem）。`cargo test --lib` 154 → 156 | N/A（`IP-01`/镜像缓存既有契约：不同来源不得共享缓存；无卡拆合） | `IP-01` 实现证据、Review log、`src/image.rs`、CHANGELOG、plan-status |
| 2026-11-13 02:05:00 UTC | review R58（标记探测要加引号；测试目录的“唯一”后缀并不唯一） | F63 两项，都是「守卫看着在守、其实没守」：① 部署标记探测拼成 `cmd /c if exist {marker} echo deployed`，**路径没有引号**——`cmd` 按空格切分，一旦标记路径带空格（或未来改成 `%ProgramData%` 展开出空格），探测就永远「文件不存在」，于是**部署已完成的 guest 会被判成没完成**，用户白等满整个预算才知道是探测写错了；② `firmware::tests::temp_dir` 的「唯一」后缀用 `Instant::now().elapsed().as_nanos()`——从紧邻创建的那一刻算起，永远是几个纳秒，**等于常量**：同 tag 的两次调用会拿到同一目录，上一轮遗留的只读 vars 模板会让「复制一次」「只读也能用」这些断言变得毫无意义。修：① 新增 `marker_probe_command()` + `MARKER_PRESENT_TOKEN`，路径加引号，`machine::deploy_marker_present` 改用它们（匹配词也走常量，避免命令文本与判据漂移）；② `temp_dir` 改用进程内 `AtomicU64` 计数器。新增 3 个单测（引号形态、只有 echo 词跟在路径之后、同 tag 两次调用必不冲突）。`cargo test --lib` 156 → 159 | N/A（`EXE-01` 既有 AC：部署完成判定必须可信；无卡拆合） | `EXE-01` 实现证据、Review log、`src/windows.rs`、`src/machine.rs`、`src/firmware.rs`、CHANGELOG、plan-status |
| 2026-11-13 02:35:00 UTC | review R59（闭包自己的失败不能被收尾失败顶掉） | F64：`with_machine` 是 `let result = f(&mut machine).await; machine.shutdown().await?; result`——**收尾失败会用 `?` 提前返回，把闭包里真正的原因丢掉**。对一个测试库来说这是最坏的失效方向：用例失败时读者看到的只有「cleanup failed」，于是去查错误的地方；Windows guest 恰恰让收尾更容易失败（忽略 ACPI 电源键、seed 介质仍被占用、QMP 不再应答）。`with_pool` 同样。修：抽出纯函数 `combine_outcome(outcome, shutdown)`——闭包的错误保持为主错误、收尾错误以 context 形式挂在它下面；只有闭包成功时收尾错误才独立成错（没能停掉的 VM 仍是资源泄漏，必须报）；两条入口都改走它。新增 3 个单测（双失败保住主因、成功+收尾失败仍报错、干净收尾原样返回）。`cargo test --lib` 159 → 162 | N/A（`OSX-02`/`OSX-03` 既有 AC：失败必须给出真实原因、VM 不得泄漏；无卡拆合） | `OSX-03` 实现证据、Review log、`src/lib.rs`、CHANGELOG、plan-status |
| 2026-11-13 03:10:00 UTC | review R60（自己的探测不该依赖 guest 的 registry 设置） | F65：`query_windows_ip` 与 `copy_file` 把 PowerShell 脚本**裸发**给 SSH——它们能跑的前提是镜像把 OpenSSH 的 `DefaultShell` 改成了 PowerShell。官方 MSI 装出来的 Windows 默认是 `cmd.exe`，于是 `Get-NetAdapter`/`Copy-Item` 只会得到 cmd 的 `'...' is not recognized`，**报错位置离真正原因（一条 registry 值）极远**；而 Qlean 自己的控制面探测本不该依赖镜像配置。原测试还写死了「不许嵌套 PowerShell，因为 `-Command` 会把路径里的 `$b` 提前展开」——结论只对 `-Command` 成立。修：新增 `powershell_command(script)`，用 `powershell -NoProfile -NonInteractive -EncodedCommand <base64 UTF-16LE>`——**payload 是 base64**，因此既不受两端默认 shell 影响，也不存在任何引号/`$`/反引号插值；`GUEST_IP_QUERY` 与 `Copy-Item` 两条都走它（`guest_ip_query_command()`/`copy_file_script`+`copy_file_command`）。用户 `exec` 仍在镜像默认 shell 里跑，README 镜像契约保留 PowerShell 要求。新增 4 个单测（base64/UTF-16LE 已知向量、copy 命令必须走编码包装且不得出现 `$b`、copy 脚本字面量不变、IP 探测必须自足）。`cargo test --lib` 162 → 165。同时按用户决定改 ER-13/14：**CI 不跑 Windows 虚拟机测试**，核心冒烟只在本地 KVM 宿主机跑 | N/A（`EXE-01`/`IP-01`/`FS-01` 既有 AC：控制面命令必须自足、失败必须可归因；无卡拆合） | `EXE-01`/`IP-01` 实现证据、ER-13/14、Review log、`src/windows.rs`、`src/machine.rs`、README、CHANGELOG、plan-status |
| 2026-11-13 03:40:00 UTC | review R61（被杀掉的 QEMU 若没人收尸，收尾不该再等 30 秒） | F66：`shutdown` 与 `terminate_qemu` 都拿「`/proc/<pid>` 是否存在」当存活判据。**僵尸进程的 `/proc` 条目依然存在**——QEMU 被 SIGKILL 而没人 `wait`（R49 的 `abort` 路径、跨路径收尾）时，脚本就会把僵尸当活人：`shutdown` 白等满 30s 预算，再打印一句「did not exit within timeout, force killing」，最后靠 `kill_if_qemu` 因为 `/proc/<pid>/cmdline` 为空而返回 false 才脱身。对一个以「等待预算」为卖点的库，这既是假阳性诊断，也是无谓的 30 秒。修：新增 `process_state`/`process_state_of`（解析 `/proc/<pid>/stat` 第 3 字段，按**最后一个 `)`** 定位，因为 comm 里可能有括号和空格）与 `process_is_gone`（条目消失，或状态为 `Z`/`X` 即算已退出）；`shutdown` 的等待循环与 `terminate_qemu` 的 5s 等待都改用它。新增 2 个单测（含 `(odd)name)` 这类 comm 形态；真实 `sleep` 子进程被 SIGKILL 且**不回收**时 `process_is_gone` 必须在 2s 内为真）。`cargo test --lib` 165 → 167 | N/A（`OSX-02`/`OSX-03` 既有 AC：收尾必须有界且给出真实判断；无卡拆合） | `OSX-03` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-13 04:10:00 UTC | review R62（QMP 也是控制面，也要有预算） | F67：`qmp::with_qmp_client`（连接 + 协商 + 执行）**没有任何超时**，而 `shutdown` 里 `qmp::powerdown(&socket).await` 是直接 `await`。QMP 跑在 QEMU 主循环上，被卡住的 guest（Windows bugcheck 后 vCPU 卡住、QEMU 在 syscall 里不返回）可以让 powerdown **永远不返回**：于是收尾根本走不到 30s 后那段 SIGKILL 兜底，`with_machine` 也永远不会返回，**用户的测试就挂在那里**。R52 把 guest 探测收了预算、R49 把启动收拾收了预算，唯独真正的控制面（QMP）还敞着。修：`QMP_TIMEOUT = 10s`，新增 `with_qmp_client_within(socket, budget, f)` 把**连接+协商+执行**整体包进 `tokio::time::timeout`，超时即返回可读错误（说明 QEMU 可能已卡死、请求被放弃、收尾将改为杀进程）；`with_qmp_client` 转发到它。新增 2 个单测：绑定一个**只 accept 不说话**的 unix socket，断言 200ms 预算内返回错误且消息含 socket 路径与「kill it instead」；缺失 socket 的错误必须带上路径。`cargo test --lib` 167 → 169 | N/A（`OSX-02`/`OSX-03` 既有 AC：收尾必须有界、失败必须可诊断；无卡拆合） | `OSX-03` 实现证据、Review log、`src/qmp.rs`、CHANGELOG、plan-status |
| 2026-11-13 04:40:00 UTC | review R63（关会话也是写 guest，也要有预算） | F68：R62 给 QMP 加了预算，但 `shutdown` 的下一条语句 `let _ = ssh.close().await;`**同样无界**——`eof`/`close`/`disconnect` 都是往 guest 写、都要等对端，guest 一旦不再应答（bugcheck、内核冻住、网络消失），收尾就卡在**杀掉 QEMU 之前**，调用者的测试还是挂住。同一族缺陷第二次出现：预算必须覆盖**每一步**，不是只覆盖显眼的那一步。修：`SSH_CLOSE_BUDGET = 5s` + 泛型 `bounded_teardown(budget, future) -> Option<T>`；`shutdown` 用 `self.ssh.take()` 取走会话后限时关闭，超时即 `warn!` 说明 guest 已不响应、收尾改为杀 QEMU。新增 2 个单测（永不完成的 future 在预算内被放弃、正常完成的 future 保留返回值）。`cargo test --lib` 169 → 171 | N/A（`OSX-03` 既有 AC：收尾必须整体有界；无卡拆合） | `OSX-03` 实现证据、Review log、`src/machine.rs`、CHANGELOG、plan-status |
| 2026-11-13 05:10:00 UTC | review R64（枚举失败不等于不存在） | F69：`ensure_network` 完全不看 `virsh net-list` 的退出码——**只要 stdout 里没有 `qlean` 就当网络不存在**。于是 libvirtd 没起/连不上（`virsh` 退出 1、stderr 说 `Failed to connect socket to '/run/libvirt/libvirt-sock'`）时，Qlean 会去**创建**一个可能已经存在的网络，最后只报一句 `failed to define qlean network`，真正的病因（libvirt 不可达）用户看不到。这正是本项目反复出现的「判据放错层」：**列举失败 ≠ 集合为空**。顺带发现同函数里那条「读不到 bridge 就假定是 qlbr0」的 warn **中间有一长串空格**（`\` 续行丢了），而专治这类问题的 `user_facing_messages_have_no_runs_of_spaces` 只覆盖了两条机器消息，没覆盖它。修：新增 `listed_networks(output, what)`——非零退出直接报错并带上 libvirt 原文与连接 URI（「is libvirtd running and reachable?」），空行不计入集合；`virsh_reason(output)` 统一把 stderr 带进 define/autostart/start 的失败消息（`status()` 改 `output()`）；空格串收敛进 `bridge_assumed_message()`。新增 3 个单测（失败列举必须报错且含 `libvirtd`/URI/`libvirt-sock`、成功列举忽略空行、三条网络消息都不许有句中空格串）。`cargo test --lib` 171 → 174 | N/A（`OSX-02` 既有 AC：宿主前置条件失败必须指向真正原因；无卡拆合） | `OSX-02` 实现证据、Review log、`src/utils.rs`、CHANGELOG、plan-status |
| 2026-11-13 05:40:00 UTC | review R65（声明值必须来自真实来源） | F70：`qlean_user_agent()` 返回**写死的** `"qlean/0.3.0"`，而 `Cargo.toml` 早就是 `0.3.1`——下载 guest 镜像时发给镜像站的 `User-Agent` 已经少报了一个版本，而且每次发布都会继续漂移，没有任何门禁会提醒。这正是本项目记过的「声明值必须来自真实来源」：版本号只有一个真相（`Cargo.toml`），不该在代码里再抄一份。修：改成 `concat!("qlean/", env!("CARGO_PKG_VERSION"))`，编译期取自 crate 版本；新增 1 个单测断言它与 `env!("CARGO_PKG_VERSION")` 相等且以 `qlean/` 开头。`cargo test --lib` 174 → 175 | N/A（`IP-01`/`OSX-02` 既有 AC：对外声明必须与实际一致；无卡拆合） | `OSX-02` 实现证据、Review log、`src/utils.rs`、CHANGELOG、plan-status |

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
- **ER-13/14 Windows 门：** CI 只编译 Windows test target，**不在 GitHub Actions 里跑 Windows 虚拟机测试**（托管 runner 没有 `/dev/kvm`，也不该为跑虚拟机放宽权限模型）；核心 Windows 冒烟一律在**本地 Linux KVM 验证宿主机**执行 `cargo test --test windows_machine -- --ignored --test-threads=1`。每个声称支持的版本都必须拿到这份本地证据；缺镜像/宿主时相关任务或发布为 `blocked`。只有 Linux VM 环境缺口或额外 TCG 矩阵可按模板登记 `DEFER-*`，核心 Windows 验收不可延后。
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
| EXE-01 | implementation | PowerShell exec 语义 | revert | yes | yes | 5/8 | 5/8 | 2/3 | S | TRN-01 | 序列化于 TRN-01 | family child | N/A | N/A |
| IP-01 | implementation | get_ip 语义 | revert | yes | yes | 4/8 | 5/8 | 2/2 | S | EXE-01 | 序列化于 EXE-01 | family child | N/A | N/A |
| FS-01 | implementation | Windows 文件语义 | revert | yes | yes | 8/8 | 5/8 | 3/3 | M | IP-01 | 序列化于 IP-01 | family child | N/A | N/A |
| REL-01 | release | 聚合发布 | immutable-release | yes | yes | 8/12 | 7/12 | 1/3 | S | 全部任务卡 | 序列化于 FS-01 | family release point | N/A | N/A |

#### Verification 判定口径

按 `plan-template.md` 生效。本地每卡门禁：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`、相关 `cargo test --lib <filter>` 与 `cargo test --lib`、`cargo test --no-run`（含 benches）。所有 `tests/windows_machine.rs` 用例均为 `(new)`、默认 `#[ignore]` 并由 `serial_test` 串行。CI（R22 起）在 `push` 到 `main` 与 PR 上执行同一组静态门：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`、`cargo test --lib`（真实运行单测）与 `cargo test --no-run --all-targets`（含 `benches` 与 ignored 硬件测试的编译）；集成测试仍需 KVM 宿主，CI 只证明其可编译。实际运行必须显式 `--ignored --test-threads=1`，并满足 `DEP-01`/`DEP-02`。命令中的 `/path/to/windows.qcow2` 与 digest 是执行者替换的参数，证据只记录 sanitized 标识，不记录私有绝对路径。

### Task SPK-01: Windows 传输可行性 spike

**Task type:** `spike`

**Lifecycle / Acceptance:** `blocked` / 空（2026-11-12 环境审计：`DEP-01` 无合法 Windows qcow2、`DEP-02` 无 QEMU/OVMF/swtpm/virsh/xorriso 与免密 sudo，spike 无法执行；ADR-WIN-02 在临时接受状态下由 `TRN-01` 落地）

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
| 2026-11-12 环境审计：无法取得连接/SFTP 证据 | 宿主机缺 `qemu-system-x86_64`/`qemu-img`/`swtpm`/`xorriso`/`virsh`/`qemu-bridge-helper`/OVMF，`sudo -n` 需密码，无 Windows qcow2（`DEP-01`/`DEP-02` 不可用） |

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

**Lifecycle / Acceptance:** `blocked` / 空（2026-11-12 环境审计：`DEP-01`/`DEP-02` 均不可用，无法取得真实首启/重启证据；ADR-WIN-03 在临时接受状态下由 `OSX-02`/`OSX-03` 落地）

**Description:** 验证统一 OVMF + TPM 2.0 基线、Secure Boot、VirtIO 与部署方案，产出 ADR-WIN-03 和具体实现输入。

**Out of scope:**
- 不实现生产引导/部署代码（由 `OSX-02`/`OSX-03` 承接）。
- 不重复传输方案对比（由 `SPK-01` 承接）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| QEMU 无 pflash/vTPM | `src/qemu.rs:74-169` |
| seed 为 cloud-init NoCloud | `src/machine.rs:220-399` |
| 2026-11-12 环境审计：无法取得首启/重启证据 | 同 `SPK-01` 宿主审计（`DEP-01`/`DEP-02` 不可用） |

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

### Task OSX-01: GuestOs 与镜像校验

**Task type:** `implementation`

**Lifecycle / Acceptance:** `done` / `complete`（A 实现与 B 本地门已过；本卡无真实 Windows KVM 门，T-1 全量门登记为 `DEFER-04`）

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
| 传输设备按 guest OS 分派 | `src/qemu.rs::vsock_args`：`vhost-vsock-pci` 仅对 Linux 追加；Windows 不再附带该设备（否则宿主缺 `/dev/vhost-vsock` 时 QEMU 直接启动失败），2 个单测覆盖两条分支（R9，`f42a942`） |
| 提交 | `50c8cff` |

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

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实 Windows KVM 门 `blocked`，见 Verification）

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

- [x] Windows 使用 OVMF `q35` + `if=pflash` code/vars（每 VM 独立 `ovmf_vars.fd`；已存在则复用，重启保留），Secure Boot 仅在使用 `secboot` OVMF 时启用（带 `smm=on` 与 `cfi.pflash01 secure=on`），Linux 参数不变。
- [x] 每 VM 在 run dir 下创建 `tpm/` 状态目录（权限 `0700`）并由独立 `swtpm` 进程提供 TPM 2.0；按 `MachineConfig::clear` 语义随 run dir 清理。
- [x] VirtIO disk/network 设备保持不变；镜像必须具备 virtio 驱动，README 镜像制作契约写明该要求（缺驱动时的错误来自镜像侧，不静默换设备）。
- [x] OVMF/swtpm 缺失时 `ensure_host_support` 一次性列出全部缺口与安装包名；Windows 缺少 KVM 时 `select_accel` 返回错误，不再回退 TCG；Linux KVM/TCG 行为不变。
- [x] QMP `powerdown`、`is_running`、shutdown 后 `spawn` 复用同一 overlay/OVMF vars/TPM 状态；`shutdown`、SSH 失败退出路径与 `Drop` 都会停止 `swtpm`，不泄漏进程。
- [x] `(new)` 单测覆盖固件参数（Secure Boot 开/关、pflash 单元、TPM 参数）、加速选择（Windows 不回退 TCG）、OVMF 解析与 vars 模板复制/尺寸校验；`tests/windows_machine.rs::windows_firmware_lifecycle` 覆盖关机/重启（`#[ignore]`，CI 只编译）。
- [x] README Host Setup 新增 Windows 前置（KVM/OVMF/swtpm/安装包/`QLEAN_OVMF_*`/`QLEAN_SWTPM`）与 CHANGELOG Added 同卡更新。
- [x] Windows 资源默认值对照 Windows 10/11 最低要求评估：`core=2`/`mem=4096` 等于最低值，README 写明最低与推荐（4 核/8192MB）及 64GB 磁盘要求，不静默降级支持矩阵。

**Verification:**

- [x] `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 通过（0 warning）
- [x] `cargo test --lib qemu`：5 passed（固件参数 2、加速选择 3）
- [x] `cargo test --no-run`：包含 `tests/windows_machine.rs` 在内全部 target 编译通过
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` —— 环境缺口 `DEFER-04`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=... QLEAN_WINDOWS_DIGEST=... cargo test --test windows_machine windows_firmware_lifecycle -- --ignored --exact --test-threads=1` —— `blocked`（无 QEMU/OVMF/swtpm 宿主与 Windows 镜像）

**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 新模块 | `src/firmware.rs`：OVMF 候选探测、`QLEAN_OVMF_CODE`/`QLEAN_OVMF_VARS`/`QLEAN_SWTPM` 覆盖、`prepare_vars`（首启复制、重启复用、拒绝 vars 模板大于 code 镜像的配对）、`Swtpm`（前台进程 + 控制 socket 等待 + `stop`/`Drop` 双保险） |
| QEMU 参数 | `src/qemu.rs::windows_firmware_args`：`q35,hpet=off[,smm=on]`、可选 `cfi.pflash01 secure`、`if=pflash unit=0 readonly` code、`unit=1` per-VM vars、`chrtpm`/`tpm-tis` |
| 选项编码防护 | 所有插入逗号分隔 QEMU 值的宿主路径（overlay、seed ISO、QMP socket、serial logfile、OVMF code/vars、swtpm socket）统一经 `src/qemu.rs::qemu_option_path` 校验：空、含逗号、含控制字符在启动前报可操作错误，避免被解析成注入属性（R27，`85bc525`） |
| 加速门 | `src/qemu.rs::select_accel`：Windows 无 KVM 或架构不匹配时 `bail!`，Linux 保持 KVM/TCG 回退 |
| 状态机报错 | `src/machine.rs::session_or_operation_error`：未运行/启动失败/已关机统一返回可操作错误（含机器 id、操作名、`init`/`spawn` 指引），任何会话级入口都不再 panic（R30，`940dbe6`） |
| Secure Boot 配对校验 | `src/firmware.rs::ensure_secure_boot_pair`：`secboot` 代码镜像必须配带 Microsoft 密钥的 vars 模板（按 UTF-16LE 主体串判定），否则在解析阶段报可操作错误，不再静默进入 setup mode（R29，`dedaacd`） |
| 生命周期 | `src/machine.rs`：`launch` 前准备固件与 `swtpm`，`shutdown`、`launch` 失败路径与 `Drop` 均停止 `swtpm`；`swtpm` 状态在 `machine.swtpm` 唯一持有 |
| 集成测试 | `tests/windows_machine.rs::windows_firmware_lifecycle`（`#[ignore]`，需要 `QLEAN_WINDOWS_IMAGE`/`QLEAN_WINDOWS_DIGEST`，缺省时返回可操作错误） |
| 资源默认值 | README Windows 表格：最低=默认 `core:2`/`mem:4096`，推荐 `core:4`/`mem:8192`，磁盘 ≥64GB |
| 固件配对规则 | `prepare_vars` 只拒绝「vars 模板大于 code 镜像」的错配，并记录尺寸差异：stock 固件（Debian/Ubuntu/Fedora/Arch）的 vars 模板约 528 KiB、code 镜像数 MiB，等长要求会拒绝所有真实宿主（R9，`8ae13ec`） |
| TPM socket 权限 | `swtpm_args` 以 `mode=0600` 创建控制 socket（run dir 可读时也不会暴露 TPM），参数构造为纯函数并被单测覆盖（R9，`3e7ebd0`） |
| Secure Boot vars | `OVMF_CANDIDATES` 为每个 code 镜像携带 vars 候选列表，secboot 镜像优先 `OVMF_VARS_4M.ms.fd` / `OVMF_VARS.4m.ms.fd` / `OVMF_VARS.secboot.fd`，普通模板仅 fallback（setup mode，Win11 拒绝）；单测覆盖优先与回退两条路径（R9，`src/firmware.rs`） |
| 首启介质前置 | `ensure_host_support` 一次性报告 KVM/OVMF/`swtpm`/`xorriso` 四类缺口，`SEED_ISO_BUILDER` 与 `DeploySeed::build` 共用同一程序名（R9，`7ddc686`） |
| 宿主前置聚合 | `host_support_problems` 纯函数 + 3 个单测：KVM/OVMF/`swtpm`/`xorriso` 全部缺失时一次性列出 4 条、齐全时为空、只缺一项时只报该项（R17，`src/firmware.rs`） |
| 提交 | `f2fc277` |

**Full-suite trigger:** `T-1: 共享 QEMU 启动路径`

**Dependencies:** `SPK-02`（固件 ADR）、`OSX-01`（GuestOs 与串行顺序）

**Deliverables:** `N/A`

**Implementation write set:** `src/qemu.rs`、`src/machine.rs`、`src/utils.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`（现有 CI 的 `cargo test --no-run --all-targets` 自动编译新 target，无需改 workflow）

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

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实首启门需 `TRN-01` 传输 + DEP-01/02，`blocked`）

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

- [x] Windows 分支严格实现 ADR-WIN-03 选定方案（pre-generalized 镜像 + 每 VM seed 介质，不写 autounattend、不重建已安装镜像）；Linux cloud-init `user-data`/`meta-data`/seed ISO 字节语义不变（`Machine::new` 早返回于 Windows 分支，Linux 路径未改动）。
- [x] 客户端公钥以 `qlean/authorized_keys` 注入 seed；README 契约要求镜像首启任务将其安装为 `C:\ProgramData\ssh\administrators_authorized_keys`（管理员）或用户级 `authorized_keys`，ACL 仅授权 `Administrators`/`SYSTEM`，并关闭 `PasswordAuthentication`；Qlean 从不生成、不传递静态管理密码。
- [x] sshd 默认 shell/SFTP 与用户名单一事实源：`windows::GUEST_USERNAME` 常量已建立并写入 `deploy.json`，README 契约已写明 `PubkeyAuthentication`/`sftp`；`TRN-01` 的 `connect_ssh_windows` 已消费该常量作为唯一用户名来源。
- [x] 每 VM 用 `windows::generate_host_key` 生成独立 ed25519 host key（私钥落 seed，公钥经 `Machine::ssh_host_key()` 交给上层用于 pinning）；seed 文件权限 `0600`，seed ISO 仅在 `init`（`is_init`）附加，部署成功后 `confirm_deployment` 删除 ISO 与暂存目录；`spawn` 复用同一 overlay/vars/TPM，不再附加 seed。
- [ ] `init` 首启部署与后续 `spawn` 可用 + test-only 连接助手取得真实首启证据：`init`/`spawn` 的启动路径已可用，部署确认挂在首个会话上（`confirm_deployment`），真实证据需 `TRN-01` 传输与 DEP-01/02，`blocked`。
- [x] `(new)` 单测覆盖：seed 三件套内容与 `deploy.json` 契约、seed 文件 `0600`、每 VM host key 互不相同、`Debug` 不泄漏密钥材料、清理删除 ISO+目录、部署超时默认值与可操作错误文案。
- [x] README 新增 “Windows image contract”（镜像/账号/ACL/首启任务/seed 消费规则）与 CHANGELOG Added 同卡更新。
- [x] 部署等待维度参数化：`windows::deploy_timeout` 默认 900s（独立于 Linux 180s/300s），`MachineConfig::ssh_timeout` 可覆盖；超时返回含 marker 路径、README 章节与 seed 保留说明的可操作错误，README 记录默认值来源（`SPK-02` 未执行，需在真实宿主复测）。

**Verification:**

- [x] `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 通过（0 warning）
- [x] `cargo test --lib windows_deploy`：7 passed
- [x] `cargo test --lib windows_deploy_timeout`：2 passed（默认值 + 超时错误路径）
- [x] `cargo test --lib timeout_tests`：3 passed（Windows `init` 用部署预算、Windows `spawn` 与 Linux 保持连接预算；R8 回归门）
- [x] `cargo test --no-run`：含 `tests/windows_machine.rs::windows_first_boot` 在内全部 target 编译通过
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` —— 环境缺口 `DEFER-04`
- [ ] 满足 DEP-01/02 且 `TRN-01` 已落地：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_first_boot -- --ignored --exact --test-threads=1` —— `blocked`
- [ ] 首启后关机、`spawn` 与 host-key seed 清理的 sanitized 证据 —— `blocked`（无 Windows 镜像与 KVM 宿主）

**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 新模块 | `src/windows.rs`：`DeploySeed::stage/build/remove`、`DeployContract`（version/username/marker）、`generate_host_key`、`deploy_timeout`、`deploy_timeout_message`；seed 文件 `0600`，`Debug` 只含路径 |
| 集成点 | `src/machine.rs`：`Machine::new` 的 Windows 早返回分支、`Machine::ssh_host_key()`、`confirm_deployment()`（轮询 `C:\ProgramData\qlean\deployed` 后删除 seed）、`deploy_marker_present()` |
| 密钥来源 | `src/ssh.rs` 抽出 `generate_keypair(&Path)`，客户端与 per-VM host key 共用同一实现（权限 `0600`） |
| 日志安全 | seed 只记录目录路径与文件名清单，不记录密钥内容；`DeploySeed` 自定义 `Debug` |
| README | “Windows image contract”：virtio 驱动、OpenSSH Server、`sysprep /generalize`、`qlean` 账号、ACL 规则、首启任务步骤、seed 生命周期、900s 预算 |
| 首启连接预算 | `src/machine.rs::resolve_connect_timeout`：Windows `init` 以 `windows::deploy_timeout`（默认 900s）作为连接/readiness 预算，`spawn` 与 Linux 仍用 `resolve_ssh_timeout`；`timeout_tests` 3 个单测覆盖三条分支（R8 修复，提交 `0e72b45`） |
| 首启失败清理 | `Machine::launch` 在 `confirm_deployment` 失败时关闭会话、`terminate_qemu`、`Swtpm::stop` 并清空 `pid`/`ssh`/`ip`，不留运行中 VM 与挂载中的 seed（R8，`f9cc1ee`） |
| 重复 init 拒绝 | `Machine::init` 在 `GuestOs::Windows && deploy_seed.is_none()` 时直接报错并提示 `spawn`，避免以已删除的 seed 引导（R8，`178ac03`） |
| 失败启动可重试 | `init`/`spawn` 在启动失败时取消并清除 cancel token（`abandon_launch`），仅在 `pid`/`ssh` 存在时拒绝重复启动；首启超时拆除后可在同一机器上重试（R11，`src/machine.rs`） |
| 启动失败收尾 | QEMU 在 SSH 阶段退出或 SSH 任务 panic 时清 `pid`、停 `swtpm`、终止 QEMU，不再遗留 TPM 进程或分离的 QEMU（R14，`src/machine.rs`） |
| 部署标记探测 | `deploy_marker_present` 返回 `Result<bool>`，传输失败与「标记不存在」分列；连续 3 次传输错误报「会话丢失 + spawn 重试」（R15，`src/machine.rs`） |
| 提交 | `8812fb4` |

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

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实连接/重连/池门需 DEP-01/02，`blocked`）

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
**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 传输抽象 | `src/ssh.rs`：`Session::connect_over` + `ConnectParams`（原 vsock 重试/错误分类语义逐条保留），`Session::connect`（vsock，Linux）与 `Session::connect_tcp`（TCP，Windows）为薄封装 |
| 主机密钥 pinning | `SshClient::with_pinned_key`；`check_server_key` 在 pin 时逐字节比对 `PublicKey`，拒绝 `Certificate`，未 pin 时（vsock）保持 TOFU |
| Windows 会话 | `connect_ssh_windows`：解析 seed 中的 host 公钥、以 `windows::GUEST_USERNAME` 认证、`call_with_output(windows::READINESS_COMMAND)`（`cmd /c ver`）为 readiness probe，非 0 即重试至 deadline，最后错误含端点与可操作提示 |
| 地址发现 | `src/utils.rs`：`DhcpLease`、`parse_dhcp_leases`、`find_lease_address`（`virsh -c qemu:///system net-dhcp-leases qlean`，500ms 有界轮询，超时错误列出已见 lease） |
| Machine 集成 | `src/machine.rs`：`windows_endpoint()`（先解析 lease 再连接）、`launch` 中 Windows 分支缓存 leased IP 到 `self.ip`（`get_ip` 不再进 guest）、地址发现失败/连接失败/QEMU 早退统一 `terminate_qemu` + `swtpm.stop()`；`open_interactive_shell` 对 Windows 立即 `bail!` |
| 前置依赖 | `src/utils.rs`：拆出 `ensure_host_prerequisites`（命令 + 网络）与 `ensure_prerequisites(guest_os)`（仅 Linux 追加 `ensure_vsock`）；`src/lib.rs::with_pool` 只做宿主通用检查，`with_machine` 传 `image.guest_os()` |
| 单测 | `src/ssh.rs`：pin 匹配/不匹配、未 pin TOFU、OpenSSH 往返、取消即失败（5 个）；`src/utils.rs`：lease 解析 MAC 映射/大小写/表头空行/IPv6（4 个） |
| 集成测试（`#[ignore]`） | `tests/windows_machine.rs`：`windows_transport`（地址、pin、unsupported、shutdown→spawn 重连）、`windows_pool`（双机地址/host key/会话隔离） |
| README/CHANGELOG | README「Windows transport and security」；CHANGELOG Added ×4 / Changed ×1 |
| 地址发现与 QEMU 退出 race | `launch` 把 DHCP lease 轮询与 `qemu_handle`、cancel token 一起 `select!`，QEMU 启动即退出时立即返回其真实错误并停 `swtpm`（R12，`src/machine.rs`） |
| 声明值来自真实来源 | 版本号只认 `Cargo.toml`，代码里不抄第二份（R65，`d6573e1`） |
| 失败不等于空集 | 命令失败与「结果为空」必须区分，报错要带工具原文（R64，`933563f`） |
| 每步都有预算 | 收尾的**每一步**都有上界（SSH 关闭 5s、QMP 10s、杀进程 30s+5s），不是只有显眼那一步（R63，`5c54113`） |
| 控制面有预算 | QMP 连接/协商/执行整体限时，卡死即放弃并转为杀进程（R62，`1a0c61a`） |
| 存活判据正确 | `/proc` 条目存在 ≠ 进程还活着；僵尸算已退出（R61，`9d4d59a`） |
| 控制面自足 | Qlean 自己的 guest 命令不依赖镜像默认 shell（R60，`af4a7ba`） |
| 失败原因优先 | 闭包/用例自身的失败是主错误，收尾错误只作 context（R59，`36f4d2b`） |
| 探测命令可信 | 标记路径加引号，判据词走常量，探测文本与匹配不漂移（R58，`6d1bbd7`） |
| 缓存名唯一 | 不同来源不得映射到同一缓存槽，含非 UTF-8 文件名（R57，`c942947`） |
| 预算只有一个 | 首启共享一个 deadline，耗尽时点名没轮到的阶段（R56，`c197e81`） |
| 死因分级可读 | `src/ssh.rs`：host key 不符 → 公钥被拒 → 泛型，三种死因各有措辞与恢复路径（R55，`bc7efbe`） |
| 致命判定分阶段 | `src/ssh.rs::pinned_key_mismatch_is_fatal`：首启期不符只等待，部署后不符即致命（R54，`714a8c4`） |
| 存量网络校验 | `src/utils.rs::ensure_network` 用 `virsh net-dumpxml` 确认桥名为 `qlbr0`（R53，`23b8626`） |
| 探测预算分层 | `src/ssh.rs::bounded`/`call_probe`：Qlean 自己的探测有界，用户 `exec` 保持无界（R52，`bc98828`） |
| 地址判据在选择点 | `src/windows.rs::select_guest_address` 只接受 IPv4，双栈不再误判 ambiguous（R51，`25e82c9`） |
| 清理幂等且不致命 | `src/windows.rs::DeploySeed::remove` + `confirm_deployment` 的 `warn!`：半途清理不算失败（R50，`0b10e09`） |
| 失败路径可终止 | `src/machine.rs::reap_launch_task`：清理阶段有界等待 QEMU，原始启动错误必定返回（R49，`0cb5988`） |
| 关停结果可验证 | `src/machine.rs::teardown_step`/`TeardownStep::Unkillable`：SIGKILL 未生效时失败并保留 pid，不谎报关停（R48，`36ab2f7`） |
| 桥接依赖进前置检查 | `src/utils.rs::bridge_helper_problem`：`qemu-bridge-helper`（`libexec`，非 `PATH`）与其 `/etc/qemu/bridge.conf` 允许列表一起被报出（R47，`f549dfb`） |
| 启动 future 不被取消 | `src/pool.rs::run_all`：单台失败不影响其余机器启动，避免留下无 pid 的 QEMU（R46，`f2426cd`） |
| 固件候选按可用性筛选 | `src/firmware.rs::resolve_ovmf_with`：无 Microsoft 密钥的 secboot pair 只记原因并继续，普通候选仍可落地（R45，`3c0ad9f`） |
| 停止路径可诊断 | `src/qemu.rs::describe_exit`：teardown 的 SIGTERM/SIGKILL 不再算失败，未请求的死亡点名信号而不再输出 `None`（R44，`1bb1af1`） |
| 安全判定不被重试 | `src/ssh.rs::is_fatal_connect_error`：固定主机密钥被拒绝时两个连接循环立即返回，诊断不再被超时信息覆盖（R43，`f3296fc`） |
| 状态机入口一致 | `src/machine.rs::spawn_guard`：池子认识的「首启未跑」状态，公开的 `spawn` 入口同样拒绝（R42，`692c456`） |
| 未知状态不误报 | `src/machine.rs::marker_probe_guard`/`running_check`：无会话不再等于「未部署」，QMP 无应答不再等于「未运行」，两者都如实报错（R41，`3505750`） |
| TPM 状态完好 | `src/firmware.rs::signal_terminate` + `SHUTDOWN_GRACE`：`swtpm` 收到 `SIGTERM` 后有两秒把状态写盘，`Drop` 路径同步等待而不是让 `kill_on_drop` 强杀；超时才 kill（R40，`c688ce3`） |
| 固件状态可信 | `src/firmware.rs::prepare_vars`：per-VM `ovmf_vars.fd` 一律 `0600` 且可写（`0444` 模板不再导致 pflash 只读），尺寸与模板不符的陈旧镜像拒绝启动并给出恢复步骤（R39，`c6c84f5`） |
| 库入口不 panic | `src/utils.rs::project_dir_or_explain` + `Drop for Machine` 的 `Ok/Err` 匹配：无 `XDG_DATA_HOME`/`HOME`、目录不可建、`launch` 缺少 token/swtpm 都返回带原因的错误，析构路径只告警（R38，`4de03cc`） |
| 构造失败无残留 | `src/machine.rs::RunDirGuard`：`Machine::new` 任一步失败即删除 `runs/<id>/`（overlay + seed + host key），成功才 `disarm()`；Windows 在建密钥前先查宿主前置（R37，`a6722f7`） |
| 宿主路径字节保真 | `src/utils.rs::path_argument`：`key=path` 以 `OsString` 拼接，非 UTF-8 家目录不再 panic 也不再被 `U+FFFD` 改写成另一个路径（R36，`450a647`） |
| 下载完整性 | `src/image.rs::truncation_problem` + `verify_fetched`：rename 前比对 `Content-Length`，截断/超长分别归因；校验失败删除产物（R35，`4efb45c`） |
| 前置缺口聚合 | `src/utils.rs::program_problems`：四个宿主程序一次探测、一条错误报全，`--version` 失败与文件缺失分开归因（R34，`ca4996c`） |
| 信号对象校验 | `src/machine.rs::kill_if_qemu`：任何 SIGKILL 之前都校验 `/proc/<pid>/cmdline` 的 argv[0] 仍为 QEMU，pid 被复用时跳过并告警，不误杀无关进程（R33，`23f387c`） |
| 物料权限 | `src/utils.rs::restrict_dir` + `src/windows.rs::seal_seed_medium`：Qlean 目录 `0700`、seed 目录 `0700`、seed 介质 `0600`（含每 VM 主机私钥），不依赖宿主 umask 或家目录权限（R32，`80a57f7`） |
| 仅接受最新 IPv4 lease | `src/utils.rs::lease_address_for`：同 MAC 多行租约时按到期时间取最新一行（`DhcpLease.expiry` 字典序即时间序），超时错误附每行到期时间（R31，`3cdf5a3`） |
| 仅接受 IPv4 lease | `lease_address_for` 跳过双栈下的 IPv6 行：链路本地地址无 scope id 不可达，误选后连接循环不会重试（R13，`src/utils.rs`） |
| 池化启停分流 | `MachinePool::init_all`/`spawn_all` 按 `wants_init`/`needs_first_boot` 选择 `init` 或 `spawn`，Windows 二次启停与未部署池启动都走正确路径（R15，`src/pool.rs`） |
| 提交 | `6711671` |

**Acceptance criteria:**

- [x] 按 ADR 建立 Windows 会话；地址/端点发现在 SSH 前完成且不调用 `get_ip`，发现的 IP 可交给 Machine 缓存。——`windows_endpoint()` 先解析 lease，成功后写入 `self.ip`。
- [x] 使用 ADR 的用户名与 Windows readiness probe；客户端公钥成功、密码禁用，Linux root/vsock 行为不变。——`GUEST_USERNAME` + `cmd /c ver`；`connect_ssh`/vsock 分支与 `root` 用户名未改。
- [x] 校验部署阶段 pinning 的 SSH host key，错误 key 必须失败；若选 TCP，仅 GuestOs::Windows 显式启用且网络暴露符合 ADR。——`check_server_key` 拒绝不匹配 key 与证书；`connect_tcp` 仅由 Windows 分支调用（单测 2 个）。
- [x] init 与 shutdown 后 spawn 都能重连；连接超时、QEMU 早退、地址冲突均清理进程和临时端点，Windows TCP 不检查 `/dev/vhost-vsock`。——清理路径与 guest_os 条件已实现并有单测；真实 `spawn` 重连证据需 DEP-01/02（`windows_transport`），`blocked`。
- [ ] 两台 Windows VM 池并发 init 时地址、端口（如有）、host key 和会话不串用，能分别执行 readiness。——`windows_pool` 已编写但需 DEP-01/02，`blocked`。
- [x] Windows `open_interactive_shell` 立即返回明确 unsupported 错误，不创建 vsock 连接或遗留进程。——在取任何会话前 `bail!`。
- [x] `(new)` 测试覆盖错误 host key、超时/清理、重启、双机隔离与 unsupported 分支。——pin 负测试与取消失败为可执行单测；重启/双机隔离在 `windows_transport`/`windows_pool` 中，执行 `blocked`。
- [x] README 传输/安全/池说明与 CHANGELOG Added/Changed 同卡更新。

**Verification:**

- [x] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test --lib ssh`（5 passed：pin 匹配/不匹配/TOFU/往返/取消）
- [x] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` —— `DEFER-04`（本机无 Linux guest 全量环境）
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_transport -- --ignored --exact --test-threads=1` —— `blocked`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_pool -- --ignored --exact --test-threads=1` —— `blocked`
- [ ] 错误 host key、超时清理与 unsupported 的 sanitized 结果写入「实施证据汇总」。——单测可执行部分已记录；真实机 sanitized 结果 `blocked`

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

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实 PowerShell 冒烟需 DEP-01/02，`blocked`）

**Description:** 按 ADR-WIN-05 实现 Windows 命令、输出和退出码语义，不改变 Linux 命令字符串解释。

**Out of scope:**
- IP 与文件操作由 `IP-01`/`FS-01` 承接。
- 不把 API 改成 argv（尚未排期；出现结构化命令需求时另立计划）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `exec` 原样调用 SSH exec channel | `src/machine.rs:495-516`、`src/ssh.rs:324-370` |
| UNIX escape 属于 `copy`，不是 `exec` | `src/machine.rs:949-955` |
**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 新模块 | `src/exec.rs`：`MAX_EXIT_CODE = 255`、`exit_status_from_code(command, code)`（0 才 success，`0..=255` 原样保留，超范围 `bail!` 并回显原始状态与命令） |
| 退出码修复 | `ExitStatus::from_raw` 接收的是 wait status，原实现把 exit code 直接传入，导致非 0 退出被报告为 success；现统一按 `code << 8` 转换（Linux 一并修正，已在 CHANGELOG `Fixed` 记录行为变更） |
| 空命令 | `Machine::exec` 在建立 SSH 请求前 `bail!` 拒绝空白命令 |
| 原始字符串 | `exec` 仍把入参原样交给 exec channel，未引入任何 escape/argv 化；Windows 依赖镜像契约把 OpenSSH `DefaultShell` 设为 PowerShell |
| stdout/stderr | `call_with_output` 分通道返回 `(code, stdout, stderr)`，未合并 |
| 单测 | `src/exec.rs`：0 success、非 0 failure、2..255 原样、300 拒绝（含可操作文案）、`0xC0000005` 不截断（5 个，`cargo test --lib windows_exec` 可过滤） |
| 集成测试（`#[ignore]`） | `tests/windows_machine.rs::windows_exec`：空命令、`whoami`、引号/空格、`cmd /c exit 3`、stdout/stderr 分离、`exit 300` 拒绝 |
| README/CHANGELOG | README「Windows command execution」+ 镜像契约补 `DefaultShell`；CHANGELOG Added ×3 / Fixed ×1 |
| 提交 | `64b1046` |

**Acceptance criteria:**

- [x] Windows 输入原文交给 PowerShell，不调用 UNIX escape；空命令返回明确错误，特殊字符不被二次解释。——`exec` 未改字符串路径，空白命令在发请求前拒绝。
- [x] `status.success()`、0..=255 的 `status.code()`、超范围错误及 stdout/stderr 分离符合 ADR-WIN-05。——`exec::exit_status_from_code` + 5 个单测；超范围返回可操作错误而非截断。
- [x] Linux 路径行为不变；若为复用 helper 修正既有退出码问题，先记录兼容说明和对应测试。——复用同一 helper 并修正了非 0 退出被报告为 success 的既有缺陷：CHANGELOG `Fixed` 写明行为变更，`src/exec.rs` 5 个单测覆盖；其余 Linux 路径未改。
- [ ] `(new)` 单测与 Windows 冒烟覆盖空命令、引号/空格、`whoami`、非零及大退出码。——单测已覆盖退出码维度；`windows_exec` 冒烟已编写但需 DEP-01/02，`blocked`。
- [x] README PowerShell 示例/退出码契约与 CHANGELOG Added 同卡更新。

**Verification:**

- [x] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test --lib windows_exec`（5 passed）
- [x] `cargo test --no-run`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1` —— `DEFER-04`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_exec -- --ignored --exact --test-threads=1` —— `blocked`

**Full-suite trigger:** `T-1: 共享 Machine/SSH 命令输出与退出码路径`

**Dependencies:** `TRN-01`

**Deliverables:** `N/A`

**Implementation write set:** `src/exec.rs`（新）、`src/machine.rs`、`src/lib.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/exec.rs`, `src/machine.rs`, `src/lib.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 明确 PowerShell 原文与退出码；CHANGELOG Added，若修 Linux bug 另列 Fixed。

**Rollback mode:** `revert`

**Security and privacy:** 命令输出证据须脱敏；不把凭据写入测试命令。

**Performance budget:** 输出仍按 channel 流式读取；不得新增无界命令重试。

**Estimated scope:** `S`

**Version increment:** `N/A`（family child）

**Release boundary:** `family child of REL-01`

**C/D coverage from:** `REL-01`

**Granularity:** `type=implementation; axis=PowerShell exec 语义; recovery=一次 revert; complete=yes; self-contained=yes; AC=5/8; VER=5/8; landing=2; prod-files=3; scope=S; deps=TRN-01; writeset=序列化于 TRN-01; release=family child; split-from=N/A; exception=N/A`

### Task IP-01: `get_ip` 的 Windows 语义

**Task type:** `implementation`

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实 `windows_get_ip` 与双机一致性需 DEP-01/02，`blocked`）

**Description:** 复用传输期发现的可信地址并提供 Windows 查询/校验路径，替换 Linux-only 硬编码。

**Out of scope:** 不负责首次 SSH 前的地址发现（由 `TRN-01` 承接，避免循环依赖）。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| Linux 命令与 Machine IP 缓存 | `src/ssh.rs:831-841`、`src/machine.rs:791-800` |
**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 缓存优先 | `Machine::get_ip` 先返回 `self.ip`（`TRN-01` 在连接成功后写入传输实际使用的 lease 地址），Windows 与 Linux 共用该快路径 |
| Windows 重新查询 | `Machine::query_windows_ip` 通过 `windows::GUEST_IP_QUERY` 在 guest 内用 PowerShell 枚举 `Get-NetAdapter`（仅 `Status -eq 'Up'`）与 `Get-NetIPAddress -AddressFamily IPv4`，排除 `127.*` 与 `169.254.*`，绝不使用 `hostname -I` |
| MAC 绑定与消歧 | `windows::normalize_mac` / `parse_adapter_addresses` / `select_guest_address`：只接受与本 VM MAC 精确匹配的单一地址；0 个结果报错并列出已见地址，多个结果报歧义错误，绝不回落到其它 VM 的 lease |
| 错误路径 | PowerShell 退出码非 0 时返回含 `stderr` 的可操作错误；解析层丢弃告警/空行，不因噪声失败 |
| 单测 | `src/windows.rs`：解析 MAC/地址对、噪声与非 IP 行、按 MAC 精确选择、无自身地址报错、同 MAC 多地址歧义、查询语句排除 loopback/APIPA（6 个，`cargo test --lib windows_ip` 可过滤） |
| 集成测试（`#[ignore]`） | `tests/windows_machine.rs::windows_get_ip`：首查、缓存复读一致、双机地址互异 |
| README/CHANGELOG | README「Windows transport and security」补 `get_ip` 语义；CHANGELOG Added |
| 提交 | `eb8fd90` |

**Acceptance criteria:**

- [x] Windows 优先返回 `TRN-01` 已发现并与本 VM MAC/端点绑定的 DHCP 地址；需查询时使用 PowerShell 解析并校验结果，不能使用 `hostname -I`。——缓存命中直接返回；未命中走 `GUEST_IP_QUERY` 并按 MAC 校验。
- [x] Linux 路径不变；无地址、多个地址无法消歧或查询失败时返回可操作错误，不能选其它 VM 的 lease。——Linux 分支仍用 `get_remote_ip`；Windows 的 0 结果/多结果/非 0 退出码均有专门错误（单测 3 个）。
- [x] `(new)` parser/选择单测与 Windows `get_ip` 冒烟覆盖缓存和重新查询；README 与 CHANGELOG 同卡更新。——单测 6 个可执行；`windows_get_ip` 已编写但需 DEP-01/02，`blocked`。
- [ ] 双机 `get_ip` 结果各自唯一且与传输实际使用地址一致。——`windows_get_ip` 已断言互异，执行需 DEP-01/02，`blocked`。

**Verification:**

- [x] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test --lib windows_ip`（6 passed）
- [x] `cargo test --no-run`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_get_ip -- --ignored --exact --test-threads=1` —— `blocked`
- [ ] 双机地址一致性结果写入「实施证据汇总」。——`blocked`

**Full-suite trigger:** `none`（共享 helper 若改变则升级为 T-1 并重审）

**Dependencies:** `EXE-01`（共享源码/文档写集串行）

**Deliverables:** `N/A`

**Implementation write set:** `src/windows.rs`、`src/machine.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/windows.rs`, `src/machine.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

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

**Lifecycle / Acceptance:** `in-progress` / `locally-accepted`（A 实现与 B 本地门已过；C 真实 `windows_files` 与 Linux `test_file_operation`/`test_file_transfer` 回归需 DEP-01/02 与完整 Linux VM 宿主，`blocked`）

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
**Implementation evidence:**

| 项 | 证据 |
|---|---|
| 唯一转换层 | 新增 `src/guest_path.rs`：`GuestPath::new(guest_os, raw)` 校验并规范化，`join`/`parent`/`file_name`/`ancestors`/`strip_prefix`/`is_root` 全部按 guest 语义；`src/lib.rs` 注册 `mod guest_path` |
| Windows 路径规范化 | 盘符必填并统一大写（`c:\users` → `C:/users`）、根写作 `C:`、`\`→`/`、保留空格与非 ASCII、去掉重复分隔符；UNC（`\\server\share`）、设备命名空间（`\\?\`、`\\.\`）、drive-relative（`C:foo`）、root-relative 与裸名一律报错 |
| 组件校验 | 拒绝 `<>:"|?*`、控制字符、结尾空格/点、保留设备名（`CON`/`NUL`/`COM1-9`/`LPT1-9`）；`..` 在构造与每次 `join` 时都拒绝，避免相对遍历逃逸根目录 |
| Linux 不变 | `GuestPath` 对 Linux 原样保存（仅拒绝空串/NUL 与反斜杠开头），`create_dir_all` 仍用 `/` 前缀逐级创建 |
| 所有远程 SFTP 入口 | `src/ssh.rs`：`create_dir_all(&GuestPath)`、`walk_remote_dir(&GuestPath)`、`upload_file(&Path, &GuestPath)`、`download_file(&GuestPath, &Path)`、`RemoteDirEntry::path() -> &GuestPath`；`src/machine.rs` 的 `upload`/`download`/`copy`/`create_dir`/`create_dir_all`/`exists`/`hard_link`/`metadata`/`read`/`read_dir`/`read_link`/`read_to_string`/`remove_dir_all`/`remove_file`/`rename`/`set_permissions`/`write` 全部经 `guest_path_from` 转换，不再用宿主 `Path::join` 拼客户机路径 |
| `copy` 不再用 POSIX `cp` | Windows 走 `powershell -NoProfile -NonInteractive -Command "Copy-Item -LiteralPath '<from>' -Destination '<to>' -Force"`；`windows::powershell_literal` 用单引号字面量并加倍内部单引号，避免 `$`/反引号插值 |
| unsupported 语义 | `guest_path::ensure_supported(GuestOs, PosixOnlyOperation, &GuestPath)` 统一拒绝 Windows 的 `hard_link`/`read_link`/`set_permissions`，错误含操作名、sanitized guest 路径与原因（ACL vs mode bits）；Linux 三个操作不变 |
| 链接不再静默跳过 | `upload` 目录树遇本地 symlink：Windows 直接报错；Linux 重建链接，`read_link` 或 `symlink` 失败即报错。`download` 遇远端 symlink/未知类型报错，不再 `continue` 静默成功 |
| 递归删除 | `remove_dir_all` 先 `walk_remote_dir` 收集，再逆序删子项与父目录，符合 `std::fs::remove_dir_all` 语义（原实现仅单层 `remove_dir`） |
| 单测 | `src/guest_path.rs` 11 个（盘符/根/分隔符、空格与非 ASCII、非法与不支持形式、非法字符与保留名、`..` 与 join 逃逸、join/parent、ancestors、strip_prefix、POSIX-only 拒绝 + Linux 可用、Linux 原样，外加 R26 的两个：768 种拼写的结构不变量、28 个非法形态的拒绝原因分类），`cargo test --lib windows_path` 过滤 |
| 集成测试（`#[ignore]`） | `tests/windows_machine.rs::windows_files`：`C:\qlean-fs-test` 下建目录、写/读/`read_to_string`、`copy`、`rename`、`remove_dir_all`、文件与目录 `upload`/`download` 往返，`read_link`/`hard_link`/`set_permissions` 三个 POSIX-only 入口逐一报错（R19，`daa6f19`） |
| README/CHANGELOG | README 新增「Windows file operations」支持矩阵与路径规则；CHANGELOG Added 四条 |
| Windows `copy` | `Machine::copy` 的 Windows 分支由 `windows::copy_file_command` 生成，直接执行 `Copy-Item -LiteralPath … -Destination … -Force`（单引号字面量，`$`/反引号/空格/非 ASCII 原样保留），不再套一层 `powershell -Command "..."`（R10，`src/windows.rs`、`src/machine.rs`） |
| 目录创建根跳过 | `create_dir_all` 对 POSIX `/` 与 Windows 盘根 `C:` 一律跳过，避免 drive-relative 的 `stat('C:')` 让递归创建失败（R12，`src/ssh.rs`） |
| 绝对子路径拒绝 | `GuestPath::join` 显式拒绝前导分隔符，不再静默变成相对路径；设备路径先于 UNC 判定（R13，`src/guest_path.rs`） |
| 提交 | `443ec5d` |

**Acceptance criteria:**

- [x] 唯一 `GuestPath`/转换层处理 Windows 盘符、根目录、分隔符、空格、非 ASCII、`..` 与 basename；所有远程 SFTP 入口使用它，不按宿主 Linux PathBuf 解释客户机路径。——`src/guest_path.rs` 为唯一转换点，`ssh.rs`/`machine.rs` 全部入口改用它。
- [x] 文件和目录 `upload`/`download` 往返一致；遇到不支持的链接/路径形式必须报错，不得静默跳过并返回成功。——目录树按 `walk_remote_dir`/`WalkDir` 逐项镜像；Windows symlink 与下载端 symlink/未知类型均报错（原实现静默 `continue`）。
- [x] `create_dir`/`create_dir_all`/`exists`/`metadata`/`read`/`read_to_string`/`write`/`read_dir`/`remove_file`/`remove_dir_all`/`rename`/`copy` 在 Windows 按各自文档语义工作，其中 `copy` 不再调用 POSIX `cp`。——`copy` 改 PowerShell `Copy-Item -LiteralPath`；`remove_dir_all` 改为真正递归。
- [x] Windows `hard_link`/`read_link`/`set_permissions` 与 UNC/device 路径明确返回 unsupported；Linux 分支不变。——`ensure_supported` + `normalize_windows`；Linux 三个操作与路径语义未改。
- [x] 路径校验防止把不支持输入转成宿主绝对路径或意外逃逸目标根；错误包含 sanitized 路径。——`..` 在构造与 join 两处拒绝，UNC/device/drive-relative 报错并回显原始输入；错误只含 guest 路径，不含宿主路径。
- [x] `(new)` 单测覆盖盘符、根、空格、非 ASCII、嵌套目录、非法/不支持路径和各 unsupported 分支。——9 个单测（含 `ensure_supported` 三个操作与 Linux 正向对照）。
- [ ] Windows 文件/目录上传下载、递归删除、重命名和复制通过真实冒烟，Linux `single_machine` 文件测试回归。——`windows_files` 已编写，执行需 DEP-01/02；Linux 回归需完整 Linux VM 宿主（另见 DEFER-04），`blocked`。
- [x] README 支持矩阵/示例/限制与 CHANGELOG Added 同卡逐文件更新。

**Verification:**

- [x] `cargo fmt --check && cargo clippy --all-targets --all-features -- -D warnings`
- [x] `cargo test --lib windows_path`（11 passed；R26 增补组合式不变量与拒绝原因分类两组）
- [x] `cargo test --lib`（69 passed）
- [x] `cargo test --no-run`
- [ ] 满足 DEP-01/02：`QLEAN_WINDOWS_IMAGE=/path/to/windows.qcow2 QLEAN_WINDOWS_DIGEST=sha256:<hex> cargo test --test windows_machine windows_files -- --ignored --exact --test-threads=1` —— `blocked`
- [ ] T-1 全量，配置齐全的 Linux VM 宿主机：`cargo test -- --test-threads=1`（覆盖 `test_file_operation` 与 `test_file_transfer`）—— `blocked`（DEFER-04）

**Full-suite trigger:** `T-1: 共享 SFTP 路径分派`

**Dependencies:** `IP-01`（共享源码/测试/文档写集串行）

**Deliverables:** `N/A`

**Implementation write set:** `src/guest_path.rs`、`src/machine.rs`、`src/ssh.rs`、`src/windows.rs`、`src/lib.rs`、`tests/windows_machine.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** `N/A`

**Files likely touched:** `src/guest_path.rs`, `src/machine.rs`, `src/ssh.rs`, `src/windows.rs`, `src/lib.rs`, `tests/windows_machine.rs`, `README.md`, `CHANGELOG.md`

**Docs and compatibility impact:** README 列出每个支持/unsupported 文件接口和路径形式；CHANGELOG Added。兼容性：`upload`/`download` 遇符号链接由「静默跳过」改为报错，`remove_dir_all` 由单层改为递归（更符合 `std::fs` 文档语义），均记入 CHANGELOG。

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

**Lifecycle / Acceptance:** `blocked` / 空（2026-11-12 R5 消歧：`SPK-01`/`SPK-02` 因 DEP-01/02 不可用而 `blocked`，全部真实 Windows KVM 核心冒烟（`windows_firmware_lifecycle`、`windows_first_boot`、`windows_transport`、`windows_pool`、`windows_exec`、`windows_get_ip`、`windows_files`）与 Linux 全量门（DEFER-04）均无证据。禁止用 TCG、`--no-run` 或 DEFER 替代，因此不 bump、不 tag、不发布）

**Description:** 作为唯一发布点聚合全部守卫，定稿 CHANGELOG、对齐 CI、发布 0.4.0；已吸收原 DOC-01 的只读文档收口审计，不承担各行为卡的补文档责任。

**Out of scope:**
- 不引入新产品行为；文档/测试缺口退回所属卡修复，不在发布点掩盖。
- 不用 TCG、`--no-run` 或 `DEFER-03` 替代 Windows KVM 核心验收。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 当前版本 0.3.1 | `Cargo.toml:1-4` |
| CI 已对齐静态门并双触发（R22）：run `43197579979`，event=`push`，ref=`refs/heads/main`，commit=`4d4d1e9`，`Setup and Cache`/`Rustfmt Check`/`Clippy Check`/`Cargo Test` 4 job 全绿；`Cargo Test` 日志 `running 85 tests` → `test result: ok. 85 passed` | `https://github.com/buck2hub/qlean/actions/runs/43197579979`；`.github/workflows/check-and-test.yml:1-8,78-83,106-112` |
| CHANGELOG Unreleased/0.3.1 | `CHANGELOG.md:8-24` |
| README 迁移节已按 CHANGELOG 校正（源码级破坏 + 两处 Linux 运行时变化，R21） | `README.md:503-536` |
| 打包前置：`cargo package --allow-dirty --no-verify` 通过，27 个文件 / 598.4KiB；锁文件已脱离 yanked 的 `crypto-bigint`（R23，`Cargo.lock`） | `Cargo.lock`；run `43198568379`（push/`main`/`bf83b3c`，全绿） |
| 打包全验证通过：`cargo publish --dry-run --allow-dirty` 从打包产物重编译成功（R24）；历史 tag 缺失：远端仅 `v0.1.0`/`v0.2.0`/`v0.3.0`，CHANGELOG 引用的 `v0.2.1`/`v0.2.2`/`v0.2.3`/`v0.3.1` 从未存在（发布面历史遗留，随 0.4.0 一并处理） | `target/package/qlean-0.3.1`；`gh api repos/buck2hub/qlean/tags` |


| 发布前阻塞项（2026-11-12） | 状态 |
|---|---|
| `SPK-01`/`SPK-02` 传输与首启 spike | `blocked`：无合法 Windows qcow2（DEP-01）、无 Windows KVM 宿主（DEP-02） |
| `OSX-01` | `done` / `complete`（纯代码 + 文档门） |
| `OSX-02`/`OSX-03`/`TRN-01`/`EXE-01`/`IP-01`/`FS-01` | `in-progress` / `locally-accepted`：实现与本地门已过，真实 Windows KVM 冒烟 `blocked` |
| Linux 全量门 | `blocked`：本机无配置齐全的 Linux VM 宿主（DEFER-04） |
| 结论 | 0.4.0 不发；`Cargo.toml` 保持 0.3.1，不打 tag，不写发布日期 |

**Acceptance criteria:**

- [ ] 全部任务卡 `Lifecycle=done` 且 `Acceptance=complete`，最终 code review PASS，P0/P1 关闭。
- [ ] `Cargo.toml` 从 0.3.1 bump 到 0.4.0，`Cargo.lock` 仅由 Cargo 工具链刷新，版本与迁移理由符合 ADR-WIN-01。
- [ ] README 支持矩阵只包含实际通过核心冒烟的 Windows 版本；CHANGELOG `[0.4.0]` 含 Added/Changed/Migration 与发布日期，链接可解析。
- [x] CI 对目标分支 push 和 PR 均触发 format/clippy/test job，clippy 使用 `--all-targets --all-features -- -D warnings`，Windows target 至少 `--no-run` 编译。（R22 完成并取得真实 push 运行证据：run `43197579979` 四 job 全绿，含 `cargo test --lib` 的 85 passed 与 `cargo test --no-run --all-targets`；PR 侧沿用既有触发配置）
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
| 编译门槛 | CI 编译所有 target，包括 ignored Windows 测试 | `cargo test --no-run --all-targets` |
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
| EXE-01 | `src/machine.rs:495-516` | machine/ssh/exec（新 `src/exec.rs`） | README exec、CHANGELOG | `windows_exec` |
| IP-01 | `src/ssh.rs:831-841` | windows/machine | README get_ip、CHANGELOG | `windows_get_ip` |
| FS-01 | `src/machine.rs:578-775,922-1137` | guest_path/machine/ssh | README 文件矩阵、CHANGELOG | `windows_files` |
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
| QEMU 启动即退出（发现 lease 期间） | 无运行 VM | 与 lease 轮询 race，立即报 QEMU 的真实错误并停 `swtpm` | 等满部署预算后误报「无 DHCP lease」 |
| QEMU 在 SSH 阶段退出 / SSH 任务 panic | 无运行 VM | 统一失败分支：终止 QEMU、清 `pid`、停 `swtpm`，再返回错误 | TPM 进程残留、`is_running` 误报、seed 介质随 VM 继续运行 |
| 首启部署期间会话断开（guest 重启） | seed 仍在 run 目录，可重试 | 连续 3 次探测失败即报错并提示 `spawn` 重试，不再等满部署预算 | 15 分钟后误报「部署未完成」 |
| 池内 Windows VM 二次启停 | 无运行 VM | `init_all` 对已部署的 VM 走 `spawn`，`spawn_all` 对未部署的 VM 走 `init` | `already completed its Windows first-boot deployment` 或启动成不可达 guest |
| host key 不匹配 | 无会话 | 立即失败并清理，不自动接受新 key | 静默信任任意 key |
| Windows 首启后重启失败 | 可保留失败 run dir 供排查（clear=false） | 终止进程、记录状态；修复后新建干净 VM 验证 | 删除证据后宣称成功或复用半部署状态 |
| `init`/`spawn` 启动失败（含首启超时、`read_pid` 失败） | 无运行 VM、无残留会话 | 取消并清除 cancel token、停 `swtpm`、必要时终止 QEMU 后可在同一 `Machine` 上重试 | 遗留 `already initialized` 之类的误导报错或无法重试 |
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
- [x] CI push/PR 触发与 format/clippy/test 命令已同步（R22：`push`(main)+`pull_request` 双触发、clippy `--all-targets --all-features`、`cargo test --lib`、`cargo test --no-run --all-targets`、rustdoc 门；run `43197579979` 全绿）。
- [ ] `tests/INDEX.md` 当前不存在，`N/A`。
- [ ] LICENSE 未改动。

## 实施证据汇总

只写 sanitized summary、命令、退出码、版本/commit、CI run ID/URL；不得新建证据文件，不得记录 secret、私有绝对路径或原始 tool payload。任务推进时同时更新 `plan-status.md` 和「修订历史」（规范性变化）/本表（执行证据）。

每张卡都必须在 Review 列记录其代码或产物 review 的 round、PASS 与问题关闭情况，然后才能按 ER-04 进入 `complete`。下方 Review log 是计划文档评审，不能替代实现后的逐卡 review。

| 任务 | UTC 时间 | 环境与 sanitized 输入 | 命令/检查与结果 | Lifecycle / Acceptance | Review | 发布/远端证据 |
|---|---|---|---|---|---|---|
| SPK-01 | 2026-11-12 07:45:12 UTC | 宿主机审计：Linux x86_64、`/dev/kvm` 存在；`qemu-system-x86_64`/`qemu-img`/`swtpm`/`xorriso`/`virsh`/`qemu-bridge-helper`/OVMF 均缺失；`sudo -n` 需密码；无 Windows qcow2（DEP-01/02 均不可用） | 未执行：无可用 Windows VM，无法取得连接/鉴权/SFTP 证据 | `blocked` / 空 | N/A（无实现产物可 review） | N/A |
| SPK-02 | 2026-11-12 07:45:12 UTC | 同上（无 QEMU/OVMF/swtpm，无 Windows 镜像） | 未执行：无可用 Windows VM，无法取得首启/重启证据 | `blocked` / 空 | N/A（无实现产物可 review） | N/A |
| OSX-01 | 2026-11-12 08:40:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib image::tests`（18 passed）、`cargo test --no-run` 全绿 | T-1 全量门未执行（无 QEMU/libvirt，`DEFER-04`） | `done` / `complete` | R6 PASS：逐条核对 8 条 AC；`ensure_cached_guest_os` 覆盖旧 JSON 默认 `Linux` 与 `windows-` 命名空间；`GuestOs`/校验/README API+Migration/CHANGELOG 一致，无遗留问题 | `50c8cff` |
| OSX-02 | 2026-11-12 09:35:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib qemu`（5 passed）、`cargo test --no-run`（含 `tests/windows_machine.rs`）全绿 | `windows_firmware_lifecycle` 未执行（DEP-01/02 不可用），T-1 全量门 `DEFER-04` | `in-progress` / `locally-accepted` | R6 PASS：核对 `windows_firmware_args`、`select_accel`（Windows 不回退 TCG）、`prepare_vars` 复用与 `swtpm` 生命周期；F1（`Drop` 与 `swtpm` 关闭顺序）本轮修复 | `f2fc277` |
| OSX-03 | 2026-11-12 10:20:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib windows_deploy`（7 passed）、`cargo test --lib windows_deploy_timeout`（2 passed）、`cargo test --no-run` 全绿 | `windows_first_boot` 与首启/重启 seed 清理证据未取得（需 `TRN-01` + DEP-01/02），T-1 全量门 `DEFER-04` | `in-progress` / `locally-accepted` | R6 PASS：核对 seed 0600/目录权限、每 VM host key、`confirm_deployment` 后删 ISO/目录、超时错误可操作；R8 修复首启连接预算（`0e72b45`） | `8812fb4` |
| TRN-01 | 2026-11-12 11:40:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib ssh`（5 passed）、`cargo test --lib utils`（4 passed）、`cargo test --no-run`（含 `windows_transport`/`windows_pool`）全绿 | `windows_transport`/`windows_pool` 与真实 spawn 重连证据未取得（DEP-01/02 不可用），T-1 全量门 `DEFER-04` | `in-progress` / `locally-accepted` | R6 PASS：核对 `connect_over`/`ConnectParams` 与 vsock 语义、`check_server_key` 拒绝错配与证书、lease 按 MAC 检索并缓存、vsock 仅 Linux 必需；无遗留问题 | `6711671` |
| EXE-01 | 2026-11-12 12:10:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib windows_exec`（5 passed）、`cargo test --no-run` 全绿 | `windows_exec` 真实 PowerShell 冒烟未取得（DEP-01/02 不可用），T-1 全量门 `DEFER-04` | `in-progress` / `locally-accepted` | R6 PASS：核对 `exit_status_from_code` 高位映射、`0..=255` 外拒绝、空命令拒绝、README 契约与 CHANGELOG `Fixed`；R7 修掉空命令错误文案里的多余空格（`c14b915`） | `64b1046` |
| IP-01 | 2026-11-12 12:50:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib windows_ip`（6 passed）、`cargo test --no-run` 全绿 | `windows_get_ip` 与双机一致性未取得（DEP-01/02 不可用） | `in-progress` / `locally-accepted` | R6 PASS：核对缓存优先、按本 VM MAC 精确选择、0/多结果报错不回落到他机 lease；无遗留问题 | `eb8fd90` |
| FS-01 | 2026-11-12 13:20:00 UTC | `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib windows_path`（10 passed）、`cargo test --lib windows`（39 passed）、`cargo test --lib`（79 passed）、`cargo test --no-run` 全绿 | `windows_files` 与 Linux 文件回归未取得（DEP-01/02、DEFER-04） | `in-progress` / `locally-accepted` | R6 PASS：核对 `GuestPath` 校验/规范化/`join`/`ancestors`/`strip_prefix`、所有 SFTP 入口改造、`copy` 去 POSIX `cp`、unsupported 分支；F2（Review 列语义）与 F3（`join` 不可达分支）本轮修复；R10 修复 `copy` 的 PowerShell 二次解析（`ec6a9a1`） | `443ec5d` |
| REL-01 | 2026-11-12 10:20:00 UTC | 未执行发布动作；仅完成 CI 静态门对齐（R22） | `SPK-01`/`SPK-02` 与全部真实 Windows KVM 冒烟 `blocked`（DEP-01/02）；Linux 全量门 `blocked`（DEFER-04）；CI 门已对齐并取得真实运行：run `43197579979`（event=`push`, ref=`refs/heads/main`, commit=`4d4d1e9`）4 job 全绿，`cargo test --lib` 85 passed、`cargo test --no-run --all-targets` 通过、clippy `--all-targets --all-features` 0 告警、rustdoc `-D warnings` 通过 | `blocked` / 空 | blocked（发布 review 未开始；AC-04 的 CI 部分已在 R22 关闭） | run `43197579979`（push/`main`/`4d4d1e9`）与 run `43198568379`（push/`main`/`bf83b3c`）均四 job 全绿；`cargo package` 通过（27 文件/598.4KiB，无 yanked 警告） |

## Review log

Result 只允许 `PASS` 或 `FAIL`。各轮 review 覆盖三份文件：`plan-template.md`、`plan-status.md`、本计划。

| Round | Scope | Result | P0/P1 | P2 处置 | Evidence |
|---|---|---|---|---|---|
| R1 | 三份文件、全部任务卡与当前源码 | FAIL | P1-01~P1-10；R2 已复核关闭 | 无 residual risk | 当前源码锚点、R1 修订历史 |
| R2 | R1 修订、执行门与安全路径 | FAIL | P1-11~P1-14；R3 已复核关闭 | 无 residual risk | 逐卡 T-1/AC-VER 复核、host-key provisioning 检查 |
| R3 | 三份文件最终一致性复审 | PASS | 无开放项；P1-01~P1-14 全部关闭 | 无 residual risk | 自动校验 PASS：10 任务/10 状态行、依赖无环、AC/VER 与审计一致、T-1/T-2 全量门齐全、表格/链接/现有锚点有效；人工语义复核通过 |
| R4 | P2 缺口修订（OSX-02 资源默认值、OSX-03 部署超时） | PASS | 无开放项；GAP-08/09 已修复 | 无 residual risk | 审计表重算：`OSX-02` AC=8/8、VER=5/8；`OSX-03` AC=8/8、VER=7/8（均在上限内）；追溯表补 `windows_deploy_timeout`；风险表新增两行；事实基线/性能摘要同步；plan-status 状态与时间戳同步；新增 AC 不扩大行为轴、不引入新依赖 |
| R5 | 环境消歧（DEP-01/DEP-02 不可用）与依赖边重排 | PASS | 无开放项；spike 阻塞已登记，ADR 临时接受已写明 revisit 条件 | 残余风险：Windows 实测证据缺失（由 `SPK-01`/`SPK-02` 与 `REL-01` 阻塞承载），具名接受人=计划 Owner | 审计命令输出（`command -v` 全缺、`sudo -n` 需密码、`/dev/kvm` 存在）；依赖图无环复核；`SPK-02 -> OSX-01` 取消理由=OSX-01 无 Phase 0 输入；粒度审计表 deps 列同步 |
| R6 | 实施后逐卡 review：`OSX-01`~`FS-01` 的实现产物、AC 对照与逐卡门禁 | PASS | 无 P0/P1 开放 | F1~F4 已在本轮修复；残余风险：真实 Windows KVM 证据与独立第二人 review 仍缺（由 `SPK-01`/`SPK-02`/`REL-01` 阻塞承载） | 逐卡门禁重跑：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、8 个 focused filter 全绿（`image::tests` 18、`qemu` 5、`windows_deploy` 7+2、`ssh::tests` 5、`utils::tests` 4、`windows_exec` 5、`windows_ip` 6、`windows_path` 9）、`cargo test --lib` 69 passed、`cargo test --no-run`；F1~F3 修订见下表 |
| R7 | 文档结构与状态一致性复核（10 张卡的标题/字段/状态机对齐 `plan-status.md`）+ 实施产物文案复核 | PASS | 无开放项 | 修复 6 处缺陷（`OSX-01` 标题与 `Task type` 行丢失、`SPK-01`/`SPK-02` 卡头仍为 `pending`、`OSX-03` 重复的第二个 `Verification` 块、`TRN-01`/`EXE-01`/`IP-01`/`FS-01` 缺失的 `Implementation evidence` 标签、修订历史表被空行截断、`Machine::exec` 空命令错误文案多余空格 `c14b915`） | 逐卡字段审计脚本比对 10 张卡：每卡含标题、`Task type`、`Lifecycle / Acceptance` 与全部模板字段且无重复字段；状态与 `plan-status.md`、实施证据汇总三处一致 |
| R8 | 首启生命周期复核（连接预算/失败清理/重复 init） | PASS | 无开放项 | F5：Windows `init` 仍用 180s/300s 连接预算等待 `sshd`，900s 部署预算永远不可达；F6：`confirm_deployment` 失败经 `?` 透传，留下运行中的 QEMU、`swtpm` 与仍挂载的 seed（含客户端公钥与每 VM host 私钥）；F7：`read_pid` 失败直接透传，跳过 `swtpm` 停止；F8：已部署的 Windows 机器可再次 `init`，此时 seed ISO 已删除 | F5 修复 `resolve_connect_timeout` + 3 个单测（`0e72b45`）；F6 失败即关会话/杀 QEMU/停 swtpm/清端点（`f9cc1ee`）；F7 有界等待并停 swtpm（`83a8b0c`）；F8 `init` 前置拒绝并提示 `spawn`（`178ac03`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 72 passed、`cargo test --no-run` 全绿 |
| R9 | 硬件对接面复核（QEMU 设备/OVMF 配对/swtpm 权限） | PASS | 无开放项 | F9：所有 guest 都被追加 `vhost-vsock-pci`，Windows 因此依赖 `/dev/vhost-vsock`；F10：`prepare_vars` 要求 code 与 vars 等长，而所有 stock 固件的 vars 远小于 code，真实宿主上必然失败；F11：swtpm 控制 socket 用默认权限创建；F12：secboot code 搭配的是空 KEK 的普通 vars 模板，guest 实为 Secure Boot setup mode（Windows 11 拒绝）；F13：`ensure_host_support` 未检查 `xorriso`，首启 seed 介质构建失败会延后暴露 | F9 `vsock_args` 分派 + 2 单测（`f42a942`）；F10 规则修正 + 2 单测（`8ae13ec`）；F11 `mode=0600` + `swtpm_args` 单测（`3e7ebd0`）；F12 候选表按 code 列出多个 vars 模板并优先 `.ms`/`.secboot`（`fec2e4d`）；F13 前置检查补 `xorriso`（`7ddc686`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 77 passed、`cargo test --no-run` 全绿 |
| R10 | Windows 命令构造复核（`Machine::copy` 的 PowerShell 调用） | PASS | 无开放项 | F14：`copy` 把 cmdlet 包在 `powershell -Command "..."` 里，而 guest 默认 shell 已是 PowerShell，外层会再解析一次双引号字符串并展开 `$`，复制 `C:/Program Files/a$b.txt` 这类路径会静默指向别的文件 | F14 抽出 `windows::copy_file_command` 直接发射 cmdlet（单引号字面量，仅一层解析）+ 单测断言不含 `-Command`/`"`（`ec6a9a1`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 79 passed、`cargo test --no-run` 全绿 |
| R11 | 失败启动的可恢复性复核（`init`/`spawn` 状态标记） | PASS | 无开放项 | F15：`ssh_cancel_token` 同时充当「已启动」标记，`launch` 失败（含 Windows 首启超时拆除、`read_pid` 失败）后 token 残留，同一 `Machine` 上无法重试且报错文案误导；残留连接任务也未被取消 | F15 `init`/`spawn` 仅在 `pid`/`ssh` 存在时拒绝重复启动，失败路径新增 `abandon_launch()` 取消并清除 token，顺带修掉 `warn!` 里的多余空格（`bf0710c`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 79 passed、`cargo test --no-run` 全绿 |
| R12 | 首启地址发现与 Windows 目录创建复核 | PASS | 无开放项 | F16：`find_lease_address` 在 `launch` 的 `select!` 之前串行执行且不响应取消，Windows 首启时最长 900s 内即使 QEMU 已退出也不会报真正原因；F17：`create_dir_all` 对 Windows 盘根 `C:` 仍执行 mkdir/stat，drive-relative 请求不保证解析到盘根，严格服务器会让整条递归创建失败 | F16 将地址发现与 `qemu_handle`/cancel token 一起 race，端点解析改为 owned 参数以解除 `self` 借用（`d2a85ab`）；F17 两种 OS 的根一律跳过（`1e1af91`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 79 passed、`cargo test --no-run` 全绿 |
| R13 | 地址选择与路径拼接复核 | PASS | 无开放项 | F18：`find_lease_address` 返回首个 MAC 匹配的 lease，双栈网络下 `fe80::/10` 行会排在前面，`SocketAddr::new(link_local, 22)` 不可达却已算成功，连接循环不再重试；F19：`normalize_relative` 用 `trim_matches('/')`，`join("/etc/passwd")` 在 Linux 上静默变成 `etc/passwd`，与 `Path::join` 语义相反；`normalize_windows` 先判 UNC，导致 `\\?\C:` 报 UNC 而非设备路径 | F18 新增 `lease_address_for`（仅 IPv4，含双栈/仅 IPv6/别机 MAC 三个用例）并在超时文案注明（`ed09b5b`）；F19 拒绝前导分隔符、设备路径先于 UNC 判定，补 Linux/Windows 用例（`33567ed`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 83 passed、`cargo test --no-run` 全绿 |
| R14 | 启动失败时的资源收尾复核 | PASS | 无开放项 | F20：SSH 阶段 `select!` 的 QEMU 分支只 `bail!`，不清 `pid`、不停 `swtpm`；SSH 任务 panic 时 `result.map_err(..)?` 直接返回，`qemu_handle` 被 detach，QEMU 带着 seed 介质（客户端公钥 + 每 VM 主机私钥）继续运行 | QEMU 退出分支改为清 `pid` + `swtpm.stop()`（`e412251`，并修正该分支不可再次 await 已完成 join handle）；SSH panic 改为错误值注入既有失败分支（`77cc1fc`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 83 passed、`cargo test --no-run` 全绿 |
| R15 | 部署标记探测与池化启停复核 | PASS | 无开放项 | F21：`deploy_marker_present` 用 `Err(_) => false` 吞掉传输错误，`confirm_deployment` 便按「还没部署」轮询满 900s，最后报与事实无关的「部署未完成」；F22：`MachinePool::init_all` 无条件 `init`，Windows 二次启停必失败；`spawn_all` 无条件 `spawn`，未部署的 Windows 会启动成 sshd 无密钥的不可达 guest | F21 改为 `Result<bool>`，区分应答与失败，连续 3 次传输错误即返回带 `spawn` 提示的错误（`9cc7eb0`）；F22 新增 `wants_init`/`needs_first_boot`，池化两处按部署状态分流（`2d8b772`）；门禁 `cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 83 passed、`cargo test --no-run` 全绿 |
| R16 | 公开文档与门禁复核 | PASS | 无开放项 | F23：Windows 工作新增的公开文档注释（`upload`/`download`）链接到私有类型 `GuestPath`，`cargo doc` 在 `-D warnings` 下报 `private_intra_doc_links` 并失败；此前门禁只跑 fmt/clippy/test，未覆盖 rustdoc | 改为代码字面量（`9297994`）；门禁补 `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` 与 `cargo test --no-run --all-targets`（含 `benches/hash_benchmark.rs`），两者现已通过；`cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 83 passed 全绿 |
| R17 | 宿主前置聚合的测试有效性复核 | PASS | 无开放项 | F24：`test_explicit_gaps_error_is_actionable` 把期望错误消息用同一批字符串拼出来再断言，未调用任何生产代码，属自证式测试；`ensure_host_support` 若退化成只报第一个缺失项也仍会通过 | 抽出 `host_support_problems` 纯函数并把探针结果作为参数，新增 3 个测试：四项同时缺失时逐条命中且聚合消息为 4 行、宿主齐全时返回空、只缺一项时只报该项（`5981c5c`）；`cargo test --lib` 83 → 85 passed |
| R18 | CI 覆盖面审计 | PASS（findings-only，无代码改动） | 缺口转 `REL-01` AC-04 | CI 的 `test` job 是 `cargo test --no-run`：只编译、不执行，因此本计划新增的 85 个单测（唯一不依赖 KVM/镜像的验证面）在 CI 上从未运行；clippy job 用 `cargo clippy -- -D warnings`，不含 `--all-targets --all-features`，测试与 benches 不被 lint | 不改 workflow：`.github/workflows/check-and-test.yml` 属 `REL-01` write set，且该卡 AC-04 已要求「CI 对 push 与 PR 均触发 format/clippy/test」并把 clippy 对齐到 `--all-targets --all-features`；本地门禁已按更严口径执行（fmt/clippy --all-targets/rustdoc -D warnings/`cargo test --lib`/`--no-run --all-targets`），故登记为发布前必须关闭的执行缺口 |
| R19 | 验收项到断言的追溯 | PASS | 无开放项 | 逐条比对 7 个 `windows_*` 冒烟的断言与卡片 AC：`windows_files` 只验证 `read_link`，缺 `hard_link`/`set_permissions` 两处接线证明；其余 6 个测试的断言与 AC 一一对应（固件生命周期、首启 marker 与 authorized_keys、pinned host key 与 PTY 拒绝、池内地址/host key 互异、PowerShell 引号/流分离/退出码、`get_ip` 缓存与双机互异） | 补两条断言，复用宿主临时文件的 `Permissions` 避免引入 unix-only 依赖（`daa6f19`）；`cargo fmt --check`、clippy `-D warnings`、`cargo test --lib` 85 passed、`cargo test --no-run --all-targets` 全绿，`--ignored` 仍为 7 failed（DEP-01 门未绕过） |
| R20 | 一次性部署的可观测性 | PASS | 无开放项 | `windows_transport` 的 `spawn` 段只证明「能连上并执行」，而 OSX-03 还要求部署后 seed 清理、host key 跨重启保持、二次 `init` 拒绝；seed 删除本身没有公开访问器，直接查宿主 run 目录会侵入私有实现 | 用公开行为观测：`spawn` 后 `ssh_host_key()` 仍等于首次 pin 的 key；随后 `init()` 必须报 `already completed its Windows first-boot deployment`（该错误仅在 `deploy_seed` 被 take+remove 后出现，且 `init` 在改动任何状态前返回）（`aa7fc0e`）；门禁 fmt/clippy/`cargo test --lib` 85 passed/`--no-run --all-targets` 全绿 |
| R21 | 迁移说明与 CHANGELOG 一致性 | PASS | 无开放项 | README 迁移节声称 Linux 运行时行为未变，与 CHANGELOG `Fixed` 的两条（`Machine::exec` 退出码换算、空命令拒绝）直接矛盾；首次修订又多写了「绝对 `upload`/`download` 目的地报错」，该路径实际走 `guest_path_from`，`GuestPath::join` 的绝对子路径修复只影响内部调用（`local_basename`/`rel` 永远相对），故用户可见影响为零 | README 改写为「源码级破坏 + 两处运行时行为变化」并列出适配动作（`943daa0`），撤回不准确的第三条（`8365972`）；核对后 CHANGELOG `Added`/`Changed`/`Fixed` 三类 40+ 条与本轮实现一一对应，无失实条目 |
| R22 | CI 门实际执行与远端证据 | PASS | 无开放项 | R18 登记的缺口：CI 只编译不运行（85 个单测从不在 CI 执行）、clippy 未覆盖测试/bench 代码、workflow 只在 PR 触发而本仓库直推 `main`（57 个提交零 CI 记录），且 `paths-ignore` 忽略 `.github/**` 使 workflow 改动无法自证 | workflow 改为 push(main)+PR 双触发、clippy `--all-targets --all-features`、新增 `cargo test --lib` 与 `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps`、去掉对 `.github/**` 的忽略（`4d4d1e9`）；推后真实运行 run `43197579979`（event=`push`, ref=`refs/heads/main`, commit=`4d4d1e9`）4 job 全绿，日志含 `running 85 tests` → `test result: ok. 85 passed` |
| R23 | 发布打包前置检查 | PASS | 无开放项 | 发布点从未验证过打包产物：`cargo package` 暴露锁文件含已 yanked 的 `crypto-bigint v0.7.5`（russh→rsa→crypto-primes 传递依赖），而仓库其它门（fmt/clippy/rustdoc/单测）都不会报出这一点 | `cargo update -p crypto-bigint` 升到 0.7.11（连带 ctutils 0.4.8），本地全门重跑（fmt/clippy/rustdoc/`cargo test --lib` 85 passed/`--no-run --all-targets`）全绿，`cargo package` 不再有 yanked 警告；CI run `43198568379`（push/`main`/`bf83b3c`）四 job 全绿 |
| R24 | 打包全验证与治理性发现 | PASS（findings-only，无代码改动） | 两条发现移交 `REL-01`：CHANGELOG 历史 compare 链接指向从未存在的 tag；外链可用性在本环境不可判定（DNS 代理伪影） | 打包面已用 `cargo publish --dry-run` 全验证（从打包产物重编译）；硬件守卫面用 `cargo test --test windows_machine -- --ignored --test-threads=1` 实测 7 failed，全部快速返回 DEP-01 提示。发现①：`gh api repos/buck2hub/qlean/tags` 仅 `v0.1.0`/`v0.2.0`/`v0.3.0`，而 CHANGELOG 引用 `v0.2.1`…`v0.3.1`，GitHub compare/release 404（发布面历史问题，不在本计划写集内）；发现②：`getent hosts buck2hub.com` → `198.18.1.149`（保留网段），curl 全部外链探测经代理，结论不可用，故不改外链 |
| R25 | 文档滞后项对齐 | PASS | 无开放项 | R22 落地后计划内仍有 3 处「将来时」表述未回写：GAP-07 表项、与其它计划关系表中的 push 门待办、测试矩阵编译门槛命令过窄（`--no-run` 而非 `--no-run --all-targets`） | 逐条改为实测事实并标注 R22 提交与 run 证据；其余 GAP 行保持 `in-progress`（实现完成但硬件证据缺失），未提前标关闭 |
| R26 | 路径层不变量与诊断准确性 | PASS | 无开放项 | F31：`..` 组件被「结尾空格或点」规则拦下，诊断说 Windows 会剥掉结尾点，而真实原因是遍历语义——行为对、解释错；既有 9 个手写用例都没覆盖「拒绝原因是否对得上」，也没覆盖拼写交叉组合后的规范化不变量 | 新增两个测试：① 768 种驱动盘/分隔符/组件/结尾分隔符交叉拼写，断言规范化后盘符大写、`/` 唯一分隔、无结尾 `/`、重解析幂等、`file_name`/`parent().join()`/`ancestors` 首尾一致；② 28 个非法形态按「必须命中哪条检查」断言（UNC/设备路径/drive-relative/无盘符/`..`/NUL/控制字符/非法字符/结尾空格点/保留名）。测试先暴露 F31 与两处期望偏差（空串、NUL 由更早的守卫报出），修 `..` 显式拒绝后全绿（`70a3155`）；`cargo test --lib` 87 passed |
| R27 | QEMU 选项编码注入面 | PASS | 无开放项 | F32：宿主任意路径进入逗号分隔的 QEMU 值（盘 overlay、seed ISO、QMP socket、serial logfile、OVMF code/vars、swtpm socket），逗号会被 QEMU 解析成额外属性，既有测试只断言固定路径下的字符串形状，从未试探非法字符 | 抽出 `qemu_option_path` 作为唯一入口并在五处全部使用，`windows_firmware_args` 返回 `Result`（启动前即失败，不产生半配置 argv）；测试覆盖 OVMF code/vars 与 swtpm socket 的逗号拒绝（错误信息含具体是哪条路径、原因写「comma」）以及含空格路径正常通过（`85bc525`）；`cargo test --lib` 88 passed、clippy/rustdoc/fmt 全绿 |
| R28 | 拒绝路径的诊断质量（钉住主机密钥） | PASS | 无开放项 | F33：钉住密钥校验失败被 russh 表示为 `Error::UnknownKey`，而 `connect_over` 无对应分支，最终报 `SSH client error: UnknownKey`；`check_server_key` 的 4 个单测只验证返回 `true`/`false`，从未验证「拒绝后用户看到什么」 | 在握手匹配中显式拦截 `UnknownKey` 并调用新的 `host_key_rejection_message`：钉住场景列出「地址可能被另一台 VM 占用（DHCP 租约移动）」与「VM 被重新部署导致密钥变化」两种成因，并指向 `get_ip` 自查；未钉住场景保持中性。新增单测锁定消息内容（`5578f52`）；`cargo test --lib` 89 passed，fmt/clippy/rustdoc 全绿 |
| R29 | Secure Boot 配对的静默降级 | PASS | 无开放项 | F34：`resolve_ovmf` 的环境变量分支仅凭 code 文件名判定 `secure_boot=true`，未校验 vars 模板是否含 Microsoft KEK/db；README 把「回退到普通模板、进入 setup mode」写成既定行为，等于把缺陷固化成契约 | `vars_template_enrolls_microsoft_keys` 直接读模板内容（UTF-16LE 主体串），`ensure_secure_boot_pair` 在两条解析路径上都执行；新增单测用真实临时文件覆盖「普通模板被拒（错误含 setup mode 与 `QLEAN_OVMF_VARS`）」「enrolled 模板通过」「未开 Secure Boot 不检查」三种情形（`dedaacd`）；README/CHANGELOG 同步；`cargo test --lib` 90 passed |
| R30 | 不完整状态下的报错质量（panic → 错误） | PASS | 无开放项 | F35：`get_ssh` 的 `expect` 让 19 个公开入口在未运行状态下 panic，`exec` 则返回无上下文的 `SSH session not established`；同一状态两种表现，且没有任何测试覆盖「机器没起来时调用会怎样」 | `session_or_operation_error` + `not_running_error` 统一错误路径，`get_ssh(operation)` 逐点传操作名，`exec`/`remove_dir_all`/`open_interactive_shell` 全部改走；新增 2 个单测覆盖两种不完整状态与文案要素（`940dbe6`）；`cargo test --lib` 92 passed |
| R31 | DHCP 租约行的时效性 | PASS | 无开放项 | F36：`lease_address_for` 用 `find`（首个匹配行），同 MAC 出现多行租约（续租后旧行仍在表内）时会选中已放弃的地址；既有用例每 MAC 只有一行，测不出该顺序问题 | `DhcpLease.expiry` 保存 libvirt 原始到期时间，选择改为 `max_by(expiry)`；超时错误附到期时间；新增「同 MAC 两行取新」「无时间戳行」两组单测（`3cdf5a3`），README/CHANGELOG 同步；`cargo test --lib` 94 passed |
| R32 | 部署物料与目录权限 | PASS | 无开放项 | F37：`R11` 的权限收紧只覆盖 seed 内的文件，`seed.iso`（含 host 私钥）与所有 Qlean 目录仍是 umask 默认；测试也只断言两个文件为 `0600`，等于把「目录可能 0755」写成了可接受状态 | `utils::restrict_dir` + `create_dir` 统一 `0700`，run/seed 目录逐级收紧，`build()` 后用 `seal_seed_medium` 把介质封为 `0600`；新增 2 个单测并扩展 seed 用例断言目录权限（`80a57f7`），README/CHANGELOG 同步；`cargo test --lib` 96 passed |
| R33 | pid 复用与信号对象 | PASS | 无开放项 | F38：三处 `kill -9 <pid>` 都以「pid 存在」为判据，`/proc/<pid>` 仍存在但已换成别的进程时会误杀；测试完全没有覆盖信号路径 | `cmdline_is_qemu` 只看 argv[0]（避免 `-D /tmp/qemu-system-x86_64.log`、`qemu-img` 之类假阳性），`process_is_qemu`/`kill_if_qemu` 统一判据，`Drop`/`shutdown`/`terminate_qemu` 全部改走并 warn 说明 pid 疑似复用（`23f387c`）；新增 2 个单测（含 2 类假阳性与当前进程自身）；`cargo test --lib` 98 passed |
| R34 | 宿主前置程序的聚合报告 | PASS | 无开放项 | F39：`ensure_host_prerequisites` 逐个 `?` 提前返回，与 `host_support_problems` 宣称的「一次性报全」矛盾且顺序更靠前；`let _ = output()` 忽略退出状态，坏安装被当成已安装 | `ProgramProbe` + `program_problems` 单次探测四个程序合并报错，`--version` 失败归为「安装疑似损坏」（`ca4996c`）；新增 3 个单测；`cargo test --lib` 101 passed |
| R35 | 镜像下载的完整性判据 | PASS | 无开放项 | F40：截断的传输被 rename 成正式缓存文件，错误归因成「校验和不符」；失败产物残留在缓存目录 | `truncation_problem` 在 rename 前比对字节数并区分短传/多传，`verify_fetched` 校验失败即删除文件并说明（`4efb45c`）；新增 3 个单测；`cargo test --lib` 104 passed |
| R36 | xorriso 参数里的宿主路径 | PASS | 无开放项 | F41：R27 只修了 QEMU 侧；seed 构建仍有 `to_str().unwrap()` 的 panic 与两处 lossy 转换，非 UTF-8 家目录会得到错误路径或崩溃 | `utils::path_argument` 以 `OsString` 拼 `key=path`，`-o` 直接传 `Path`，三处 `-graft-points` 参数改走新函数（`450a647`）；新增 2 个单测（含 `\xff` 字节逐位断言）；`cargo test --lib` 106 passed |
| R37 | 构造失败时的残留 | PASS | 无开放项 | F42：`Machine::new` 半途失败时 `Machine` 不存在、`Drop` 不执行，run 目录/overlay/seed 全泄漏；Windows 分支还把宿主前置检查排在建 ISO 之后 | `RunDirGuard` 在 armed 状态删除半成品目录，成功路径 `disarm()`；Windows 分支前置 `ensure_host_support()`（`a6722f7`）；新增 2 个单测；`cargo test --lib` 108 passed |
| R38 | 库入口的 panic 面 | PASS | 无开放项 | F43：R30 之后仍有 6 处 `expect` 在生产路径上，其中 `Drop for Machine` 的 `expect` 可导致 abort，`QleanDirs::new` 的 `expect` 让所有入口在无 `HOME` 环境下崩溃 | `project_dir_or_explain` 取代 `ProjectDirs` 的 `expect`，`create_dir`/`launch`/`get_sftp`/`strip_prefix` 改为带上下文的错误，`Drop` 匹配 `Ok/Err` 且只 `warn!`（`4de03cc`）；新增 2 个单测；`cargo test --lib` 110 passed |
| R39 | 每 VM 的 OVMF vars 镜像 | PASS | 无开放项 | F44：`std::fs::copy` 复制模板权限位，`0444` 模板导致 pflash 只读、固件变量写不回；复用路径不校验尺寸，旧 OVMF 留下的 NVRAM 被直接启动 | `utils::restrict_file`（`0600` 且可写）在创建后与复用前施加；复用前比对尺寸，不一致则拒绝并给恢复步骤，绝不覆盖 NVRAM（`c6c84f5`）；新增 2 个单测；`cargo test --lib` 112 passed |
| R40 | swtpm 的停止路径 | PASS | 无开放项 | F45：`stop`/`stop_now` 用 `SIGKILL`，而 swtpm 在关闭时才写盘；`stop_now` 发完信号即丢弃 `Child`，`kill_on_drop` 又补一发强杀，优雅停止根本来不及发生 | `signal_terminate` 发 `SIGTERM`，`stop()`/`stop_now()` 各等 2s 宽限期后才 kill（`Drop` 里同步等待，避开 `kill_on_drop`）（`c688ce3`）；新增 2 个单测分别证明优雅路径与兜底路径都真实执行；`cargo test --lib` 114 passed |
| R41 | 「问不到」被当成「没有」 | PASS | 无开放项 | F46：`deploy_marker_present` 无会话返回 `Ok(false)`（违背自身文档），导致空转 900s 并误报部署超时；`is_running` 把 QMP 失败折成 `false`，可能让池子在活 domain 上再起 QEMU | `marker_probe_guard` 返回 `not_running_error`，两处 `Ok(false)` 改为显式不可能状态；`running_check` 三分支判定，QMP 失败如实报错（`3505750`）；新增 2 个单测；`cargo test --lib` 116 passed |
| R42 | `spawn` 前必须已部署 | PASS | 无开放项 | F47：`needs_first_boot()` 的判据只存在于 `MachinePool`，`Machine::spawn` 仍会不带 seed 介质启动 Windows guest，失败只能在 900 秒后暴露 | `spawn_guard` 在 `spawn` 内拒绝该状态并给出 `init` 处置（`692c456`）；新增 1 个单测；`cargo test --lib` 117 passed |
| R43 | 被拒绝的固定主机密钥不得重试 | PASS | 无开放项 | F48：安全判定被当作瞬时故障无限重试，真正的原因被「仍然不可达」覆盖；另有三处消息残留连续空格 | `PINNED_KEY_REJECTED` + `is_fatal_connect_error` 让两处重试循环快速失败；清理三处消息空格（`f3296fc`）；新增 3 个单测；`cargo test --lib` 120 passed |
| R44 | QEMU 进程如何结束必须说清楚 | PASS | 无开放项 | F49：teardown 自己发的 SIGTERM/SIGKILL 被报成启动失败；信号死亡被格式化成 `error code: None` | `describe_exit`/`signal_name` 让两个方向都说得出真因，已请求的停止不再报错（`1bb1af1`）；新增 4 个单测；`cargo test --lib` 124 passed |
| R45 | 固件解析取第一个可用候选 | PASS | 无开放项 | F50：`find_map` 取第一个存在候选，可用性检查在选定之后，导致「secboot code + 普通 vars」布局整机被拒，而旁边的非 secboot 候选本可用 | `ResolvedFirmware`/`skipped` 把可用性判定前移到候选筛选，全部不可用时逐条解释并给出覆盖方式（`3c0ad9f`）；新增 3 个单测；`cargo test --lib` 127 passed |
| R46 | 池子不得取消其他机器的启动 | PASS | 无开放项 | F51：`try_join_all` 短路会丢弃其他启动 future，留下无 pid 记录的 QEMU，重试时在活磁盘上重建 overlay | `run_all` 统一三处，`join_all` + 按机器名聚合错误，绝不取消启动（`f2426cd`）；新增 3 个单测；`cargo test --lib` 130 passed |
| R47 | bridge helper 纳入前置检查 | PASS | 无开放项 | F52：DEP-02 列了 `qemu-bridge-helper`，但前置检查没有它，缺它时只在 QEMU 桥接阶段炸；且它在 `libexec`，`--version` 探测看不见 | `bridge_helper_path`/`bridge_helper_problem` + 与程序探测合并报错（`f549dfb`）；新增 3 个单测；`cargo test --lib` 133 passed |
| R48 | teardown 不得报告没有发生的关停 | PASS | 无开放项 | F53：强杀后无条件 `break`+`Ok`，`kill_if_qemu` 丢弃外部 `kill` 退出码，powerdown 失败仅 `debug!` | `TeardownStep` 纯决策 + `Unkillable` 时 `bail!` 且保留 pid、`signal_kill` 走 `libc::kill`、powerdown 失败 `warn!`（`36ab2f7`）；新增 3 个单测；`cargo test --lib` 136 passed |
| R49 | 启动失败路径不得无限挂起 | PASS | 无开放项 | F54：失败清理里 `qemu_handle.await` 无界等待，QEMU 杀不掉时 `launch` 永不返回、原始错误永不呈现 | `reap_launch_task` 有界等待 + `abort`，`signal_term` 走 `libc::kill`（`0cb5988`）；新增 2 个单测；`cargo test --lib` 138 passed |
| R50 | 已部署的 guest 不因清理失败被判失败 | PASS | 无开放项 | F55：`remove` 对目录的 `NotFound` 不宽容、调用点把「清理失败」当「部署失败」，与函数文档相反 | 两条路径都幂等 + `confirm_deployment` 只 `warn!`（`0b10e09`）；新增 1 个单测；`cargo test --lib` 139 passed |
| R51 | guest 地址只在 IPv4 里选 | PASS | 无开放项 | F56：地址选择只按 MAC 匹配，不筛地址族，双栈时被判 ambiguous、或把链路本地 IPv6 交给传输层 | 解析器与选择点双重过滤 `is_ipv4()`（`25e82c9`）；新增 3 个单测；`cargo test --lib` 142 passed |
| R52 | 探测有预算、用户命令无预算 | PASS | 无开放项 | F57：控制面探测无超时，单次探测挂住会吃掉整个部署预算，表现为「卡住」而非可诊断失败 | `bounded` + `call_probe` 只约束 Qlean 自己的探测（`bc98828`）；新增 3 个单测；`cargo test --lib` 145 passed |
| R53 | 先确认网络真的提供 qlbr0 | PASS | 无开放项 | F58：只查网络存在/active，不查桥名，存量 `qlean` 网络桥名不符时 QEMU 报错且根因不可见 | `network_bridge_name` + `existing_network_bridge` 前置校验，附可粘贴恢复命令（`23b8626`）；新增 3 个单测；`cargo test --lib` 148 passed |
| R54 | 首启窗口里换 key 是预期的 | PASS | 无开放项 | F59：R43 的 pinned-key 立即致命被套到首启阶段，一次瞬时不符就作废整个部署预算，且死因是通用错 | `pinned_key_mismatch_is_fatal` 按部署阶段分流，预算耗尽时报 `host_key_pending_message`（`714a8c4`）；新增 2 个单测；`cargo test --lib` 150 passed |
| R55 | 钥匙被拒就说被拒 | PASS | 无开放项 | F60：握手成功但公钥被拒的尝试被归入泛型失败，超时后只报「连不上」，掩盖 authorized_keys/ACL/空密码这些真实死因 | `is_auth_rejection` + `auth_rejected_message` 分级报死因（`bc7efbe`）；README 契约补 `LimitBlankPasswordUse` 陷阱；新增 2 个单测；`cargo test --lib` 152 passed |
| R56 | 一个预算管整段首启 | PASS | 无开放项 | F61：首启三段各拿满一份部署预算，实际可烧 3× 文档承诺的时长，`ssh_timeout` 形同虚设 | 共享 `first_boot_deadline` + `remaining_budget`/`spent_first_boot_budget`（`c197e81`）；README 同步；新增 2 个单测；`cargo test --lib` 154 passed |
| R57 | 非 UTF-8 镜像名各有缓存槽 | PASS | 无开放项 | F62：非 UTF-8 本地文件名统一回退 `custom-image`，不同镜像共用缓存、切换即重下 | `local_cache_stem` 对原始字节取 FNV-1a 作回退名（`c942947`）；新增 2 个单测；`cargo test --lib` 156 passed |
| R58 | 标记探测加引号、测试目录真唯一 | PASS | 无开放项 | F63：标记路径未加引号会让已完成的部署被判成未完成；测试目录的唯一后缀恒为常量，遗留文件可污染断言 | `marker_probe_command()`/`MARKER_PRESENT_TOKEN` + 引号（`6d1bbd7`）；`temp_dir` 改 `AtomicU64`；新增 3 个单测；`cargo test --lib` 159 passed |
| R59 | 闭包失败保持主因 | PASS | 无开放项 | F64：`with_machine`/`with_pool` 用 `shutdown().await?` 提前返回，收尾失败吞掉闭包的真实失败原因 | `combine_outcome` 纯函数 + 两条入口改走（`36f4d2b`）；新增 3 个单测；`cargo test --lib` 162 passed |
| R60 | 探测不依赖 guest 默认 shell | PASS | 无开放项 | F65：地址查询与文件复制裸发 PowerShell，镜像默认 shell 是 `cmd` 时报错离原因极远；原测试还误以为只能用裸命令 | `powershell_command()` 走 `-EncodedCommand`（`af4a7ba`）；4 个单测；`cargo test --lib` 165 passed |
| R61 | 僵尸进程算已退出 | PASS | 无开放项 | F66：以 `/proc/<pid>` 存在为存活判据，僵尸被当活人，收尾白等 30s 并误报 force kill | `process_state`/`process_is_gone`（含 `Z`/`X`）替代存在性判断（`9d4d59a`）；新增 2 个单测；`cargo test --lib` 167 passed |
| R62 | QMP 有预算 | PASS | 无开放项 | F67：QMP 连接/协商/执行均无超时，卡死的 QEMU 会让 `shutdown` 与调用者的测试永久挂起 | `QMP_TIMEOUT` + `with_qmp_client_within` 整体限时（`1a0c61a`）；新增 2 个单测（静默 socket 200ms 内放弃）；`cargo test --lib` 169 passed |
| R63 | 关会话也有预算 | PASS | 无开放项 | F68：`ssh.close().await` 无界，guest 不响应时收尾卡在杀 QEMU 之前 | `SSH_CLOSE_BUDGET` + `bounded_teardown`（`5c54113`）；新增 2 个单测；`cargo test --lib` 171 passed |
| R64 | 枚举失败不是空集 | PASS | 无开放项 | F69：`virsh net-list` 的退出码被忽略，libvirt 不可达被读成「网络不存在」，病因不可见；bridge 警告含空格串 | `listed_networks`/`virsh_reason`/`bridge_assumed_message`（`933563f`）；新增 3 个单测；`cargo test --lib` 174 passed |
| R65 | 声明值来自真实来源 | PASS | 无开放项 | F70：`User-Agent` 写死 `0.3.0`，crate 已是 `0.3.1`，发布后继续漂移且无门禁提醒 | `concat!("qlean/", env!("CARGO_PKG_VERSION"))`（`d6573e1`）；新增 1 个单测；`cargo test --lib` 175 passed |

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

### R6 findings 与修订对照

| ID | 问题 | 修订 |
|---|---|---|
| F1 | `Machine::Drop` 先删 run dir 再依赖字段 drop 顺序停止 `swtpm`，控制 socket 可能被先行删除 | `Drop` 内显式 `swtpm.take()` 并 `stop_now()`；`Swtpm::stop_now` 为同步停止入口，注释说明无法 await |
| F2 | 实施证据表的 `Review` 列被用于承载 Lifecycle/Acceptance，缺少 P1-13 要求的逐卡 review round/PASS | 表新增 `Lifecycle / Acceptance` 列；`Review` 列逐卡写 `R6 PASS` 与核对范围（spike 与 `REL-01` 记 N/A/blocked） |
| F3 | `GuestPath::join` 中“Windows 根回退”分支不可达（Windows 根写作 `C:`，`trim_end_matches('/')` 不会为空） | 删除该分支并注释说明只有 POSIX 根会 trim 成空串；`windows_path_*` 9 个单测保持全绿 |
| F4 | 证据表 `TRN-01` 行的提交号误写为 `64b1046`（实为 `EXE-01`） | 更正为 `6711671`（`feat(ssh): connect to Windows guests over TCP with a pinned host key`） |

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
