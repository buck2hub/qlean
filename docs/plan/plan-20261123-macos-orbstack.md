# macOS 宿主支持计划（2026-11-23）

本文解决 Qlean 在 macOS 上不能编译、也不能跑虚拟机的问题。目标是：Mac 上安装并启动 OrbStack 之后，现有的 `with_machine` / `with_pool` / `Machine` 能驱动 OrbStack 的 Linux 机器完成隔离测试。Linux 宿主继续走 QEMU/KVM，行为与 0.4.0 一致。收口版本是 **0.5.0**。

本文只规划任务，不宣称实现完成。落地时每个任务都必须先刷新源码锚点，再按任务卡验收。

**模板版本:** `v1.1`（遵循 `plan-template.md` 的结构与 `G-*`/`ER-*`/`GC-*` 条款。）

**目标分支:** `main`。实现提交直接进入 `main`，与本仓库既有的主干流程一致。

**计划状态同步义务（强制）:** 单一执行状况视图是 [`plan-status.md`](plan-status.md)。任何 Agent 推进或完成一张任务卡时，必须在同一变更中同步状态、发布版本/commit 和该卡的 UTC 更新时间。

## 文档职责

### 适用范围

- **公开 API：** `with_machine`、`with_pool`、`Machine` 的 `init` / `spawn` / `exec` / 文件操作 / `get_ip` / `shutdown` / `is_running`，以及 `MachinePool`。macOS 上这些入口不再返回「只支持 Linux」。
- **macOS 宿主依赖：** OrbStack，以及 PATH 上的 `orb`。不新增 QEMU、libvirt、OVMF、swtpm 或 bridge helper 作为 Mac 前提。
- **客户机：** OrbStack 提供的 Debian、Ubuntu、Fedora、Arch。架构是宿主原生架构，以及 Apple Silicon 上经 Rosetta 的 amd64。
- **传输：** OrbStack 自带的 localhost SSH（`127.0.0.1:32222`），russh 复用现有 TCP 客户端。Linux 宿主的 vsock 路径不改。
- **测试与发布：** macOS 上 `cargo test --lib` 进 CI；真机冒烟在装了 OrbStack 的 Mac 上跑。发布 0.5.0。

### 非目标

- **在 OrbStack 里嵌套运行现有 QEMU/KVM 栈。** OrbStack 文档 [Linux machines](https://docs.orbstack.dev/machines/) 的 Nested virtualization 写明：Apple Silicon 上目前不能做嵌套 KVM，要等 macOS 侧支持。issue [orbstack#1504](https://github.com/orbstack/orbstack/issues/1504) 至本计划成稿仍打开。这条路登记为 `DEFER-MAC-01`，本计划不实现。
- **macOS 上的原生 HVF、vmnet、libvirt 桥、vhost-vsock。** 这些是被 OrbStack 换掉的宿主前提。
- **macOS 上的 Windows 客户机。** OrbStack 不提供 Windows 机器。见 `DEFER-MAC-02`。
- **`GuestArch::Riscv64`。** OrbStack 的机器架构是 aarch64 与 amd64。见 `DEFER-MAC-03`。
- **调用方自带的 qcow2。** OrbStack 自定义镜像仍是 [orbstack#11](https://github.com/orbstack/orbstack/issues/11)。见 `DEFER-MAC-04`。
- **把 `/mnt/mac` 文件共享当作 `upload` / `download`。** 文件 API 仍走 SSH/SFTP，避免拆开 `guest_path` 的语义。
- **为 Linux 宿主的 Linux 客户机加 TCP 退路。** `src/ssh.rs` 里这条禁令继续只约束 Linux 宿主。

### 成功定义

- Mac 上 `brew install orbstack` 且 `orb` 处于运行状态后，`with_machine` 能在对应发行版里执行命令、传文件，返回后机器被停止。
- `with_pool` 的两台机器能用 `get_ip` 返回的地址互相访问，契约与 `tests/machine_pool.rs` 的 `test_ping` 相同。
- 未安装 OrbStack、OrbStack 未启动、或请求了本计划不支持的客户机时，一条错误说明缺什么、如何安装，并且不把「在 Mac 上安装 QEMU」说成解法。
- Linux 上的命令行、错误文本和测试保持 0.4.0 的行为。
- README、CHANGELOG 与 CI 同步。`MAC-06` 若证明机器之间没有 IP 路由，则本计划不得标记完成，也不得把单机能力单独发成 0.5.0。

## 事实基线

> 行号锚定在成稿时的 `main`（本计划提交之前的 `b199345`）。开工时按 ER-02 刷新。

| 类别 | 当前事实 | 证据 |
|---|---|---|
| 公开入口 | 非 Linux 的 `with_machine` / `with_pool` 直接失败 | `src/lib.rs:68-71`、`src/lib.rs:88-91`，文本 `Qlean currently only supports Linux hosts.` |
| KVM 探测 | `is_kvm_available()` 在非 Linux 返回 `false`，但 `use kvm_ioctls::Kvm` 无条件存在 | `src/lib.rs:54-61` |
| 依赖 | `kvm-ioctls`、`tokio-vsock` 在无条件 `[dependencies]` | `Cargo.toml:22`、`Cargo.toml:37` |
| Linux 传输 | SSH 只走 vsock，注释写明不为 Linux 客户机加 TCP 退路 | `src/ssh.rs:3144-3145`、`src/ssh.rs:3505` |
| 已有 TCP 客户端 | `connect_tcp` 今天只服务 Windows，并要求钉住主机公钥 | `src/ssh.rs:3129` |
| 网络 | 唯一 netdev 是 `bridge,br=qlbr0`；Windows 地址来自 `virsh net-dhcp-leases` | `src/qemu.rs:267` |
| 进程身份 | 生死和「是不是这台 QEMU」读 `/proc` | `src/machine.rs` 的 `process_is_gone`、`cmdline_is_this_machines_qemu` |
| 内置镜像 | 只有 amd64 qcow2；aarch64 / riscv64 在目录函数里拒绝 | `src/image.rs:323-363` |
| 机器 id | 12 位十六进制 nanoid | `src/machine.rs:736` |
| 池互访 | `get_ip` 之后 `ping` | `tests/machine_pool.rs:10` |
| 客户机地址 | Linux 用 `hostname -I` 的第一段 | `src/ssh.rs:3943` |
| 数据目录 | `directories::ProjectDirs` 在 macOS 上是 `~/Library/Application Support/qlean` | `src/utils.rs` 的 `QleanDirs::new` 与 `CommandExt` |
| CI | 只有 `ubuntu-latest` | `.github/workflows/check-and-test.yml` |
| 版本 | `0.4.0` | `Cargo.toml:3` |
| VCS | 本 checkout 是 Libra，`libra status` 可用 | 2026-11-23 成稿核对 |

OrbStack 文档核对日为 2026-11-23：

- 安装与无界面用法：[Command line & CI](https://docs.orbstack.dev/headless)，`brew install orbstack`。
- 创建：`orb create ubuntu:noble <name>`，资源 `--cpus`、`--memory`、`--disk`；Apple Silicon 上的 Intel 机器是 `orb create --arch amd64`。四个内置发行版的名字与 OrbStack 相同：`debian`、`ubuntu`、`fedora`、`arch`（[distros](https://docs.orbstack.dev/machines/distros)）。
- cloud-init：`orb create <distro> <name> -c user-data.yml`（[cloud-init](https://docs.orbstack.dev/machines/cloud-init)）。本计划的默认传输不依赖它。
- 执行与删除：`orb -m <name> -u root <cmd>`，`orb delete <name>`。
- SSH：`127.0.0.1:32222`，用户名形如 `root@<machine>`，私钥 `~/.orbstack/ssh/id_ed25519`，只监听 localhost，只接受公钥（[SSH access](https://docs.orbstack.dev/machines/ssh)）。
- 地址：文档示例机器 IP 为 `198.19.249.204`，域名 `<name>.orb.local`。机器之间能否用该 IP 互 ping，必须由 `MAC-00` 实测，不能只用比较表里的 “Connect between machines”。

### 当前缺口

| ID | 缺口 | 影响 | 证据 | 计划动作 |
|---|---|---|---|---|
| GAP-MAC-01 | crate 在 macOS 上因 Linux 专用依赖无法编译 | Mac 上连错误提示都到不了 | `Cargo.toml:22`、`Cargo.toml:37`，`src/lib.rs:54` | `MAC-01` |
| GAP-MAC-02 | 入口把所有非 Linux 宿主合成一句拒绝 | 用户不知道 Mac 的前提是 OrbStack | `src/lib.rs:70` | `MAC-01`、`MAC-02` |
| GAP-MAC-03 | 启动、传输、探活、镜像下载都假设 QEMU/KVM/vsock/libvirt | 有 OrbStack 也跑不起来 | `src/qemu.rs:267`、`src/ssh.rs:3505`、`src/image.rs:323` | `MAC-03` 至 `MAC-06` |
| GAP-MAC-04 | CI 不编译 Apple 目标 | macOS cfg 分叉可以在合入后才爆 | `.github/workflows/check-and-test.yml` | `MAC-07` |

## 与其它计划的关系

| 计划/文档 | 关系 | 本计划处理 |
|---|---|---|
| `plan-long.md` | 当前不存在 | `N/A` |
| `plan-template.md` | 模板 | 使用 v1.1 |
| `plan-20261104-windows-guest.md` | 已完成的 Linux 宿主 Windows 客户机计划 | 不改其行为。macOS 上的 Windows 是本计划的非目标，不复用那套 OVMF/swtpm 任务 |
| `plan-status.md` | 执行状况单一视图 | 本计划成稿时登记；每卡同步 |
| `README.md` / `CHANGELOG.md` | 用户契约 | 行为卡同卡更新；`MAC-08` 只把 Unreleased 收成 `[0.5.0]` |
| `.github/workflows/check-and-test.yml` | CI 契约 | `MAC-07` 增加 `macos-latest` 的 `cargo test --lib`，不在 CI 安装 OrbStack |

## 评审结论与修订记录

成稿自审只核对计划文本是否自洽。实现 review 不在本机进行，由另一台执行机器上的 review 接手。本表不是代码 PASS。

| 维度 | 结论 | 修订动作 |
|---|---|---|
| 合理性 | Mac 上的隔离测试值得做，而且用户已指定 OrbStack 为宿主前提 | 保留 |
| 可行性 | 嵌套 KVM 被官方文档否定，所以客户机必须是 OrbStack 机器本身 | ADR-MAC-01；`MAC-00` 只核对 CLI 与互访，不重开嵌套 KVM |
| 任务卡粒度 | 文档不单列卡；发布只在 `MAC-08` | 行为卡自带 README/CHANGELOG 条目 |
| 依赖与顺序 | 卡片都写本计划与 `plan-status.md`，且都改 `src/machine.rs` 或入口 | 全串行 |
| 完整性 | 池互访未在文档层证实 | `MAC-06` 失败则整计划不发布 |
| 安全性 | OrbStack SSH 只监听 localhost；清扫不能删用户的机器 | ADR-MAC-02、ADR-MAC-03 |
| 接口兼容 | 不新增公开类型字段，不改 Linux 语义 | 0.5.0 为 minor 功能，不是源码破坏 |
| 可靠性 | `orb create` 失败必须删掉半成品；`shutdown` 不删除，以便 `spawn` | `MAC-05` |
| 性能 | Apple Silicon 上默认 amd64 走 Rosetta | README 说明改用 `GuestArch::Aarch64`；不改默认架构 |
| 可维护性 | 名字、端口、密钥路径、发行版映射各有一处 | `src/orbstack.rs` |

### 修订历史

| 时间 | 触发 | 变更内容 | 原卡 → 新卡 | 受影响的引用 |
|---|---|---|---|---|
| 2026-11-23 15:35:53 UTC | 成稿 | 建立本计划。宿主前提定为 OrbStack 机器，不移植 QEMU。用户批准写入，review 改到另一台执行机器 | 无 → `MAC-00`…`MAC-08` | 实施顺序、依赖表、追溯表、风险表 |

## 已决议设计决策

实现时若偏离本节，必须先改计划。`MAC-00` 只允许改「命令的具体拼写和单位」，不允许改这三条决策。

### ADR-MAC-01: macOS 的客户机是 OrbStack 机器

- **Status:** Accepted
- **Context:** Darwin 没有 `/dev/kvm`、vhost-vsock 和 libvirt 桥。本机 QEMU 的 `vmnet` 需要 `com.apple.vm.networking`，Homebrew 的 QEMU 没有这份授权。把现有栈放进 OrbStack 又碰到嵌套 KVM 不可用。
- **Decision:** `target_os = macos` 时，`orb` 是唯一运行时。Linux 宿主代码不调用它。`is_kvm_available()` 在 Mac 上仍返回 `false`。
- **Alternatives considered:** 原生 HVF + SLIRP/vmnet；在 OrbStack 机器里跑 `qemu-system-* -accel kvm`。前者被本计划的范围替换，后者被 OrbStack 文档否定。
- **Consequences:** macOS 功能集小于 Linux：没有 Windows、没有 riscv64、没有自定义 qcow2。
- **Revisit when:** OrbStack 文档删除「nested KVM 不可用」，或自定义镜像落地。届时另立计划，不在本计划预埋开关。

### ADR-MAC-02: 传输用 OrbStack 自带的 localhost SSH

- **Status:** Accepted
- **Context:** 机器不必再装 sshd。文档给出固定端口、用户名语法和私钥路径。qlean 已有 russh 的 TCP 客户端。
- **Decision:** 连接 `127.0.0.1:32222`，用户 `root@qlean-<id>`，私钥 `~/.orbstack/ssh/id_ed25519`，钉住 OrbStack SSH 服务的主机公钥。exec 以 root 执行，与现在的 vsock 会话一致。
- **Alternatives considered:** 每条命令外壳执行 `orb -m … -u root`（文件 API 和 PTY 要重做）；向客户机注入 qlean 自己的 sshd（多一次 cloud-init，并改写「不依赖发行版 sshd」的边界）。
- **Consequences:** 主机密钥属于 OrbStack，不属于客户机。信任边界是「只有本机能连 32222」。不修改 `~/.orbstack/ssh/authorized_keys`。Linux 的 vsock 与 Windows 的每机钉钥都不改。
- **Revisit when:** OrbStack 改掉端口、用户名语法或密钥路径。三者都是具名常量。

### ADR-MAC-03: 只管理 `qlean-` 前缀的机器

- **Status:** Accepted
- **Decision:** 创建、停止、删除都限定 `qlean-` 加现有的 12 位机器 id。启动时的清扫只删除「前缀匹配，且对应 run 目录已经不存在」的机器。
- **Consequences:** 用户自己的 OrbStack 机器不在清扫范围内。`shutdown` 只 `orb stop`，留下机器以便 `spawn`。本进程 Drop 时停止自己创建的机器。
- **Revisit when:** 机器名规则与 nanoid 长度不再一致。

## 全局工程约束

按 `plan-template.md` 的 GC-01~GC-11 生效。本计划额外强调：

- **GC-02：** 发行版映射、机器名、`orb create` 参数、SSH 端口和密钥路径只在 `src/orbstack.rs`。禁止在 `machine.rs` 的每个方法里各写一遍 `orb` 参数。
- **GC-03：** 不给公开结构体加字段，不加公开枚举变体。macOS 是同一 API 的新宿主行为。
- **GC-07：** 不把 qlean 的 `secrets/` 私钥写进 OrbStack 的全局 `authorized_keys`。清扫名单必须先过前缀检查。
- **GC-08：** `orb create` 失败时删除已经出现的半成品机器。`shutdown` 不删除机器。

## 执行检查必备需求（强制）

按 `plan-template.md` 的 ER-01~ER-14 生效。本计划补充：

- **ER-13/14 macOS 门：** GitHub `macos-latest` 只跑 `cargo test --lib`，不安装 OrbStack，不传 `--ignored`。真机冒烟在 `DEP-MAC-01` 的 Mac 上执行测试注释里的命令。没有这台 Mac 时，`MAC-00` 与真机验收为 `blocked`，编译卡仍可做；`MAC-08` 在真机冒烟完成前不得发布。
- **VCS：** 本 checkout 使用 `libra status` / `libra add <路径>` / `libra commit` / `libra push origin main`。不得改用 git，也不得把无关文件暂存进去。

## 实施顺序

依赖边（`A -> B` 表示 A 先于 B）：

- `MAC-00 -> MAC-03 -> MAC-04 -> MAC-05 -> MAC-06 -> MAC-07 -> MAC-08`
- `MAC-01 -> MAC-02 -> MAC-03`
- `MAC-00` 与 `MAC-01` 没有代码依赖。`MAC-01` 可以在没有 Mac 时开工。`MAC-03` 及之后要等 `MAC-00` 把命令拼写写回本计划。

### 依赖登记表

| ID | direction | 类型 | 对象 | Owner | 产物与可用性判据 | 证据 | 超时与失败策略 |
|---|---|---|---|---|---|---|---|
| DEP-MAC-01 | incoming | 外部前置 | 一台已安装并启动 OrbStack 的 Mac | 计划 Owner | `orb status` 成功，且 `orb create` 能得到可执行命令的机器 | 成稿时未提供。`MAC-00` 把命令输出写回本计划后关闭 | 没有这台机器则 `MAC-00`、`MAC-06` 真机项与 `MAC-08` 为 `blocked`。不改用嵌套 QEMU 或本机 HVF 代替 |

### 发布分组与并发窗口

| ID | 成员 | 唯一发布点 | 窗口规则 | 失败回滚顺序 | 理由 |
|---|---|---|---|---|---|
| REL-MAC-01 | `MAC-01` … `MAC-07` | `MAC-08` | 子卡不单独 bump。发布点一次 minor 到 0.5.0。窗口期不插入其它发布 | 发布后按依赖逆序前滚，并发新版本 | 中间版本会在 Mac 上露出「能编译但不能跑」或「能跑单机但不能互访」的半成品 |

**并发声明:** 全串行。每张卡的实现写集都含本计划与 `plan-status.md`。

**发布者:** 计划 Owner。

**发布窗口顺序:** `MAC-08` 独自 bump、提交、推送、等待 CI。tag 与 GitHub Release 在用户要求发布时做。本计划不默认 `cargo publish`。

### Phase 0: 命令契约

**目标:** 在真机上钉死 `orb` 的参数、SSH 与互访，再写实现。

**进入条件:** `DEP-MAC-01` 可用。

**退出条件:** `MAC-00` 的结论已写回本计划。互 ping 失败时，`MAC-06` 的进入条件不成立。

### Phase 1: 能编译，并能说明前提

**目标:** macOS 目标编译通过，缺 OrbStack 时有可操作错误。

**进入条件:** 无。

**退出条件:** `MAC-01`、`MAC-02` 完成。Linux 测试仍绿。

### Phase 2: 单机生命周期与传输

**目标:** `init` / `exec` / `shutdown` / `spawn` 走 OrbStack SSH。

**进入条件:** Phase 0 与 Phase 1 完成。

**退出条件:** `MAC-03`、`MAC-04`、`MAC-05` 完成。

### Phase 3: 池、CI 与发布

**目标:** 互访契约成立，CI 编译 Mac 目标，发布 0.5.0。

**进入条件:** Phase 2 完成，且 `MAC-00` 的互 ping 为成功。

**退出条件:** `MAC-06`、`MAC-07`、`MAC-08` 完成。

## 任务卡

任务 ID 使用 `MAC-`，避免与 `plan-20261104-windows-guest.md` 里已经用过的 `OSX-` 冲突。

### 任务卡粒度规则（强制）

按 `plan-template.md` 的 G-01~G-11 生效。

#### 字段全局默认与例外

- **Release boundary 默认:** `family child of REL-MAC-01`
- **Task type 默认:** `implementation`
- **Rollback mode 默认:** `revert`
- **Security and privacy 默认:** 继承 GC-07。清扫与密钥路径见 ADR-MAC-02、ADR-MAC-03。
- **Performance budget 默认:** 继承 GC-10。`orb create` 只在 `init` 发生一次，不进入 `exec` 热路径。

**默认覆盖：**

| 任务 | 字段 | 取值与理由 |
|---|---|---|
| `MAC-00` | Task type / Release boundary / Version increment | `spike` / `no-release` / `N/A` |
| `MAC-08` | Task type / Release boundary / Version increment | `release` / `family release point of REL-MAC-01` / `minor` |

**规则 waiver（`EX-*`）：** 无。

#### 任务卡粒度审计表

| 任务 | type | axis | recovery | complete | self-contained | AC | VER | landing / prod-files | scope | deps | writeset | release | split-from | exception |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MAC-00 | spike | CLI 契约 | 删掉本计划里的实测小节 | yes | yes | 5/8 | 1/8 | 1/0 | S | DEP-MAC-01 | 序列化于后续全部卡 | no-release | N/A | N/A |
| MAC-01 | implementation | macOS 可编译 | revert | yes | yes | 4/8 | 2/8 | 3/2 | M | 无 | 序列化于 MAC-02 | family child | N/A | N/A |
| MAC-02 | implementation | 前置检查 | revert | yes | yes | 3/8 | 1/8 | 2/1 | S | MAC-01 | 序列化于 MAC-03 | family child | N/A | N/A |
| MAC-03 | implementation | create 参数 | revert | yes | yes | 4/8 | 1/8 | 3/2 | M | MAC-00, MAC-02 | 序列化于 MAC-04 | family child | N/A | N/A |
| MAC-04 | implementation | SSH 传输 | revert | yes | yes | 4/8 | 2/8 | 3/2 | M | MAC-03 | 序列化于 MAC-05 | family child | N/A | N/A |
| MAC-05 | implementation | 生命周期 | revert | yes | yes | 5/8 | 2/8 | 3/2 | M | MAC-04 | 序列化于 MAC-06 | family child | N/A | N/A |
| MAC-06 | implementation | 池地址 | revert | yes | yes | 3/8 | 2/8 | 3/2 | M | MAC-05 | 序列化于 MAC-07 | family child | N/A | N/A |
| MAC-07 | implementation | CI | revert | yes | yes | 3/8 | 1/8 | 2/1 | S | MAC-06 | 序列化于 MAC-08 | family child | N/A | N/A |
| MAC-08 | release | 0.5.0 | immutable-release | yes | yes | 4/12 | 3/12 | 3/2 | S | MAC-07 | 发布写集 | family release point | N/A | N/A |

### Task MAC-00: 核对 OrbStack 命令契约

**Task type:** spike

**Lifecycle / Acceptance:** pending /

**Description:** 不改生产代码。在 `DEP-MAC-01` 的 Mac 上把后续卡片要写死的命令测出来，写回本计划的「OrbStack 实测」小节。

**Out of scope:** 不改 `src/`。不尝试在 OrbStack 里启动 QEMU。嵌套 KVM 维持 `DEFER-MAC-01`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 文档给出 create/SSH/资源 flag，但互 ping 与探活输出格式未实测 | 本文「事实基线」的 OrbStack 文档列表 |

**Acceptance criteria:**

- [ ] `orb status`、`orb create`、`orb start`、`orb stop`、`orb delete`、`orb list` 的成功与失败形态已记录，并选定一种机器可读的探活方式。
- [ ] 以 root 连上 `127.0.0.1:32222` 的用户名、私钥路径、主机公钥文件位置已记录。
- [ ] 两台机器的 IP 已记录，A ping B 的结果是明确的成功或失败。
- [ ] `--cpus`、`--memory`、`--disk`、`--arch` 的单位，以及 Apple Silicon 上 amd64 / aarch64 的写法已记录。
- [ ] Intel Mac 能否创建 aarch64 机器已有结论；没有 Intel 机器则写成「未测，实现按拒绝处理」。

**Verification:**

- [ ] 命令原文和脱敏输出写在本计划内，不新建证据目录。

**Full-suite trigger:** N/A（no-release）

**Dependencies:** DEP-MAC-01

**Deliverables:** 本计划「OrbStack 实测」小节。

**Implementation write set:** `docs/plan/plan-20261123-macos-orbstack.md`、`docs/plan/plan-status.md`

**Release write set:** N/A

**Files likely touched:** 上述两个计划文件

**Docs and compatibility impact:** N/A（无用户文档；生产代码零改动）

**Rollback mode:** revert

**Security and privacy:** 输出不得包含私钥、主机公钥全文或家目录用户名。只记路径模式与是否匹配。

**Performance budget:** N/A

**Estimated scope:** S

**Version increment:** N/A

**Release boundary:** no-release

**C/D coverage from:** `MAC-08`

**Granularity:** `type=spike; axis=CLI 契约; recovery=删掉实测小节; complete=yes; self-contained=yes; AC=5/8; VER=1/8; landing=1; prod-files=0; scope=S; deps=DEP-MAC-01; writeset=序列化于后续全部卡; release=no-release; split-from=N/A; exception=N/A`

### Task MAC-01: 让 crate 在 macOS 上能编译

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** 把 Linux 专用依赖和引用收进 `cfg(target_os = "linux")`。macOS 上调用入口时返回「需要 OrbStack」，而不是编译失败，也不是笼统的「只支持 Linux」。

**Out of scope:** 不创建 OrbStack 机器。真实的 `orb` 探测由 `MAC-02` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `kvm-ioctls` 与 `tokio-vsock` 无条件依赖；入口在非 Linux 上 bail | `Cargo.toml:22`、`Cargo.toml:37`、`src/lib.rs:68-71` |

**Acceptance criteria:**

- [ ] `kvm-ioctls` 与 `tokio-vsock` 只出现在 Linux 目标依赖里。
- [ ] `cargo check` 在 macOS 与 Linux 上都通过。没有 Mac 时，至少 Linux 上 `cargo check` 通过，且 macOS cfg 分支能被阅读到「OrbStack」错误文本；Mac 编译证据补在 `MAC-07`。
- [ ] macOS 上 `with_machine` / `with_pool` 的错误包含 `OrbStack` 和 `brew install orbstack`，且不说在 Mac 上安装 QEMU 即可使用。
- [ ] Linux 上原有的前置失败文本不被这段 cfg 改写。

**Verification:**

- [ ] `cargo test --lib macos_host_gate`
- [ ] Linux：`cargo check`

**Full-suite trigger:** T-1: 依赖表与 `src/lib.rs` 入口是所有宿主共享的编译入口

**Dependencies:** 无

**Deliverables:** N/A

**Implementation write set:** `Cargo.toml`、`Cargo.lock`（仅工具链刷新）、`src/lib.rs`、被 `kvm_ioctls` / `tokio_vsock` 牵连而必须加 cfg 的模块、`README.md`（Host Setup 增加 macOS 节的首段）、`CHANGELOG.md`（Unreleased 一条）、本计划、`plan-status.md`

**Release write set:** N/A（family child）

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README Host Setup 增加「macOS 需要 OrbStack，不要按 Linux 章节去装 libvirt / bridge helper」；CHANGELOG Unreleased / Added 一条。Linux 调用方无迁移。

**Rollback mode:** revert

**Security and privacy:** 继承 GC-07

**Performance budget:** 继承 GC-10

**Estimated scope:** M

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=macOS 可编译; recovery=revert; complete=yes; self-contained=yes; AC=4/8; VER=2/8; landing=3; prod-files=2; scope=M; deps=none; writeset=序列化于 MAC-02; release=family child; split-from=N/A; exception=N/A`

### Task MAC-02: OrbStack 前置检查

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** 一个函数回答现在能不能用 `orb`。没找到二进制、找到了但不能执行、OrbStack 没启动，三条错误分开。

**Out of scope:** 不 `orb create`。参数拼装由 `MAC-03` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 今天没有任何 `orb` 探测 | `src/` 无 `orbstack` 模块 |

**Acceptance criteria:**

- [ ] 三条失败各有一句可操作说明：安装、修权限或 `noexec`、执行 `orb` / `orb start`。
- [ ] 检查本身不创建机器。
- [ ] 命令查找和「是否在运行」可以注入，单测不执行真的 `orb`。

**Verification:**

- [ ] `cargo test --lib orbstack_prerequisite`

**Full-suite trigger:** none

**Dependencies:** MAC-01

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/lib.rs`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** 错误文本即契约，不另加 README 节。`MAC-01` 已指向安装方式。

**Rollback mode:** revert

**Security and privacy:** 继承 GC-07

**Performance budget:** 继承 GC-10。探测有超时，不无限等待一个挂起的 `orb`。

**Estimated scope:** S

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=前置检查; recovery=revert; complete=yes; self-contained=yes; AC=3/8; VER=1/8; landing=2; prod-files=1; scope=S; deps=MAC-01; writeset=序列化于 MAC-03; release=family child; split-from=N/A; exception=N/A`

### Task MAC-03: 创建参数、架构与机器名

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** 把发行版、架构和 `MachineConfig` 收成一条 `orb create` 参数列表。机器名只由 `qlean-` 加 id 生成。非法组合在拼参数之前拒绝。macOS 上四个内置发行版不下载 qcow2。

**Out of scope:** 不建立 SSH，不调用真的 `orb`。生命周期由 `MAC-05` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 内置镜像只返回 amd64 qcow2 | `src/image.rs:323-363` |
| 机器 id 为 12 位十六进制 | `src/machine.rs:736` |

**Acceptance criteria:**

- [ ] Debian / Ubuntu / Fedora / Arch 映射到同名 distro。版本钉扎以 `MAC-00` 写回的结论为准；没有额外钉扎时用 OrbStack 的默认稳定版。
- [ ] 架构 flag 符合 `MAC-00`。riscv64、Windows、带 `source` 的镜像各自一条错误，错误里不出现「安装 KVM」。
- [ ] 停止和删除的参数构造拒绝缺少 `qlean-` 前缀或 id 不是 12 位十六进制的名字。
- [ ] 内存换算与 `MAC-00` 的单位一致，换算结果进入启动日志。

**Verification:**

- [ ] `cargo test --lib orb_create_args`

**Full-suite trigger:** T-1: `builtin_remote_image` 是镜像目录的单一事实源

**Dependencies:** MAC-00、MAC-02

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/image.rs`、`README.md`（架构表：默认 amd64 在 Apple Silicon 上走 Rosetta；不支持的三项）、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README 写明支持矩阵与拒绝项。不改 `ImageConfig` 的字段。

**Rollback mode:** revert

**Security and privacy:** 继承 ADR-MAC-03 的前缀约束。

**Performance budget:** 继承 GC-10

**Estimated scope:** M

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=create 参数; recovery=revert; complete=yes; self-contained=yes; AC=4/8; VER=1/8; landing=3; prod-files=2; scope=M; deps=MAC-00,MAC-02; writeset=序列化于 MAC-04; release=family child; split-from=N/A; exception=N/A`

### Task MAC-04: 经 localhost SSH 建立 root 会话

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** macOS 上 `Machine` 的会话走 OrbStack SSH。Linux 目标不编译这条路径，vsock 保持「没有 TCP 退路」。

**Out of scope:** 不改 Windows 的每机主机密钥。不把 qlean 私钥写入 OrbStack 的 `authorized_keys`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| TCP 连接函数已存在且要求钉钥 | `src/ssh.rs:3129` |
| Linux 连接明确拒绝缺少 vsock | `src/ssh.rs:3505-3514` |

**Acceptance criteria:**

- [ ] 连接参数是 `127.0.0.1`、`MAC-00` 确认的端口、用户名 `root@qlean-<id>`、私钥 `~/.orbstack/ssh/id_ed25519`。
- [ ] 主机公钥与钉住的值不一致时失败，错误写明这是 OrbStack 的 SSH 服务。
- [ ] 私钥文件缺失时的错误指出该路径，并说明不要改 `authorized_keys`。
- [ ] Linux 目标上原有「vsock 没有 TCP 退路」的测试仍然通过。

**Verification:**

- [ ] `cargo test --lib orb_ssh`
- [ ] Linux：`cargo test --lib connect_ssh`

**Full-suite trigger:** none

**Dependencies:** MAC-03

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/ssh.rs`（只收窄 `connect_tcp` 的注释与可见性，不改变 Linux 调用）、`README.md`（传输一小节）、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README 写明 Mac 的 SSH 走本机端口，主机密钥属于 OrbStack。Linux 传输章节保持 vsock。

**Rollback mode:** revert

**Security and privacy:** 信任边界是 localhost。日志不打印私钥。

**Performance budget:** 继承 GC-10。沿用现有 SSH 连接预算。

**Estimated scope:** M

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=SSH 传输; recovery=revert; complete=yes; self-contained=yes; AC=4/8; VER=2/8; landing=3; prod-files=2; scope=M; deps=MAC-03; writeset=序列化于 MAC-05; release=family child; split-from=N/A; exception=N/A`

### Task MAC-05: init、spawn、shutdown 与清扫

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** 把 `Machine` 的启动和停止接到 `orb create` / `orb start` / `orb stop`。启动时清扫失去 run 目录的 `qlean-` 机器。

**Out of scope:** 不实现 `get_ip`。不在 `shutdown` 时 `orb delete`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `init` 今天写 cloud-init 并启动 QEMU | `src/machine.rs` 的 Linux `init` 路径 |
| 每次 `Machine::new` 使用新的 nanoid | `src/machine.rs:736` |

**Acceptance criteria:**

- [ ] `init` 创建机器并等到 SSH 能执行一条命令。已存在的同名机器改为 `orb start`，不第二次 `create`。
- [ ] `shutdown` 停止机器且不删除，随后 `spawn` 仍连得上同一名字。
- [ ] Drop 停止本进程创建的机器。
- [ ] 清扫只会删除「`qlean-` 加 12 位十六进制，且 run 目录不存在」的名字。差一个字符的名字不会出现在删除参数里。
- [ ] `orb create` 失败时，若机器已经出现，错误路径删除它。

**Verification:**

- [ ] `cargo test --lib orb_lifecycle`（注入的执行器，不调用真 `orb`）
- [ ] 真机冒烟 `#[ignore]`，命令写在测试上：`cargo test --lib orb_lifecycle_live -- --ignored`。前提是 `DEP-MAC-01`。

**Full-suite trigger:** T-1: `Machine::init` / `shutdown` 是生命周期的单一入口

**Dependencies:** MAC-04

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/machine.rs`、`README.md`（生命周期：stop 保留、清扫范围）、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README 说明 qlean 只管理 `qlean-` 机器，用户的其它机器不会被删除。

**Rollback mode:** revert

**Security and privacy:** ADR-MAC-03。单测必须包含「前缀差一个字符不删除」。

**Performance budget:** 继承 GC-10

**Estimated scope:** M

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=生命周期; recovery=revert; complete=yes; self-contained=yes; AC=5/8; VER=2/8; landing=3; prod-files=2; scope=M; deps=MAC-04; writeset=序列化于 MAC-06; release=family child; split-from=N/A; exception=N/A`

### Task MAC-06: get_ip 与池互访

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** macOS 上 `get_ip` 返回 `MAC-00` 确认的那类 OrbStack 地址。池的契约是用这个地址互相 ping。

**Out of scope:** 若 `MAC-00` 的互 ping 失败，本卡保持 `blocked`，不改用文件共享或 localhost 端口转发冒充互访，也不进入 `MAC-08`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| Linux `get_ip` 走客户机里的 `hostname -I` 第一段 | `src/ssh.rs:3943` |
| 池测试 ping 这个返回值 | `tests/machine_pool.rs:25-30` |

**Acceptance criteria:**

- [ ] 地址来自宿主侧对这台 `qlean-` 机器的查询，不来自 `hostname -I`。
- [ ] 查不到地址时，错误带上机器名和一行脱敏的原始输出摘要。
- [ ] `MAC-00` 互 ping 失败时，本卡状态为 `blocked`，计划不标记完成。

**Verification:**

- [ ] `cargo test --lib orb_guest_ip`
- [ ] 真机：`cargo test --test machine_pool test_ping -- --ignored --test-threads=1`，仅在 `DEP-MAC-01` 且互 ping 结论为成功时执行。

**Full-suite trigger:** none

**Dependencies:** MAC-05，以及 `MAC-00` 的互 ping 结论为成功

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/machine.rs`、`README.md`（`get_ip` 在 Mac 上的地址含义）、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README 写明 Mac 上 `get_ip` 是 OrbStack 地址，不是 `192.168.221.0/24`。

**Rollback mode:** revert

**Security and privacy:** 错误摘要不得包含用户家目录。

**Performance budget:** 继承 GC-10。地址查询一次并缓存在 `Machine` 上，与现有 `get_ip` 的缓存方式相同。

**Estimated scope:** M

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=池地址; recovery=revert; complete=yes; self-contained=yes; AC=3/8; VER=2/8; landing=3; prod-files=2; scope=M; deps=MAC-05; writeset=序列化于 MAC-07; release=family child; split-from=N/A; exception=N/A`

### Task MAC-07: CI 编译 macOS 目标

**Task type:** implementation

**Lifecycle / Acceptance:** pending /

**Description:** `macos-latest` 上跑 `cargo test --lib`。CI 不安装 OrbStack。

**Out of scope:** 不在 CI 里跑 `#[ignore]` 的真机测试。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 工作流只有 `ubuntu-latest` | `.github/workflows/check-and-test.yml` |

**Acceptance criteria:**

- [ ] 新 job 与 Ubuntu job 并列。一边失败不取消另一边已开始的结论（`fail-fast: false` 覆盖含 Mac 的矩阵，或 Mac job 独立）。
- [ ] 依赖 `/proc`、libvirt、KVM 的单测在 macOS 上不编译进失败路径；Ubuntu 上仍执行。
- [ ] 真机测试保持 `#[ignore]`，CI 命令不含 `--ignored`。

**Verification:**

- [ ] 工作流中能定位 `macos-latest` 与 `cargo test --lib`。推送后的 run 记入「实施证据汇总」。

**Full-suite trigger:** T-4: 改共享 CI 工作流

**Dependencies:** MAC-06

**Deliverables:** N/A

**Implementation write set:** `.github/workflows/check-and-test.yml`、需要 cfg 的测试模块、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** N/A（CI 不改变用户可见契约；README 已在前序卡写明真机前提）

**Rollback mode:** revert

**Security and privacy:** CI 不接收 OrbStack 密钥，也不把开发者家目录写进日志。

**Performance budget:** N/A

**Estimated scope:** S

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=CI; recovery=revert; complete=yes; self-contained=yes; AC=3/8; VER=1/8; landing=2; prod-files=1; scope=S; deps=MAC-06; writeset=序列化于 MAC-08; release=family child; split-from=N/A; exception=N/A`

### Task MAC-08: 以 0.5.0 收口

**Task type:** release

**Lifecycle / Acceptance:** pending /

**Description:** 家族唯一发布点。版本从 0.4.0 升到 0.5.0。不在本卡新增行为。

**Out of scope:** 不 `cargo publish`，除非用户另要求。不在本卡修改 OrbStack 语义。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 当前版本 0.4.0 | `Cargo.toml:3` |

**Acceptance criteria:**

- [ ] `Cargo.toml` 为 `0.5.0`，CHANGELOG 有 `[0.5.0]` 段，Unreleased 中属于本计划的条目已移入该段。
- [ ] Linux：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib` 通过。
- [ ] macOS：`cargo test --lib` 通过。真机冒烟（create、exec、两机 ping、shutdown 后再 spawn、清扫不删非 `qlean-` 名字）在 `DEP-MAC-01` 上跑过并记入本计划。
- [ ] 相对 0.4.0 没有 Linux 行为变化。若发现有，先回到对应子卡，不在本卡改语义。

**Verification:**

- [ ] 上列三条命令。
- [ ] `libra push origin main` 之后，Ubuntu 与 macOS job 在该提交上全绿，run id 写入「实施证据汇总」。
- [ ] 用户要求发布时再打 `v0.5.0` 与 GitHub Release。未要求则本卡到 CI 全绿为止，tag 记为未做。

**Full-suite trigger:** T-2: 发布点

**Dependencies:** MAC-07。全部子卡 `Acceptance=complete`。`MAC-06` 不得为 `blocked`。

**Deliverables:** N/A

**Implementation write set:** `Cargo.toml`、`Cargo.lock`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** 同上

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** CHANGELOG 版本段。README 不再改行为，只核对与代码一致。

**Rollback mode:** immutable-release

**Security and privacy:** 发布说明不包含密钥和家目录。

**Performance budget:** N/A

**Estimated scope:** S

**Version increment:** minor

**Release boundary:** family release point of REL-MAC-01

**C/D coverage from:** self

**Granularity:** `type=release; axis=0.5.0; recovery=immutable-release; complete=yes; self-contained=yes; AC=4/12; VER=3/12; landing=3; prod-files=2; scope=S; deps=MAC-07; writeset=发布写集; release=family release point; split-from=N/A; exception=N/A`

## 测试矩阵

| 类别 | 必须覆盖 | Target / command |
|---|---|---|
| 单元 | 门禁文本、前置三条错误、create 参数、SSH 参数、生命周期状态机、地址解析、前缀清扫 | `cargo test --lib` |
| 真机单机 | create、root exec、shutdown 后再 spawn | `cargo test --lib orb_lifecycle_live -- --ignored`（仅 `DEP-MAC-01`） |
| 真机池 | 两机 `get_ip` 后互 ping | `cargo test --test machine_pool test_ping -- --ignored --test-threads=1` |
| Linux 回归 | 现有 lib 测试，含 vsock 无 TCP 退路 | `cargo test --lib`（Ubuntu） |
| 编译门槛 | macOS 与 Linux 都能编过单测 | CI 的 Ubuntu job 与 `macos-latest` job |

## 追溯表

| 任务 | 来源 | 代码落点 | 文档 | 测试 |
|---|---|---|---|---|
| MAC-00 | OrbStack 文档与 GAP-MAC-03 | 无 | 本计划实测小节 | 无生产测试 |
| MAC-01 | GAP-MAC-01、GAP-MAC-02 | `Cargo.toml`、`src/lib.rs` | README Host Setup 首段、CHANGELOG | `macos_host_gate` |
| MAC-02 | GAP-MAC-02 | `src/orbstack.rs` | 错误文本 | `orbstack_prerequisite` |
| MAC-03 | GAP-MAC-03、ADR-MAC-03 | `src/orbstack.rs`、`src/image.rs` | README 支持矩阵 | `orb_create_args` |
| MAC-04 | ADR-MAC-02 | `src/orbstack.rs`、`src/ssh.rs` | README 传输 | `orb_ssh` |
| MAC-05 | ADR-MAC-03 | `src/machine.rs`、`src/orbstack.rs` | README 生命周期 | `orb_lifecycle` |
| MAC-06 | `tests/machine_pool.rs` | `src/machine.rs` | README `get_ip` | `orb_guest_ip`、`test_ping` |
| MAC-07 | GAP-MAC-04 | `.github/workflows/check-and-test.yml` | N/A | CI job |
| MAC-08 | 成功定义 | `Cargo.toml`、CHANGELOG | `[0.5.0]` | 全量门 |

## 里程碑验收与回滚

| 里程碑 | 完成条件 | 发布/证据 | 回滚或前滚 |
|---|---|---|---|
| M0 | `MAC-00` 结论写回，互 ping 有明确结果 | 本计划实测小节 | 互 ping 失败则停在 M0，不发布 |
| M1 | Mac 上能编译，缺 OrbStack 有可操作错误 | `MAC-01`、`MAC-02` 的 lib 测试 | revert 这两张卡的提交 |
| M2 | 单机能 init、exec、stop、再 spawn | `MAC-05` 真机冒烟 | revert；半成品机器按失败路径删除 |
| M3 | 两机能互 ping，0.5.0 的 CI 全绿 | `MAC-08` | 已发布则前滚新版本，不改写已推送的 tag |

### 故障恢复矩阵

| 故障点 | 可接受残留 | 恢复动作 | 禁止结果 |
|---|---|---|---|
| `orb create` 失败 | 无 `qlean-` 机器 | 错误路径 `orb delete` 同名机器 | 留下半成品占用名字 |
| SSH 就绪超时 | 已创建的机器 | 停止并删除该名字，返回超时错误 | 把超时当成「机器可用」 |
| 进程被杀掉 | 运行中的 `qlean-<id>` | 下次启动按 run 目录缺失清扫；Drop 能走到则先 stop | 删除用户的非 `qlean-` 机器 |
| `shutdown` 之后 | 已停止的机器还在 | `spawn` 使用 `orb start` | `shutdown` 时 `orb delete` 导致不能 spawn |

## 风险登记

| 风险 | 影响 | 缓解 | 任务 |
|---|---|---|---|
| 机器之间不能互 ping | 池契约不成立，不能发 0.5.0 | `MAC-06` blocked 则停止发布 | `MAC-00`、`MAC-06` |
| `orb` 没有稳定的机器可读输出 | 解析随版本破碎 | `MAC-00` 选定一种；解析失败带摘要，禁止猜 IP | `MAC-00`、`MAC-06` |
| OrbStack 默认内存上限约 8 GiB | 多机测试被杀掉 | README 写 `orb config` 的内存上限；集成测试保持串行 | `MAC-06` |
| 端口、用户名或密钥路径变化 | Mac 上全部连接失败 | 三处常量；错误文本指向 OrbStack SSH 文档 | `MAC-04` |
| 清扫误删用户机器 | 数据丢失 | 只删除精确的 `qlean-` + 12 位十六进制，且 run 目录已不在 | `MAC-05` |
| 默认 amd64 在 Apple Silicon 上走 Rosetta | 首启看起来像挂死 | README 说明改用 aarch64；沿用现有 SSH 预算 | `MAC-03` |
| CI 的 macOS runner 没有 OrbStack | 真机回归不在 CI | CI 只编译；真机是 `MAC-08` 的人工门 | `MAC-07` |

## 性能与容量摘要

| 操作 | 单次成本 | 累积成本 | 预算/上限 | 验证 |
|---|---|---|---|---|
| `orb create` | 一次发行版准备，首台较慢 | 每台 `Machine` 一次，不在 `exec` 重复 | 落在现有 SSH 就绪预算内 | `MAC-05` 真机冒烟 |
| SSH `exec` | 一条 russh 命令 | 与 Linux 相同，按调用次数 | 不新增轮询 | 代码审查：地址缓存一次 |
| 清扫 | 一次 `orb list` 加按名删除 | 每次进程启动一次 | 只检查 `qlean-` 前缀 | `orb_lifecycle` 单测 |

## 兼容与文档收口

- [ ] `README.md` 的 macOS Host Setup、支持矩阵、传输和 `get_ip` 由 `MAC-01`、`MAC-03`、`MAC-04`、`MAC-05`、`MAC-06` 分别写入。
- [ ] `CHANGELOG.md` 的条目由上述行为卡写入 Unreleased，由 `MAC-08` 收成 `[0.5.0]`。
- [ ] `.github/workflows/check-and-test.yml` 由 `MAC-07` 更新。
- [ ] `tests/INDEX.md`：`N/A`，仓库中不存在该文件。
- [ ] `LICENSE` 不改。

## 实施证据汇总

成稿时无实现证据。`MAC-00` 起，命令输出与 CI run id 只写在这里。

### OrbStack 实测

待 `MAC-00` 填写。

## Review log

实现 review 按用户要求留到另一台执行机器。本机成稿不单开 review 轮次。

| Round | Scope | Result | P0/P1 | P2 处置 | Evidence |
|---|---|---|---|---|---|
| — | 成稿写入，review 未在本机执行 | 未评审 | 未开始 | 由执行机器上的 review 填写 | 2026-11-23 用户批准写入并明确推迟 review |

## 非目标与延后项

| ID | 延后内容 | 原因 | 重启条件 | 承接位置 |
|---|---|---|---|---|
| DEFER-MAC-01 | 在 OrbStack Linux 机器里运行现有 QEMU/KVM 栈 | 官方文档写明 Apple Silicon 不能嵌套 KVM | OrbStack 文档删除该限制，且 `/dev/kvm` 在机器内可用 | 新计划 |
| DEFER-MAC-02 | macOS 上的 Windows 客户机 | OrbStack 无 Windows 机器；现有 Windows 路径要 KVM | OrbStack 提供 Windows 机器，或另选已授权的 macOS 虚拟化 | 新计划 |
| DEFER-MAC-03 | macOS 上的 riscv64 客户机 | OrbStack 机器架构只有 aarch64 与 amd64 | OrbStack 能创建 riscv64 机器 | 新计划 |
| DEFER-MAC-04 | macOS 上使用调用方的 qcow2 | 自定义镜像是 orbstack#11，尚未提供 | 该 issue 关闭且 `orb create` 能吃 qcow2 | 新计划 |

## 完成判据

- [ ] 任务卡满足 `G-*`，粒度审计表已填，无未登记的 L 例外。
- [ ] `MAC-00` 至 `MAC-08` 的 `Lifecycle=done` 且 `Acceptance=complete`。`MAC-06` 若 `blocked`，本计划不得完成。
- [ ] 各卡 Verification 已跑并记入「实施证据汇总」。真机命令注明 `DEP-MAC-01`。
- [ ] 收口门：Linux 上 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib`；macOS 上 `cargo test --lib`；真机冒烟通过。
- [ ] README、CHANGELOG、CI 已按追溯表更新。
- [ ] 实现 review 在执行机器上的最终轮次为 PASS，P0/P1 关闭。本机写入不代替那次 review。
- [ ] `MAC-08` 已把版本定为 0.5.0，锁文件只由工具链刷新。tag 与 GitHub Release 仅在用户要求时执行。
- [ ] 「修订历史」记录成稿后的规范性变更。
- [ ] `plan-status.md` 与任务卡一致。
- [ ] 未新建证据目录。
