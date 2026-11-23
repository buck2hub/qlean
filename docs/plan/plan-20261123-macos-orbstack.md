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
- **测试与发布：** macOS 的编译与 `cargo test --lib` 在开发者的 Mac 上跑（本计划的执行机已安装 OrbStack 2.2.5）。GitHub Actions 保持只有 `ubuntu-latest`，不增加 macOS 测试、macOS job 或 `macos-latest`。真机冒烟在这台 Mac 上显式跑 `#[ignore]` 用例。发布 0.5.0。提交和推送不等待 Actions 变绿。

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
- README 与 CHANGELOG 同步。CI 保持 Ubuntu-only，不新增 macOS job。`MAC-06` 若证明机器之间没有 IP 路由，则本计划不得标记完成，也不得把单机能力单独发成 0.5.0。`MAC-01` 至 `MAC-05` 在互 ping 失败时仍可做完；`MAC-06` 保持 `blocked`，版本留在 0.4.0。

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
| GAP-MAC-04 | 没有 Mac 上的编译证据时，macOS cfg 分叉可以在合入后才爆 | 本地 Mac 门是 `cargo test --lib`；CI 不为此增加 runner | `.github/workflows/check-and-test.yml` 今天只有 `ubuntu-latest` | `MAC-01` 在本机编译；`MAC-07` 核对工作流仍无 `macos-latest` |

## 与其它计划的关系

| 计划/文档 | 关系 | 本计划处理 |
|---|---|---|
| `plan-long.md` | 当前不存在 | `N/A` |
| `plan-template.md` | 模板 | 使用 v1.1 |
| `plan-20261104-windows-guest.md` | 已完成的 Linux 宿主 Windows 客户机计划 | 不改其行为。macOS 上的 Windows 是本计划的非目标，不复用那套 OVMF/swtpm 任务 |
| `plan-status.md` | 执行状况单一视图 | 本计划成稿时登记；每卡同步 |
| `README.md` / `CHANGELOG.md` | 用户契约 | 行为卡同卡更新；`MAC-08` 只把 Unreleased 收成 `[0.5.0]` |
| `.github/workflows/check-and-test.yml` | CI 契约 | `MAC-07` 核对它继续只有 `ubuntu-latest`。禁止添加 macOS 测试、macOS job 或 `macos-latest` |

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
| 2026-11-23 17:10:19 UTC | 实现 review IMP-R3 = PASS | 记录 Codex 实现 review。R1/R2 的 P1 已关闭。IMP-R2-P2-01 由计划 Owner 接受为残余：清扫的 list/delete 失败不另报，且每个进程只清扫一次。`MAC-00` 至 `MAC-08` 改为 done / complete。版本 0.5.0。不打 tag | `MAC-00`..`MAC-07` locally-accepted → complete；`MAC-08` pending → done / complete | Review log、`Cargo.toml`、CHANGELOG、`plan-status.md` |
| 2026-11-23 16:38:23 UTC | `MAC-07` | 核对 CI 仍只有 ubuntu-latest，不新增 macOS 测试 | `MAC-07` pending → done / locally-accepted | `.github/workflows/check-and-test.yml`（未改）、实施证据汇总 |
| 2026-11-23 16:37:42 UTC | `MAC-06` | macOS `get_ip` 使用 `orb info` 的 `ip4`。两机 `test_ping` 两次通过 | `MAC-06` pending → done / locally-accepted | `src/orbstack.rs`、`src/machine.rs`、`tests/machine_pool.rs`、README、CHANGELOG |
| 2026-11-23 16:34:00 UTC | `MAC-03` `MAC-04` `MAC-05` | macOS 用注入的执行器拼 `orb create`、走 localhost SSH、并完成 stop 不删除的生命周期。真机冒烟两次通过 | 三张卡 pending → done / locally-accepted | `src/orbstack.rs`、`src/machine.rs`、`src/ssh.rs`、`src/image.rs`、README、CHANGELOG |
| 2026-11-23 16:18:04 UTC | `MAC-02` | 三条 OrbStack 前置错误可注入，检查不创建机器。README 与 CHANGELOG 写了安装、权限和未启动 | `MAC-02` pending → done / locally-accepted | `src/orbstack.rs`、`src/lib.rs`、README、CHANGELOG |
| 2026-11-23 16:15:19 UTC | `MAC-01` | macOS 能编译。`kvm-ioctls` 与 `tokio-vsock` 收到 Linux target 依赖。宿主门说明 OrbStack，不把安装 QEMU 当成解法。7 个依赖 `/proc` 的既有单测改为 `cfg(target_os = "linux")` | `MAC-01` pending → done / locally-accepted | `Cargo.toml`、`src/lib.rs`、`src/ssh.rs`、README、CHANGELOG |
| 2026-11-23 16:07:52 UTC | `MAC-00` 实测 | 写回「OrbStack 实测」。互 ping 成功。创建参数带 `--isolated`。地址字段是 `orb info -f json` 的 `ip4`。无参数 `orb stop` 禁止 | `MAC-00` pending → done / locally-accepted | ADR-MAC-04、实施证据汇总、`plan-status.md` |
| 2026-11-23 16:02:36 UTC | Codex 计划 review R2 = PASS | 记录 R2。P2-R2-01 接受为残余：`MAC-01` 的 Linux `cargo check` 不是本机门 | 无 | Review log |
| 2026-11-23 15:55:15 UTC | Codex 计划 review R1 = FAIL（P0-01..P0-04，P1-01..P1-08） | 绑定约束：GitHub Actions 不得增加 macOS 测试或 `macos-latest`。`MAC-07` 改为核对 CI 仍只有 Ubuntu。补 ADR-MAC-04、动态 SSH 用户名、失败清理的新旧机器区分、`is_running` 与文件传输归属、`test_ping` 的 macOS ignore、ER-14 的本机回退与 `DEFER-MAC-05`、`MAC-02` 同卡文档、粒度计数。P2 三条已写入正文（崩溃后 run 目录还在则不扩大清扫；互 ping 失败不挡住 `MAC-01`..`MAC-05`；Review log 的 Result 只用 PASS/FAIL） | 无拆卡。`MAC-07` 改轴，编号保留 | 适用范围、GAP-MAC-04、关系表、ER-13/14、Phase 3、任务卡、测试矩阵、追溯表、风险表、完成判据、`plan-status.md` |
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

### ADR-MAC-04: OrbStack 机器不是 QEMU 等价隔离

- **Status:** Accepted。`MAC-00` 在 OrbStack 2.2.5 上已选定：`orb create` 带 `--isolated`，不带 `--isolate-network`，不带 `--forward-ssh-agent`。该组合下两台机器用 `ip4` 互 ping 成功。
- **Context:** 普通 OrbStack 机器共享内核，并默认带宿主文件共享与集成。文档 [Isolated machines](https://docs.orbstack.dev/machines/isolated) 给出 `--isolated`（关掉文件共享与集成）、`--isolate-network`（并切断到其它机器和宿主 IP 的网络）和 `--forward-ssh-agent`。不用 `/mnt/mac` 做 `upload` / `download` 并不会关掉这些集成。池契约要求两台机器能用 `get_ip` 互 ping，因此不能用切断机器间网络的开关换隔离。
- **Decision:**
  - 创建参数永不包含 `--isolate-network`，也永不包含 `--forward-ssh-agent`。
  - `MAC-00` 已证明「`--isolated` 且不带 `--isolate-network`」的两台机器能互 ping。`orb create` 带 `--isolated`。
  - 若以后的 OrbStack 让这个组合不能互 ping，再改计划。在那之前不退回非隔离机器。文件 API 仍只走 SSH/SFTP。实测里隔离机器没有 `/mnt/mac` 目录，SSH agent 也没有转发。
  - 两种结果都不声称与 QEMU/KVM 等价的隔离。README 写明这些机器共享 OrbStack 的内核。支持的工作负载就是现有公开 API：在机器里执行命令，并用 SFTP 传文件。这是 GC-07 下收窄后的边界，不是把宿主目录挂进客户机。
- **Alternatives considered:** 总是 `--isolated --isolate-network`（池契约不成立，不能发 0.5.0）；把文件共享当成 `upload` / `download`（拆开 `guest_path`，本计划的非目标）。
- **Consequences:** `MAC-03` 的参数测试必须断言没有 `--isolate-network` 和 `--forward-ssh-agent`，并断言 `--isolated` 与 `MAC-00` 的结论一致。
- **Revisit when:** OrbStack 提供与 QEMU 相当的虚拟化隔离，或池不再要求机器间 IP 互通。另立计划。

## 全局工程约束

按 `plan-template.md` 的 GC-01~GC-11 生效。本计划额外强调：

- **GC-02：** 发行版映射、机器名、`orb create` 参数、SSH 端口和密钥路径只在 `src/orbstack.rs`。禁止在 `machine.rs` 的每个方法里各写一遍 `orb` 参数。
- **GC-03：** 不给公开结构体加字段，不加公开枚举变体。macOS 是同一 API 的新宿主行为。
- **GC-07：** 不把 qlean 的 `secrets/` 私钥写进 OrbStack 的全局 `authorized_keys`。清扫名单必须先过前缀检查。
- **GC-08：** `orb create` 失败时删除已经出现的半成品机器。`shutdown` 不删除机器。

## 执行检查必备需求（强制）

按 `plan-template.md` 的 ER-01~ER-14 生效。本计划补充：

- **ER-13/14 本计划的门：** GitHub Actions 不增加 macOS 测试、macOS job 或 `macos-latest`。现有 Ubuntu job（format、clippy、`cargo test --lib`、`cargo test --test windows_machine`、`cargo test --no-run`）保持不变，只作为推送之后的事后证据。提交和推送不等待 Actions 变绿。macOS 编译与单测的门是这台 Mac 上的 `cargo test --lib`。真机冒烟在 `DEP-MAC-01` 上执行测试注释里的命令，命令必须带 `--ignored`，证据必须显示用例名被执行而不是 0 tests。本执行机不是配齐的 Linux VM 宿主机，因此 ER-14 的全量 `cargo test`（含 `tests/**` 的 KVM 集成）登记为 `DEFER-MAC-05`；收口至少跑 `cargo test --lib` 与 `cargo test --no-run`。没有这台 Mac 时，`MAC-00` 与真机验收为 `blocked`；`MAC-08` 在真机冒烟完成前不得发布。互 ping 失败时同样不得发布，见成功定义。
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

**发布窗口顺序:** `MAC-08` 独自 bump、提交、推送。推送前的门是本机 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib`、`cargo test --no-run`。不等待 GitHub Actions。Ubuntu CI 若随后出现，只记为事后证据，不作为完成条件，也不因此添加 macOS job。tag 与 GitHub Release 在用户要求发布时做。本计划不默认 `cargo publish`。

### Phase 0: 命令契约

**目标:** 在真机上钉死 `orb` 的参数、SSH 与互访，再写实现。

**进入条件:** `DEP-MAC-01` 可用。

**退出条件:** `MAC-00` 的结论已写回本计划。互 ping 失败时，`MAC-06` 的进入条件不成立。`MAC-01` 至 `MAC-05` 不因此停工。停的是 `MAC-06`、0.5.0 和本计划的完成标记。

### Phase 1: 能编译，并能说明前提

**目标:** macOS 目标编译通过，缺 OrbStack 时有可操作错误。

**进入条件:** 无。

**退出条件:** `MAC-01`、`MAC-02` 完成。Linux 测试仍绿。

### Phase 2: 单机生命周期与传输

**目标:** `init` / `exec` / `shutdown` / `spawn` 走 OrbStack SSH。

**进入条件:** Phase 0 与 Phase 1 完成。

**退出条件:** `MAC-03`、`MAC-04`、`MAC-05` 完成。

### Phase 3: 池、CI 与发布

**目标:** 互访契约成立，本机 Mac 门通过，CI 仍只有 Ubuntu，发布 0.5.0。

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

**规则 waiver（`EX-*`）：**

| ID | 任务 | 豁免项 | 理由与补偿 | 审批人 | 轮次 | 位置 | 范围 |
|---|---|---|---|---|---|---|---|
| EX-MAC-01 | `MAC-00` | G-03 条目上限 | 一次真机测量要分别记下六条命令的成败、SSH、互 ping、架构单位、隔离开关。拆成两张 spike 会把同一次机器会话拆开。补偿：每条 AC 仍是独立 pass/fail，全部写进「OrbStack 实测」 | 计划 Owner | R1 复审 | `MAC-00` Acceptance criteria | 本计划内 |

#### 任务卡粒度审计表

| 任务 | type | axis | recovery | complete | self-contained | AC | VER | landing / prod-files | scope | deps | writeset | release | split-from | exception |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MAC-00 | spike | CLI 契约 | 删掉本计划里的实测小节 | yes | yes | 10/8@EX-MAC-01 | 1/8 | 1/0 | S | DEP-MAC-01 | 序列化于后续全部卡 | no-release | N/A | EX-MAC-01 |
| MAC-01 | implementation | macOS 可编译 | revert | yes | yes | 5/8 | 2/8 | 3/2 | M | 无 | 序列化于 MAC-02 | family child | N/A | N/A |
| MAC-02 | implementation | 前置检查 | revert | yes | yes | 4/8 | 1/8 | 2/1 | S | MAC-01 | 序列化于 MAC-03 | family child | N/A | N/A |
| MAC-03 | implementation | create 参数 | revert | yes | yes | 5/8 | 1/8 | 3/2 | M | MAC-00, MAC-02 | 序列化于 MAC-04 | family child | N/A | N/A |
| MAC-04 | implementation | SSH 传输 | revert | yes | yes | 4/8 | 2/8 | 3/2 | M | MAC-03 | 序列化于 MAC-05 | family child | N/A | N/A |
| MAC-05 | implementation | 生命周期 | revert | yes | yes | 6/8 | 3/8 | 4/3 | M | MAC-04 | 序列化于 MAC-06 | family child | N/A | N/A |
| MAC-06 | implementation | 池地址 | revert | yes | yes | 4/8 | 2/8 | 3/3 | M | MAC-05 | 序列化于 MAC-07 | family child | N/A | N/A |
| MAC-07 | implementation | CI 仍为 Ubuntu | revert | yes | yes | 3/8 | 1/8 | 1/0 | S | MAC-06 | 序列化于 MAC-08 | family child | N/A | N/A |
| MAC-08 | release | 0.5.0 | immutable-release | yes | yes | 5/12 | 3/12 | 3/3 | M | MAC-07 | 发布写集 | family release point | N/A | N/A |

### Task MAC-00: 核对 OrbStack 命令契约

**Task type:** spike

**Lifecycle / Acceptance:** done / complete

**Description:** 不改生产代码。在 `DEP-MAC-01` 的 Mac 上把后续卡片要写死的命令测出来，写回本计划的「OrbStack 实测」小节。

**Out of scope:** 不改 `src/`。不尝试在 OrbStack 里启动 QEMU。嵌套 KVM 维持 `DEFER-MAC-01`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 文档给出 create/SSH/资源 flag，但互 ping 与探活输出格式未实测 | 本文「事实基线」的 OrbStack 文档列表 |

**Acceptance criteria:**

- [x] `orb status` 的成功与失败形态已记录。
- [x] `orb create` 的成功与失败形态已记录，包括半创建时列表里是否出现该名字。
- [x] `orb start <name>` 的成功与失败形态已记录。
- [x] `orb stop <name>` 的成功与失败形态已记录，并且写明无参数的 `orb stop` 会停掉整个 OrbStack，实现不得使用无参数形式。
- [x] `orb delete <name>` 的成功与失败形态已记录。删除前若需要确认，记录非交互写法。
- [x] `orb list` 的机器可读形式已选定（`orb list -f json` 或 `orb info <name> -f json`），字段名写进本计划，作为探活与地址解析的唯一来源。
- [x] SSH 已记录：端口、用户名形态 `root@<machine>`、私钥路径、`known_hosts` 中 `[127.0.0.1]:<port>` 的键类型。不记录私钥、主机公钥全文或家目录用户名。
- [x] 两台机器的 IP 已记录，A ping B 的结果是明确的成功或失败。
- [x] `--cpus`、`--memory`、`--disk`、`--arch` 的单位，以及 Apple Silicon 上 `amd64` / `arm64` 的写法已记录。没有 Intel Mac，aarch64 客户机在 Intel 宿主上的结论写成「未测，实现按拒绝处理」。`GuestArch::Aarch64` 对应的 flag 值以实测为准，不把 `aarch64` 这个枚举名直接当成 `--arch` 的参数。
- [x] OrbStack 2.2.5 上 `--isolated`、`--isolate-network`、`--forward-ssh-agent` 是否存在已记录。`--isolated` 且不带 `--isolate-network` 时，两台机器能否互 ping 已有成功或失败。结论写回 ADR-MAC-04 的二选一。默认是否转发 SSH agent 已记录。

**Granularity 计数:** `AC=10/8@EX-MAC-01`。见规则 waiver。

**Verification:**

- [x] 命令原文和脱敏输出写在本计划内，不新建证据目录。

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

**Granularity:** `type=spike; axis=CLI 契约; recovery=删掉实测小节; complete=yes; self-contained=yes; AC=10/8@EX-MAC-01; VER=1/8; landing=1; prod-files=0; scope=S; deps=DEP-MAC-01; writeset=序列化于后续全部卡; release=no-release; split-from=N/A; exception=EX-MAC-01`

### Task MAC-01: 让 crate 在 macOS 上能编译

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** 把 Linux 专用依赖和引用收进 `cfg(target_os = "linux")`。macOS 上调用入口时返回「需要 OrbStack」，而不是编译失败，也不是笼统的「只支持 Linux」。

**Out of scope:** 不创建 OrbStack 机器。真实的 `orb` 探测由 `MAC-02` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `kvm-ioctls` 与 `tokio-vsock` 无条件依赖；入口在非 Linux 上 bail | `Cargo.toml:22`、`Cargo.toml:37`、`src/lib.rs:68-71` |

**Acceptance criteria:**

- [x] `kvm-ioctls` 与 `tokio-vsock` 只出现在 Linux 目标依赖里。
- [x] 本机 macOS 上 `cargo check` 通过。Linux 交叉编译不是本机的门；Linux cfg 路径不改写原有前置失败文本，Ubuntu CI 事后仍编译它们。
- [x] macOS 上宿主门的错误包含 `OrbStack` 和 `brew install orbstack`，且不说在 Mac 上安装 QEMU 即可使用。`with_machine` / `with_pool` 在 OrbStack 不可用时走这句，而不是「只支持 Linux」。
- [x] Linux 上原有的前置失败文本不被这段 cfg 改写。
- [x] 依赖 `/proc`、libvirt 或 KVM 才能成立的既有 `cargo test --lib` 用例用 `cfg(target_os = "linux")` 留在 Linux 上执行。macOS 上 `cargo test --lib` 不因缺少这些设施而失败。这些用例的源码仍在，不删测试。

**Verification:**

- [x] `cargo test --lib macos_host_gate`
- [ ] Linux：`cargo check`（不是本机门。归 `DEFER-MAC-05` 与 Ubuntu CI 事后证据。计划 Owner 在 R2 接受了这条残余。）

**Full-suite trigger:** T-1: 依赖表与 `src/lib.rs` 入口是所有宿主共享的编译入口

**Dependencies:** 无

**Deliverables:** N/A

**Implementation write set:** `Cargo.toml`、`Cargo.lock`（仅工具链刷新）、`src/lib.rs`、被 `kvm_ioctls` / `tokio_vsock` 牵连而必须加 cfg 的模块、依赖 `/proc` 或 KVM 或 libvirt 才能在 macOS 上通过的既有 `#[cfg(test)]` 模块（只加 `cfg(target_os = "linux")`，不删用例）、`README.md`（Host Setup 增加 macOS 节的首段）、`CHANGELOG.md`（Unreleased 一条）、本计划、`plan-status.md`

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

**Granularity:** `type=implementation; axis=macOS 可编译; recovery=revert; complete=yes; self-contained=yes; AC=5/8; VER=2/8; landing=3; prod-files=2; scope=M; deps=none; writeset=序列化于 MAC-02; release=family child; split-from=N/A; exception=N/A`

### Task MAC-02: OrbStack 前置检查

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** 一个函数回答现在能不能用 `orb`。没找到二进制、找到了但不能执行、OrbStack 没启动，三条错误分开。

**Out of scope:** 不 `orb create`。参数拼装由 `MAC-03` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 今天没有任何 `orb` 探测 | `src/` 无 `orbstack` 模块 |

**Acceptance criteria:**

- [x] 三条失败各有一句可操作说明：安装（含 `brew install orbstack`）、修权限或 `noexec`、执行 `orb` / 启动 OrbStack。三条都不把「在 Mac 上安装 QEMU」说成解法。
- [x] 检查本身不创建机器。
- [x] 命令查找和「是否在运行」可以注入，单测不执行真的 `orb`。
- [x] README 与 CHANGELOG 写明这三条失败和对应处置。安装句与 `MAC-01` 的 Host Setup 一致，不另起一套安装说明。

**Verification:**

- [x] `cargo test --lib orbstack_prerequisite`

**Full-suite trigger:** none

**Dependencies:** MAC-01

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/lib.rs`、`README.md`、`CHANGELOG.md`、本计划、`plan-status.md`

**Release write set:** N/A

**Files likely touched:** 见实现写集

**Docs and compatibility impact:** README Host Setup 的 macOS 节写明三条失败（没有二进制、有二进制但不能执行、OrbStack 没启动）。CHANGELOG Unreleased 各记一条。不把安装 QEMU 写成 Mac 的解法。

**Rollback mode:** revert

**Security and privacy:** 继承 GC-07

**Performance budget:** 继承 GC-10。探测有超时，不无限等待一个挂起的 `orb`。

**Estimated scope:** S

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=前置检查; recovery=revert; complete=yes; self-contained=yes; AC=4/8; VER=1/8; landing=2; prod-files=1; scope=S; deps=MAC-01; writeset=序列化于 MAC-03; release=family child; split-from=N/A; exception=N/A`

### Task MAC-03: 创建参数、架构与机器名

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** 把发行版、架构和 `MachineConfig` 收成一条 `orb create` 参数列表。机器名只由 `qlean-` 加 id 生成。非法组合在拼参数之前拒绝。macOS 上四个内置发行版不下载 qcow2。

**Out of scope:** 不建立 SSH，不调用真的 `orb`。生命周期由 `MAC-05` 承接。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 内置镜像只返回 amd64 qcow2 | `src/image.rs:323-363` |
| 机器 id 为 12 位十六进制 | `src/machine.rs:736` |

**Acceptance criteria:**

- [x] Debian / Ubuntu / Fedora / Arch 映射到同名 distro。版本钉扎以 `MAC-00` 写回的结论为准；没有额外钉扎时用 OrbStack 的默认稳定版。
- [x] 架构 flag 符合 `MAC-00`。riscv64、Windows、带 `source` 的镜像各自一条错误，错误里不出现「安装 KVM」。
- [x] 停止和删除的参数构造拒绝缺少 `qlean-` 前缀或 id 不是 12 位十六进制的名字。
- [x] 内存换算与 `MAC-00` 的单位一致，换算结果进入启动日志。
- [x] 创建参数遵守 ADR-MAC-04：永不包含 `--isolate-network` 与 `--forward-ssh-agent`；`--isolated` 是否出现与 `MAC-00` 的互 ping 结论一致。单测覆盖这两种拼法中 `MAC-00` 选定的那一种，并断言另外两个 flag 不出现。

**Verification:**

- [x] `cargo test --lib orb_create_args`

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

**Granularity:** `type=implementation; axis=create 参数; recovery=revert; complete=yes; self-contained=yes; AC=5/8; VER=1/8; landing=3; prod-files=2; scope=M; deps=MAC-00,MAC-02; writeset=序列化于 MAC-04; release=family child; split-from=N/A; exception=N/A`

### Task MAC-04: 经 localhost SSH 建立 root 会话

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** macOS 上 `Machine` 的会话走 OrbStack SSH。用户名是运行时的 `root@qlean-<id>`，不是 `'static` 的 Windows 或 Linux 用户名。`ConnectTarget` 要能携带这个动态用户名；Linux 的 `linux_connect_target` / `vsock_connect_params` 与 Windows 的钉钥参数保持原样。Linux 目标不编译 OrbStack 路径，vsock 保持「没有 TCP 退路」。

**Out of scope:** 不改 Windows 的每机主机密钥。不把 qlean 私钥写入 OrbStack 的 `authorized_keys`。不把 Linux 客户机改成 TCP。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| TCP 连接函数已存在且要求钉钥 | `src/ssh.rs:3129` |
| Linux 连接明确拒绝缺少 vsock | `src/ssh.rs:3505-3514` |

**Acceptance criteria:**

- [x] 连接参数是 `127.0.0.1`、`MAC-00` 确认的端口、用户名 `root@qlean-<id>`、私钥 `~/.orbstack/ssh/id_ed25519`。
- [x] 主机公钥与钉住的值不一致时失败，错误写明这是 OrbStack 的 SSH 服务。
- [x] 私钥文件缺失时的错误指出该路径，并说明不要改 `authorized_keys`。
- [x] Linux 目标上原有「vsock 没有 TCP 退路」的测试仍然通过。

**Verification:**

- [x] `cargo test --lib orb_ssh`。输出必须出现 `orb_ssh` 且不是 `0 tests`。覆盖用户名 `root@qlean-` + 12 位十六进制、主机 `127.0.0.1`、`MAC-00` 的端口、私钥路径，以及主机公钥不一致时的失败（错误写明这是 OrbStack 的 SSH 服务）。
- [x] `cargo test --lib connect_target_tests` 与新增的 `linux_guest_has_no_tcp_fallback`。后者断言 `connect_ssh` 在缺少 `/dev/vhost-vsock` 时的失败文本含 `no TCP fallback`，且该函数不调用 `connect_tcp`。证据必须显示这两个名字被执行。本机是 macOS，这条 Linux 断言用源码守卫实现，不要求本机有 vsock。

**Full-suite trigger:** none

**Dependencies:** MAC-03

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/ssh.rs`（允许内部连接参数携带动态用户名 `root@qlean-<id>`，并让 OrbStack 会话复用现有 TCP 钉钥客户端；不改变 `linux_connect_target`、`vsock_connect_params` 与 Windows 钉钥）、`README.md`（传输一小节）、`CHANGELOG.md`、本计划、`plan-status.md`

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

**Lifecycle / Acceptance:** done / complete

**Description:** 把 `Machine` 的构造、启动、探活和停止接到 OrbStack。macOS 上 `Machine::new` 不调用 `qemu-img`、libvirt 或 KVM 门槛。`init` / `spawn` / `shutdown` / `Drop` 使用 `orb create` / `orb start` / `orb stop <name>`。`is_running` 区分在跑、已停止和探活失败。`upload` / `download` 走这条 SSH/SFTP 会话，不走 `/mnt/mac`。启动时清扫失去 run 目录的 `qlean-` 机器。

**Out of scope:** 不实现 `get_ip`。不在 `shutdown` 时 `orb delete`。不扩大清扫到「进程崩溃但 run 目录还在」的机器，见风险表。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `init` 今天写 cloud-init 并启动 QEMU | `src/machine.rs` 的 Linux `init` 路径 |
| 每次 `Machine::new` 使用新的 nanoid | `src/machine.rs:736` |

**Acceptance criteria:**

- [x] macOS 上 `Machine::new` 不调用 `qemu-img`、libvirt 或 KVM 门槛。`init` 创建机器并等到 SSH 能执行一条命令。已存在的同名机器改为 `orb start`，不第二次 `create`。公开的 `Machine` / `MachineConfig` 签名与字段不改。
- [x] `shutdown` 只 `orb stop <name>`，不删除。随后 `spawn` 对同一名字执行 `orb start`。Drop 停止本进程创建的机器，同样不删除。
- [x] `is_running`：OrbStack 报告在跑则为 `Ok(true)`，报告已停止则为 `Ok(false)`，探活命令失败则是带机器名的 `Err`。池用这个结果决定启停，不把「已停止」当成错误，也不把「问失败」当成没在跑。
- [x] 清扫只会删除「`qlean-` 加 12 位十六进制，且 run 目录不存在」的名字。差一个字符的名字不会出现在删除参数里。
- [x] 只有这次尝试新创建的机器才会在失败时被 `orb delete`：`orb create` 失败后若名字已经出现，或新机器的 SSH 就绪超时。删除失败必须和原错误一起返回，不得吞掉。已经存在的机器若 `orb start` 或 SSH 就绪失败，只停止它，不删除。
- [x] `upload` 与 `download` 使用 OrbStack SSH/SFTP 会话。参数与实现都不把 `/mnt/mac` 当作文件 API。

**Verification:**

- [x] `cargo test --lib orb_lifecycle`（注入的执行器，不调用真 `orb`）。必须覆盖：只 create 一次、shutdown 的参数是 stop 不是 delete、差一个字符的名字不删除、新机器失败会 delete、已存在机器失败不 delete、清理失败被返回、`is_running` 的三种答案。
- [x] 真机冒烟 `#[ignore]`，命令写在测试上：`cargo test --lib orb_lifecycle_live -- --ignored`。前提是 `DEP-MAC-01`。证据必须出现该测试名并且不是 0 tests。覆盖 create、root exec、upload/download 往返、shutdown 后再 spawn。两次都是 1 passed / 0 failed（54.68s 与 54.12s）。
- [x] 池的停止再启动：`tests/machine_pool.rs` 的 `test_concurrency` 在 macOS 上改为 `#[ignore]`（Linux 上仍是普通测试，本卡拥有这个注解）。真机命令 `cargo test --test machine_pool test_concurrency -- --ignored --test-threads=1`，仅在 `DEP-MAC-01` 上执行。证据必须显示 `test_concurrency` 被执行。互 ping 失败不取消这条冒烟，也不许用文件共享代替它；互 ping 失败仍按成功定义挡住 `MAC-06` 与 0.5.0。本机结果：1 passed / 0 failed，80.50s。测完删除了这四台 `qlean-` 机器。

**Full-suite trigger:** T-1: `Machine::init` / `shutdown` 是生命周期的单一入口

**Dependencies:** MAC-04

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/machine.rs`、`tests/machine_pool.rs`（仅为 `test_concurrency` 增加 macOS `ignore`）、`README.md`（生命周期：stop 保留、清扫范围、`is_running` 三分、文件 API 不走 `/mnt/mac`）、`CHANGELOG.md`、本计划、`plan-status.md`

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

**Granularity:** `type=implementation; axis=生命周期; recovery=revert; complete=yes; self-contained=yes; AC=6/8; VER=3/8; landing=4; prod-files=3; scope=M; deps=MAC-04; writeset=序列化于 MAC-06; release=family child; split-from=N/A; exception=N/A`

### Task MAC-06: get_ip 与池互访

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** macOS 上 `get_ip` 返回 `MAC-00` 确认的那类 OrbStack 地址。池的契约是用这个地址互相 ping。

**Out of scope:** 若 `MAC-00` 的互 ping 失败，本卡保持 `blocked`，不改用文件共享或 localhost 端口转发冒充互访，也不进入 `MAC-08`。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| Linux `get_ip` 走客户机里的 `hostname -I` 第一段 | `src/ssh.rs:3943` |
| 池测试 ping 这个返回值 | `tests/machine_pool.rs:25-30` |

**Acceptance criteria:**

- [x] 地址来自宿主侧对这台 `qlean-` 机器的查询（`MAC-00` 选定的 `orb info` 或 `orb list` 字段），不来自 `hostname -I`。
- [x] 查不到地址时，错误带上机器名和一行脱敏的原始输出摘要。
- [x] `MAC-00` 互 ping 失败时，本卡状态为 `blocked`，计划不标记完成，版本保持 `0.4.0`。本机互 ping 成功，所以本卡没有 blocked。
- [x] `tests/machine_pool.rs` 的 `test_ping` 由本卡加上 `#[cfg_attr(target_os = "macos", ignore)]`。Linux 上它仍是普通测试。macOS 上只有显式 `--ignored` 才会运行它。

**Verification:**

- [x] `cargo test --lib orb_guest_ip`。输出必须出现该测试名。
- [x] 真机：`cargo test --test machine_pool test_ping -- --ignored --test-threads=1`，仅在 `DEP-MAC-01` 且 `MAC-00` 互 ping 结论为成功时执行。证据必须显示 `test_ping` 被执行，且两台 `get_ip` 地址互相 ping 成功。互 ping 结论为失败时不跑这条命令，也不改用其它传输。本机两次都是 1 passed / 0 failed（61.83s、60.59s）。

**Full-suite trigger:** none

**Dependencies:** MAC-05，以及 `MAC-00` 的互 ping 结论为成功

**Deliverables:** N/A

**Implementation write set:** `src/orbstack.rs`、`src/machine.rs`、`tests/machine_pool.rs`（仅为 `test_ping` 增加 macOS `ignore`）、`README.md`（`get_ip` 在 Mac 上的地址含义）、`CHANGELOG.md`、本计划、`plan-status.md`

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

**Granularity:** `type=implementation; axis=池地址; recovery=revert; complete=yes; self-contained=yes; AC=4/8; VER=2/8; landing=3; prod-files=3; scope=M; deps=MAC-05; writeset=序列化于 MAC-07; release=family child; split-from=N/A; exception=N/A`

### Task MAC-07: 核对 CI 保持 Ubuntu-only

**Task type:** implementation

**Lifecycle / Acceptance:** done / complete

**Description:** 关闭 GAP-MAC-04 的方式是本机 Mac 上的 `cargo test --lib`，不是 GitHub Actions 的 macOS runner。本卡核对 `.github/workflows/check-and-test.yml` 仍然只有 `ubuntu-latest`，并且本计划的 diff 不添加 macOS 测试、macOS job 或 `macos-latest`。依赖 `/proc`、libvirt、KVM 的单测 cfg 归 `MAC-01`，本卡只核对它们没有被删掉。

**Out of scope:** 不新增 macOS job。不在 CI 安装 OrbStack。不在 CI 传 `--ignored`。不把 Actions 变绿当作本卡或后续推送的前置条件。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 工作流只有 `ubuntu-latest` | `.github/workflows/check-and-test.yml` |
| 本机 OrbStack | 2.2.5，`MAC-00` 写回实测 |

**Acceptance criteria:**

- [x] 工作流全文没有 `macos-latest`，没有 macOS 测试步骤或 job。本卡提交相对开工时的工作流不新增这些内容。
- [x] Ubuntu job 的命令保持：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib`、`cargo test --test windows_machine`、`cargo test --no-run`。这些命令都不带 `--ignored`。
- [x] 提交和推送不等待 GitHub Actions。若推送后能看到 Ubuntu run，只把 run id 记为事后证据；看不到也不挡住本卡。本卡不要求 macOS run。

**Verification:**

- [x] 检索 `.github/workflows/check-and-test.yml` 的 `macos-latest` 与 macOS 测试步骤，无匹配。检索输出写入「实施证据汇总」。

**Full-suite trigger:** none（不改共享 CI 工作流）

**Dependencies:** MAC-06

**Deliverables:** N/A

**Implementation write set:** 本计划、`plan-status.md`。不修改 `.github/workflows/check-and-test.yml` 来添加 Mac。若发现工作流里已经有 `macos-latest`（成稿时没有），删除该 job，而不是保留它。

**Release write set:** N/A

**Files likely touched:** 上述两个计划文件

**Docs and compatibility impact:** N/A（用户可见契约已由前序卡写入 README）

**Rollback mode:** revert

**Security and privacy:** CI 不接收 OrbStack 密钥，也不把开发者家目录写进日志。

**Performance budget:** N/A

**Estimated scope:** S

**Version increment:** N/A

**Release boundary:** family child of REL-MAC-01

**C/D coverage from:** `MAC-08`

**Granularity:** `type=implementation; axis=CI 仍为 Ubuntu; recovery=revert; complete=yes; self-contained=yes; AC=3/8; VER=1/8; landing=1; prod-files=0; scope=S; deps=MAC-06; writeset=序列化于 MAC-08; release=family child; split-from=N/A; exception=N/A`

### Task MAC-08: 以 0.5.0 收口

**Task type:** release

**Lifecycle / Acceptance:** done / complete

**Description:** 家族唯一发布点。版本从 0.4.0 升到 0.5.0。不在本卡新增行为。

**Out of scope:** 不 `cargo publish`，除非用户另要求。不在本卡修改 OrbStack 语义。

**Current evidence:**

| 事实 | 证据 |
|---|---|
| 版本 0.5.0，CHANGELOG `[0.5.0] - 2026-11-23` | `Cargo.toml`、`CHANGELOG.md`。`Cargo.lock` 的 qlean 包由 `cargo check` 写成 0.5.0 |

**Acceptance criteria:**

- [x] `Cargo.toml` 为 `0.5.0`，CHANGELOG 有 `[0.5.0]` 段，Unreleased 中属于本计划的条目已移入该段。`Cargo.lock` 只由 `cargo check` 或 `cargo build` 刷新。
- [x] 本机 macOS：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib`、`cargo test --no-run` 都退出 0。这是 ER-14 在非 Linux VM 宿主机上的回退。Linux 全量 `cargo test`（含 KVM 集成）登记为 `DEFER-MAC-05`，本卡不声称它已通过。
- [x] 真机冒烟已记入本计划：create、root exec、upload/download 往返、shutdown 后再 spawn、清扫不删非 `qlean-` 名字、两机 `get_ip` 后互 ping。证据来自 `MAC-05` 与 `MAC-06`，本卡只核对它们在。
- [x] 相对 0.4.0，Linux cfg 路径的行为没有为了 Mac 而改写。若发现有，先回到对应子卡。
- [x] `libra push origin main` 发生在本机门通过之后，不等待 GitHub Actions。不打 `v0.5.0` tag，不开 GitHub Release，不 `cargo publish`。Ubuntu CI 只是事后证据。工作流里没有 macOS job。

**Verification:**

- [x] 上列本机四条命令，输出记入「实施证据汇总」，且都是退出 0。
- [x] `libra push origin main` 在本机门通过后执行。不把 Actions 的结论写成本卡的通过条件。
- [x] `libra status` 与 tag 列表证明没有 `v0.5.0`。用户另行要求时才打 tag 与 GitHub Release。

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

**Estimated scope:** M

**Version increment:** minor

**Release boundary:** family release point of REL-MAC-01

**C/D coverage from:** self

**Granularity:** `type=release; axis=0.5.0; recovery=immutable-release; complete=yes; self-contained=yes; AC=5/12; VER=3/12; landing=3; prod-files=3; scope=M; deps=MAC-07; writeset=发布写集; release=family release point; split-from=N/A; exception=N/A`

## 测试矩阵

| 类别 | 必须覆盖 | Target / command |
|---|---|---|
| 单元 | 门禁文本、前置三条错误、create 参数、SSH 参数、生命周期状态机、地址解析、前缀清扫 | 本机 `cargo test --lib`。证据必须出现 `macos_host_gate`、`orbstack_prerequisite`、`orb_create_args`、`orb_ssh`、`orb_lifecycle`、`orb_guest_ip`，且不是 0 tests |
| 真机单机 | create、root exec、upload/download、shutdown 后再 spawn | `cargo test --lib orb_lifecycle_live -- --ignored`（仅 `DEP-MAC-01`，证据里出现该测试名） |
| 真机池重启 | init、shutdown、再 spawn | `cargo test --test machine_pool test_concurrency -- --ignored --test-threads=1`（macOS 上该测试为 ignore；Linux 上仍直接跑） |
| 真机池互访 | 两机 `get_ip` 后互 ping | `cargo test --test machine_pool test_ping -- --ignored --test-threads=1`（仅互 ping 结论为成功时；macOS 上 `#[cfg_attr(target_os = "macos", ignore)]`） |
| Linux 回归 | 现有 lib 测试，含 vsock 无 TCP 退路 | 本机源码守卫 `linux_guest_has_no_tcp_fallback` 与 `connect_target_tests`。完整 Linux `cargo test` 见 `DEFER-MAC-05`。Ubuntu CI 的 `cargo test --lib` 是事后证据 |
| 编译门槛 | 本机 Mac 能编过并跑过单测；CI 不增加 Mac runner | 本机 `cargo test --lib` 与 `cargo test --no-run`。工作流保持只有 `ubuntu-latest` |

## 追溯表

| 任务 | 来源 | 代码落点 | 文档 | 测试 |
|---|---|---|---|---|
| MAC-00 | OrbStack 文档与 GAP-MAC-03 | 无 | 本计划实测小节 | 无生产测试 |
| MAC-01 | GAP-MAC-01、GAP-MAC-02 | `Cargo.toml`、`src/lib.rs` | README Host Setup 首段、CHANGELOG | `macos_host_gate` |
| MAC-02 | GAP-MAC-02 | `src/orbstack.rs` | README 三条失败、CHANGELOG | `orbstack_prerequisite` |
| MAC-03 | GAP-MAC-03、ADR-MAC-03、ADR-MAC-04 | `src/orbstack.rs`、`src/image.rs` | README 支持矩阵与隔离边界 | `orb_create_args` |
| MAC-04 | ADR-MAC-02 | `src/orbstack.rs`、`src/ssh.rs`（动态用户名，Linux vsock 不变） | README 传输 | `orb_ssh`、`connect_target_tests`、`linux_guest_has_no_tcp_fallback` |
| MAC-05 | ADR-MAC-03 | `src/machine.rs`、`src/orbstack.rs`、`tests/machine_pool.rs` 的 `test_concurrency` | README 生命周期与 `is_running` | `orb_lifecycle`、`orb_lifecycle_live`、`test_concurrency` |
| MAC-06 | `tests/machine_pool.rs` | `src/machine.rs`、`test_ping` 的 macOS ignore | README `get_ip` | `orb_guest_ip`、`test_ping` |
| MAC-07 | GAP-MAC-04 | 不改工作流以添加 Mac。核对 `.github/workflows/check-and-test.yml` 仍无 `macos-latest` | N/A | 检索无匹配 |
| MAC-08 | 成功定义 | `Cargo.toml`、`Cargo.lock`、CHANGELOG | `[0.5.0]` | 本机 fmt、clippy、`cargo test --lib`、`cargo test --no-run`；`DEFER-MAC-05` |

## 里程碑验收与回滚

| 里程碑 | 完成条件 | 发布/证据 | 回滚或前滚 |
|---|---|---|---|
| M0 | `MAC-00` 结论写回，互 ping 有明确结果 | 本计划实测小节 | 互 ping 失败不撤销 M0。`MAC-01` 至 `MAC-05` 可以继续。不发布 0.5.0，计划不标记完成 |
| M1 | Mac 上能编译，缺 OrbStack 有可操作错误 | `MAC-01`、`MAC-02` 的 lib 测试 | revert 这两张卡的提交 |
| M2 | 单机能 init、exec、传文件、stop、再 spawn；`is_running` 三分 | `MAC-05` 真机冒烟 | revert；只删除这次新创建的半成品 |
| M3 | 两机能互 ping，本机收口门通过，CI 仍只有 Ubuntu | `MAC-08`。不等待 Actions | 未打 tag。若用户日后发布，只能前滚新版本 |

### 故障恢复矩阵

| 故障点 | 可接受残留 | 恢复动作 | 禁止结果 |
|---|---|---|---|
| `orb create` 失败且名字已经出现 | 无这台新机器 | 错误路径 `orb delete` 这个新名字。删除失败和原错误一起返回 | 留下半成品占用名字，或吞掉清理错误 |
| 新机器 SSH 就绪超时 | 无这台新机器 | 停止并 `orb delete` 这个新名字，返回超时错误 | 把超时当成「机器可用」 |
| 已存在机器的 `orb start` 或 SSH 失败 | 机器还在，处于停止 | 只 `orb stop <name>`，不 `orb delete` | 删掉用户上次留下的 `qlean-` 数据 |
| 进程被杀掉 | 运行中的 `qlean-<id>`，run 目录通常还在 | Drop 能走到则先 stop。run 目录还在时清扫不删除它。手动恢复是操作者执行 `orb stop <name>` 与 `orb delete <name>`，或删掉 run 目录后再启动 qlean 让清扫命中 | 扩大清扫，或删除用户的非 `qlean-` 机器 |
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
| 有人把 macOS 测试加进 GitHub Actions | 违反本计划的绑定约束 | `MAC-07` 核对工作流没有 `macos-latest`。Mac 门是本机 `cargo test --lib` 与显式的 ignored 真机命令。OrbStack 2.2.5 在 `DEP-MAC-01` 上 | `MAC-07` |
| 崩溃后 run 目录还在，清扫因此不删机器 | 停止的 `qlean-<id>` 留到操作者处理 | 不扩大删除条件。风险表上一行写了手动恢复。P2，责任人：计划 Owner | `MAC-05` |

## 性能与容量摘要

| 操作 | 单次成本 | 累积成本 | 预算/上限 | 验证 |
|---|---|---|---|---|
| `orb create` | 一次发行版准备，首台较慢 | 每台 `Machine` 一次，不在 `exec` 重复 | 落在现有 SSH 就绪预算内 | `MAC-05` 真机冒烟 |
| SSH `exec` | 一条 russh 命令 | 与 Linux 相同，按调用次数 | 不新增轮询 | 代码审查：地址缓存一次 |
| 清扫 | 一次 `orb list` 加按名删除 | 每次进程启动一次 | 只检查 `qlean-` 前缀 | `orb_lifecycle` 单测 |

## 兼容与文档收口

- [x] `README.md` 的 macOS Host Setup、支持矩阵、传输和 `get_ip` 由 `MAC-01`、`MAC-03`、`MAC-04`、`MAC-05`、`MAC-06` 分别写入。
- [x] `CHANGELOG.md` 的条目由上述行为卡写入 Unreleased，由 `MAC-08` 收成 `[0.5.0]`。
- [x] `.github/workflows/check-and-test.yml` 由 `MAC-07` 核对为仍然只有 `ubuntu-latest`。本计划不向它添加 macOS 测试。
- [x] `tests/INDEX.md`：`N/A`，仓库中不存在该文件。
- [x] `LICENSE` 不改。

## 实施证据汇总

成稿时无实现证据。`MAC-00` 起，命令输出与 CI run id 只写在这里。

### OrbStack 实测

宿主：Apple Silicon（`uname -m` = `arm64`），OrbStack 2.2.5，`orb status` 成功输出为 `Running`（exit 0）。测量用的机器名是 `qlean-` 加 12 位十六进制，测完已 `orb delete -f`。最终 `orb list -f json` 为 `[]`。下面不记录私钥、主机公钥全文或家目录用户名。

**探活与地址。** 唯一来源是 `orb info <name> -f json`。`record.state` 为 `running` 或 `stopped`。地址是顶层字符串 `ip4`（例：`192.168.139.148`、`192.168.139.146`），不是文档示例里的 `198.19.0.0/16`，也不是客户机里的 `hostname -I`。`stopped` 时没有 `ip4`。`orb list -f json` 有 `name` 与 `state`，没有 IP，清扫只拿它列名字。找不到机器时 stdout/stderr 为 `[-32098] machine not found: '<name>'`，exit 非 0。

**create。** 成功：`orb create --isolated --cpus 2 --memory 2G --disk 8G debian:bookworm qlean-00a11e000001` exit 0，无 stdout。随后 `info` 里 `config.isolated=true`，`forward_ssh_agent=false`，`isolate_network=false`，`memory_limit_mib=2048`，`cpu_limit=2`，`disk_limit_bytes=8589934592`，`image.arch=arm64`，`image.distro=debian`，`image.version=bookworm`，`state=running`。第一次同样的 create 失败为 `[-32603] Post "http://sconrpc": EOF`（exit 1），列表里没有这个名字，没有半成品。同名再 create：`[-32098] create '<name>': machine already exists: '<name>'`（exit 1）。坏发行版：`Error: invalid distro: notadistro`。`--memory 512`：`memory limit must be at least 1 GiB`，不留下机器。因此裸 `--memory` 的单位是 MiB，且至少 1024。`--memory 2G` 存成 2048 MiB，所以 `G` 是 GiB。`--disk` 的 help 单位是 GiB；`--disk 8G` 存成 8589934592 字节。实现传 `--memory <mem>`（`MachineConfig.mem` 按 MiB，小于 1024 在调用 `orb` 前拒绝）和 `--disk <disk>G`。

**start / stop / delete。** `orb stop <name>` 与 `orb start <name>` 成功都是 exit 0、无 stdout。停之后 `state=stopped` 且没有 `ip4`；再 start 后回到 `running`，这次 `ip4` 仍是 `192.168.139.148`。实现仍在每次启动后重新读 `ip4`，不把「IP 不变」写成契约。缺名字：`[-32098] machine not found: '<name>'`。无参数的 `orb stop` 按 help 会停掉整个 OrbStack，本轮没有执行，实现禁止。`orb delete <name>` 在非 TTY 下 exit 0 并删掉机器，没有确认提示。`orb delete -f <name>` 同样 exit 0。实现始终加 `-f`，避免终端卡住。删完 `orb list -f json` 为 `[]`。

**SSH。** `ssh -p 32222 -i ~/.orbstack/ssh/id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=~/.orbstack/ssh/known_hosts -l 'root@<machine>' 127.0.0.1 id -u` 输出 `0`，`hostname` 等于机器名。用户名是 `root@<machine>` 这一个 SSH 用户，主机是 `127.0.0.1`，端口 `32222`，私钥 `~/.orbstack/ssh/id_ed25519`。`known_hosts` 里 `[127.0.0.1]:32222` 有两行，类型是 `ssh-ed25519` 与 `ecdsa-sha2-nistp256`。实现钉住 `ssh-ed25519` 那一行，不把密钥写进日志。对已停止的机器发起这次 SSH 会把机器拉起来并让命令成功，所以 `is_running` 只读 `record.state`，不用 SSH 成败判断停机。`orb -m <name> -u root id -u` 也能得到 `0`，但传输仍走上面的 SSH，不把 `orb run` 当成文件 API。

**互 ping。** 两台都是 `--isolated` 且没有 `--isolate-network`。`ip4` 分别是 `192.168.139.148` 与 `192.168.139.146`。A `ping -c 3 -W 2` B 与 B ping A 都是 3 包 0% 丢失（exit 0）。ADR-MAC-04 因此选定 `--isolated`。隔离机器上没有 `/mnt/mac` 目录，`SSH_AUTH_SOCK` 未设置。

**架构与发行版。** `--arch aarch64` 被拒：`Error: invalid architecture: aarch64`。help 只接受 `arm64` 与 `amd64`。不写 `--arch` 时 Apple Silicon 上得到 `arm64`。`--arch amd64` 的 `debian:bookworm` 创建成功，`image.arch=amd64`，`state=running`，有 `ip4`。`GuestArch::Aarch64` 映射为 `--arch arm64`，`GuestArch::Amd64` 映射为 `--arch amd64`。没有 Intel Mac，Intel 宿主上的 aarch64 写成「未测，实现按拒绝处理」。发行版参数用裸名字 `debian`、`ubuntu`、`fedora`、`arch`，不额外钉版本。2.2.5 的 help 默认是 debian bookworm/12、ubuntu resolute/26.04、fedora 44、arch current。本轮启动的是 `debian:bookworm`（等于 debian 默认）和它的 amd64 变体。

**实现要写死的拼法。** `orb create --isolated --cpus <n> --memory <mem> --disk <disk>G --arch <arm64|amd64> <distro> <qlean-id>`。已存在则改为 `orb start <name>`，不第二次 create。停止是 `orb stop <name>`。失败清理新机器用 `orb delete -f <name>`。地址与探活解析 `orb info <name> -f json` 的 `ip4` 与 `record.state`。列名字用 `orb list -f json`。

**MAC-07 证据。** 检索 `.github/workflows/check-and-test.yml` 的 `macos-latest` 与 `macos`：无匹配。工作流没有新增 macOS job。推送不等待 Actions。

**MAC-08 证据。** `Cargo.toml` 与 `Cargo.lock` 的 qlean 包是 `0.5.0`，锁文件由 `cargo check` 刷新。CHANGELOG 的 OrbStack 三条在 `[0.5.0] - 2026-11-23`。本机 `cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 退出 0。`cargo test --lib` 两次都是 576 passed / 0 failed / 14 ignored。`cargo test --no-run` 退出 0。没有 `v0.5.0` tag，没有 GitHub Release，没有 `cargo publish`。Linux 全量 `cargo test` 仍是 `DEFER-MAC-05`。

**MAC-06 证据（DEP-MAC-01，OrbStack 2.2.5）。** `get_ip` 读 `orb info -f json` 的 `ip4`。`cargo test --test machine_pool test_ping -- --ignored --test-threads=1` 两次都是 1 passed / 0 failed（61.83s、60.59s）。测完 `orb list` 为空。

**MAC-03 至 MAC-05 证据（DEP-MAC-01，OrbStack 2.2.5）。** `cargo test --lib` 566 passed / 0 failed / 14 ignored。`cargo test --lib orb_lifecycle_live -- --ignored` 跑了两次，都是 1 passed / 0 failed（54.68s、54.12s）：root `id -u` 为 0，SFTP 往返读回 `orb-live`，`shutdown` 后名字仍在列表里，`spawn` 后再读到同一文件。`cargo test --test machine_pool test_concurrency -- --ignored --test-threads=1` 为 1 passed / 0 failed，80.50s。结束后 `orb list` 已清空这些 `qlean-` 机器。

## Review log

成稿时 review 还没做。那一句不是评审结论，所以不放进 Result 列。Result 只允许 `PASS` 或 `FAIL`。

| Round | Scope | Result | P0/P1 | P2 处置 | Evidence |
|---|---|---|---|---|---|
| IMP-R3 | 自计划 PASS 提交 `0a68938` 起的实现，含工作区。Codex 只读，非实现者自评。绑定约束：GitHub Actions 不得增加 macOS 测试或 `macos-latest` | PASS | 无未关闭 P0/P1。R2 残留的 IMP-P1-01（Linux dead_code）与 IMP-P1-04（`true` 使用连接前的剩余时间）已关闭。更早的 IMP-P1-02、03、05、06、07 已关闭 | IMP-R2-P2-01 由计划 Owner 接受：清扫时 list 失败或 delete 失败不另报，并且每个进程只清扫一次 | 2026-11-23 17:10:19 UTC，Codex CLI `codex exec -s read-only`，无 `--worktree`。判定行是 `PASS` |
| R2 | 同上计划文本，复审 R1 的修订。Codex 只读 | PASS | 无未关闭 P0/P1。R1 的 P0-01..P0-04 与 P1-01..P1-08 已关闭 | P2-01 仍由计划 Owner 接受：崩溃后 run 目录还在则不扩大清扫。P2-R2-01 由计划 Owner 接受为残余：`MAC-01` 验证里的「Linux：`cargo check`」不是本机门，也不是完成条件；Linux 执行归 `DEFER-MAC-05`，Ubuntu CI 只作事后证据 | 2026-11-23，Codex CLI `codex exec -s read-only`，无 `--worktree`。判定行是 `PASS` |
| R1 | `docs/plan/plan-20261123-macos-orbstack.md` 计划文本。Codex 只读，非实现者自评。绑定约束：GitHub Actions 不得增加 macOS 测试或 `macos-latest` | FAIL | P0-01 适用范围 / GAP-MAC-04 / 关系表 / ER-13/14 / Phase 3 仍要求 Mac CI。P0-02 `MAC-07` 要求 `macos-latest`。P0-03 `MAC-08` 要求 macOS Actions 全绿。P0-04 测试矩阵与 CI 风险行要求 Mac runner。P1-01 SSH 用户名超出当时写集。P1-02 `test_ping --ignored` 与 `connect_ssh` 过滤器会假绿。P1-03 `is_running` 与文件传输没有归属。P1-04 Linux 全量门与 ER-14 不一致。P1-05 失败清理不分新旧机器。P1-06 隔离边界没写。P1-07 `MAC-02` 缺同卡文档。P1-08 粒度计数与模板不符。本轮修订已改上述正文，待 R2 复审 | P2-01 崩溃后 run 目录仍在则不扩大清扫，手动恢复写入故障矩阵，责任人计划 Owner。P2-02 `MAC-01`..`MAC-05` 在互 ping 失败时可以继续，`MAC-06` 与 0.5.0 不行。P2-03 成稿「未评审」已移出 Result 列 | 2026-11-23 15:55 UTC 前后，Codex CLI `codex exec -s read-only`，无 `--worktree`。判定行是 `FAIL` |

## 非目标与延后项

| ID | 延后内容 | 原因 | 重启条件 | 承接位置 |
|---|---|---|---|---|
| DEFER-MAC-01 | 在 OrbStack Linux 机器里运行现有 QEMU/KVM 栈 | 官方文档写明 Apple Silicon 不能嵌套 KVM | OrbStack 文档删除该限制，且 `/dev/kvm` 在机器内可用 | 新计划 |
| DEFER-MAC-02 | macOS 上的 Windows 客户机 | OrbStack 无 Windows 机器；现有 Windows 路径要 KVM | OrbStack 提供 Windows 机器，或另选已授权的 macOS 虚拟化 | 新计划 |
| DEFER-MAC-03 | macOS 上的 riscv64 客户机 | OrbStack 机器架构只有 aarch64 与 amd64 | OrbStack 能创建 riscv64 机器 | 新计划 |
| DEFER-MAC-04 | macOS 上使用调用方的 qcow2 | 自定义镜像是 orbstack#11，尚未提供 | 该 issue 关闭且 `orb create` 能吃 qcow2 | 新计划 |
| DEFER-MAC-05 | 配齐的 Linux 宿主机上的全量 `cargo test`（含 `tests/**` 的 KVM 集成） | 本执行机是 macOS，不是 ER-14 要求的 Linux VM 宿主机。不把本机结果说成 Linux 集成已通过 | 在配齐 KVM、QEMU、libvirt、xorriso 与 bridge helper 的 Linux 宿主机上跑通 `cargo test` 并写回证据 | 该宿主机上的后续验证，不在本计划用 TCP 或 OrbStack 代替 |

## 完成判据

- [x] 任务卡满足 `G-*`，粒度审计表已填，无未登记的 L 例外。
- [x] `MAC-00` 至 `MAC-08` 的 `Lifecycle=done` 且 `Acceptance=complete`。`MAC-06` 若 `blocked`，本计划不得完成。
- [x] 各卡 Verification 已跑并记入「实施证据汇总」。真机命令注明 `DEP-MAC-01`。
- [x] 收口门在本机 macOS 上：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test --lib`、`cargo test --no-run`，以及真机冒烟。Linux 全量集成是 `DEFER-MAC-05`，不作为本计划完成条件。GitHub Actions 不增加 macOS 测试或 `macos-latest`。提交和推送不等待 Actions。
- [x] README、CHANGELOG 已按追溯表更新。CI 工作流已核对为仍然只有 `ubuntu-latest`。
- [x] 计划 review 与实现 review 的最终轮次都是 PASS，P0/P1 关闭。实现者自己的笔记不算 PASS。
- [x] `MAC-08` 已把版本定为 0.5.0，锁文件只由工具链刷新。不打 tag，不开 GitHub Release，不 `cargo publish`，除非用户另行要求。
- [x] 「修订历史」记录成稿后的规范性变更。
- [x] `plan-status.md` 与任务卡一致。
- [x] 未新建证据目录。
