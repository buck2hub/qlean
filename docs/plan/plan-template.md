# Qlean 计划模板

本文是 `docs/plan/` 下新建计划的标准模板（参照 `libra/docs/development/plan/plan-template.md` 的结构，按 Qlean 的实际规模裁剪）。新计划应复制本文件结构，替换 `<...>` 占位符，并删除不适用的说明性文字；**强制章节不得删除**，不适用时写 `N/A` 并说明原因。

**模板版本:** `v1.1`（Qlean 仓库自己的模板谱系，不沿用 Libra 的 v2.x 编号与迁移政策。）

## 使用规则

- **文件命名:** 日期计划命名为 `plan-YYYYMMDD.md`，或 `plan-YYYYMMDD-<word>[-<word>]{0,4}.md`；`<word>` 是 1 至 5 个小写英文单词（`[a-z]+`），用单个 `-` 连接，只作内容简述。Issue 计划放在 `docs/plan/issues/`，命名为 `<number>.md` 或 `<number>-<word>[-<word>]{0,4}.md`。
- **更新时间（强制）:** 状态推进、`plan-status.md` 的当前快照、以及「修订历史」的每一新行，都记录写入时的 UTC 时钟时间，格式 `YYYY-MM-DD HH:MM:SS UTC`（24 小时制，精确到秒）。
- **单一执行状况视图（强制）:** `docs/plan/plan-status.md` 是全仓计划的单一执行状况视图，按任务卡粒度汇总状态。新建计划时必须登记；每次推进任务卡时在同一变更中同步更新状态、发布版本/commit 和该卡的 UTC 更新时间。
- **证据只写入计划文件（强制）:** 执行、验收或评审计划时，不得新建证据文件或证据文件夹（`evidence/`、`baseline/`、`scratch/` 等）。测试摘要、命令输出、哈希、CI run ID/URL 等全部写入**对应计划文件**的专门小节（「实施证据汇总」或该卡的 `Verification`），并在「修订历史」登记。
- **事实基线以当前 checkout 为准:** 每个计划必须以当前 checkout 的源码、测试、用户文档为事实基线。历史计划、issue 评论或外部文档只能作为线索，不能作为已实现证据。
- **任务卡可独立执行:** 每个任务卡必须能被单个 Agent 独立执行：范围明确、依赖明确、文件落点明确、验收标准明确、验证命令明确。
- 长期路线图只进 `docs/plan/plan-long.md`（若存在）；日期计划可以链接能力编号，但不得把长期路线图复制成重复任务表。

## 标题

`# <主题>计划（<YYYY-MM-DD>）`

**目标分支（强制）:** `<branch>`；上游提交与远端验收必须引用同一分支。

## 文档职责

本文解决 `<问题/能力>`，目标是 `<可交付结果>`。

本文只规划任务，不宣称实现完成。落地时每个任务都必须先刷新源码锚点，再按任务卡验收。

### 适用范围

- `<包含的公开 API / 模块 / 用户工作流>`
- `<包含的宿主机依赖（QEMU、libvirt、xorriso、qemu-bridge-helper）、镜像目录、网络或运行目录>`
- `<包含的测试、文档、变更日志或发布动作>`

### 非目标

- `<明确不做的能力>`
- `<延后到其它计划 / RFC / ADR 的范围>`
- `<容易被误解但本计划不承诺的行为>`

### 成功定义

- `<用户或系统行为变化>`
- `<机器接口或数据/状态变化>`
- `<文档、测试、发布证据>`
- `<何时可标记计划完成>`

## 事实基线

> 所有行号和源码锚点必须在开工当天刷新。过期锚点只能作为历史线索。

| 类别 | 当前事实 | 证据 |
|---|---|---|
| 公开 API | `<qlean::Image / ImageConfig / Machine / MachineConfig / MachinePool / with_machine / with_pool / is_kvm_available / InteractiveShell / Distro / GuestArch>` | `<src/lib.rs:line>` |
| 镜像目录 | `<Distro（Debian/Ubuntu/Fedora/Arch）、GuestArch（Amd64/Aarch64/Riscv64）、内置镜像目录与校验>` | `<src/image.rs:line>` |
| VM 生命周期 | `<Machine::new/init/spawn/exec/shutdown、cloud-init seed ISO、vsock SSH 注入>` | `<src/machine.rs:line>` |
| QEMU/KVM 启动 | `<qemu-system-*、-accel kvm/-accel tcg、vhost-vsock、virtio、bridge netdev>` | `<src/qemu.rs:line>` |
| 通信 | `<SSH over vhost-vsock（tokio-vsock + russh），无 TCP fallback>` | `<src/ssh.rs:line>` |
| 网络 | `<libvirt 网络 "qlean"、桥 qlbr0、子网 192.168.221.0/24、NAT + DHCP>` | `<README.md:line>` |
| 用户文档 | `<README.md（Host Setup / API Reference）>` | `<README.md:line>` |
| 变更日志 | `<CHANGELOG.md（Keep a Changelog + SemVer）>` | `<CHANGELOG.md:line>` |
| CI | `<check-and-test.yml：format / clippy / test(--no-run)>` | `<.github/workflows/check-and-test.yml:line>` |
| 版本 | `<Cargo.toml [package].version = "0.3.1">` | `<Cargo.toml:line>` |

### 当前缺口

| ID | 缺口 | 影响 | 证据 | 计划动作 |
|---|---|---|---|---|
| GAP-01 | `<问题>` | `<用户/生产影响>` | `<file:line 或外部证据>` | `<任务 ID>` |

## 与其它计划的关系

| 计划/文档 | 关系 | 本计划处理 |
|---|---|---|
| `plan-long.md` | `<关联能力编号>` | `<链接、消费、更新状态或不触碰>` |
| `plan-YYYYMMDD[-<words>].md` 或 `issues/<number>[-<words>].md` | `<前置/并行/替代/冲突>` | `<复用、不重做、迁移、关闭>` |
| `README.md` / `CHANGELOG.md` / `.github/workflows/` | `<事实源或契约>` | `<同步方式>` |

## 评审结论与修订记录

计划成稿前必须从以下维度做一次自审；如果有阻断项，先修计划再开工。

| 维度 | 结论 | 修订动作 |
|---|---|---|
| 合理性 | `<目标是否值得做>` | `<调整>` |
| 可行性 | `<任务是否可拆、可交付>` | `<调整>` |
| 任务卡粒度 | `<是否存在多轴卡、L/XL 卡、碎片卡、未登记的合并发布>` | `<按 G-* 拆分/合并/登记例外>` |
| 依赖与顺序 | `<依赖图是否无环、是否缺边、发布顺序是否可执行>` | `<调整>` |
| 完整性 | `<测试/文档/CHANGELOG/回滚是否齐全>` | `<调整>` |
| 安全性 | `<SSH 密钥、secrets 目录、bridge 权限、root 客户机、路径>` | `<调整>` |
| 接口兼容 | `<公开 API / SemVer / 行为契约>` | `<调整>` |
| 可靠性与容错 | `<QEMU 崩溃恢复、CID 分配、锁、资源释放>` | `<调整>` |
| 性能与容量 | `<镜像下载、hash 计算、启动热路径、存储增长>` | `<调整>` |
| 可维护性 | `<事实源、抽象边界、重复实现>` | `<调整>` |

### 修订历史

计划成稿后的每次规范性变更（任务卡拆分/合并、依赖调整、发布边界变化、决策反转）都必须在此登记一行，时间用 `YYYY-MM-DD HH:MM:SS UTC`。

| 时间 | 触发 | 变更内容 | 原卡 → 新卡 | 受影响的引用 |
|---|---|---|---|---|
| `<YYYY-MM-DD HH:MM:SS UTC>` | `<自审 / review R<n> / 现状核对>` | `<做了什么规范性修改>` | `<TASK-ID> → <TASK-ID>, <TASK-ID>` | `<实施顺序、依赖登记表、追溯表、测试矩阵、里程碑、风险表>` |

## 已决议设计决策

实现时若需偏离本节，必须先修改计划并说明原因，不得在代码中静默改语义。

### ADR-<PREFIX>-01: <决策标题>

- **Status:** Accepted
- **Context:** `<为什么需要这个决策>`
- **Decision:** `<选定方案>`
- **Alternatives considered:** `<备选方案及拒绝理由>`
- **Consequences:** `<带来的约束、风险、后续工作>`
- **Revisit when:** `<何时应重审>`

## 全局工程约束

以下约束对本文所有任务生效。任务条目不再逐条重复，违反任一项即视为任务未完成。

- **GC-01 现状核实前置:** 每个任务开工前重新核对计划、README、相关开发文档、当前代码和测试。如果已实现，则任务改为补测试、补文档、更新状态或关闭，不重复实现。
- **GC-02 单一事实源:** 镜像目录与校验、QEMU 启动参数、vsock SSH 注入、CID 分配、网络定义等共享逻辑必须有单一事实源。禁止在 `machine.rs` / `qemu.rs` / 测试 fixture 之间复制同一逻辑。
- **GC-03 公开 API 与兼容边界:** Qlean 是发布到 crates.io 的库，`src/lib.rs` 的 `pub` 重导出即公开 API 表面。任何公开 API 的新增、删除、重命名或语义变化必须评估 SemVer 级别，并在 README API Reference 与 CHANGELOG 同步。给全公开结构体加字段会破坏外部字面量构造，给可被穷尽匹配的公开枚举加变体也可能破坏下游 match；`Default` 或 Serde 默认值不等于源码兼容。
- **GC-04 错误契约:** 库代码使用 `anyhow::Result` / `Result<T, E>` 返回可操作错误，禁止把可恢复错误吞掉。生产路径不得新增未解释的 `unwrap()`、`expect()` 或 `panic!()`；确属不可失败逻辑必须有 `// INVARIANT:` 注释并在任务验收中说明。
- **GC-05 文档同步:** 公开行为变化必须同步 `README.md`（Host Setup / API Reference / 示例）与 `CHANGELOG.md`（Keep a Changelog 格式）。
- **GC-06 CI 同步:** 新增/调整测试 target、feature、MSRV 或构建约束时，必须同步 `.github/workflows/check-and-test.yml`，保证 CI 能编译并运行相关检查。
- **GC-07 安全默认值:** SSH 密钥存放在 `~/.local/share/qlean/secrets/`（私钥 0600）；vsock 客户机 SSH 禁用密码认证；bridge 配置依赖宿主机的 `qemu-bridge-helper` 白名单。任何放宽默认安全姿态的改动必须有显式理由和测试。
- **GC-08 资源生命周期:** VM/QEMU 进程、vsock 连接、CID 分配锁（`dir-lock`）、overlay 镜像、seed ISO、运行目录必须有确定性的创建/释放语义；测试不得遗留 QEMU 进程或未清理的运行目录。
- **GC-09 并发与全局状态:** 涉及 KVM/VM 的集成测试必须使用 `serial_test` 串行化；CID 分配依赖文件锁，测试不得依赖未隔离的全局状态。
- **GC-10 性能预算:** 镜像下载、hash 流式计算、VM 启动与 `exec` 热路径不得引入无界扫描、无界内存或 N+1 网络调用。需要时写出数据规模与断言。
- **GC-11 精确暂存:** Git checkout 只 `git add <相关路径>`，Libra checkout 使用等价的精确路径 add；不得使用 `git add -A` / `git commit -a` 或 Libra 等价的全量暂存。发现无关脏状态时保留并报告，不得清理、重置或混入提交。

## 执行检查必备需求（强制）

任一要求未满足，对应任务不得标记完成。条目使用稳定 ID，正文引用时用 ID 而不是序号。

1. **ER-01 开工前安全检查:** Git checkout 运行 `git status --short --branch`，Libra checkout 运行 `libra status --short --branch`；确认当前分支与计划的「目标分支」一致、工作区脏状态、目标文件是否已有无关改动。若目标文件已有未确认用户改动，先报告并避免覆盖。
2. **ER-02 先核对后实现:** 刷新本任务相关源码锚点、文档锚点、测试 target，再决定实现、补测、补文档、关闭或降级。
3. **ER-03 粒度门禁:** 开工前按粒度规则 `G-*` 逐条复核本任务卡，并逐字段核对该卡的 `Granularity` 摘要行。若核对后发现范围已扩大（新增行为轴、AC/Verification 超限、写集与其它在跑任务重叠），先修改计划拆卡再开工。
4. **ER-04 每卡验收门:** 门由 **A 表面 focused 门** + **B 类型门** + **C 发布收口门**（独立发布卡/家族唯一发布点）+ **D 远端后置门**（CI / crates.io 等不可本地复现的语义）组成，所有适用行累加，全部通过才算验收。
   - **A 表面 focused 门**（按实际改动的表面）：
     | 实际改动的表面 | focused 门 |
     |---|---|
     | Rust 内部逻辑（`src/**` 的 `#[cfg(test)]`） | `cargo test --lib [<filter>]` |
     | Rust 集成 / VM 行为（`tests/**`） | 需 Linux 宿主机 + KVM（或 TCG）+ QEMU/libvirt/xorriso/bridge-helper，`cargo test --test <target> [<filter>] -- --test-threads=1`；无法满足环境时至少 `cargo test --no-run` 并登记环境缺口 |
     | 只改文档 / 索引（无代码） | 无表面 focused 门，只走 B 组的文档门 |
     | CI / 仓库配置（`.github/workflows/**`、`Cargo.toml` 非版本行、`rustfmt.toml`） | 受影响 job 的本地等价命令，不可本地复现的部分归 D 组 |
   - **B 类型门**（按 `Task type` 取一行）：
     | Task type | 类型门 |
     |---|---|
     | `implementation` / `removal` | 无额外类型门（由 A 组 + 适用 C/D 构成完整验收） |
     | `docs` / `audit` / `handoff` | 结构与链接门：产物文件存在且章节完整、内部链接与 `file:line` 锚点可解析、VCS status 无越界改动 |
     | `spike` | 产物门：结论文档或 ADR 已落盘、go/no-go 已判定、承接卡已登记；生产代码零改动 |
     | `release` | 聚合守卫 + 兼容证据 + CHANGELOG / release note |
   - **C 发布收口门（由独立发布卡/家族唯一发布点执行，顺序强制）:** ① 版本 parity 预检（`Cargo.toml` 唯一版本源）→ ② 按 ER-08 做版本 bump（默认 `patch + 1`，无上限）→ ③ **禁止手改 `Cargo.lock`**：改 `Cargo.toml` 后执行 `cargo build`（或 `cargo check`），由工具链刷新 lockfile → ④ 在**已 bump 的状态**上跑收口门：`cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、按 ER-13 判定测试面 → ⑤ `cargo build --release` → ⑥ 精确 add + commit → ⑦ 推送并等待 CI 全绿 → ⑧ 打 `v<version>` tag + GitHub Release，并按需 `cargo publish`（crates.io）。
   - **D 远端后置门（post-push）:** CI（`.github/workflows/check-and-test.yml` 的 format/clippy/test job）与 crates.io 发布结果只能在推送后取得。任务卡必须写明要看的 job、触发事件与 ref、判据，并在推送后取证。D 组失败一律前滚修复（新提交/新版本），不得回退已推送提交或已发布 crate。
   - **两个正交状态字段（每卡登记）:**
     - `Lifecycle`：`pending` | `in-progress` | `blocked` | `done`。
     - `Acceptance`：空 | `locally-accepted`（A+B 已过，review/C 尚未完成）| `remote-pending`（独立发布卡/发布点的 A/B/C 已过、D 未全绿）| `complete`（本卡全部适用门与 review 已通过）。`Lifecycle=done` 必须以 `Acceptance=complete` 为前提。
     - `independent`/`release` 卡的唯一转移路径：A/B 通过 → `locally-accepted` → review PASS → 取得 C 覆盖 →（无 D：`complete`；有 D：`remote-pending` → D 全绿 → `complete`）。
     - `family child`/`no-release` 卡的唯一转移路径：A/B 通过 → `locally-accepted` → review PASS → `complete`。它们不独立执行 C/D；继承发布点的 C/D 是覆盖归属和发布追踪信息，**不是**子卡进入 `complete` 的前置条件。发布点可以要求子卡先 `complete`，再由发布点独自完成家族 C/D，避免循环等待。
   - **C/D 组覆盖与执行归属:** `independent` 卡自行执行完整 C/D；`family child` 继承家族唯一发布点的 C/D 覆盖；`no-release` 卡继承其显式声明的承载发布点的 C/D 覆盖（必须写明 ID）。只有执行该 C/D 的卡负责等待并记录其绿色证据。
5. **ER-05 review 闭环:** 实现和本地验收完成后进行代码 review；review 问题修复后重跑相关验收，直到 review 明确给出 PASS。P0/P1 必须关闭。
6. **ER-06 文档与 CHANGELOG 同步:** 涉及公开行为的任务必须在**同一张任务卡**同步 `README.md` 与 `CHANGELOG.md`（Keep a Changelog：Added/Changed/Fixed/Removed），不得用后续「补文档」卡拆开同一行为轴。每个受影响文件必须有逐文件交付和验收证据。
7. **ER-07 VCS 工作流与提交:** 上游仓库使用 Git/GitHub；本地 Git checkout 使用 `git status` → `git add <相关路径>` → `git commit` → `git push origin <branch>`，Libra checkout 使用等价的 `libra status/add/commit/push`。提交信息用 `<scope>: <summary>` 惯例，证据记录实际 VCS 和命令；不得转换 VCS 元数据或把一种工具的命令伪装成另一种工具的结果。
8. **ER-08 版本与发布:** 版本权威源是 `Cargo.toml` 的 `[package].version`（SemVer）。独立发布默认 `PATCH + 1`（无上限）；向后兼容的新功能可声明 minor。破坏性 API 变更必须有 ADR + 兼容窗口/迁移证据，0.x 使用 minor，1.x 起使用 major；新增公开结构体字段或公开枚举变体时必须先按 GC-03 做源码兼容分析，不得默认视为兼容。bump 后同步：`Cargo.lock`（仅工具链刷新）、`CHANGELOG.md`（Unreleased → 新版本段）。发布动作：`git tag v<version>` + GitHub Release +（若维护 crate 发布）`cargo publish`；Libra checkout 使用等价 tag/push 能力并记录实际命令。
9. **ER-09 push 失败策略:** 非 fast-forward 需要 pull/merge 后重新验收再推；认证、权限、网络或服务端失败不 blind retry，记录原因，待下一次修复/发布窗口处理。
10. **ER-10 内部/外部服务错误（有界重试）:** 镜像下载、crates.io、GitHub API 等错误不得直接把任务宣告完成。确定性错误（4xx、编译/配置缺陷）不重试，按 ER-03 判定归属；暂时性错误（超时、5xx、限流）按指数退避重试，默认 ≤ 5 次、总计 ≤ 30 分钟，超预算后置 `blocked` 并记录 sanitized 证据。
11. **ER-11 证据卫生:** 验收证据不得保存 secret、API key、token、PII、未脱敏 transcript、绝对私有路径或原始 tool payload。需要留存时只写 sanitized summary。
12. **ER-12 并发边界与串行发布:** 并发只适用于实现与 review 阶段，且仅当各卡 `Implementation write set` 不相交。**发布动作一律串行**：同一时刻只允许一张卡处于「已 bump 未完成推送/发布」状态，由计划声明的单一发布者执行。
13. **ER-13 测试执行分层:** 执行阶段默认只跑本卡 focused 测试（A 组 + 卡内 `Verification` 指定用例）。`cargo fmt --check` 与 `cargo clippy --all-targets --all-features -- -D warnings` 是静态门，不属于「测试」，任何会推送的卡都必须跑。命中以下条件之一时本卡跑全量：`T-1` 共享逻辑/单一事实源（GC-02）；`T-2` 发布点卡（`release`）；`T-3` 删除或重命名公开 API surface；`T-4` 改动共享测试基建；`T-5` 计划或用户显式要求；`T-6` focused 出现无法归因的失败。每张会推送的卡在 `Full-suite trigger` 字段登记 `none` 或 `T-<n>: <依据>`。
14. **ER-14 全量测试执行器与 VM 测试门槛:** 全量门用 `cargo test`（含 `tests/**` 的 VM 集成测试）。**VM 集成测试只能在满足前提的 Linux 宿主机上运行**（KVM 或 TCG + QEMU + libvirt + xorriso + `qemu-bridge-helper` 已配置）。CI 上只有 `cargo test --no-run`（编译门）。计划收口阶段的全量门必须在配置齐全的宿主机上跑通并记录证据；确无该环境时，至少 `cargo test --lib` + `cargo test --no-run` 全绿，并在计划中登记环境缺口为 `DEFER-*`。

## 实施顺序

依赖边格式：`A -> B` 表示 A 必须先于 B。依赖图必须无环，且每条边都指向具体任务卡而不是整个 Phase。

- `<TASK-01> -> <TASK-02>`

### 依赖登记表

本计划外的一切依赖关系（其它日期计划、外部服务、人工审批、上游镜像/release），以及本计划向外移交的范围，都必须在此登记后才能被任务卡引用。

| ID | direction | 类型 | 对象 | Owner | 产物与可用性判据 | 证据 | 超时与失败策略 |
|---|---|---|---|---|---|---|---|
| DEP-01 | `<incoming / outgoing>` | `<跨计划 / 外部服务 / 审批 / 上游 release>` | `<plan-...#TASK-ID 或外部对象>` | `<负责人/系统>` | `<交付什么、如何判定可用>` | `<file:line / commit / URL + 核对日期>` | `<等待上限、超时后降级或回落>` |

### 发布分组与并发窗口

默认每张卡独立发布。只有需要合并发布或显式串行窗口时才登记本表，并在任务卡 `Release boundary` 中引用。

| ID | 成员 | 唯一发布点 | 窗口规则 | 失败回滚顺序 | 理由 |
|---|---|---|---|---|---|
| REL-01 | `<TASK-ID 列表>` | `<TASK-ID>` | `<family child 不单独 bump/publish；唯一发布点执行一次声明的版本递增与发布；窗口期禁止插入其它发布>` | `<按依赖逆序前滚修复>` | `<为何需要协调窗口>` |

**并发声明:** `<实现阶段可并发的卡组（实现写集互不相交）/ 全串行>`

**发布者:** `<负责 C 组 bump/构建/提交/推送/tag/release/publish，并跟踪 D 组证据的唯一 Agent/人>`

### Phase 0: <基线冻结和消歧>

**目标:** `<本阶段目标>`

**进入条件:** `<前置条件>`

**退出条件:** `<阶段完成判据>`

### Phase 1: <实现第一个可发布切片>

**目标:** `<本阶段目标>`

**进入条件:** `<前置条件>`

**退出条件:** `<阶段完成判据>`

## 任务卡

任务 ID 使用稳定前缀（如 `A0-01`、`IMG-02`、`VM-03`）。编号被引用后不重排；拆分出的新卡在所属 Phase 末尾追加新编号。

### 任务卡粒度规则（强制）

新增或修改任务卡时必须逐条满足 `G-*`。任一条不满足即为「粒度不合格」，必须在开工前拆分或合并。

- **G-01 单一行为轴与恢复模式:** 一张卡只承担一个可独立恢复的行为轴。`Rollback mode` 必须是四者之一：`revert`（纯代码/文档，一次 revert 撤销，默认）、`forward-only`（产生不可逆数据/运行目录/镜像缓存变更）、`compensating`（对外部服务已有副作用）、`immutable-release`（已发布 crate 不可撤回，只能发新版本）。
- **G-02 完整可交付:** 同一行为轴的实现、测试、文档与 CHANGELOG 同步是**同一张卡**的验收内容，禁止拆成「实现卡 / 补测试卡 / 补文档卡」。
- **G-03 条目上限:** `Acceptance criteria` 按独立 pass/fail 谓词计，`Verification` 按独立验证门计。上限：`implementation` / `removal` / `spike` 为 8/8；`release` 为 12/12；`docs` / `audit` / `handoff` 为 20/20。ER-04 强制门与 ER-06 同卡文档同步门不计入本卡特有条目。
- **G-04 规模上限:** `Estimated scope` 开工态只允许 `S` 或 `M`。`S` ≤ 2 个行为落点、≤ 3 个生产文件；`M` ≤ 4 个行为落点、≤ 12 个生产文件，仍是单一行为轴。超出即 L，必须拆分；不可拆的机械变更（全仓重命名、格式化、同型 API 机械替换）登记 `L-exception:EX-<n>`。
- **G-05 Agent 可独立执行:** 一张卡不读其它卡正文即可执行：`Current evidence` 有可核对锚点、`Acceptance criteria` 自洽、`Verification` 是可复制命令、`Dependencies` 只引用 `DEP-*` 或任务 ID。
- **G-06 依赖闭合且无环:** 计划内依赖直接引用任务 ID；跨计划与外部前置先登记 `DEP-*`。互相等待、循环依赖、「等某 Phase 完成」都是拆分错误。
- **G-07 发布切片对齐:** 默认「一张卡 = 一个发布切片」（review + ER-04 门 + `patch + 1` + 提交 + 推送 + tag/release/publish）。`docs`/`audit`/`spike`/`handoff` 卡不 bump、不发布，`Release boundary` 写 `no-release`。合并发布必须在「发布分组与并发窗口」登记 `REL-*`。
- **G-08 家族卡:** 当公开 API 删除或破坏性变更确实无法切成可独立发布的切片时，拆成多张子卡共用一个唯一发布点卡（`Task type = release`，不引入新行为）。子卡 `Release boundary` 写 `family child`，发布点卡写 `family release point`。
- **G-09 拆分协议:** 拆分已被引用的卡时，原编号保留给主轴，新子卡在所属 Phase 末尾追加新编号；原卡写「拆出 `<ID>`」，新卡写「自 `<ID>` 拆出」，并同步实施顺序、依赖表、追溯表、测试矩阵、风险表及「修订历史」一行。
- **G-10 写集与并发:** 每张卡声明 `Implementation write set`（I）与 `Release write set`（R）。I 必须包含本卡执行时会写的计划文件、`plan-status.md` 与证据区，不能通过省略共享簿记文件制造“无冲突”。I–I 相交禁止并发（只能补顺序边或合并到唯一集成卡）；I–R 与 R–R 由 ER-12 的串行发布窗口顺序化。并发判定以 I 为准。
- **G-11 任务类型:** `implementation`（默认）、`removal`（公开 surface 删除）、`spike`（探索，不得改生产代码）、`docs`/`audit`（只读或文档收敛）、`release`（发布点卡）、`handoff`（跨计划移交）。Qlean 无数据库，`migration` 不适用；涉及持久化数据布局变化（镜像缓存命名、运行目录布局、secrets 目录）时按 `implementation` + `forward-only` 处理并写明数据不变量。

#### 推荐拆分维度

| 维度 | 切法 | 典型结果 |
|---|---|---|
| API 表面轴 | 内部实现 → 公开 API + README → 示例/测试收口 | 2–3 张卡 |
| 生命周期轴 | 新实现 → 默认启用 → deprecation shim → 删除公开 API | 按发布窗口分卡 |
| 传输/协议轴 | vsock 传输 → SSH 会话 → 上层 exec/fs 接口 | 2–3 张卡 |
| 平台/架构轴 | amd64 目录 → aarch64/riscv64 支持 → 文档矩阵 | 按架构分卡 |

#### 粒度反模式速查

| 反模式 | 症状 | 处理 |
|---|---|---|
| 巨型卡 | `Estimated scope`=L；AC>8；Description 含多个并列目标 | 按「推荐拆分维度」拆分 |
| 碎片卡 | 「补测试」「补文档」单独成卡 | 合并回所属行为轴（G-02） |
| 多轴伪装 | 多条 AC 合成一条长句压到 8 条内 | 按独立谓词还原计数（G-03） |
| 隐式依赖 | Description 写「按 X 卡的约定」而 X 卡未交付 | 写进本卡或提升为 ADR（G-05） |
| 幽灵验收 | `Verification` 只写全量 `cargo test` | 指定 target 与 test fn（G-05） |
| 假回滚 | 已发布/已写数据的卡仍写「一次 revert 撤销」 | 按实际选 `forward-only` 等（G-01） |
| 并发冲撞 | 两张无依赖的卡实现写集相交 | 补顺序边或合并（G-10 不可豁免） |

#### 字段全局默认与例外

计划在本节声明字段全局默认值后，任务卡中取默认值的字段可整行省略或写 `Inherited`。`Task type`、`Lifecycle / Acceptance`、`Rollback mode`、`Implementation write set`、`Version increment`、`C/D coverage from`、`Granularity` 摘要行每卡必填。

- **Release boundary 默认:** `<independent / 其它>`
- **Task type 默认:** `<implementation / 其它>`
- **Rollback mode 默认:** `<revert / 其它>`
- **Security and privacy 默认:** `<继承 GC-07 / 其它>`
- **Performance budget 默认:** `<继承 GC-10 / 其它>`

**规则 waiver（`EX-*`，需具名审批）**：可豁免项为白名单，仅 `G-03 条目上限` 与 `G-04 规模上限`；`G-01/G-02/G-05/G-06/G-07/G-08/G-09/G-10/G-11` 永不可豁免。

| 例外 ID | 任务 | 豁免项 | 理由与补偿措施 | Approver | Review round | 证据 | 有效期 |
|---|---|---|---|---|---|---|---|
| EX-01 | `<ID>` | `<G-03 条目上限>` | `<文档-only 卡；补偿 = 逐文件 checklist>` | `<具名审批人>` | `<R-n>` | `<file:line>` | `<本计划内>` |

#### 任务卡粒度审计表

| 任务 | type | axis | recovery | complete | self-contained | AC | VER | landing / prod-files | scope | deps | writeset | release | split-from | exception |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `<ID>` | `<type>` | `<行为轴>` | `<恢复动作>` | `<yes>` | `<yes>` | `<n/上限[@EX-ID]>` | `<n/上限[@EX-ID]>` | `<n>/<n>` | `<S/M/L-exception:EX-n>` | `<ID/DEP/none>` | `<no-overlap/序列化于 ID>` | `<independent/family child/family release point/no-release>` | `<ID/N/A>` | `<EX-ID/N/A>` |

#### Verification 判定口径

- 零命中守卫必须区分「无命中」与「命令失败」：`rg` 退出码 `0`=有命中、`1`=零命中、`>1`=执行失败。使用三段式模板：

  ```bash
  if rg -n "<pattern>" <paths>; then
    echo "FAIL: forbidden pattern found"; exit 1
  else
    rc=$?
    if [ "$rc" -ne 1 ]; then echo "ERROR: rg failed with exit $rc"; exit "$rc"; fi
    echo "OK: zero hits"
  fi
  ```

- 仅用于定位符号的 `rg` 必须注明「锚点定位用，非判据」。
- 本任务新增的 test fn 必须标 `(new)`，并确保其所属 `--test` target 已存在。
- VM 集成测试（`tests/**`）必须注明宿主机前提（KVM/TCG + QEMU/libvirt/xorriso/bridge-helper），并给出执行命令；环境不满足时写 `cargo test --no-run` 作为最低编译门并登记环境缺口。

### Task <ID>: <任务标题>

**Task type:** `<implementation | removal | spike | docs | audit | release | handoff>`（G-11）

**Lifecycle / Acceptance:** `<pending | in-progress | blocked | done>` / `<空 | locally-accepted | remote-pending | complete>`（ER-04）

**Description:** `<要做什么、为什么、现实影响。一句话点明本卡唯一的行为轴。>`

**Out of scope:** `<逐项列出本卡明确不做的内容，每项标注状态：「由 <ID> 承接」/「尚未排期，重启条件 …」/「永久非目标，理由 …」。>`

**Current evidence:**

| 事实 | 证据 |
|---|---|
| `<当前实现或缺口>` | `<file:line / test / external repo@sha>` |

**Acceptance criteria:**

- [ ] `<用户可见或系统行为判据>`
- [ ] `<机器输出/错误/状态判据>`
- [ ] `<失败路径/边界条件判据>`
- [ ] `<ER-06 同卡强制门：README/CHANGELOG 中每个受影响文档已交付并逐文件验收；不计入任务卡特有 AC 上限>`

**Verification:**

- [ ] `<exact command>`
- [ ] `<manual/sanitized evidence, if required>`

**Full-suite trigger:** `<none | T-<n>: <命中依据> | N/A（no-release / family child）>`（ER-13）

**Dependencies:** `<无 / 本计划 Task ID + 消费的具体产物 / 「依赖登记表」中的 DEP-ID>`（G-06）

**Deliverables:** `<docs / audit / spike / handoff 卡必填：产物文件清单。代码卡写 N/A。>`

**Implementation write set:** `<承载本卡行为的代码/测试/文档文件或目录；ER-06 命中的文档须逐文件列出。>`（G-10）

**Release write set:** `<Inherited（= Cargo.toml 版本 + Cargo.lock + CHANGELOG.md）/ N/A（family child / no-release）>`

**Files likely touched:** `<src/...>, <tests/...>, <README.md>, <CHANGELOG.md>`（估计值；并发判定以 `Implementation write set` 为准）

**Docs and compatibility impact:** `<每卡必填：逐文件列出 README.md / CHANGELOG.md 及受影响的示例/测试；或 N/A + 理由>`

**Rollback mode:** `<revert | forward-only | compensating | immutable-release>`（G-01）

**Security and privacy:** `<N/A 或权限、密钥、路径、bridge 约束>`

**Performance budget:** `<N/A 或数据规模、复杂度、wall-clock/benchmark 断言>`

**Estimated scope:** `<S / M / L-exception:EX-<n>>`（G-04）

**Version increment:** `<patch（默认：PATCH + 1）| minor | major | N/A>`（ER-08）

**Release boundary:** `<independent | family child of REL-<n> | family release point of REL-<n> | no-release>`（G-07/G-08）

**C/D coverage from:** `<self | <TASK-ID>（继承该发布点的 C/D 覆盖）>`（ER-04）

**Granularity:** `type=<Task type>; axis=<本卡唯一的行为轴>; recovery=<单一恢复动作>; complete=<yes>; self-contained=<yes>; AC=<n>/<上限>[@EX-ID]; VER=<n>/<上限>[@EX-ID]; landing=<n>; prod-files=<n>; scope=<S|M|L-exception:EX-n>; deps=<none|TASK-ID,…|DEP-ID,…>; writeset=<no-overlap|序列化于 TASK-ID>; release=<independent|family child|family release point|no-release>; split-from=<TASK-ID|N/A>; exception=<EX-ID|N/A>`

## 测试矩阵

本表登记「本计划最终必须被覆盖到什么」，不是「每张卡都要跑完整张表」。执行阶段按 ER-13 只跑相关行；整张表由收口阶段的全量门统一覆盖。

| 类别 | 必须覆盖 | Target / command |
|---|---|---|
| 单元 | `<纯逻辑、hash、CID、parser、state machine>` | `<cargo test --lib>` |
| 集成 | `<真实 VM 工作流（exec/upload/download/network）>` | `<cargo test --test single_machine 等>` |
| 多机 | `<machine pool、多 VM 网络互 ping>` | `<cargo test --test machine_pool>` |
| 多发行版 | `<Debian/Ubuntu/Fedora/Arch 镜像冒烟>` | `<cargo test --test muti_distro>` |
| 性能 | `<hash 流式计算吞吐>` | `<cargo bench --bench hash_benchmark>` |
| 编译门槛 | `<无 KVM 环境下的编译检查>` | `<cargo test --no-run>` |

## 追溯表

| 任务 | 来源/证据 | 代码落点 | 文档/CHANGELOG 动作 | 指定测试 |
|---|---|---|---|---|
| `<ID>` | `<file:line / issue / repo@sha>` | `<src/tests>` | `<README, CHANGELOG>` | `<target::test_fn>` |

## 里程碑验收与回滚

| 里程碑 | 完成条件 | 发布/证据 | 回滚或前滚 |
|---|---|---|---|
| M0 | `<基线冻结>` | `<commit/test/doc>` | `<N/A>` |
| M1 | `<首个可发布切片>` | `<version/test/review>` | `<rollback/forward fix>` |

### 故障恢复矩阵

| 故障点 | 可接受残留 | 恢复动作 | 禁止结果 |
|---|---|---|---|
| `<CID 分配后、QEMU 启动前>` | `<cid 文件/运行目录>` | `<清理运行目录重试>` | `<CID 冲突/遗留 QEMU 进程>` |

## 风险登记

| 风险 | 影响 | 缓解 | 任务 |
|---|---|---|---|
| `<风险>` | `<高/中/低 + 影响>` | `<测试/设计/门禁>` | `<ID>` |

## 性能与容量摘要

| 操作 | 单次成本 | 累积成本 | 预算/上限 | 验证 |
|---|---|---|---|---|
| `<操作>` | `<O(...)>` | `<O(...)>` | `<阈值>` | `<测试/benchmark>` |

## 兼容与文档收口

- [ ] `README.md`（Host Setup / API Reference / 示例）已同步，或说明 `N/A`。
- [ ] `CHANGELOG.md`（Keep a Changelog + SemVer）已同步，或说明 `N/A`。
- [ ] `.github/workflows/check-and-test.yml` 已同步，或说明 `N/A`。
- [ ] `tests/INDEX.md`（若存在）已同步，或说明 `N/A`。
- [ ] `LICENSE` 未改动，或说明改动理由。

## Review log

Result 只允许 `PASS` 或 `FAIL`。`FAIL` 必须列出 P0/P1 条目并在下一轮复审关闭；P2 可由具名责任人书面接受为 residual risk。

| Round | Scope | Result | P0/P1 | P2 处置 | Evidence |
|---|---|---|---|---|---|
| R1 | `<files/tasks>` | `<PASS / FAIL>` | `<条目与关闭状态>` | `<修复 / 具名接受人>` | `<test commands / 复审轮次>` |

## 非目标与延后项

| ID | 延后内容 | 原因 | 重启条件 | 承接位置 |
|---|---|---|---|---|
| DEFER-01 | `<内容>` | `<原因>` | `<何时重启>` | `<plan/RFC/ADR>` |

## 完成判据

计划只有在以下条件全部满足后才能标记完成：

- [ ] 所有任务卡满足粒度规则 `G-*`：「任务卡粒度审计表」已填齐，无未登记的 L 例外、无碎片卡、无未登记的合并发布例外、实现写集冲突均已消解。
- [ ] 所有非延后任务的 acceptance criteria 已满足，且 `Lifecycle=done` **且** `Acceptance=complete`（ER-04）。任何停在 `remote-pending` 的卡都必须先取得其 D 组远端后置门的绿色证据；任何 `blocked` 卡必须先解除阻塞或按 `DEFER-*` 正式延后。
- [ ] 所有任务的 Verification 命令已运行并记录结果（含 VM 测试的宿主机环境与命令）。
- [ ] **计划完成门 / 全量收口门（ER-13/ER-14）**：全部任务卡完成后运行一次 `cargo fmt --check`、`cargo clippy --all-targets --all-features -- -D warnings`、`cargo test`（含 `tests/**`，在配置齐全的 Linux 宿主机上；无该环境时至少 `cargo test --lib` + `cargo test --no-run` 全绿并登记环境缺口 `DEFER-*`）。
- [ ] 全量收口门暴露的 Bug 已全部处理：本计划引入的失败已前滚修复并重跑全量至全绿；判定为既有失败的用例已附基线复现证据并登记 `DEFER-*`。
- [ ] 必要的 README / CHANGELOG / CI 更新已完成。
- [ ] 每张卡的 `Rollback mode` 都已被实际验证或记录为不可验证的原因。
- [ ] Review 最终结论为 `PASS`，P0/P1 全部关闭。
- [ ] 如有发布要求：本卡已 `patch + 1`（或声明的 minor/major）、`Cargo.lock` 仅由工具链刷新、CHANGELOG 已更新、tag/GitHub Release/crates.io 发布已取得证据（ER-08）。
- [ ] 「修订历史」已记录成稿后的全部规范性变更（G-09）。
- [ ] `plan-status.md` 已与任务卡同步状态、发布版本/commit、每卡 UTC 时间以及全部 DEFER/DEP；不存在只改计划正文而遗漏状态视图的情况。
- [ ] 本计划未新建证据文件或证据文件夹；验收摘要、命令输出、哈希、CI run ID/URL 都写在本计划文件内。
