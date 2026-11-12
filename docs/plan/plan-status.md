# 计划执行状况单一视图

本文是 `docs/plan/` 下全仓计划的单一执行状况视图，按任务卡粒度汇总每份计划的状态，并登记计划内延后决策/实施项（`DEFER-*`）与外部/跨计划依赖。

> 更新规则（见 `plan-template.md`）：任何 Agent 在完成或推进一张任务卡时，必须在同一变更中同步更新本文件（状态、发布版本/commit、该卡的 `YYYY-MM-DD HH:MM:SS UTC`）。冲突时以任务卡自身 `Lifecycle / Acceptance` 为准，并立即修正本视图。

## 计划一览

| 计划 | 主题 | 状态 | 目标分支 | 目标版本 | 最近更新时间 |
|---|---|---|---|---|---|
| [`plan-20261104-windows-guest.md`](plan-20261104-windows-guest.md) | Windows 客户机支持 | `in-progress`（R5 环境消歧：`SPK-01`/`SPK-02` 因 DEP-01/02 不可用而 `blocked`；实现卡在临时接受的 ADR 上推进，`OSX-01` 完成、`OSX-02`/`OSX-03`/`TRN-01`/`EXE-01`/`IP-01`/`FS-01` 本地验收，`REL-01` 阻塞；R6 实施后逐卡 review PASS；R7 结构/状态一致性复核 PASS；R8 修复首启连接预算与首启失败清理；R9 修复 vsock 设备分派/OVMF 配对规则/swtpm socket 权限/Secure Boot vars 模板/xorriso 前置；R10 修复 `copy` 的 PowerShell 二次解析；R11 修复失败启动无法重试；R12 让 lease 发现与 QEMU 退出 race、跳过盘根创建） | `main` | 0.4.0（minor；公开结构体字面量构造的源码兼容破坏） | 2026-11-12 17:00:00 UTC |

## 任务卡状态

### plan-20261104-windows-guest.md

| 任务 | type | Lifecycle | Acceptance | 依赖 | 发布版本 / commit | 最近更新时间 | 备注 |
|---|---|---|---|---|---|---|---|
| SPK-01 | spike | blocked | 空 | DEP-01, DEP-02 | — / — | 2026-11-12 07:45:12 UTC | 传输可行性；DEP-01/02 不可用（无 QEMU/无 Windows 镜像）；ADR-WIN-02 已临时接受 TCP |
| SPK-02 | spike | blocked | 空 | SPK-01, DEP-01, DEP-02 | — / — | 2026-11-12 07:45:12 UTC | 引导/部署可行性；DEP-01/02 不可用；ADR-WIN-03 已临时接受首启 seed 盘 |
| OSX-01 | implementation | done | complete | 无（R5 取消 SPK-02 边） | 继承 REL-01 / `50c8cff`（DEFER-04：Linux 全量门环境缺口） | 2026-11-12 08:40:00 UTC | GuestOs 抽象与镜像校验；串行起点；T-1 全量门登记 DEFER-04 |
| OSX-02 | implementation | in-progress | locally-accepted | SPK-02, OSX-01 | 继承 REL-01 / `f2fc277`（DEFER-04） | 2026-11-12 09:35:00 UTC | OVMF/TPM/swtpm 与生命周期；C 门 `blocked`（无 Windows 镜像与 KVM 宿主）；R4 补资源默认值 AC |
| OSX-03 | implementation | in-progress | locally-accepted | OSX-02 | 继承 REL-01 / `8812fb4`（DEFER-04） | 2026-11-12 16:30:00 UTC | pre-generalized 镜像 + 每 VM seed 介质；C 门需 TRN-01 与 DEP-01/02，`blocked` |
| TRN-01 | implementation | in-progress | locally-accepted | SPK-01, OSX-03 | 继承 REL-01 / `6711671`（DEFER-04） | 2026-11-12 17:00:00 UTC | TCP 传输 + MAC/lease 地址发现 + host key pinning 已实现；vsock 仅 Linux 需要；`windows_transport`/`windows_pool` 与真实 spawn 重连 `blocked`（DEP-01/02） |
| EXE-01 | implementation | in-progress | locally-accepted | TRN-01 | 继承 REL-01 / `64b1046`（DEFER-04） | 2026-11-12 12:10:00 UTC | PowerShell 原文 + 退出码契约（`src/exec.rs`）；顺带修正非 0 退出被报为 success 的既有缺陷；真实 `windows_exec` 冒烟 `blocked`（DEP-01/02） |
| IP-01 | implementation | in-progress | locally-accepted | EXE-01 | 继承 REL-01 / `eb8fd90`（DEFER-04） | 2026-11-12 12:50:00 UTC | 缓存优先 + PowerShell 查询按本 VM MAC 消歧；真实 `windows_get_ip`/双机一致性 `blocked`（DEP-01/02） |
| FS-01 | implementation | in-progress | locally-accepted | IP-01 | 继承 REL-01 / `443ec5d`（DEFER-04） | 2026-11-12 17:00:00 UTC | `GuestPath` 唯一转换层 + Windows 文件语义与 unsupported 分支；真实 `windows_files`/Linux 回归 `blocked` |
| REL-01 | release | blocked | 空 | SPK-01, SPK-02, OSX-01, OSX-02, OSX-03, TRN-01, EXE-01, IP-01, FS-01 | 0.4.0 / — | 2026-11-12 13:30:00 UTC | 唯一发布点；`SPK-01`/`SPK-02` 与全部真实 Windows KVM 冒烟 `blocked`（DEP-01/02），Linux 全量门 `blocked`（DEFER-04），故不 bump/tag/发布 |

## 延后项与外部/跨计划依赖

| ID | 类别 | 计划 | 内容 | 状态 | 重启/解除条件 | 最近更新时间 |
|---|---|---|---|---|---|---|
| DEFER-01 | 延后 | plan-20261104-windows-guest.md | Windows 内置镜像目录（当前许可约束） | open | 出现可合法再分发的镜像源 | 2026-11-04 04:10:47 UTC |
| DEFER-02 | 延后 | plan-20261104-windows-guest.md | Windows on ARM（aarch64 客户机） | open | 出现真实需求且固件/驱动生态经过验证 | 2026-11-04 04:10:47 UTC |
| DEFER-03 | 延后 | plan-20261104-windows-guest.md | Windows TCG 冒烟矩阵（不替代 KVM 核心验收） | open | 出现真实 TCG 需求并有可接受的启动时限 | 2026-11-04 04:10:47 UTC |
| DEP-01 | incoming | plan-20261104-windows-guest.md | 每个拟声明支持的 Windows 版本的合法 qcow2 + sha256 | open（2026-11-12 审计未提供） | Owner 提供镜像、版本和校验值 | 2026-11-12 07:45:12 UTC |
| DEP-02 | incoming | plan-20261104-windows-guest.md | Linux KVM Windows 验证宿主机及 QEMU/OVMF/swtpm/libvirt/xorriso/bridge-helper | open（2026-11-12 审计：工具全缺，`sudo` 需密码） | Owner 验证全部前置命令、KVM 与桥接网络可用 | 2026-11-12 07:45:12 UTC |
