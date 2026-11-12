# 计划执行状况单一视图

本文是 `docs/plan/` 下全仓计划的单一执行状况视图，按任务卡粒度汇总每份计划的状态，并登记计划内延后决策/实施项（`DEFER-*`）与外部/跨计划依赖。

> 更新规则（见 `plan-template.md`）：任何 Agent 在完成或推进一张任务卡时，必须在同一变更中同步更新本文件（状态、发布版本/commit、该卡的 `YYYY-MM-DD HH:MM:SS UTC`）。冲突时以任务卡自身 `Lifecycle / Acceptance` 为准，并立即修正本视图。

## 计划一览

| 计划 | 主题 | 状态 | 目标分支 | 目标版本 | 最近更新时间 |
|---|---|---|---|---|---|
| [`plan-20261104-windows-guest.md`](plan-20261104-windows-guest.md) | Windows 客户机支持 | `in-progress`（R5 环境消歧：`SPK-01`/`SPK-02` 因 DEP-01/02 不可用而 `blocked`；实现卡在临时接受的 ADR 上推进，`OSX-01` 已完成，`REL-01` 阻塞） | `main` | 0.4.0（minor；公开结构体字面量构造的源码兼容破坏） | 2026-11-12 08:40:00 UTC |

## 任务卡状态

### plan-20261104-windows-guest.md

| 任务 | type | Lifecycle | Acceptance | 依赖 | 发布版本 / commit | 最近更新时间 | 备注 |
|---|---|---|---|---|---|---|---|
| SPK-01 | spike | blocked | 空 | DEP-01, DEP-02 | — / — | 2026-11-12 07:45:12 UTC | 传输可行性；DEP-01/02 不可用（无 QEMU/无 Windows 镜像）；ADR-WIN-02 已临时接受 TCP |
| SPK-02 | spike | blocked | 空 | SPK-01, DEP-01, DEP-02 | — / — | 2026-11-12 07:45:12 UTC | 引导/部署可行性；DEP-01/02 不可用；ADR-WIN-03 已临时接受首启 seed 盘 |
| OSX-01 | implementation | done / complete | 34c6eb9 | 无（R5 取消 SPK-02 边） | 继承 REL-01 / DEFER-04（Linux 全量门环境缺口） | 2026-11-12 08:40:00 UTC | GuestOs 抽象与镜像校验；串行起点；T-1 全量门登记 DEFER-04 |
| OSX-02 | implementation | pending | 空 | SPK-02, OSX-01 | 继承 REL-01 / — | 2026-11-12 07:20:33 UTC | Windows 固件与 QEMU 生命周期；R4 补资源默认值 AC |
| OSX-03 | implementation | pending | 空 | OSX-02 | 继承 REL-01 / — | 2026-11-12 07:20:33 UTC | Windows 首次部署；具体方案待 SPK-02 回写；R4 补部署超时 AC |
| TRN-01 | implementation | pending | 空 | SPK-01, OSX-03 | 继承 REL-01 / — | 2026-11-04 04:10:47 UTC | Windows 传输、地址发现与主机密钥校验 |
| EXE-01 | implementation | pending | 空 | TRN-01 | 继承 REL-01 / — | 2026-11-04 04:10:47 UTC | PowerShell exec 语义 |
| IP-01 | implementation | pending | 空 | EXE-01 | 继承 REL-01 / — | 2026-11-04 04:10:47 UTC | get_ip 语义；序列化于 EXE-01 |
| FS-01 | implementation | pending | 空 | IP-01 | 继承 REL-01 / — | 2026-11-04 04:10:47 UTC | 文件路径与文件操作语义；序列化于 IP-01 |
| REL-01 | release | pending | 空 | SPK-01, SPK-02, OSX-01, OSX-02, OSX-03, TRN-01, EXE-01, IP-01, FS-01 | 0.4.0 / — | 2026-11-04 04:10:47 UTC | 唯一发布点；已吸收 DOC-01 的收口审计 |

## 延后项与外部/跨计划依赖

| ID | 类别 | 计划 | 内容 | 状态 | 重启/解除条件 | 最近更新时间 |
|---|---|---|---|---|---|---|
| DEFER-01 | 延后 | plan-20261104-windows-guest.md | Windows 内置镜像目录（当前许可约束） | open | 出现可合法再分发的镜像源 | 2026-11-04 04:10:47 UTC |
| DEFER-02 | 延后 | plan-20261104-windows-guest.md | Windows on ARM（aarch64 客户机） | open | 出现真实需求且固件/驱动生态经过验证 | 2026-11-04 04:10:47 UTC |
| DEFER-03 | 延后 | plan-20261104-windows-guest.md | Windows TCG 冒烟矩阵（不替代 KVM 核心验收） | open | 出现真实 TCG 需求并有可接受的启动时限 | 2026-11-04 04:10:47 UTC |
| DEP-01 | incoming | plan-20261104-windows-guest.md | 每个拟声明支持的 Windows 版本的合法 qcow2 + sha256 | open（2026-11-12 审计未提供） | Owner 提供镜像、版本和校验值 | 2026-11-12 07:45:12 UTC |
| DEP-02 | incoming | plan-20261104-windows-guest.md | Linux KVM Windows 验证宿主机及 QEMU/OVMF/swtpm/libvirt/xorriso/bridge-helper | open（2026-11-12 审计：工具全缺，`sudo` 需密码） | Owner 验证全部前置命令、KVM 与桥接网络可用 | 2026-11-12 07:45:12 UTC |
