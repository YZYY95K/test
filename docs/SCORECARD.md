# GOAI 2026 Agent Infra 官方评分对齐

核对基准：2026-07-28。官方来源：[Global Open-source AI Challenge —
Agent Infra](https://www.goaihz.com/tracks)。初赛截止日期为 **2026-08-16**；
正式提交时仍应以报名页面显示的时区、文件大小和字段限制为准。

## 官方规则摘要

| 评分维度 | 权重 | DevFlow 当前可引用证据 | 尚不能宣称 / 最高优先级缺口 |
|---|---:|---|---|
| 场景价值 | 25% | 面向真实软件仓库的问题处理；三个固定版本开源仓库、24 项路由与边界任务，历史实测 24/24 精确决策、6/6 安全决策；另有 21 个 execution-ready mutation fixtures 完成 baseline pass→mutation fail→restore pass 的确定性预验证 | 24 项是协作/边界基准，21 项只是任务夹具预验证；Agent 对 21 项的 attempted/executed 均为 0，二者都不是完整补丁解决率 |
| 多 Agent 协同 | 25% | 1 个 TeamLeader + 5 个专业 Worker；仓库本地集成测试已覆盖受控 Leader→Router→Worker 路由、结构化失败事件、同一路由并发去重审计，以及验证失败与测试失败共享的 Coder 全局三次模型调用预算；Reviewer 拒绝由 TeamLeader 校验后 fail-closed；2026-07-27/28 历史 AgentTeams 现场另已观察机器人交接、两节点项目完成、结果验收和 Worker 冒充 Leader 被拒绝，并完成一次 fresh、operator-driven 的 T2 GitHub 边界任务；T4 已暂停且无批准恢复被拒 | 本地失败恢复测试不是 AgentTeams Team Room 现场证据；历史 T2 也只是一项固定范围边界任务，不代表当前 v2.1.0、整体成功率或六阶段修复闭环；Tester→Coder 现场失败回传、T4 真人签名后恢复和正式录屏仍待完成 |
| Skill 工程 | 25% | 7 个 Skill，均有契约、触发/拒绝规则、验证器和所属角色；六个 v2.1.0 候选角色包已在本地确定性重建并通过源码重放校验；2026-07-27 的 v1.2.0 包另有集群摘要/字节实证，`final4.4` 当时将固定七项策略收敛到控制器归档缓存、控制器持久 Skill 缓存、Worker 本地树和 MinIO，独立检查为 0 drift | v2.1.0 尚未部署，不能继承 v1.2.0 的集群实证；GLM-5.2 成对行为评测只覆盖早期 6 个 Skill；`devflowPolicyVerified=true` 仅覆盖固定七项，不能扩写成未知/平台 Skill 的完整边界或强 OS 隔离 |
| 工程运行、安全与审计 | 20% | 仓库实现包含默认拒绝的 Agent + Skill + MCP 权限交集、单一 Tester `run_tests` 动作、SQLite 调度路由账本与哈希审计、RAG/记忆、OTLP 导出和 Prometheus 端点；本地集成验证 OTLP/gRPC collector 网络回执、Prometheus HTTP 抓取、便携 FastMCP 测试链及凭据代理；AgentTeams Tester 候选代码进一步固定 handoff、revision、workspace、隔离策略和 120 秒 Ed25519 回执合同，签发/验签与故障路径仅有本地测试 | 当前 AgentTeams 未授权通用流水线、部署或回滚；独立 Streamable HTTP Tester CI Deployment 仅支持镜像固定仓库与两条决赛演示 assignment，仍待镜像、Bubblewrap、CNI 和真实 E2E 取证。当前 Leader Pod 内完全相同的 JTI/接受请求/结果绑定可幂等读回，冲突绑定拒绝，不确定状态保持 `pending` 并 fail closed；Pod replacement 会丢历史。Worker replay slot、部分失败去重/预算仍含进程内状态，外部副作用不是分布式 exactly-once；loopback collector 不能外推为生产现场；同 UID 仍有 TOCTOU 风险且 `strongBoundaryEnforceable=false`；完整 T4 签名批准、更广泛仓库证据和正式视频仍待补齐 |
| 开放与开源 | 5% | Apache-2.0、README、贡献说明、可复现脚本和接口文档已在工程中 | 提交前需确认公开仓库可访问、固定发布标签/commit、依赖清单与最终代码包一致；不要把本地仓库等同于已公开发布 |

官方基础约束：至少 3 个 Agent；以 AgentTeams 为协同基点；Skill 为必选项；
RAG、记忆、共享状态、轨迹观测四项中至少实现两项。DevFlow 的设计满足这些
结构性要求：六个 Agent 角色、七个 Skill，并同时具备 RAG、经验记忆、共享任务
状态和轨迹/指标观测。结构满足不等于对应评分已拿满，评分仍取决于现场证据质量。

本文统一使用四层证据：**本地已验证**、**候选/部署预检**、
**2026-07-27/28 历史现场**、**当前版本待服务器实证**。不同层级不得拼接为
同一条已经发生的生产闭环。

## 证据成熟度检查

- [x] 六个非同质角色及职责边界已文档化。
- [x] AgentTeams 是协同与部署基点，且已有真实运行记录。
- [x] 七个 Skill 是可独立验证的工程资产。
- [x] RAG、经验记忆、共享状态、轨迹/指标观测至少四项可在工程中定位。
- [x] 三仓库 24 项边界基准有固定 revision 和哈希绑定结果。
- [x] 真实 AgentTeams 两节点项目完成、机器人通信与越权拒绝有记录。
- [x] 2026-07-27 的六个角色专属 v1.2.0 包在集群内按长度和 SHA-256 验证，六个替换 Pod
  Ready；包交付与运行面收敛是两条独立证据。
- [x] 六个 v2.1.0 候选包已在本地确定性重建，摘要、大小、清单和当前源码重放一致；尚未部署到集群。
- [x] 固定七项 DevFlow Skill 策略已在控制器归档缓存、控制器持久 Skill 缓存、
  Worker 本地树和 MinIO 收敛；独立检查为 0 drift，Locator 替换后仍恰有两项
  预期 DevFlow Skill，六个角色 Pod 为 6/6 Ready。该结论不覆盖未知/平台 Skill。
- [x] 真实 Locator 任务因旧 Skill 运行时错配返回 `FAILED`；相同结果重试幂等，
  不同结果重试返回 `submit_result_conflict`。
- [x] 通过直接 stdio/Streamable HTTP 加固路径完成一次 fresh、operator-driven
  的 T2 AgentTeams GitHub 边界任务：validator、首提、幂等重试、冲突拒绝、
  冲突后读回和 Leader `effective` 均通过，项目 `completed` 且 requester report
  `pending=false`；项目同步为 2/2，并分别读回 `meta.json` 与 `plan.md` 的存在性。
- [x] SQLite 调度路由账本已验证跨进程竞争只产生一个租约、过期租约可恢复、
  封存结果和哈希链可重启读回。同一 canonical failure route 的去重、Worker
  replay slot 与 issue-global 1..3 生成预算仍含进程内状态；外部副作用不是
  分布式 exactly-once，也不是服务器 AgentTeams 闭环。
- [ ] 六阶段软件修复在同一个真实 AgentTeams 项目中完成并留存证据。
- [ ] 真实测试失败转换为结构化、脱敏且有界的证据返回 Coder，重试后闭环。
- [x] T4 项目真实暂停，且未提供批准的恢复被稳定拒绝。
- [ ] 人工对精确 T4 摘要签名批准，随后成功恢复；不得用上一项替代。
- [x] GitHub 能力边界已完成固定仓库/版本/路径正例、同 capability 错路径
  403、Reviewer 403 与 Locator 直连 Broker 被 NetworkPolicy 阻断；细节见
  [AgentTeams 现场证据](evidence/AGENTTEAMS_LIVE_20260727.md#scope-bound-github-mcp)。
- [x] 上述 fresh T2 只证明一次固定范围的成功闭环；两个独立 `stat` 仅证明对象
  存在，不是远端字节摘要证明，也不能据此计算或外推整体任务成功率。
- [x] 当前候选工作树已共同完成全量测试、覆盖率、Ruff、严格 mypy、七 Skill 与
  14 项行为结构门：1,330 passed / 24 skipped，覆盖率 84.06%。这些结果尚未绑定
  同一最终 clean commit、CI 与 release attestation，只能作为当前候选本地证据。
- [x] 当前 finals deck 已从正式模板重新生成，PPTX/PDF 均完成 12/12 逐页检查，
  材料哈希与安全检查见 `docs/finals/MATERIAL_QA_20260728.md`；该 QA 仍不代表最终
  clean commit、CI、tag 或比赛平台提交。
- [x] OpenClaw 原生工具边界审计已运行并诚实记录
  `strongBoundaryEnforceable=false` 与六项稳定 blocker。
- [ ] 正式演示视频、正式比赛平台提交回执、新提交包、最终 commit/tag 与上传材料
  完成一致性校验。

## 可用数字与口径

| 项目 | 可对外使用的准确表述 | 不可使用的表述 |
|---|---|---|
| Agent | 六角色：TeamLeader、Triage、Locator、Coder、Tester、Reviewer | “六个 Worker”或把 HumanReviewer 算作自主 Agent |
| Skill | 当前共七个；七个有静态质量门 | “七个都完成 GLM 成对行为评测” |
| 仓库基准 | 三个固定 revision、24 项路由/边界任务 | “24 个真实缺陷全部修复”或“SWE-bench 24/24” |
| AgentTeams | 2026-07-27/28 历史 v1.2.0 部署、两节点生命周期和一次 fresh operator-driven T2 GitHub 边界任务已验证；T2 项目完成、报告不再 pending，提交/重试/冲突/读回/Leader 验收证据齐全；当前 v2.1.0 仍是未部署候选 | “v2.1.0 已部署”“完整六阶段闭环已录制”“整体成功率已由一次 T2 证明”或“全自动自主运行” |
| 结构化失败恢复 | SQLite 调度路由注册、跨进程租约、过期恢复、封存和哈希链可持久；Coder 验证/测试失败共用全局三次模型调用预算，Reviewer 拒绝经 Leader 校验后 fail-closed | “已在真实 AgentTeams 完成 Tester→Coder 闭环”“所有 replay/失败去重均跨进程”“外部副作用 exactly-once”或“Reviewer 拒绝会自动生成安全补丁” |
| 角色 Skill 策略 | v2.1.0 六包已通过本地确定性/源码重放门禁；2026-07-27 的 v1.2.0 包另有 SHA-256/长度及四运行面现场实证 | “v2.1.0 已部署”、把 v1.2.0 现场结果继承给 v2.1.0，或声称未知/平台 Skill 的完整边界和强 OS 隔离 |
| T4 | 真实暂停及无批准恢复拒绝已验证 | “已完成真人签名批准和恢复” |
| GitHub MCP | 固定范围正例、同 capability 错路径 403、Reviewer 403、Locator 直连阻断；fresh T2 的项目同步为 2/2，且 `meta.json`、`plan.md` 均独立确认存在 | “已覆盖任意仓库”、把一次 T2 写成完整修复闭环，或把 `stat exists=true` 写成远端字节摘要证明 |
| OpenClaw 工具边界 | 原生审计结果为 `strongBoundaryEnforceable=false`，六项 blocker 已记录 | “当前具备强 OS 沙箱”或“可抵抗敌对 root” |
| 方案材料 | 当前 12 页 PPTX/PDF 已完成 2026-07-30 本地逐页视觉、模板忠实度、凭据形态与 PDF 安全检查；仍是候选材料 | “当前材料已绑定 clean commit/CI/release attestation”“已在比赛平台正式提交”或“最终 commit/tag/ZIP 已冻结” |
| 覆盖率 | 2026-07-30 当前候选工作树完整运行：1,330 passed / 24 skipped，6,325 statements / 1,008 missed，84.06%；Ruff、143 文件 mypy、编译与配置门同时通过 | 该结果尚待在 clean final commit 上复跑并由 CI/提交包 provenance 绑定；不得沿用旧数字、用聚焦测试数替代，或把本地结果写成官方验收结果 |

## 初赛材料门槛

初赛必交：**500 字以内作品简介**、**方案 PPT 或 PDF**。代码包为可选材料；
如提交，必须能定位运行入口、依赖、配置方式、样例输入/输出与运行证据。当前
外层提交包文件 `02_方案_DevFlow.pptx` 与 `02_方案_DevFlow.pdf` 均为 12 页，
且已完成本地逐页 QA；比赛平台上传、最终 commit/tag 与可选代码包仍是单独的待办。
材料状态由仓库工作文件 `docs/submission/PRELIM_SUBMISSION_CHECKLIST_CN.md` 管理；
该检查表不进入嵌套源码 ZIP，因此这里不创建无法在源码包内解析的相对链接。

## 演示验收边界

只有同时出现以下证据，才可称为“完整软件修复闭环”：原始测试失败、结构化
分类、固定 revision 的定位证据、最小候选补丁、一次性副本测试转绿、Reviewer
结论、经验沉淀、完整事件轨迹，以及 canonical checkout 未被 Worker 修改。
AgentTeams 两节点生命周期、离线 calculator 演示和 24 项边界基准可以分别作为
真实证据，但三者不得拼接成一个并未实际发生的现场闭环。
