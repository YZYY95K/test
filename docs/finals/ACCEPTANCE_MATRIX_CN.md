# DevFlow 决赛验收矩阵

核验日期：2026-07-29。本文只使用当前公开的 GOAI Agent Infra 规则；组委会
尚未公开的答辩时长、PPT 页数/大小、线上提交时刻、现场网络和设备条件均标为
未确认，不作推断。

## 决赛事实与必交物

- 决赛：2026-09-22，杭州线下答辩与展示；GOAI DAY / 颁奖为 2026-09-23。
- 决赛必交：决赛路演 PPT/PDF、现场 Demo、最终可访问代码仓库或等价工程包。
- 最终工程材料至少应包含 README、部署说明、开源协议、示例配置和测试方法。
- AgentTeams 是协同设计基点，Skill 是必选项；MCP、RAG、可观测是推荐项，
  不能把“接入数量”当作加分依据。
- 记忆、知识库 RAG、共享状态、轨迹可观测四项至少真实实现两项。

## 官方评分与当前证据

状态：`可验收` 表示仓库内已有可重跑证据；`局部` 表示实现存在但缺少决赛级
现场或统计证据；`未放行` 表示不得对外宣称完成。

证据统一分为四层：**本地已验证**、**候选/部署预检**、**2026-07-27/28
历史现场**、**当前版本待服务器实证**。历史现场不能继承给未部署的 v2.1.0，
本地集成与部署预检也不能拼接为真实 AgentTeams 六阶段。

| 维度 | 权重 | 当前状态 | 已有可定位证据 | 决赛放行条件 |
|---|---:|---|---|---|
| 场景价值与行业可复制性 | 25% | 局部 | 软件研发全流程与官方方向三直接匹配；3 个开源仓库固定 commit/tree/license；21 个仓库修复任务具有来源、命令、路径和哈希清单；另有 24 项路由/边界基准 | 在隔离 checkout 中真实执行 21 项修复任务；报告成功率、成本、P50/P95 时延、安全率、人工介入率及失败分类；当前 `attempted=0`、`executed=0`、`success_rate=null`，不得写成修复成功率 |
| 多 Agent 协同与自主闭环 | 25% | 局部 | 1 个 TeamLeader + 5 个专业 Worker；本地确定性 AgentTeams/TeamHarness 一致性夹具在受控后端验证 21 次 `message.send` 调用并覆盖 `FAILED → replan`、幂等与冲突拒绝，但尚未在线上 Room 执行，实际模型调用为 0 且没有仓库 checkout；SQLite 跨进程租约和哈希链；历史真实 T4 项目已暂停并证明无签名恢复被拒 | 同一真实 AgentTeams 项目由各 Worker 产生六阶段结果，留存 Team Room、Tester→Coder 失败闭环、T4 外部真人精确确认→签名→恢复、最终经验沉淀与正式录屏；不得把一致性夹具拼接为自主仓库闭环 |
| Skill 工程体系与生态复用 | 25% | 局部 | 7 个 Skill 具备版本化目录、触发/拒绝说明、契约、独立验证器和确定性包；失败统一为 `SkillFailure` 并只回 TeamLeader；语义验证器、Ed25519 GitHub receipt，以及候选独立 CI 的签发/TeamHarness 验签合同已完成本地正负例测试；当前 Leader Pod 内完全相同的 JTI 与接受请求/结果绑定可幂等读回，冲突绑定拒绝，不确定权威状态保持 `pending` 并 fail closed；ledger 不跨 Pod replacement，回执 120 秒过期 | 将最终全量门绑定同一 commit；把未发布 v2.1.0 角色包和独立 Tester CI 部署并读回；使用持久原子 verifier 补跨 Pod replacement 的重放门；在至少两个固定仓库重放核心 Skill；补当前版本的外部模型成对行为评估。结构 100/100 只代表结构门，不作语义质量结论 |
| 工程落地、运行验证与安全可审计 | 20% | 局部 | 历史 portable profile 有真实隔离测试服务记录；当前 AgentTeams Tester CI 是仅本地测试的候选。仓库另有 MCP 默认拒绝、RAG 租户/仓库/精确 revision 双重隔离和 HMAC 鉴别、路由/审批哈希链；本地离线 Demo 输出真实 SQLite 协作账本，本地测试收到 OTLP/gRPC loopback 网络回执与 Prometheus HTTP 抓取，并闭合 portable FastMCP、凭据代理、回滚健康检查、原子状态和审计链 | 在干净服务器重放同一集成并留存当前 Tester MCP receipt、外部 collector/抓取/提供商 receipt；T4 真人签名闭环；全量测试和覆盖率绑定最终 commit。本地 loopback、历史 portable 服务和部署预检都不等于当前 AgentTeams 生产集成成功 |
| 开放 / 开源贡献 | 5% | 局部 | Apache-2.0、README、贡献/安全文档、契约、样例和固定 `v1.3.0` 初赛标签 | 决赛 commit/tag、源码包、PPT/PDF、测试报告、依赖许可/SBOM、SHA-256 完全一致；公共仓库匿名可访问；确认第三方素材与商业 API 边界 |

## 官方闭环逐项映射

AgentTeams 的五项强制映射已单独固化为
[`docs/submission/AGENTTEAMS_MAPPING_CN.md`](../submission/AGENTTEAMS_MAPPING_CN.md)。
其中明确区分 Manager/Team/Worker、Team Room/Worker Room、taskflow 等框架原生
能力与 `HandoffEnvelope`、持久路由账本、签名审批等 DevFlow 扩展，避免把
“使用框架名称”误写为“完成协同设计”。

| 官方环节 | 唯一责任边界 | 机器可验收证据 | 当前状态 |
|---|---|---|---|
| 任务输入 | TeamLeader 接收，Triage 只分类 | `IssueIntake → ClassifiedIssue` 契约与父摘要 | 可验收 |
| 任务拆解 | 仅 TeamLeader 编排 | 角色定向 `task.route.*`、不可变任务 ID/摘要 | 可验收 |
| 上下文传递 | Worker 只接收所属 Skill 的最小输入 | `HandoffEnvelope`、精确 consumer/producer、父路由绑定 | 可验收 |
| 工具调用 | Skill 表达能力；MCP 表达外部工具 | Agent∩Skill 双授权、服务端签名上下文、参数边界 | 局部，缺现场全链 receipt |
| 结果验证 | Tester 设计上运行隔离 CI；TeamLeader 校验 attestation | 本地 portable 副本测试与候选 AgentTeams CI 合同覆盖基线/候选清单、策略摘要、隔离路径、回归事实 | 可验收（本地合同）；当前独立 CI Pod 待服务器实跑 |
| 执行证据 | 调度权威与各集成分别留证 | SQLite 路由租约、18 条离线 Demo 哈希链、MCP 审计、本地真实 OTLP/gRPC receipt 与 Prometheus HTTP scrape | 局部，仍缺干净服务器和外部 collector/看板证据 |
| 审批与发布边界 | Reviewer 只能请求；外部 Human Authority 才能授权；Leader 只验证和消费；当前发布禁用部署与回滚 | 精确 `HumanApprovalTarget`、新鲜签名、一次性消费、终态 receipt，以及无 deploy/rollback grant 的配置读回 | 可验收（本地）；真实 AgentTeams 签名恢复未放行 |
| 经验沉淀 | Reviewer 的 `experience-distiller`，仅接受已验证终态包 | `VerifiedRunBundle → ExperiencePattern`，含测试/审批摘要 | 可验收（本地） |

## 决赛发布阻断项

- [ ] 21 个固定仓库任务真实执行且原始结果可复跑。
- [ ] 真实 AgentTeams 六阶段成功、测试失败重试和 T4 签名恢复三条演示链。
- [ ] 干净服务器 OTLP collector、Prometheus 抓取和 AgentTeams Tester MCP receipt；
  便携回滚库只作为禁用边界/本地故障测试，不宣称当前发布具备回滚授权。
- [ ] 干净 Linux 主机按文档一次安装成功，另有完全离线备用 Demo。
- [ ] 全量测试、覆盖率、7 Skill 验证、基准清单均绑定同一最终 commit。
- [ ] 决赛 PPT/PDF、现场脚本、Agent Identity、答辩题库、最终仓库一致。
- [ ] 最终 tag、SBOM、第三方许可证、源码包和材料 SHA-256 固定。
- [ ] 官网/邮件/社群公布现场细则后，补答辩时长、文件限制和设备要求。

本轮 PPT/PDF 的结构、来源、模板忠实度、逐页渲染与可重建性结果见
[`MATERIAL_QA_20260728.md`](MATERIAL_QA_20260728.md)；该记录不代表最终 commit/tag 已冻结。

任何一项未完成时，可以陈述“已有实现与局部证据”，但不得写成“决赛已完成”或
“保证夺冠”。

## 官方来源

- [Agent Infra 官方赛道页](https://www.goaihz.com/tracks?track=infra)：技术要求、
  阶段材料、赛程、评分权重与赛道专项说明。
- [赛事 FAQ](https://www.goaihz.com/faq)：现场参赛、商业 API、开放边界及通知口径。
- [官方参赛指南](https://www.goaihz.com/guide)：仓库、Demo、开源协议和依赖披露。
- [Agent Infra 官方手册 PDF](https://oss.goaihz.com/prod/20260720/6e21b053-f18b-4857-83e2-835bd96d5434.pdf)：
  Agent Identity 附录等手册材料；引用具体字段前仍需逐页核对。
