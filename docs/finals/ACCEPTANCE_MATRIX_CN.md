# DevFlow 决赛验收矩阵

核验日期：2026-07-28。本文只使用当前公开的 GOAI Agent Infra 规则；组委会
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

| 维度 | 权重 | 当前状态 | 已有可定位证据 | 决赛放行条件 |
|---|---:|---|---|---|
| 场景价值与行业可复制性 | 25% | 局部 | 软件研发全流程与官方方向三直接匹配；3 个开源仓库固定 commit/tree/license；21 个仓库修复任务具有来源、命令、路径和哈希清单；另有 24 项路由/边界基准 | 在隔离 checkout 中真实执行 21 项修复任务；报告成功率、成本、P50/P95 时延、安全率、人工介入率及失败分类；当前 `attempted=0`、`executed=0`、`success_rate=null`，不得写成修复成功率 |
| 多 Agent 协同与自主闭环 | 25% | 局部 | 1 个 TeamLeader + 5 个专业 Worker；本地六阶段真实路由；父路由摘要、状态语义、失败回传、全局三次生成预算；SQLite 跨进程租约和哈希链；本地 T4 精确签名目标、恢复及防重放；AgentTeams guard 在提交和验收前验证 7 个 Skill | 同一真实 AgentTeams 项目留存 Team Room、六阶段状态、Tester→Coder 失败闭环、T4 暂停→外部签名→恢复、最终经验沉淀；正式录屏。当前真实环境只证明过两节点/T2 边界和未批准恢复拒绝 |
| Skill 工程体系与生态复用 | 25% | 局部 | 7 个 Skill 均有精确契约、正反例、独立验证器、所有者、失败状态和安全边界；静态评分 7/7 为 100/100，14 个行为案例结构门通过；AgentTeams 使用固定验证器/契约摘要 | 在至少两个固定仓库重放核心 Skill；记录正例、拒绝例、版本升级和回滚；补当前版本的外部模型成对行为评估。静态 100 分不是实际任务成功率 |
| 工程落地、运行验证与安全可审计 | 20% | 局部 | 真实隔离测试服务与测试完整性证明；MCP 默认拒绝；RAG 租户/仓库/精确 revision 双重隔离和 HMAC 鉴别；路由/审批哈希链；本地离线 Demo 输出真实 SQLite 协作账本；本地测试已收到真实 OTLP/gRPC 网络回执与 Prometheus HTTP 抓取，并闭合 FastMCP、凭据代理、回滚健康检查、原子状态和审计链 | 在干净服务器重放同一集成并留存外部 collector/抓取/提供商 receipt；T4 真人签名闭环；全量测试和覆盖率绑定最终 commit。本地 loopback 成功不等于生产集成成功 |
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
| 结果验证 | Tester 运行隔离 CI；TeamLeader 校验 attestation | 基线/候选清单、策略摘要、隔离路径、回归事实 | 可验收（本地） |
| 执行证据 | 调度权威与各集成分别留证 | SQLite 路由租约、18 条离线 Demo 哈希链、MCP 审计、本地真实 OTLP/gRPC receipt 与 Prometheus HTTP scrape | 局部，仍缺干净服务器和外部 collector/看板证据 |
| 审批与回滚 | Reviewer 只能请求；外部 HumanReviewer 才能授权；Leader 只验证和消费 | 精确 `HumanApprovalTarget`、新鲜签名、一次性消费、终态 receipt | 可验收（本地）；真实 AgentTeams 未放行 |
| 经验沉淀 | Reviewer 的 `experience-distiller`，仅接受已验证终态包 | `VerifiedRunBundle → ExperiencePattern`，含测试/审批摘要 | 可验收（本地） |

## 决赛发布阻断项

- [ ] 21 个固定仓库任务真实执行且原始结果可复跑。
- [ ] 真实 AgentTeams 六阶段成功、测试失败重试和 T4 签名恢复三条演示链。
- [ ] OTLP collector、Prometheus 抓取、真实 MCP receipt 与回滚故障注入证据。
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
