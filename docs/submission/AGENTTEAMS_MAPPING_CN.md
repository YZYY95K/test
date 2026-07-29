# AgentTeams 五项强制映射

核验日期：2026-07-28。GOAI Agent Infra 官方规则明确：初赛以方向与方案设计为主，
不强制提交可运行代码；但多 Agent 设计必须以 AgentTeams（原名 Hiclaw）为协同
基点，说明角色编排、任务拆解、上下文传递、协同执行与状态追踪如何映射到框架
能力。本文只证明这一结构性门槛，不把可选代码包或本地测试当成初赛必交物。

## 一页验收矩阵

| 官方核验项 | DevFlow 方案 | AgentTeams 原生映射 | DevFlow 有界扩展 | 可定位材料 |
|---|---|---|---|---|
| 角色编排 | 1 个 TeamLeader + Triage、Locator、Coder、Tester、Reviewer 5 个专职 Worker；Human Authority 是系统外授权主体，不是第七个 Agent | Manager 创建 Team；Team Leader 统一编排；Worker 在 Team Room 可见、在 Worker Room 执行专职任务 | `Agent ∩ Skill ∩ MCP ∩ scope ∩ state ∩ approval` 权限交集；Worker 不能自称 Leader 或直接分派同伴 | `agentteams/team.yaml`、`config/agents.yaml`、`docs/submission/AGENT_IDENTITY_APPENDIX.md` |
| 任务拆解 | TeamLeader 先建立分类、定位、补丁、测试、审查五个执行节点；仅在测试与审查终态可验后追加第六个经验沉淀节点。只有 Leader 能创建下一条可执行路由 | project / taskflow 表达项目与任务状态；Leader 向目标 Worker 发 assignment，Worker 幂等 ACK | assignment 固定任务 ID、风险等级、Skill、payload type、父路由与摘要；同 ID 不同摘要冲突拒绝；动态第六节点必须绑定 verified terminal receipt | `agentteams/team.yaml`、`src/devflow/agents/team_leader.py`、`src/devflow/collaboration/ledger.py` |
| 上下文传递 | Team Room 只放可见的任务摘要、状态与结果；Worker Room 只接收当前角色所需的最小上下文；大对象不在聊天里复制 | Team Room / Worker Room / Matrix 消息承担协作上下文；Leader 控制 artifact / filesync | `HandoffEnvelope` 绑定 producer、consumer、task、Skill、payload type、digest、trace、idempotency 与 parent route；任一错配即拒绝 | `src/devflow/skills/contracts.py`、`docs/BOUNDARIES_AND_MCP.md`、`docs/AGENTTEAMS.md` |
| 协同执行 | Worker 只运行所属 Skill；结果全部返回 TeamLeader 校验，禁止 Worker 点对点形成第二套状态；测试失败只由 Leader 回送 Coder | assignment → ACK → Worker result → Leader accept/retry；Team Room 展示执行与失败 | `ready` 必须绑定 `SUCCESS`，`retry/blocked` 必须绑定 `FAILED`；Skill 独立验证器与 MCP 服务端策略同时放行 | `agentteams/teamharness/guarded_server.py`、`tests/test_teamharness_skill_semantics.py`、`skills/` |
| 状态追踪 | Leader 跟踪 DAG、预算、重试、冲突、暂停、恢复与终态；完成必须读回 `pending=false` | taskflow / project / room 状态；mark → push → readback；失败和完成状态在 Team Room 可见 | SQLite 路由账本提供注册、租约、封存与哈希链；T4/T5 只能进入 `PAUSED`，外部主体对精确目标签名且一次消费后恢复 | `src/devflow/collaboration/ledger.py`、`src/devflow/models/human_approval.py`、`tests/test_human_approval.py` |

## 端到端方案链

```text
Issue
  → TeamLeader 建项目、拆 DAG、固定风险与证据要求
  → Triage 分类 → Leader 验收
  → Locator 在固定 tenant/repo/revision/path 只读定位 → Leader 验收
  → Coder 生成最小补丁候选 → Leader 验收
  → Tester 在隔离副本验证
      ├─ FAILED：有界红测证据 → Leader → Coder 重试
      └─ SUCCESS：签名 TestEvidence → Leader → Reviewer
  → Reviewer 返回 ready / retry / blocked
      ├─ retry：Leader 重排
      ├─ blocked(T4/T5)：PAUSED → Human Authority 精确签名 → Leader 恢复
      └─ ready：Leader 固化 VERIFIED 终态包
  → Reviewer 只从 VERIFIED 终态包沉淀经验
  → Leader mark → push → pending=false readback
```

## 口径边界

- AgentTeams 是协同基点，不是文档中的品牌名：上表五项均有框架对象和运行语义。
- `HandoffEnvelope`、持久账本、签名测试证据与精确人工批准是 DevFlow 在
  AgentTeams 之上的安全扩展，不伪称 AgentTeams 原生能力。
- 初赛代码包是可选项。代码、测试和现场证据只能增强可行性，不能替代作品简介、
  方案 PPT、Agent Identity、Skill 清单和五项框架映射。
- 当前真实 AgentTeams 现场证据只覆盖两节点/T2 与若干权限负例；本地六阶段、
  T4 成功恢复和持久账本不能被拼接为已经发生的真实集群六阶段闭环。

## 官方来源

- [GOAI Agent Infra 官方赛道页](https://www.goaihz.com/tracks?track=infra)：
  “作品技术要求”“推荐工具链与资源使用说明”“初赛阶段：方向与方案设计”及
  “赛题个性化评审补充”，访问日期 2026-07-28。
- [GOAI 参赛指南](https://www.goaihz.com/guide)：通用提交与开源边界，访问日期
  2026-07-28。
