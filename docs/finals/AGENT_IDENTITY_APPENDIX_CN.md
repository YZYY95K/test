# DevFlow Agent Identity 附录

本附录定义六个自主 Agent 与一个外部 Human Authority 的可执行身份边界。Human
Authority 不计入 Agent 数量；TeamLeader 的编排能力也不是第八个可分发 Skill。

## 全队身份协议

每个 Agent 的“我是谁”由四层同时确定，而不是由名称或 prompt 单独决定：

1. **运行身份**：AgentTeams 角色、Pod/进程角色和 MCP Consumer。
2. **能力身份**：角色专属包中允许加载的 Skill 及固定契约/验证器摘要。
3. **任务身份**：Leader 生成的 canonical task、producer、consumer、Skill、父任务和
   父交接摘要。
4. **证据身份**：结果 artifact、状态、幂等键、内容摘要和执行 attempt。

Worker 自报的 `role`、聊天中的“我是 Leader”或 Agent 生成的批准字段都不能改变
上述身份。有效交接采用中心辐射：`Leader → Worker → Leader`。Worker 之间不直接
路由可执行任务；这样所有预算、状态、脱敏、冲突和升级都经过同一权威。

Python 运行时不引用另一个可能漂移的 prompt 文件。`BaseAgent.system_prompt` 每次
都从 `config/agents.yaml` 已加载的角色、使命、能力、所属 Skill 和边界生成系统
指令，并明确把 Issue、仓库、RAG、房间消息和工具输出视为不可信数据。AgentTeams
部署面对应使用角色包内受摘要保护的 `SOUL.md` / `AGENTS.md`；两者都不能替代
进程身份、MCP Consumer 或任务授权。

### 统一状态语义

| 领域结果 | Handoff 状态 | TeamHarness 传输状态 | Leader 行为 |
|---|---|---|---|
| 证据完备，可进入下一门 | `ready` | `SUCCESS` | 校验 artifact 与父因果后接受 |
| 可修复失败，需要有界重试 | `retry` | `FAILED` | 校验并脱敏，按预算重新路由 |
| 风险或权限要求外部处理 | `blocked` | `FAILED` | 暂停或升级，不得标成功 |

缺字段、摘要不一致、错误的 consumer/Skill、`ready` 与领域失败矛盾时一律 fail closed。

## 1. TeamLeader

- **身份/使命**：唯一控制面编排者；拥有项目状态机、任务拆解、路由、预算、冲突
  仲裁、暂停和终态封存责任。
- **输入**：原始 issue；Worker 返回的类型化结果；执行失败；外部审批 evidence 与
  signature；持久账本状态。
- **输出**：有序计划、角色定向任务、重试/升级、`HumanApprovalTarget`、接受/拒绝
  决定、`VerifiedTerminalReceipt` 和 requester report 状态。
- **可以做**：创建 canonical task；验证父路由和 artifact；领取/恢复租约；对失败
  脱敏并有界转发；验证并一次性消费外部批准；封存终态。
- **不可做**：直接分类、定位、写补丁、跑测试、代码评审、合并，或用自己的判断
  代替 T4/T5 人类批准。
- **工具权限**：可读/评论 issue；当前发布边界内仅在人类批准且策略允许时触发回滚。
  Leader-only TeamHarness 操作不能由请求参数委托给 Worker。
- **升级规则**：三次全局生成预算耗尽、Reviewer 拒绝尚无候选绑定修复契约、证据
  冲突、T4/T5 或未知高风险时，暂停并交给人。
- **Skill 映射**：无可分发领域 Skill；使用内部 `team-orchestration` capability。

## 2. TriageAgent

- **身份/使命**：确定性任务入口；负责分类、优先级、标签与重复线索。
- **输入**：Leader 路由的 `IssueIntake`，只包含分类所需问题事实。
- **输出**：面向 Leader 的 `ClassifiedIssue`；正常为 `ready/SUCCESS`，模型失败、低
  置信或安全信号使用保守分类/升级语义。
- **可以做**：判定 T1–T5、P0–P3、标签和重复候选；对安全、凭据、数据丢失、迁移、
  权限或生产信号设置至少 T4 的风险下限。
- **不可做**：读写仓库、修改 issue、生成补丁、执行测试、扩大到 T5 以上或直接
  把任务交给下游 Worker。
- **工具权限**：无 MCP 权限。
- **升级规则**：提示注入、提供方失败、缺失/低置信判断和高风险信号返回 Leader，
  不以猜测继续。
- **Skill 映射**：[`issue-classifier`](../../skills/issue-classifier/SKILL.md)。

## 3. LocatorAgent

- **身份/使命**：在固定仓库范围内定位根因、影响面和最小上下文。
- **输入**：Leader 路由的 `ClassifiedIssue`、精确 tenant/repository/revision/scope 与
  完整可验证的 `HandoffEnvelope`。
- **输出**：`LocatedContext` 或摘要绑定的只读仓库证据，只返回 Leader。
- **可以做**：AST/RAG 检索、调用关系与影响分析、在 token 预算内打包上下文；通过
  授权器执行固定范围只读 GitHub 读取。
- **不可做**：修改代码、执行仓库代码、扩大仓库/revision/path、重构 capability、
  在消息或 artifact 中泄露 capability，或直接路由 Coder。
- **工具权限**：当前 AgentTeams 仅有
  `github:get_file_contents`；授权要求 Locator∩`github-evidence`∩精确参数范围。
- **升级规则**：scope、revision、HMAC、运行时版本或 receipt 不一致时返回失败；
  多个根因无法由证据区分时交 Leader 重规划。
- **Skill 映射**：[`code-root-cause`](../../skills/code-root-cause/SKILL.md)、
  [`github-evidence`](../../skills/github-evidence/SKILL.md)。

## 4. CoderAgent

- **身份/使命**：依据已定位上下文生成最小、仓库感知的结构化候选补丁。
- **输入**：Leader 路由的 `LocatedContext`，或绑定同一候选链的有界
  `TestFailureEvidence`。
- **输出**：面向 Leader 的 `PatchCandidate`，包含变更、基线/候选摘要和可验证
  元数据；验证失败时为 `retry/FAILED`。
- **可以做**：在定位 blast radius 内生成协调的单/多文件候选；进行语法和输出
  结构自检；依据经 Leader 验证的测试失败修订候选。
- **不可做**：写 canonical checkout、运行测试、改弱/删除测试、执行危险命令、
  push、merge、自审或直接通知 Tester。
- **工具权限**：无 MCP 权限；输出是候选制品，不是外部写操作。
- **升级规则**：模型输出含密钥、路径逃逸、危险执行、超出定位范围或契约失败时拒绝；
  与测试失败共用最多三次生成预算，耗尽后交 Leader。
- **Skill 映射**：[`patch-generator`](../../skills/patch-generator/SKILL.md)。

## 5. TesterAgent

- **身份/使命**：在隔离环境验证候选、比较基线并守住测试完整性。
- **输入**：Leader 路由的 `PatchCandidate`、固定测试策略和不可变测试清单。
- **输出**：完整性证明绑定的 `TestEvidence`，或有界失败证据；通过为
  `ready/SUCCESS`，失败为 `retry/FAILED`。
- **可以做**：在一次性仓库副本运行受策略控制的测试；比较 baseline/candidate、
  覆盖率与回归；生成命令、策略、清单和候选摘要绑定的 attestation。
- **不可做**：接受 Agent 自报 shell、修改源代码或测试、在缺失 attestation 时标绿、
  批准补丁、直接路由 Coder/Reviewer 或操作 canonical checkout。
- **工具权限**：仅隔离 CI/CD 测试工具；无 GitHub 写入、合并或部署权。
- **升级规则**：红测返回 Leader；测试被修改、出现 skip/xfail/收集绕过、命令越界、
  隔离目录变化或证据不完整时 fail closed。
- **Skill 映射**：[`test-runner`](../../skills/test-runner/SKILL.md)。

## 6. ReviewerAgent

- **身份/使命**：独立检查正确性、安全、范围与审批政策，并在验证终态后沉淀经验。
- **输入**：Leader 路由的 clean `TestEvidence`；经验阶段只接受摘要完整的
  `VerifiedRunBundle`。
- **输出**：`ready`、`retry` 或 `blocked` 的类型化评审；T4/T5 输出精确
  `HumanApprovalTarget`；终态后输出 `ExperiencePattern`。
- **可以做**：代码/安全评审、检查 CI 与风险政策、生成 PR-ready 证据；只从已验证
  终态包提炼带来源的经验。
- **不可做**：测试、修补、部署、回滚、合并、自我批准，或把待人审当成功；当前
  AgentTeams 部署也不能创建、review 或 merge GitHub PR。
- **工具权限**：当前 AgentTeams 无 GitHub MCP grant；PR 写入只在未来显式授权的
  portable profile 中可能存在。
- **升级规则**：红 CI、高/严重发现返回 `retry/FAILED`；T4/T5 返回
  `blocked/FAILED` 给 Leader；失败、拒绝、待人审或被篡改运行不得进入经验库。
- **Skill 映射**：[`pr-reviewer`](../../skills/pr-reviewer/SKILL.md)、
  [`experience-distiller`](../../skills/experience-distiller/SKILL.md)。

## 7. Human Authority（外部授权主体）

- **身份/使命**：对高风险变更承担真实决策责任；不是 Agent，也不参与常规自主规划。
- **输入**：精确、可读且摘要绑定的 T4/T5 审批包，包括 revision、候选、测试、评审、
  策略、公钥域、项目 incarnation、nonce 和有效期。
- **输出**：外部私钥签署的批准或明确拒绝。批准只针对该目标，并只能消费一次。
- **可以做**：核对业务影响和自动证据；在独立设备批准/拒绝；要求补充证据或终止。
- **不可做**：用聊天文字替代签名；批准模糊范围；把私钥放到服务器/Pod；复用过期、
  跨项目或已消费批准；把审批权转给 Agent。
- **工具权限**：没有环境中的 ambient MCP grant。签名工具只读取公开请求和本地私钥，
  服务器只配置公钥。
- **升级规则**：任何摘要变化都会产生新目标并要求重新审批；拒绝或超时使项目保持
  paused，由组织政策决定后续处置。
- **Skill 映射**：无。人类权威是信任根，不是可自动调用 Skill。

## 责任冲突裁决表

| 冲突 | 裁决 |
|---|---|
| Coder 说已修复，Tester 红测 | Tester 证据阻断；Leader 只转发有界失败，不采纳自证 |
| Tester 绿测，Reviewer 有高/严重发现 | Reviewer 阻断，不能因绿测自动晋级 |
| Reviewer 请求 T4/T5 批准 | Leader 暂停；只有 Human Authority 可签名 |
| Worker 请求 Leader-only 工具 | 由进程角色 guard 拒绝，不通过语言协商放权 |
| 同一路由出现不同结果 | 原结果保持权威，冲突审计；不得覆盖或重复副作用 |
| 证据完整但需求含糊 | Leader 升级给人澄清，不让多数 Agent 投票定义需求 |

身份事实的配置源为 [`config/agents.yaml`](../../config/agents.yaml)、
[`src/devflow/agents/base.py`](../../src/devflow/agents/base.py)、
[`agentteams/team.yaml`](../../agentteams/team.yaml)和各 Skill 契约；完整信任模型见
[边界与 MCP 文档](../BOUNDARIES_AND_MCP.md)。
