# Agent Identity 与职责边界附录

## 六个自主 Agent

| 身份 | 唯一职责 | 所属 Skill | 允许产物 / 工具面 | 明确禁止 |
|---|---|---|---|---|
| TeamLeader | 分解、DAG、状态、冲突仲裁、失败重排与暂停 | 无领域 Skill；编排能力不作为普通 Skill 下发 | TeamHarness 的房间、项目、任务、文件同步与结果验收控制面 | 写代码、跑测试、代做审查、伪造 Worker 结果、代替人工批准 |
| TriageAgent | 分级、去重、优先级 | `issue-classifier` | `ClassifiedIssue`；TeamHarness `ack_task` / `submit_task` | 读写仓库、生成补丁、跳过去重 |
| LocatorAgent | 固定 revision 的只读根因与影响分析 | `code-root-cause`、`github-evidence` | `LocatedContext`；经任务范围能力授权的只读 GitHub 证据 | 修改/执行代码、扩大仓库/版本/路径范围、把能力凭证写入消息或产物 |
| CoderAgent | 最小候选修复 | `patch-generator` | 结构化 `PatchCandidate` | 写 canonical checkout、跑测试、推送、合并、自审 |
| TesterAgent | 一次性副本验证、基线与回归判定 | `test-runner` | `TestEvidence`；仓库内已实现并本地测试的服务器预注册 CI/CD 测试/结果/覆盖率工具 | 接受 Agent 自带 shell、修改源码或测试、批准补丁 |
| ReviewerAgent | 正确性与安全审查、风险识别/阻断升级、经验提炼 | `pr-reviewer`、`experience-distiller` | 审查决定、PR-ready 证据、脱敏经验；TeamHarness `ack_task` / `submit_task` | 合并、部署、回滚、签发人工批准、绕过高危发现；当前 AgentTeams 部署无 GitHub 写能力 |

HumanReviewer 是六个自主 Agent 之外的外部授权主体。其职责是对 T4/T5 的
精确动作、目标、参数摘要和有效期签名批准或拒绝；普通聊天文字和 Agent
自述都不是有效批准。仓库代码与测试覆盖签名校验；当前服务器实证只覆盖暂停
和无批准恢复拒绝，尚未覆盖真人签名后成功恢复。

## 交接不变量

每个 `HandoffEnvelope` 必须验证生产者、消费者、所属 Skill、任务 ID、状态、
payload 类型、SHA-256、trace 与 idempotency key。Worker 只接受发给自己的
任务，只能 `ack_task` 和 `submit_task`；Leader 才能委派、验收、暂停、恢复和
完成项目。Worker 没有直接 `artifact` / `filesync` 控制面；共享文件由 Leader
或受控任务生命周期同步。本地运行时把测试失败或审查拒绝转换成结构化、脱敏且
有界的证据返回 Coder，不能被 TeamLeader 改写为成功；这条回路已有仓库测试，
但尚无真实 AgentTeams 现场闭环。T4/T5 必须进入 HumanReviewer，不能静默降级。

对 TeamHarness task-result submission，同一 assignment 的重试必须保持 ID 和
字节级摘要一致；相同幂等键但不同结果摘要属于冲突，必须失败。Python Agent
runtime 的 execution-route claim 则只保存在当前 TeamLeader/Worker 进程内：
本地并发重复投递最多产生一个重试路由并分别留审计，但不能宣称跨进程、重启后
或多副本持久 exactly-once。大产物走共享任务路径，房间消息只传引用与摘要，
减少上下文重复和 token 损耗。

## 有效权限计算

`Agent 身份 ∩ 活动 Skill ∩ MCP 工具授权 ∩ 安全参数 ∩ 任务上下文 ∩ 人工批准`

任一维度未知、不匹配、过期或不可验证即默认拒绝。AgentTeams 房间负责协作
可见性，不承担最终授权；Guard、Higress/MCP 服务和下游适配器必须独立复核。
提示词中的“我是 Leader”不能改变进程身份。

## 运行面 Skill 边界

现场 apply 和独立只读检查已经把固定七项 DevFlow Skill 策略收敛到
控制器归档缓存、控制器持久 Skill 缓存、Worker 本地树和 MinIO。Locator 替换
后仍恰有 `code-root-cause` 与 `github-evidence`，六个角色 Pod 为 6/6 Ready，
最新独立检查为 0 drift。可引用结论是 `devflowPolicyVerified=true`；同一结果保留
`completeRoleSkillBoundaryVerified=false`，因此不能把内建、平台或未知 Skill
说成已形成完整角色边界，也不能把这项一致性检查说成强 OS 隔离。OpenClaw
审计仍为 `strongBoundaryEnforceable=false`；同 UID 文件访问仍有 TOCTOU 风险，
当前不是 OS sandbox。

## 协作状态与 MCP 边界

TeamHarness Guard 的当前代码/测试不接受调用者自报风险、来源或成员关系：风险
来自根权限账本，来源来自持久项目状态，Matrix 私有邀请规则和完整实际成员集
必须读回验证；响应中的 `invite`/`members` 只是有明确标签的“非创建者、请求
加入的 Worker”投影，完整成员关系以计数与摘要表示。任务重试和冲突同时绑定
`taskId` 与 submission digest。

成功路径驱动直接使用 stdio/Streamable HTTP，敏感值不进入子进程 argv，并
固定角色×服务器配置/schema 与硬截止。该执行是 operator-driven；一次 fresh
T2 GitHub 边界任务已沿该路径完成：项目 `completed`、requester report
`pending=false`，validator、首提、幂等重试、冲突拒绝、冲突后读回与 Leader
`effective` 均通过。项目文件同步为 2/2，并分别确认 `meta.json`、`plan.md`
远端存在。独立 `stat` 只证明对象存在，不证明远端字节摘要；一次 T2 不代表
整体成功率或六阶段修复。

## 规范设计与运行证据的区别

此表定义目标权限上限，不代表每个外部工具已经在集群中完成现场闭环。当前
真实证据覆盖六角色部署、bot-to-bot 交接、两节点项目生命周期、Worker 冒充
Leader 被拒绝以及 Reviewer 无 Git/GitHub 调用。Locator 的短期 GitHub 能力链
已完成固定范围正例和一次 fresh T2 任务，并完成同 capability 错路径 403、
Reviewer 403 与 Locator 直连 Broker 被 NetworkPolicy 阻断。Tester 失败回传
Coder、完整六阶段修复、T4 真人签名批准恢复、正式平台回执与正式视频仍须以
新的现场记录为准。

## 冲突优先级

安全边界 > 人工风险策略 > 测试证据 > Reviewer 判断 > Coder 自检 >
TeamLeader 计划。TeamLeader 可以重排或升级，但不能推翻高危发现、伪造绿色
测试或替代人工批准。
