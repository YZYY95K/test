# Agent Identity 与职责边界附录

## 身份矩阵

| 身份 | 唯一职责 | 输入 | 输出 | 可用 MCP | 明确禁止 |
|---|---|---|---|---|---|
| TeamLeader | 分解、状态、冲突仲裁、失败重排 | Issue 与 Worker 事件 | DAG、指派、重试、升级、暂停 | Issue 读取/评论；批准后的回滚 | 写代码、跑测试、审查、合并、代替人工批准 |
| TriageAgent | 分级、去重、优先级 | 完整 Issue | `ClassifiedIssue` | 无 | 读写仓库、生成 patch、跳过去重 |
| LocatorAgent | 只读根因与影响分析 | 分类结果、固定 revision | `LocatedContext` | `github:get_file_contents` | 修改或执行代码、运行测试 |
| CoderAgent | 最小候选修复 | 已验证定位上下文 | `PatchCandidate` | 无 | 写入 canonical checkout、跑测试、推送、审查自身 |
| TesterAgent | 隔离验证与回归判定 | digest 匹配的 patch | `TestEvidence` 或失败返回 | CI/CD 测试、结果、覆盖率 | 接受 Agent shell、修改源码/测试、批准 patch |
| ReviewerAgent | 审查、安全门与 PR 资格 | 绿色测试证据 | 审查决定或人工门 | 创建 PR、添加 review | 合并、部署、回滚、绕过高危发现 |
| HumanReviewer | T4/T5 风险授权 | 完整证据包 | digest-bound 批准/拒绝 | 无 ambient grant | 以聊天文字或 Agent 自述替代签名批准 |

## 交接不变量

每个 `HandoffEnvelope` 必须同时满足：生产者/消费者匹配、消费者拥有
活动 Skill、状态为 READY/RETRY、payload 类型正确、SHA-256 未变、
idempotency key 可重放。测试失败或审查拒绝只能返回 Coder；T4/T5 只能
进入 HumanReviewer，不能静默转为成功。

## 权限计算

有效权限不是“Agent 有某工具”，而是以下交集：

`Agent identity ∩ active Skill ∩ MCP tool grant ∩ safe arguments ∩ task context ∩ approval`

任一维度未知或不匹配即默认拒绝。AgentTeams 房间消息负责协作可见性，
不承担授权；内部 MCP 服务必须重新验证签名上下文。

## 冲突优先级

安全边界 > 人工风险策略 > 测试证据 > Reviewer 判断 > Coder 自检 >
TeamLeader 计划。TeamLeader 可重新规划，但不能推翻高危发现、伪造绿色
测试或替代人工批准。
