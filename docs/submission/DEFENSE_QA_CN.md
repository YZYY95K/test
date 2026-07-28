# 答辩问题库

## 1. 这和串行工作流有什么区别？

区别不在并发数量，而在独立身份、私有边界、失败返回、可验证交接和不同
授权。任一 Worker 可拒绝输入并把证据返回 TeamLeader；TeamLeader 不能
代做领域工作。Worker 只能进行自身任务的 `ack_task` / `submit_task`，没有直接
`artifact` / `filesync` 控制面；文件同步由 TeamLeader 或受控任务生命周期完成。

## 2. 为什么 TeamLeader 不是一个可分发 Skill？

它拥有的是运行时状态与调度权限，不是可复用的领域能力。把它发布为普通
Skill 会模糊“谁能改计划”和“谁能做工作”的边界。

## 3. Prompt 写了“禁止越权”还不够吗？

不够。DevFlow 在模型之外验证 Agent+Skill grant、签名上下文、参数、路径、
批准和摘要；拒绝发生在 transport 前，内部服务再验证一次。

## 4. MCP 为什么不是配置型伪实现？

仓库实现的五个工具可由 FastMCP endpoint 枚举和调用，本地集成测试验证了这条
链路。流水线在一次性副本执行 server-owned argv，覆盖率接口读取
`coverage.json`；回滚调用原子 symlink provider 并做健康检查。这些是代码与
本地测试证据，不是当前 AgentTeams 服务器已完成 CI/CD 或回滚现场闭环的声明。

## 5. Agent 能不能把 shell 命令藏在参数里？

不能。接口不接收命令文本，只接收 typed patch、suite、branch、pipeline id
或受限 release；实际 argv 在服务器环境预注册并以 `shell=False` 执行。

## 6. 人工批准如何防止复用？

本地实现与测试中，签名绑定 action、canonical target、完整参数 SHA-256、
批准人和时间，并有有效期；改环境、release 或任一参数都会使验证失败。当前
服务器仅实证 T4 暂停和无批准恢复拒绝，真人签名批准后恢复仍未完成。

## 7. 审计链能否防止管理员重写全部日志？

本地 SHA-256 链能发现局部篡改和断链，但不能对抗可重写全部磁盘的管理员。
生产方案必须把日志同步到外部 append-only/WORM 存储；项目文档不夸大这一点。

## 8. 凭据代理是否真的不泄露密钥？

Agent 只拿短期、任务与仓库范围绑定的 capability，真实凭据只存在于服务端
适配器。集群 E2E 已完成一次 fresh、operator-driven 的固定范围 T2 边界任务；
项目完成且 requester report 不再 pending，validator、首提、幂等重试、冲突
拒绝、冲突后读回与 Leader `effective` 均通过。同一 capability 换路径和
Reviewer 入口均返回 403，Locator 直连 Broker 被 NetworkPolicy 阻断。证据不
保存 capability、上游凭据、Consumer 凭据或原始仓库内容，也不把一次 T2
扩写为任意仓库、总体成功率或完整修复闭环。

## 9. RAG 离线模式是不是语义检索？

不是。`local-hash` 是确定性 feature hashing 降级模式，用于离线可用与测试；
生产语义质量必须使用已开通的 embedding provider。两者在报告中明确区分。

## 10. 为什么不直接用覆盖率证明系统可靠？

覆盖率只说明哪些代码被执行，不证明职责边界正确或现场闭环真实。2026-07-28
当前 v1.3.0 候选工作树的完整结果是 846 passed、17 skipped、84.40%
（3,874/4,590），但尚未
绑定最终 commit，提交前必须在冻结版本上复跑。最终证据还要同时包含行为评测、
拒绝测试、真实服务器状态和人工门记录。

## 11. 三仓库 24 项是否等于完整补丁解决基准？

不等于。它测量真实源码条件下的路由、边界、安全与成本。完整 issue-resolution
必须在固定、可复现的仓库环境中应用补丁并运行项目测试。当前 24 项不得表述为
“修复 24 个缺陷”，也不得写成“SWE-bench 24/24”。

## 12. AgentTeams 真实运行到底完成了什么？

新服务器已运行真实 AgentTeams：一个 Leader、五个 Worker，完成了机器人交接
以及 Triage 到 Reviewer 的两节点项目生命周期，并观察到 Worker 冒充 Leader
被拒绝。固定七项 DevFlow Skill 策略随后在控制器两级缓存、Worker 本地树和
MinIO 四个运行面完成收敛，Locator 替换后仍只保留两项预期 DevFlow Skill，
六个角色 Pod 为 6/6 Ready，独立检查为 0 drift。此后又完成一次 fresh、
operator-driven 的 T2 GitHub 边界任务：项目 `completed`、requester report
`pending=false`，并具备 validator、首提、幂等、冲突拒绝、冲突后读回、
Leader `effective` 与文件同步 2/2 证据。它仍不是六阶段软件修复；Tester 失败
回传 Coder、T4 真人签名批准恢复、正式平台回执和正式录屏尚未完成。一次 T2
成功也不能用作整体成功率。早期受限服务器的 Docker 阻塞记录仍保留，但不再
代表当前环境。

## 13. Tester 或 Reviewer 与 Coder 冲突时听谁的？

设计与本地运行时均坚持证据优先：红测先返回 TeamLeader，只有完整摘要验证
通过后才以结构化、脱敏且有界的失败证据重路由 Coder。Reviewer 拒绝同样先由
TeamLeader 校验，但当前没有候选绑定的修复契约，因此 fail-closed 并要求人工
重规划，不把裸审查意见直接执行为补丁。T4/T5 进入人工门，TeamLeader 不能覆盖
这些硬门。Tester→Coder 的真实 AgentTeams 现场回路仍是待办。

## 14. 如何控制成本与无限重试？

契约和配置定义调用时间、token 与 attempt 上限；当前本地失败恢复测试进一步
验证 generic execution retry 的 route-level claim，以及每个 canonical Coder
route 只授权一次模型调用。候选验证失败与 Tester 语义失败共享由 TeamLeader
顺序签发的 issue-global 1..3 预算，不会产生第四次调用，也不会再叠加通用执行
重试。route claim 是进程内状态，不是
跨重启或多副本 exactly-once。基准只在 provider 返回可用数据时记录 token 与
p50/p95 时延；不能用配置中的 exponential backoff 字段冒充已观察到的运行行为。

## 15. 开源复用价值在哪里？

Agent 身份、Skill 包、typed contracts、MCP grants、评测清单和验证脚本都在
Apache-2.0 仓库中，可替换模型、Git 提供商或 CI provider，而不改变信任模型。

## 16. 为什么说有七个 Skill，行为评测表却只有六个？

`github-evidence` 是后续新增的第七个 Skill，已有严格契约、独立验证器、静态
质量门和篡改负例；2026-07-24 的 GLM-5.2 成对评测早于它，因此只覆盖六个
Skill。我们不会把旧分数平移给新 Skill，新增行为评测完成后再更新材料。

## 17. HumanReviewer 为什么不算第七个 Agent？

它是系统外部的授权主体，不是自主执行 Worker。把真人审批者算成 Agent 会混淆
责任与信任边界。参赛口径始终是六个自主 Agent，T4/T5 由外部 HumanReviewer
提供摘要绑定批准或拒绝。

## 18. 角色 Skill 已经“完全隔离”了吗？

不能这样表述。现场 apply 与独立只读检查证明的是固定七项 DevFlow Skill 策略
在控制器归档缓存、控制器持久 Skill 缓存、Worker 本地树和 MinIO 一致，即
`devflowPolicyVerified=true`，最新独立检查为 0 drift，六个角色 Pod 为 6/6
Ready。结果同时明确
`completeRoleSkillBoundaryVerified=false`：内建、平台和未知 Skill 没有被扩写
为完整边界；OpenClaw 审计也仍为 `strongBoundaryEnforceable=false`。这是经过
验证的窄边界，不是敌对 root 或 OS 沙箱声明；同 UID 文件检查与使用之间仍存在
TOCTOU 风险。

## 19. TeamHarness 和 MCP 如何避免只信调用者自述？

当前 Guard 代码与测试从根权限账本读取项目风险、从持久项目状态读取来源，
直接查询 Matrix 以验证私有邀请规则和完整实际成员集合，并用 taskId 与提交摘要
约束幂等/冲突。成功路径驱动直接使用 stdio 与 Streamable HTTP，敏感值不进入
子进程 argv，同时校验角色×服务器配置/schema 并设置硬截止。一次 fresh T2
现场任务已沿该路径完成：项目完成、报告关闭，validator、三种提交语义、冲突后
读回与 Leader `effective` 均验证；项目 push 报告 2/2，对 `meta.json` 与
`plan.md` 又分别执行了 `stat exists=true`。这些独立 stat 只证明对象存在，
不证明远端字节摘要；一次 T2 也不能替代六阶段修复或总体成功率基准。这里的
持久 task-result 冲突语义也不能外推为 Python execution-route claim 的分布式
exactly-once。
