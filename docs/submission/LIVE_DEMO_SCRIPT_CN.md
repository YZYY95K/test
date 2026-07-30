# 现场演示脚本（8 分钟，证据对齐版）

本脚本只展示已经落盘或当场可复验的结果。初赛官方必交材料不包含演示视频；
视频与现场闭环在完成后作为增强材料，不应在完成前写入报名表。

## 0:00–0:45｜对齐赛题

用一页说明 DevFlow 覆盖五个评分维度。指出六角色超过“至少三个 Agent”的
门槛，AgentTeams 是协同基点，七个 Skill 是必选工程资产；RAG、经验记忆、
共享状态、轨迹/指标观测覆盖官方要求的“至少两项”。

## 0:45–1:45｜职责不是角色扮演

打开 Agent Identity 矩阵：TeamLeader 只能编排项目、房间、任务与状态；
Triage 分类；Locator 只读证据；Coder 只产候选补丁；Tester 隔离验证；
Reviewer 只给审查结论。HumanReviewer 是外部授权主体，不计入六个 Agent。
Worker 只允许自身任务的 `ack_task` / `submit_task`，不直接调用 `artifact` 或
`filesync`；共享文件控制面由 TeamLeader 或受控任务生命周期承担。

展示有效权限交集：`身份 ∩ Skill ∩ MCP ∩ 参数 ∩ 任务上下文 ∩ 批准`。

## 1:45–2:45｜真实 AgentTeams 协作证据

展示 `docs/evidence/AGENTTEAMS_LIVE_20260727.md`：一个 Leader 与五个 Worker、
机器人到机器人交接、一个脱敏项目的两个依赖节点、Worker ack/submit、Leader
accept、项目 completed 与 requester report 已发送。不得展示项目 ID 或房间标识。

明确说明这是真实 Triage + Reviewer 两节点生命周期，不是六阶段软件修复。
展示首次完成通知遇到 Matrix 启动故障后自动重试成功，说明该通知路径由状态机
和 TeamHarness 幂等语义处理，而不是靠重复生成结果；不得把这一点外推为所有
Agent 执行都具备持久 exactly-once。

## 2:45–3:45｜fresh T2 边界任务

展示一次 fresh、operator-driven T2 GitHub 边界任务的脱敏摘要：项目
`completed`、requester report `pending=false`；validator、首提、同结果幂等
重试、不同结果冲突拒绝、冲突后读回和 Leader `effective` 全部通过。再展示
项目 push 的 2/2 对象证明，以及 `meta.json`、`plan.md` 两次独立
`stat exists=true`。只显示状态、计数和摘要，不显示项目 ID、房间、capability、
连接信息或原始仓库内容。

角标必须写明：“单次固定范围 T2，不是成功率统计，不是六阶段修复；stat 仅证明
对象存在，不证明远端字节摘要。”

## 3:45–4:35｜边界拒绝

展示已观察到的负例：Worker 在参数中声称 `role=leader` 并调用
`taskflow.delegate_task`，Guard 使用进程身份覆盖不可信参数并返回
`forbidden_tool`。再展示自动测试中的错 consumer、错摘要、错路径和未知工具
拒绝；清楚区分“集群现场证据”与“仓库测试证据”。

展示 2026-07-28 的四运行面收敛记录：固定七项 DevFlow Skill 策略在控制器
归档缓存、控制器持久 Skill 缓存、Worker 本地树和 MinIO 一致；独立检查为
0 drift，Locator 替换后仍恰有两项预期 DevFlow Skill，六个角色 Pod 为 6/6
Ready。屏幕同时
保留 `completeRoleSkillBoundaryVerified=false`，明确未知/平台 Skill 与强 OS
隔离不在这项结论内；同时显示 `strongBoundaryEnforceable=false`，说明同 UID
仍有 TOCTOU 风险，当前不是 OS sandbox。

## 4:35–5:25｜本地修复链（独立证据）

运行固定 calculator fixture：原始测试失败，依次产生分类、定位、候选补丁、
一次性副本测试、审查与经验记录，最后验证 canonical checkout 未改变。
屏幕角标始终标注“本地确定性演示”，不得把这段称为 AgentTeams Team Room
执行结果。

随后展示本地 Leader→Router→Worker 失败恢复聚焦测试：SQLite 调度路由只允许
一个进程取得租约，过期后可恢复并封存；每个 canonical Coder route 只授权一次
模型调用，验证失败与测试失败共享 issue-global 1..3 预算且不产生第四次调用。
Reviewer 拒绝经 TeamLeader 校验后 fail-closed，不伪造 Coder 重试。画面必须
同时标注“调度租约可持久；Worker replay/失败去重含进程内状态；非外部副作用
exactly-once”。

## 5:25–6:30｜MCP 与安全工程

展示 Agent/Skill/MCP 精确授权、本地实现的服务端预注册 CI 命令、摘要绑定批准、
本地哈希审计、短期能力凭证及凭据不进入提示词。对 CI/CD、批准和审计明确标注
“仓库代码/本地测试”；只显示脱敏身份、trace 和摘要，不在终端、截图、日志或
视频中展示 token、密码、房间标识和服务器地址。

把 TeamHarness 的“风险来自根权限账本、来源来自持久项目状态、Matrix 私有
邀请与完整成员集合必须读回验证、taskId 与提交摘要绑定重试/冲突”标为代码与
测试证据。把直接 stdio/Streamable HTTP、角色×服务器配置/schema attestation、
敏感值不进子进程 argv 和硬截止标为实现证据；随后用上一节的单次 T2 现场结果
证明这条固定边界路径实际完成过一次，但不得外推到任意仓库或完整修复。

展示已完成的 GitHub 短期能力链：固定 repo/revision/path 读取成功、object 与
content digest 可复核、receipt response digest 重算一致；同 capability 换路径
和 Reviewer 入口均为 403，Locator 直连 Broker 被 NetworkPolicy 阻断。画面
只显示摘要与 HTTP 状态，不显示 capability、PAT 或 Consumer 凭据。

## 6:30–7:20｜量化证据

展示三个固定 revision、24 项路由/边界基准的精确决策、安全率、p50/p95
时延与 token。展示七个 Skill 的静态质量门；同时指出 GLM-5.2 成对行为评测
只覆盖较早的六个 Skill，`github-evidence` 不沿用该分数。2026-07-30 当前候选
工作树完整结果为 1,330 passed、24 skipped、84.06%（6,325 statements /
1,008 missed）；它尚未绑定 clean commit、CI 或 release provenance，只有冻结后
复跑一致，才把数字作为最终发布证据展示。

## 7:20–8:00｜结论与缺口

总结：职责不会漂移、越权不能靠提示词绕过、推进必须有可验证证据。最后主动
列出尚缺项：真实六阶段修复、Tester 失败返回 Coder、T4 真人签名批准后恢复，
以及正式比赛平台提交回执与正式视频。它们完成前不使用“全流程已验证”或
“已经正式提交”字样；一次 T2 成功不换算为整体成功率。

## T4 演示启用条件

只有满足下列条件才加入正式视频：真实项目已进入 paused；未批准恢复被拒绝；
人工对精确 action、target、arguments digest 和有效期签名；批准后同一项目
恢复；审计链可从 pause 关联到 approval 与 resume。任一条件缺失就从视频中
移除该段，并在缺口页如实说明。

## 演示前检查

- 最终 commit、PPT、代码包与证据数字一致；
- `.env`、终端历史、截图和视频中无密钥或个人连接信息；
- 所有运行证据标注环境、时间、commit 与证据文件；
- 本地演示、仓库测试、真实集群证据使用不同角标；
- 失败路径使用固定 fixture，不临场制造不可控故障；
- 未完成项保留为未完成，不以设计图或测试替代现场记录。
