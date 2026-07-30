# DevFlow 参赛简介（500 字以内）

DevFlow 面向真实软件仓库修复，以 AgentTeams 为协同基点，由 TeamLeader 与分类、定位、编码、测试、评审五个专职 Worker 组成。Leader 独占拆解、路由和验收；Worker 只执行所属 Skill。七个版本化 Skill 均有输入输出契约、触发/拒绝规则、失败处理和独立验证器。

Handoff 绑定任务、双方身份、Skill、制品摘要、状态与父路由；Agent、Skill、MCP、scope 和批准必须同时满足，未知组合默认拒绝。测试在隔离副本比较基线与候选，失败只经 Leader 返回 Coder；T4/T5 进入 PAUSED，只有外部人类对精确目标签名后可一次恢复。RAG 绑定租户、仓库和不可变版本，SQLite 账本提供跨进程租约、恢复与哈希审计。

离线 Demo 已执行六阶段、红转绿、经验沉淀和 6/6 路由封存。三个固定仓库共 21 个 mutation 任务已完成确定性预验证，但 Agent 尚未执行，故不报告修复成功率。项目采用 Apache-2.0，证据分本地已验证、候选预检、历史现场与当前版本待服四层。
