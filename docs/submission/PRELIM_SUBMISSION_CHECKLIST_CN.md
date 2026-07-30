# GOAI 2026 Agent Infra 初赛提交检查表

核对日期：2026-07-28。官方赛道页：
[Global Open-source AI Challenge — Agent Infra](https://www.goaihz.com/tracks)。
初赛截止 **2026-08-16**；提交当天以报名页面显示的时区、大小和格式限制为准。
当前公开规则的逐项合规结论见
[`PRELIM_COMPLIANCE_20260728.md`](PRELIM_COMPLIANCE_20260728.md)，AgentTeams
五项强制映射见 [`AGENTTEAMS_MAPPING_CN.md`](AGENTTEAMS_MAPPING_CN.md)。

## 必交材料

- [x] 作品简介正文已写入 `INTRO_500_CN.md`。
- [x] 本地按 .NET UTF-16 `String.Length` 检查：粘贴正文为 499，计入文件末尾换行为 500，
  不超过 500；仍需以
  报名表计数器为最终标准，标题不粘贴。
- [x] 12 页最终候选方案已生成两种格式：
  [PPT](../../outputs/DevFlow_GOAI_2026_初赛方案_20260728.pptx)（52,153 bytes，
  SHA-256 `7199d4765b768c1c38938d6a4842df68226417ad1ac6c05657335adcaab1f32d`）与
  [PDF](../../outputs/DevFlow_GOAI_2026_初赛方案_20260728.pdf)（1,236,379 bytes，
  SHA-256 `cf0031eb132f65025f830865b9419bd631764b00e0a80035c2e791fc1086ba23`）。
  初赛只需上传其中一种，除非平台允许且团队决定同时提交。
- [x] 已确认现有 `GOAI_2026_AgentInfra_DevFlow_初赛提交包_v1.3.0_20260728.zip`
  内的 PPT 为更早候选（SHA-256
  `03aca4383523193e313d360388a3c45cfb6d9f1cebfeb2909d9d12922d1e7372`），
  与上述当前成品不同；**旧 ZIP 不得上传**。初赛按官网要求分别
  粘贴作品简介并上传当前 PPT 或 PDF；如需新 ZIP，必须从最终干净
  commit 重新构建并复验。
- [x] 第 5 页集中展示 AgentTeams 五项硬映射：角色编排、任务拆解、上下文传递、
  协同执行与状态追踪；原生框架对象和 DevFlow 有界扩展另有逐项证据表。
- [x] PPT/PDF 已完成本地逐页核对：12 页均渲染为 1280×720 检查，模板忠实度
  与画布溢出门通过，未发现中文乱码、截断或重叠；凭据形态扫描零命中；PDF
  未加密且无表单/JavaScript。
- [ ] 在最终 commit/tag 冻结后再次核对材料中的版本、测试数字和仓库链接；
  当前本地 QA 不等于与尚未生成的最终代码包完成一致性校验。
- [ ] 报名表中的项目名、团队/联系人、公开仓库 URL 等参赛者字段由提交人确认。
- [ ] 在 2026-08-16 前完成网页预览并由提交人点击最终提交；本仓库不会代替
  参赛者完成网页确认。

## 方案材料内容映射

- [x] 场景价值 25%：用户、痛点、失败成本、可复制工作流与 24 项边界基准。
- [x] 多 Agent 25%：六角色身份、DAG、交接摘要、失败返回、幂等与人工门。
- [x] Skill 25%：七个 Skill 的契约、触发/拒绝、验证器、所属角色和复用方式。
- [x] 工程安全审计 20%：MCP 权限交集、服务端复核、短期能力、审计链、回滚、
  OTLP/Prometheus，以及真实证据与待办的界线。
- [x] 开放开源 5%：许可证、公开仓库、运行入口、贡献方式、固定版本与复现步骤。
- [x] 官方结构性要求单独一页：至少 3 Agent；AgentTeams 为协同基点；Skill
  必选；RAG/记忆/共享状态/轨迹观测至少两项。

## 可选代码包

只有提交最终代码包时才需完成本节；代码包不是初赛必交项。

- [ ] 从最终、干净、固定 commit 重新构建，不复用 2026-07-25 的旧 ZIP。
- [ ] 包内明确运行入口、Python/系统依赖、配置方法和无密钥的环境变量模板。
- [ ] 包内提供固定样例输入、预期输出和可复验运行证据。
- [ ] 排除 `.git`、`.env`、虚拟环境、缓存、私钥、访问 token、密码、真实主机与
  个人连接信息。
- [ ] 对代码包与外层材料执行凭据扫描；仅报告通过/失败和命中位置，不复制
  凭据值。
- [ ] 生成 SHA-256 清单，并在一个全新目录解包后按文档复现。
- [ ] 确认公开仓库 URL 可匿名访问，提交 commit/tag 与代码包内容一致。

## 当前证据可用性

- [x] 六角色与边界：`AGENT_IDENTITY_APPENDIX.md`。
- [x] 七个 Skill 静态质量记录：`docs/evidence/AGENTTEAMS_LIVE_20260727.md`。
- [x] 三个固定 revision、24 项边界基准：`docs/BENCHMARK.md` 及哈希绑定结果。
- [x] 真实 AgentTeams 两节点生命周期、机器人交接与越权拒绝：
  `docs/evidence/AGENTTEAMS_LIVE_20260727.md`。
- [x] 2026-07-27 的六个 v1.2.0 角色专属包已确定性构建，并在集群内逐一核对长度和
  SHA-256；六个替换 Pod Ready。包交付与运行面收敛分别留证。
- [x] 六个 v1.3.0 候选包已在本地确定性重建并通过源码重放、摘要、大小和清单校验；尚未部署，不能继承 v1.2.0 的集群证据。
- [x] `final4.4` 已把固定七项 DevFlow Skill 策略收敛到控制器归档缓存、控制器
  持久 Skill 缓存、Worker 本地树和 MinIO；最新独立检查为 0 drift。Locator
  替换后仍恰有 `code-root-cause` 与 `github-evidence`，六个角色 Pod 为 6/6 Ready。
- [x] 收敛结果明确为 `devflowPolicyVerified=true`、
  `completeRoleSkillBoundaryVerified=false`；未知/平台 Skill 不在完整边界声明内，
  且该结果不代表强 OS 隔离。
- [x] 真实 Locator GitHub 任务诚实返回 `FAILED`：旧 Skill 运行时版本错配；
  相同结果重试幂等、不同结果重试返回 `submit_result_conflict`。
- [x] 六个早期 Skill 的 GLM-5.2 成对行为评测：
  `docs/evidence/SKILL_BEHAVIOR_GLM52.md`。
- [ ] `github-evidence` 的成对行为评测；不得把六 Skill 的历史分数扩写成七个。
- [ ] 真实六阶段 AgentTeams 软件修复闭环。
- [ ] Tester 失败返回 Coder 并成功重试的现场证据。
- [x] T4 真实暂停与“无批准恢复被拒绝”的现场证据。
- [ ] T4 真人对精确摘要签名批准并成功恢复；不得把上一项扩写为真人闭环。
- [x] GitHub 短期能力链已完成固定 repo/revision/path 正例、同 capability 错路径
  403、Reviewer 403 与 Locator 直连 Broker 被 NetworkPolicy 阻断；证据见
  `docs/evidence/AGENTTEAMS_LIVE_20260727.md`。未单独声称错仓库现场负例。
- [x] OpenClaw 原生工具边界审计真实返回
  `strongBoundaryEnforceable=false`，并记录六项固定 blocker；不得宣称当前为强
  OS/敌对 root 沙箱。
- [x] TeamHarness 代码/测试已把风险绑定根权限账本、来源绑定持久项目状态，
  验证 Matrix 私有邀请规则和完整实际成员集合，并把重试/冲突绑定到 taskId 与
  submission digest；MCP 驱动已改为直接 stdio/Streamable HTTP、角色×服务器
  配置/schema 校验和硬截止。
- [x] 使用上述加固路径完成一次 fresh、operator-driven 的真实 T2 AgentTeams
  GitHub 边界任务：项目 `completed`、requester report `pending=false`；validator、
  首提、同结果幂等重试、不同结果冲突拒绝、冲突后读回与 Leader `effective`
  均通过；项目文件同步证明 2/2 对象，并分别对 `meta.json`、`plan.md` 获得
  `stat exists=true`。
- [x] 仓库本地聚焦测试验证真实 Leader→Router→Worker 执行、结构化失败事件、
  同一 canonical execution route 并发重复/冲突的双审计与单重试，以及
  Coder 验证失败与测试失败共享的 issue-global 三次模型调用预算；
  `CANDIDATE_INVALID` 不触发通用 execution retry，也不会生成第四次模型调用。
- [x] 调度路由已接入 SQLite 持久账本，并验证跨进程竞争、租约过期恢复、封存、
  重启读回与哈希链；Worker replay slot、失败路由去重/生成预算仍有进程内部分。
- [ ] 外部副作用、多副本 broker redelivery 与所有进程内 replay 状态尚未形成
  分布式 exactly-once；完成前不得使用该表述。
- [x] 对这一次 T2 保留窄口径：两个 `stat` 只证明远端对象存在，不证明远端
  字节摘要；一次成功不能外推整体任务成功率，也不是六阶段软件修复。
- [x] 安全限制继续明示：同 UID 文件操作仍有 TOCTOU 风险，当前不是 OS sandbox；
  `completeRoleSkillBoundaryVerified=false` 且
  `strongBoundaryEnforceable=false`。
- [x] 12 页 PPT/PDF 已完成本地逐页视觉与凭据形态检查；PDF 另确认无表单或
  JavaScript。
- [ ] 正式演示视频。官方已核对的初赛必交清单不要求视频，未完成时不要占位或
  声称已上传。

## 数字冻结表

最终 PPT、简介、答辩和网页字段只使用以下口径：

| 项目 | 当前口径 |
|---|---|
| 自主 Agent | 6：1 Leader + 5 Worker |
| Skill | 7 |
| 固定仓库 | 3 |
| 边界/路由任务 | 24，不是补丁解决任务 |
| GLM 成对 Skill 评测 | 6 个早期 Skill，不含 `github-evidence` |
| 真实 AgentTeams 项目 | 已完成 2 个依赖节点；另有旧 Locator `FAILED` 任务；最新一次 fresh operator-driven T2 边界任务完成并验证提交、重试、冲突、读回、Leader 验收及 2/2 文件同步；均不是六阶段修复，也不构成成功率统计 |
| 角色 Skill 策略 | v1.3.0 六包已通过本地确定性/源码重放校验；2026-07-27 的 v1.2.0 包另有长度/SHA-256 和四运行面现场实证；未知/平台 Skill 不在完整边界内 |
| GitHub MCP | 固定范围只读正例及错路径、错身份、直连阻断负例；fresh T2 已完成，项目同步 2/2，`meta.json`/`plan.md` 分别确认存在，但未证明远端字节摘要 |
| 结构化失败回路 | 本地 Leader→Router→Worker 闭环已通过；SQLite 调度路由可跨进程租约与恢复；Reviewer 拒绝经 Leader 校验后 fail-closed；仍不是 AgentTeams Team Room 现场证据，也不代表所有 replay 状态或外部副作用 exactly-once |
| T4 真人闭环 | 已验证暂停和无批准拒绝；真人签名批准及恢复未完成 |
| OpenClaw 强边界 | `strongBoundaryEnforceable=false`，6 项 blocker 已记录 |
| 方案文件 | 12 页 PPT/PDF 已完成本地 QA；未等同平台提交 |
| 正式视频 | 未完成 |
| 当前候选工作树覆盖率 | 2026-07-30 完整门：1,330 passed、24 skipped、84.06%（6,325 statements / 1,008 missed）；尚未绑定 clean commit、CI 或 release provenance，最终 commit 必须再次复跑 |

## 最终提交前 30 分钟

- [ ] 再次打开官方页面，核对截止时间、上传字段、格式和大小限制。
- [ ] 对简介做报名表内计数并检查换行、英文字符和标点。
- [ ] 用无缓存环境打开最终 PDF/PPT；抽查所有外链与二维码。
- [ ] 确认仓库匿名可访问，commit/tag 存在且没有未提交的参赛改动。
- [ ] 运行最终测试门并把日期、commit、通过数、覆盖率写入证据，不手工改数。
- [ ] 对全部上传文件做最后一次凭据与个人信息扫描。
- [ ] 保存平台提交成功页或回执；回执才代表真正完成提交。
