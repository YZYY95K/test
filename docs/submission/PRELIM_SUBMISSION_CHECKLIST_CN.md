# GOAI 2026 Agent Infra 初赛提交检查表

核对日期：2026-07-28。官方赛道页：
[Global Open-source AI Challenge — Agent Infra](https://www.goaihz.com/tracks)。
初赛截止 **2026-08-16**；提交当天以报名页面显示的时区、大小和格式限制为准。

## 必交材料

- [x] 作品简介正文已写入 `INTRO_500_CN.md`。
- [x] 本地按 .NET UTF-16 `String.Length`（包含空格与段落换行）检查为 489，
  小于 500；仍需以
  报名表计数器为最终标准，标题不粘贴。
- [x] 12 页最终候选方案已生成两种格式：
  [PPT](../../outputs/DevFlow_GOAI_2026_初赛方案_20260727.pptx)（51,885 bytes，
  SHA-256 `ffc838971097db2d6909c901a6684f7324daaca51e060a4bd7596ef2be321e6f`）与
  [PDF](../../outputs/DevFlow_GOAI_2026_初赛方案_20260727.pdf)（1,242,343 bytes，
  SHA-256 `c350edda5880b23ae93f2ff045a0833e492960f793b5df32f64aefac4378db07`）。
  初赛只需上传其中一种，除非平台允许且团队决定同时提交。
- [x] PPT/PDF 已完成本地逐页核对：12 页均渲染为 1920×1080 检查，未发现
  中文乱码、截断或重叠；凭据形态扫描零命中；PDF 未加密且无表单/JavaScript。
- [ ] 在最终 commit/tag 冻结后再次核对材料中的版本、测试数字和仓库链接；
  当前本地 QA 不等于与尚未生成的最终代码包完成一致性校验。
- [ ] 报名表中的项目名、团队/联系人、公开仓库 URL 等参赛者字段由提交人确认。
- [ ] 在 2026-08-16 前完成网页预览并由提交人点击最终提交；本仓库不会代替
  参赛者完成网页确认。

## 方案材料内容映射

- [ ] 场景价值 25%：用户、痛点、失败成本、可复制工作流与 24 项边界基准。
- [ ] 多 Agent 25%：六角色身份、DAG、交接摘要、失败返回、幂等与人工门。
- [ ] Skill 25%：七个 Skill 的契约、触发/拒绝、验证器、所属角色和复用方式。
- [ ] 工程安全审计 20%：MCP 权限交集、服务端复核、短期能力、审计链、回滚、
  OTLP/Prometheus，以及真实证据与待办的界线。
- [ ] 开放开源 5%：许可证、公开仓库、运行入口、贡献方式、固定版本与复现步骤。
- [ ] 官方结构性要求单独一页：至少 3 Agent；AgentTeams 为协同基点；Skill
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
- [x] 六个 v1.2.0 角色专属包已确定性构建，并在集群内逐一核对长度和
  SHA-256；六个替换 Pod Ready。包交付与运行面收敛分别留证。
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
| 角色 Skill 策略 | 6 个确定性包已按长度/SHA-256 验证；固定七项策略在四个运行面收敛，Locator 替换后仍为预期两项；未知/平台 Skill 不在完整边界内 |
| GitHub MCP | 固定范围只读正例及错路径、错身份、直连阻断负例；fresh T2 已完成，项目同步 2/2，`meta.json`/`plan.md` 分别确认存在，但未证明远端字节摘要 |
| T4 真人闭环 | 已验证暂停和无批准拒绝；真人签名批准及恢复未完成 |
| OpenClaw 强边界 | `strongBoundaryEnforceable=false`，6 项 blocker 已记录 |
| 方案文件 | 12 页 PPT/PDF 已完成本地 QA；未等同平台提交 |
| 正式视频 | 未完成 |
| 当前最终覆盖率 | 待最终分支重跑，不沿用旧 82.73% |

## 最终提交前 30 分钟

- [ ] 再次打开官方页面，核对截止时间、上传字段、格式和大小限制。
- [ ] 对简介做报名表内计数并检查换行、英文字符和标点。
- [ ] 用无缓存环境打开最终 PDF/PPT；抽查所有外链与二维码。
- [ ] 确认仓库匿名可访问，commit/tag 存在且没有未提交的参赛改动。
- [ ] 运行最终测试门并把日期、commit、通过数、覆盖率写入证据，不手工改数。
- [ ] 对全部上传文件做最后一次凭据与个人信息扫描。
- [ ] 保存平台提交成功页或回执；回执才代表真正完成提交。
