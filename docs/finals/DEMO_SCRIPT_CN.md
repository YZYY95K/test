# DevFlow 决赛现场演示脚本

本文是决赛讲解与操作的统一台本。组委会尚未公布最终答辩时长、现场网络与设备
限制，因此“完整版”和“压缩版”只是排练模板，不代表官方时限。正式演示前必须
把所有命令、镜像、材料和证据绑定到同一最终 commit；未通过放行门的真实集群链路
不得在台上称为已完成。

## 一句话主张

DevFlow 不是让六个模型自由聊天，而是让六个有边界的 Agent 在 AgentTeams 上按
契约协作：Leader 独占编排权，Worker 只执行所属 Skill，每次交接都可校验，测试
失败有界返回，高风险任务暂停给外部人类授权，最终以测试、评审、审计和终态回执
共同证明任务是否解决。

## 演示口径与放行门

屏幕左上角始终显示当前证据标签：`LIVE AGENTTEAMS`、`LOCAL REPRODUCIBLE` 或
`RECORDED REHEARSAL`，三者不得混用。

| 演示链 | 当前可以证明 | 决赛主链放行条件 |
|---|---|---|
| 成功链 | 本地凭据无关 Demo 真实执行六阶段、基线红到候选绿、6/6 路由封存、18 条哈希链审计；真实集群另有一个两节点 T2 项目完成 | 同一真实 AgentTeams 项目完成六阶段，并留存 Team Room、任务状态、共享制品和终态回执 |
| 失败链 | 本地集成测试真实覆盖 Tester→Leader→Coder、有界失败证据、幂等/冲突与全局三次生成预算；真实集群有一次版本错配 `FAILED`、幂等重提和冲突拒绝 | Team Room 中真实出现红测、`FAILED` 回传、Leader 验证、Coder 第二候选和最终转绿 |
| T4 审批链 | 本地集成覆盖精确目标签名、恢复、一次性消费与防重放；真实集群已证明 `paused` 和无批准恢复被拒 | 外部真人在独立签名端批准精确目标，真实项目成功恢复，并再次重放被拒绝 |

当前现场证据详见[验收矩阵](ACCEPTANCE_MATRIX_CN.md)和
[AgentTeams 现场记录](../evidence/AGENTTEAMS_LIVE_20260727.md)。只有右栏全部完成并
绑定最终 commit 后，才把对应画面标为 `LIVE AGENTTEAMS`。

## 演示前检查

演示负责人在候场时完成下列检查，任何一项失败都切换到离线备用，不在台上修环境。

- 最终仓库为干净工作树，屏幕可见 commit 与发布 tag，PPT/PDF、源码包、SBOM 和
  证据清单的 SHA-256 已固定。
- 六个 AgentTeams Pod 均 Ready；测试项目为新项目，Team Room 为私有且成员精确。
- 成功、失败、T4 三个场景使用不同项目 ID，避免缓存或幂等键相互污染。
- 只准备短期、最小范围的演示凭据；终端历史、环境变量、Matrix 房间 ID、服务器
  地址、能力票据和原始仓库内容均不投屏。
- 外部批准私钥只在独立签名设备；服务器和 Agent Pod 只有公钥，且签名设备时钟正确。
- 本地备用环境已运行 `devflow validate` 和 `devflow demo`；输出目录为空或使用新时间戳。
- 录屏同时保留系统时钟、项目状态与证据摘要；摄像机画面不拍键盘输入的凭据。

## 完整版台本（约 9 分钟）

### 0:00—0:45　问题与判断标准

讲解：

> 自动生成补丁不等于解决问题。我们把“解决”定义为：固定版本上的问题被定位，
> 候选补丁没有改坏测试，隔离环境中由基线失败转为候选通过，评审与安全门通过，
> 高风险审批被正确消费，完整证据可重算；其中任何一项缺失都不是成功。

画面：六角色闭环图。指出 Human Authority 是外部授权主体，不是第七个自主 Agent。

### 0:45—3:25　链一：成功闭环

决赛主链（仅在真实六阶段放行后使用）：

1. 在 `LIVE AGENTTEAMS` 画面创建一个固定 revision 的 T2 缺陷项目。
2. 展示 Leader 生成的有序节点，但不展开提示词：Triage、Locator、Coder、Tester、
   Reviewer、Experience。
3. Team Room 中逐个指出完整交接的四类事实：生产者/消费者、Skill、父任务摘要、
   `READY` 状态。强调 Worker 只能回 Leader，不能私下串联。
4. Locator 展示固定仓库、revision、路径的只读 MCP receipt 摘要；隐藏能力和凭据。
5. Coder 只产出结构化候选，不写 canonical checkout；Tester 在一次性副本中展示
   `baseline_passed=0`、候选测试转绿和测试完整性 attestation。
6. Reviewer 返回 `ready/SUCCESS`，Experience 只接收已验证终态包。Leader 接受所有
   节点后，展示项目 `completed`、requester report `pending=false` 与审计头摘要。

收束句：

> 这不是六段对话拼接；每一步都有一个唯一所有者、一个可验证输入、一个可拒绝输出。

当前可立即重跑的本地证据（也是断网主备用）：

```powershell
.\.venv\Scripts\devflow.exe validate
.\.venv\Scripts\devflow.exe demo --output-dir .devflow\runs\finals-demo
```

投屏只展示结果表和新生成的证据文件。依次指出：`T2` 分类、`calculator.py` 根因、
基线红到候选绿、Review `approved`、Experience `stored`、`6/6 sealed`、
`18 entries / valid` 和终态 `verified`。明确说“这是本地可复现六阶段，不是
AgentTeams 集群六阶段录像”。

### 3:25—5:30　链二：失败不是异常文本，而是受控状态

决赛主链（仅在真实 Team Room 重试放行后使用）：

1. 提交一个第一候选仍会红测的固定场景。
2. Tester 返回 `retry/FAILED`，结果必须包含失败证据；若它谎报
   `ready/SUCCESS`，TeamHarness guard 当场拒绝。
3. Leader 校验 Tester 路由、候选摘要、测试完整性与父因果摘要，删除原始日志中的
   敏感信息，只把有界 `TestFailureEvidence` 路由给 Coder。
4. Coder 生成第二候选，Tester 再测，展示从红到绿。重复投递返回缓存结果；同一路由
   不同结果被记录为冲突，不会多执行一次。
5. 指出全局生成预算最多三次；预算耗尽后升级给人，不会无限自修。

当前本地可重跑证据：

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests/test_agents.py::test_local_router_closes_coder_tester_retry_loop_from_one_route `
  tests/test_agent_failure_recovery.py::test_verified_failure_routes_real_retry_and_is_idempotent `
  -q
```

讲解必须使用“本地集成测试验证”。真实集群目前只另行证明过版本错配返回
`FAILED`、相同结果幂等、改变结果冲突拒绝，不能把两者拼成一次不存在的现场修复。

### 5:30—7:45　链三：T4 人工审批是外部授权，不是聊天同意

决赛主链（只有真实签名恢复放行后使用）：

1. Reviewer 对 T4 返回 `blocked/FAILED` 和精确 `HumanApprovalTarget`；Leader 将项目
   置为 `paused`。
2. 先展示一次无批准恢复，系统稳定拒绝。不要修改策略或手工改数据库。
3. 服务器侧生成公开审批请求；输出只含项目绑定、revision、候选、测试、评审、策略
   公钥摘要、nonce 和有效期。示例命令中的项目 ID 必须是新建的演示项目：

```powershell
.\.venv\Scripts\python.exe scripts\run_agentteams_t4_approval.py `
  --prepare --project-id <fresh-t4-project> `
  --confirm EXECUTE_FRESH_T4_APPROVAL_PREPARE
```

4. 将公开请求交给独立签名设备。真人核对差异、测试和评审后，使用请求输出给出的
   `APPROVE_T4_RESUME:<approvalRequestDigest>` 精确确认词签名。私钥路径、私钥内容和
   原始签名命令不投屏；签名文件只返回公开 evidence 与 signature。
5. Leader 验证签名、域、公钥策略、项目 incarnation、目标摘要、新鲜度与 nonce 后
   恢复项目；展示批准被消费一次。用同一批准再次恢复，必须被重放门拒绝。

当前本地可重跑证据：

```powershell
.\.venv\Scripts\python.exe -m pytest `
  tests/test_human_approval.py::test_t4_requires_exact_external_approval_and_resumes_once `
  tests/test_human_approval.py::test_durable_approval_consumption_is_one_shot_across_processes `
  tests/test_agentteams_t4_approval.py::test_resume_accepts_exact_public_shape_and_proves_replay_denial `
  -q
```

讲解边界：真实集群现在只证明了暂停和未批准恢复拒绝；上面三项是本地集成证据。
在真实签名恢复录制完成前，不说“集群 T4 已闭环”。

### 7:45—9:00　证据总结与评分映射

用一张表收束，不滚动代码：

- 场景价值：固定仓库/版本/任务；21 个修复任务目前 `attempted=0`、`executed=0` 时不报成功率。
- 多 Agent：Leader 中心辐射、父因果交接、失败回传、持久租约与 T4 暂停。
- Skill：七个独立、版本化、带契约和验证器的资产；静态 100/100 只代表结构质量门。
- 工程安全：Agent∩Skill∩MCP 默认拒绝、测试完整性、RAG 精确隔离、哈希审计。
- 开源：Apache-2.0、部署/测试入口、最终 commit、SBOM 和材料摘要一致。

结束句：

> DevFlow 的价值不是让 Agent 看起来忙，而是让每个结果都知道由谁产生、为何可信、
> 失败如何返回、风险由谁批准，以及我们凭什么说问题真的解决了。

## 断网备用方案

断网后不伪造在线 Team Room，也不使用预制 JSON 冒充本次运行。

1. 立即切换屏幕标签为 `LOCAL REPRODUCIBLE`。
2. 运行凭据无关的 `devflow validate` 和 `devflow demo`，现场生成新的 JSON 与 SQLite
   账本；用系统时间和新文件名证明是本次运行。
3. 运行失败链与 T4 链的三个聚焦测试，展示测试名、通过状态和对应源码位置。
4. 若本机也无法执行，切换到 `RECORDED REHEARSAL`：播放绑定最终 commit 的完整录屏，
   同屏展示视频 SHA-256、项目证据清单与提前导出的只读日志。明确说这是录制证据。
5. 网络恢复后只做问答，不在剩余时间临时切回未验证环境。

## 三分钟压缩版

| 时间 | 画面 | 必说句 |
|---:|---|---|
| 0:00—0:30 | 六角色和边界图 | “Leader 独占编排，Worker 只运行所属 Skill，Human 不是 Agent。” |
| 0:30—1:15 | 成功链终态与证据摘要 | “成功要求基线红、候选绿、评审通过、6/6 路由和可重算审计同时成立。” |
| 1:15—2:00 | Tester 红测→Leader→Coder | “失败使用 `retry/FAILED` 和有界证据返回；重复不重做，三次预算后升级。” |
| 2:00—2:40 | T4 暂停、签名目标、重放拒绝 | “聊天同意没有权限；只有外部人类对精确摘要的新鲜签名可恢复一次。” |
| 2:40—3:00 | 验收矩阵 | “当前本地证据、真实集群证据和待录制项分开陈述，不用配置代替运行。” |

## 台上禁语

- 不说“保证夺冠”“完全自主”“零风险”“绝对 exactly-once”。
- 不把 7/7 静态 100 分说成真实任务成功率。
- 不把 21 个 `attempted=0`、`executed=0` 的仓库任务说成已修复。
- 不把一次 T2 或本地六阶段说成真实 AgentTeams 六阶段。
- 不把 `strongBoundaryEnforceable=false` 的当前 OpenClaw 环境说成强 OS 沙箱。
- 不展示或口述任何 token、密码、能力票据、私钥、服务器地址和房间标识。
