# 现场演示脚本（8 分钟）

## 0:00–0:45｜先讲边界

打开职责矩阵：说明六个 Agent 为什么不可互换。强调 TeamLeader 只能
编排，Coder 无 Git/MCP 权限，Tester 只执行服务端预注册命令，Reviewer
不能合并。

## 0:45–2:00｜展示正常闭环

提交一个 T2 缺陷。依次展示分类、定位、typed patch、隔离测试、审查与
经验沉淀的 envelope；每一步指出 producer、consumer、Skill、digest 和
trace id。展示 canonical checkout 未改变。

## 2:00–3:10｜展示失败返回

注入一个会让测试失败的候选。展示 Tester 输出失败证据并返回 Coder，
TeamLeader 保持状态为 retry，而不是继续到 Reviewer。再次交付修复后展示
同一 idempotency key 不会产生重复副作用。

## 3:10–4:10｜展示 MCP 默认拒绝

尝试三次越权：Coder 调 CI、Locator 请求路径逃逸、Reviewer 请求回滚但
不带批准。展示三次均在 transport 前失败；打开审计记录，只显示身份、
trace 与参数摘要，不显示 token 或原始参数。

## 4:10–5:20｜展示 T4 人工门

将同一修复标为 T4。Reviewer 即使看到绿色测试也只发
`approval.required`。在 Team Room 由现场人员批准精确 digest，展示暂停、
批准、恢复三种状态。若 AgentTeams 主机未就绪，必须明确跳过此段，不能
用本地事件日志冒充 Team Room。

## 5:20–6:25｜展示真实回滚

触发 staging 原子回滚：发布指针切到上一版本，健康检查通过，随后恢复；
运行完整审计链校验。指出批准同时绑定 action、target 与 arguments digest。

## 6:25–7:15｜展示量化证据

展示服务器覆盖率、六个 Skill 质量门、三仓库 24 项基准的成功率、安全率、
p50/p95 时延、人工介入率和 token。明确区分“路由/边界基准”与完整
SWE-bench patch-resolution。

## 7:15–8:00｜收束

总结三个价值：职责不会漂移、危险动作不能靠提示词越权、任何推进都有
可追溯证据。最后给出未完成项：官方 AgentTeams Team Room 录屏需要可运行
Docker/K8s 主机。

## 演示前检查

- 发布 commit、测试报告与 PPT 数字一致；
- `.env`、终端历史、截图中无密钥；
- MCP/metrics 仅监听 loopback；
- staging 指针可回滚且 production 不参与演示；
- 人工批准人、目标 release 与 patch digest 预先确认；
- 失败路径使用固定 fixture，不临场制造不可控故障。
