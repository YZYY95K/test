# 答辩问题库

## 1. 这和串行工作流有什么区别？

区别不在并发数量，而在独立身份、私有边界、失败返回、可验证交接和不同
授权。任一 Worker 可拒绝输入并把证据返回 TeamLeader；TeamLeader 不能
代做领域工作。

## 2. 为什么 TeamLeader 不是一个可分发 Skill？

它拥有的是运行时状态与调度权限，不是可复用的领域能力。把它发布为普通
Skill 会模糊“谁能改计划”和“谁能做工作”的边界。

## 3. Prompt 写了“禁止越权”还不够吗？

不够。DevFlow 在模型之外验证 Agent+Skill grant、签名上下文、参数、路径、
批准和摘要；拒绝发生在 transport 前，内部服务再验证一次。

## 4. MCP 为什么不是配置型伪实现？

五个工具可由真实 FastMCP endpoint 枚举和调用。流水线在一次性副本执行
server-owned argv，覆盖率来自 `coverage.json`；回滚调用原子 symlink
provider 并做健康检查。

## 5. Agent 能不能把 shell 命令藏在参数里？

不能。接口不接收命令文本，只接收 typed patch、suite、branch、pipeline id
或受限 release；实际 argv 在服务器环境预注册并以 `shell=False` 执行。

## 6. 人工批准如何防止复用？

签名绑定 action、canonical target、完整参数 SHA-256、批准人和时间，并有
有效期。改环境、release 或任一参数都会使验证失败。

## 7. 审计链能否防止管理员重写全部日志？

本地 SHA-256 链能发现局部篡改和断链，但不能对抗可重写全部磁盘的管理员。
生产方案必须把日志同步到外部 append-only/WORM 存储；项目文档不夸大这一点。

## 8. 凭据代理是否真的不泄露密钥？

Agent 只拿到短期签名 capability handle。可信适配器在调用时复查身份、能力、
有效期和当前授权，再从服务端环境解析密钥；handle 本身没有 secret。

## 9. RAG 离线模式是不是语义检索？

不是。`local-hash` 是确定性 feature hashing 降级模式，用于离线可用与测试；
生产语义质量必须使用已开通的 embedding provider。两者在报告中明确区分。

## 10. 82.73% 覆盖率是否足够？

它超过当前 80% CI 门且 TeamLeader/LLM/核心 RAG 达到重点覆盖，但覆盖率不等于
正确性。项目同时保留行为评测、默认拒绝测试、真实服务器集成和人工门证据。

## 11. 三仓库 24 项是否等于 SWE-bench？

不等于。它测量真实源码条件下的路由、边界、安全与成本。完整 issue-resolution
必须在 Docker 标准环境运行 SWE-bench；当前受限服务器不满足前置条件。

## 12. 为什么没有真实 AgentTeams 录屏？

供应服务器是缺少 `CAP_SYS_ADMIN` 的受限容器，不能启动 Docker/K8s；官方
AgentTeams 依赖其中之一。我们保留清晰阻塞证据，不用本地 event bus 冒充。

## 13. Tester 或 Reviewer 与 Coder 冲突时听谁的？

证据优先：红测返回 Coder，高危发现阻断推进，T4/T5 进入人工门。TeamLeader
只能重排和升级，不能覆盖这些硬门。

## 14. 如何控制成本与无限重试？

每个 Agent 有调用时间、token、连续失败和重试上限；失败采用指数退避并在
阈值后交回 TeamLeader。基准记录 provider token 与 p50/p95 时延。

## 15. 开源复用价值在哪里？

Agent 身份、Skill 包、typed contracts、MCP grants、评测清单和验证脚本都在
Apache-2.0 仓库中，可替换模型、Git 提供商或 CI provider，而不改变信任模型。
