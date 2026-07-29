import path from "node:path";
import os from "node:os";
import fs from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const key = argv[index];
    if (!key.startsWith("--")) throw new Error(`Unexpected argument: ${key}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      options[key.slice(2)] = true;
      continue;
    }
    options[key.slice(2)] = value;
    index += 1;
  }
  return options;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  console.log([
    "Usage:",
    "  node scripts/author_finals_deck.mjs [--source <template.pptx>] [--out <final.pptx>]",
    "",
    "Defaults:",
    "  --source docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx",
    "  --out    outputs/DevFlow_GOAI_2026_决赛路演_20260728.pptx",
  ].join("\n"));
  process.exit(0);
}

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, "..");
const sourcePptxPath = path.resolve(
  repoRoot,
  args.source || "docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx",
);
const finalPptxPath = path.resolve(
  repoRoot,
  args.out || "outputs/DevFlow_GOAI_2026_决赛路演_20260728.pptx",
);

const runtimeDependencies = path.resolve(
  process.env.CODEX_RUNTIME_DEPENDENCIES ||
    path.join(os.homedir(), ".cache", "codex-runtimes", "codex-primary-runtime", "dependencies"),
);
const artifactEntrypoints = [
  process.env.CODEX_ARTIFACT_TOOL_ENTRYPOINT,
  path.join(runtimeDependencies, "node", "node_modules", "@oai", "artifact-tool", "dist", "node", "artifact_tool.mjs"),
  path.join(runtimeDependencies, "node", "node_modules", "@oai", "artifact-tool", "dist", "artifact_tool.mjs"),
].filter(Boolean);
let artifactEntrypoint;
for (const candidate of artifactEntrypoints) {
  try {
    await fs.access(candidate);
    artifactEntrypoint = candidate;
    break;
  } catch {
    // Continue to the next supported bundled-runtime location.
  }
}
if (!artifactEntrypoint) {
  throw new Error(
    "Could not locate @oai/artifact-tool. Set CODEX_RUNTIME_DEPENDENCIES or CODEX_ARTIFACT_TOOL_ENTRYPOINT.",
  );
}
const { FileBlob, PresentationFile } = await import(pathToFileURL(artifactEntrypoint).href);

const presentation = await PresentationFile.importPptx(await FileBlob.load(sourcePptxPath));

// Artifact-tool anchor ids are scoped to the current import. Resolve the
// inherited template elements by their exact source text inside this import.
const inspection = await presentation.inspect({
  kind: "slide,textbox,shape,image,table,chart",
  maxChars: 200000,
});
const inspectionRecords = String(inspection.ndjson || "")
  .split(/\r?\n/)
  .filter(Boolean)
  .map((line) => JSON.parse(line));

function replaceExact(label, before, after) {
  const candidates = inspectionRecords.filter(
    (record) => record.kind === "textbox" && record.text === before,
  );
  if (candidates.length !== 1) {
    throw new Error(`Expected one inherited textbox for ${label}; found ${candidates.length}: ${before}`);
  }
  const currentRecord = candidates[0];
  const target = presentation.resolve(currentRecord.id);
  if (!target?.text) {
    throw new Error(`Text target not found: ${label}`);
  }
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  if (beforeLines.length !== afterLines.length) {
    throw new Error(`Line-count-changing replacement is not allowed for ${label}`);
  }
  // Replacing one inherited paragraph at a time preserves the source run
  // formatting. Cross-paragraph replacement is intentionally avoided because
  // imported OOXML paragraph boundaries are not represented as a single run.
  for (let line = 0; line < beforeLines.length; line += 1) {
    if (beforeLines[line] !== afterLines[line]) {
      target.text.replace(beforeLines[line], afterLines[line]);
    }
  }
}

const replacements = [
  ["sh/0nepknq1", "DevFlow\n边界驱动的多 Agent 研发闭环", "DevFlow\n可审计的多 Agent 研发闭环"],
  ["sh/mpw7mx87", "以 AgentTeams 为协同基点｜职责清晰、交接可验、工具默认拒绝", "AgentTeams 基点｜职责有界｜交接可验｜风险暂停"],
  ["sh/nq58vips", "GOAI 2026 · AGENT INFRA", "GOAI 2026 · AGENT INFRA · FINALS"],

  ["sh/hw36t03u", "复杂研发问题，失败往往发生在协作边界", "研发自动化的难点不是“会写代码”，而是协作结果可信"],
  ["sh/utc7il43", "专职角色\n职责不漂移", "自主角色\n职责不漂移"],
  ["sh/4zepofm5", "可复用 Skill\n输入输出可验", "可复用 Skill\n契约与验证器"],
  ["sh/vulorqlo", "路由 / 边界基准\n不是补丁解决率", "固定仓库任务\n当前不虚报成功率"],
  ["sh/ozatgby1", "24 项", "3×7"],
  [
    "sh/3y1c76hg",
    "场景与价值\n同一 Issue 在分类、定位、修改、测试、审查之间流转。身份、证据与权限一旦混在聊天里，结果就难复验；DevFlow 把每次协作收敛为可验证合同。",
    "场景与价值\n同一 Issue 需要分类、定位、修改、测试、审查与经验沉淀。DevFlow 不把身份、证据和权限藏在聊天里，而把每次协作收敛为可验证合同；3 个固定版本仓库各 7 个任务已建清单，尚未执行就不报告成功率。",
  ],

  ["sh/gz6tkzat", "六角色不是角色扮演：每个身份只有一个可追责出口", "六个自主角色，一个外部授权主体：责任不重叠"],
  ["sh/54faxorq", "TeamLeader\n拆解 DAG、跟踪状态、冲突仲裁、失败重排；不写代码、不跑测试。", "TeamLeader\n拆任务、签发有界路由、仲裁恢复；唯一分派/验收出口。"],
  ["sh/y5krapsv", "Triage\nissue-classifier → ClassifiedIssue；不读写仓库。", "Triage\n只做分类；不读写仓库，结构化结果回 Leader。"],
  ["sh/z6tsja9g", "Locator\n固定 revision 只读定位；不得修改、执行或扩大路径范围。", "Locator\n固定四元 scope 只读；不修改、不执行、不扩权。"],
  ["sh/vy54jqxw", "Coder\n仅产最小补丁候选；不测试、不推送、不合并。", "Coder\n只产最小补丁；不测试、不推送，结果回 Leader。"],
  ["sh/h0fat4re", "Tester\n一次性副本验证；只运行服务器预注册 CI 动作。", "Tester\n隔离副本跑预注册 CI，签名测试证据；不改 canonical。"],
  ["sh/i1obm9sz", "Reviewer\n独立审查与经验提炼；不合并、不部署、无 GitHub 写能力。", "Reviewer\n只给 ready/retry/blocked；不合并、不部署、不直达 Coder。"],
  ["sh/32xsve9k", "HumanReviewer\n系统外部授权主体；只批准 T4/T5，不计入六个 Agent。", "Human Authority\n外部授权主体；只对精确 T4/T5 目标签名，不是 Agent。"],
  ["sh/436toja5", "冲突优先级\n安全 > 人工策略 > 测试证据 > 审查 > Coder 自检。", "冲突优先级\n安全 > 外部批准 > 签名测试 > 审查 > Coder 自检。"],

  ["sh/vapwjitg", "身份可执行，交接可校验\n房间消息只做协作，不做授权", "身份、交接、权限三层同时成立\n任务才可以执行"],
  ["sh/u9gvadsv", "01｜我是谁\n进程身份 + Worker 角色 + Skill owner。\n提示词里的“我是 Leader”不能改变进程身份。", "01｜我是谁\n进程身份 + Worker + Skill owner。\n提示词不能升级身份或权限。"],
  ["sh/87yd83ap", "02｜我拿到什么\nHandoffEnvelope 绑定 producer / consumer / task / Skill / payload type / SHA-256 / trace / idempotency。", "02｜我拿到什么\nHandoff 绑定 parent route/status、双方身份、Skill、payload digest、trace 与幂等键。"],
  ["sh/987eh8ba", "03｜我能做什么\n身份 ∩ Skill ∩ MCP ∩ 参数 ∩ 上下文 ∩ 人工批准。任一未知、错配或过期，默认拒绝。", "03｜我能做什么\n身份 ∩ Skill ∩ MCP ∩ scope ∩ 状态 ∩ 外部批准；未知、错配或过期即拒绝。"],

  ["sh/1orip4ju", "TeamHarness 将“协作”约束成有状态协议", "AgentTeams 五项硬映射：从框架对象到协作语义"],
  ["sh/orihkj25", "ASSIGN / ACK", "01 角色 / 02 拆解"],
  ["sh/3upgfa1g", "SUBMIT / ACCEPT", "03 上下文 / 04 执行"],
  ["sh/itwz65kv", "REPORT / READBACK", "05 状态追踪"],
  ["sh/t8j6d43a", "风险先冻结\nLeader 固定 T1–T5；有界 assignment。Worker 只对自己的任务幂等 ACK。", "角色编排｜任务拆解\nManager 建 Team；Leader 拆 DAG 并定向 assignment；Worker 只 ACK 自己的任务。"],
  ["sh/snqp4z25", "摘要不漂移\n同 assignment 重试必须保持同一摘要；不同摘要直接冲突失败。红测经 Leader 转发脱敏、有界证据。", "上下文传递｜协同执行\nTeam Room 共享状态，Worker Room 保持最小上下文；Handoff 验证后调用所属 Skill。"],
  ["sh/6l8729kz", "完成要读回\nmark → push → pending=false。T4/T5 设计要求外部 Ed25519 批准；真人闭环尚待实证。", "状态追踪\ntaskflow 跟踪 ACK、结果、验收与读回；失败 retry，高风险 PAUSED。"],

  ["sh/0juhszid", "GitHub 只读能力：请求必须穿过五道边界", "MCP 权限不是提示词：每次读取穿过五道边界"],
  ["sh/e9cnelcb", "Leader：签发固定 repo / revision / path", "Leader：签发 tenant / repo / revision / path"],
  ["sh/ofe5kfud", "Locator：仅 github-evidence，可读不可写", "Locator：仅 github-evidence；只读、不可扩大 scope"],
  ["sh/mdwni5cn", "Higress：Consumer=Locator；Wasm FAIL_CLOSE", "Higress：Consumer=Locator；身份错配 FAIL_CLOSE"],
  ["sh/nml03eh4", "Broker：复核能力签名、Agent + Skill 与精确 scope", "Broker：复核 token、Agent/Skill 与精确 scope"],
  ["sh/bq507eh0", "回执：Git object + content digest，可独立重算", "回执：task/request + Git object + content digest"],
  ["sh/poni54zu", "默认拒绝：错路径 403｜Reviewer 403｜Locator 直连 Broker 被阻断", "默认拒绝：错路径｜错租户｜错身份｜直连｜过期或重放"],

  ["sh/476tsrux", "七个 Skill 的工程标准：可调用、可拒绝、可验证、可复用", "七个 Skill 是可发布资产，不是七段提示词"],
  ["sh/58fu1wvi", "test-runner\nTester｜隔离副本、基线与回归 → TestEvidence", "test-runner\nTester｜隔离基线→候选；签名 attestation → TestEvidence"],
  ["sh/uh4bmxcv", "pr-reviewer\nReviewer｜正确性、安全性与是否可进入人工门", "pr-reviewer\nReviewer｜ready / retry / blocked；T4/T5 只能 blocked"],
  ["sh/vidsv2dg", "experience-distiller\nReviewer｜脱敏复盘 → 可复用经验", "experience-distiller\nReviewer｜只消费 VERIFIED 终态证据；无终态不沉淀"],
  ["sh/w3mto7u1", "统一质量门\n输入输出、触发拒绝、依赖失败、角色归属、安全验证、版本；7/7 静态 100/100。", "统一质量门\n7/7 静态 100/100；14 组行为案例结构门；每个 Skill 可独立校验与回滚。"],
  ["sh/fehc76dk", "github-evidence\nLocator｜固定 repo / revision / path 的只读证据", "github-evidence\nLocator｜固定 tenant / repo / revision / path 的只读证据"],

  ["sh/zq1cnulc", "真实环境已验证的不是“会说”，而是状态与拒绝", "离线 Demo 不是预制 JSON：六阶段、真实测试、持久审计"],
  ["sh/rmhcjulg", "2 节点", "6/6"],
  ["sh/3mh4rmxc", "3 层", "18"],
  ["sh/2l83yhgr", "84.40%", "7/7"],
  ["sh/0ratwz2x", "Triage → Reviewer\ncompleted；pending=false", "阶段路由\n注册→租约→封存"],
  ["sh/ql8bqp4v", "错路径 / 错身份 / 直连\n分别被拒绝或阻断", "审计事件\n哈希链可离线重算"],
  ["sh/lsjup43i", "846 passed / 17 skipped\n7/7 Skill 静态 100/100", "Skill 包\n独立验证器全部通过"],
  ["sh/pozmtwfi", "现场证据 + 本地发布门\n2026-07-27 AgentTeams v1.2.0-beta.1 现场；2026-07-28 DevFlow v1.3.0 本地门。数字分别对应项目状态、边界负例与本地质量。", "本地确定性证据\n同一 task 走六个阶段路由：隔离 CI、SQLite 路由账本、跨进程租约、哈希审计链均真实执行。它只证明本地状态机与边界可复跑；不冒充集群现场或仓库修复成功率。"],

  ["sh/t43y1on6", "证据矩阵：把“现场”“测试”“待验证”明确分层", "证据矩阵：能力、失败与诚实口径逐项对齐"],
  ["sh/s3ux836l", "证据纪律\n每条能力只使用与其成熟度匹配的表述；真实集群、本地确定性演示与边界基准不得拼接成未发生的完整修复。", "证据纪律\n真实现场、本地集成与清单验证分别陈列。尚未发生的集群六阶段、真人批准恢复与仓库修复，不用拼接证据代替。"],

  ["sh/4fqds3it", "官方评分不是堆工具：五项权重围绕闭环证据", "官方评分的 95% 在价值、协同、Skill 与工程证据"],
  ["sh/5gzel8jy", "75%｜价值 + 协同 + Skill\n场景 25%：真实问题与可复制价值。\n协同 25%：身份、状态、异常与人工门。\nSkill 25%：七项资产与复用边界。", "75%｜价值 + 协同 + Skill\n场景25%：三仓固定任务与价值。\n协同25%：六角色、失败、人工门。\nSkill 25%：七项资产可验证、复用、回滚。"],
  ["sh/vqxwfy1w", "20%｜工程、安全、审计\n可运行材料；日志、Trace、Metrics。\nMCP、RAG 与观测链可验证。\n密钥、审批、回滚、降级、审计不缺位。", "20%｜工程 / 安全 / 审计\n可运行交付；Trace / Metrics / Log。\nMCP、RAG、凭据、回滚与审计可验证。\n配置存在不等于集成完成。"],
  ["sh/apovmt0b", "5%｜开放 / 开源\nApache-2.0、接口契约、README、复现实例与贡献说明。公开仓库、最终 tag 与提交包一致性仍需提交人终检。", "5%｜开放 / 开源\nApache-2.0、README、部署与测试；固定 tag 和交付包用 SHA-256 对齐。"],

  ["sh/zudsz2tw", "距离“夺冠作品”还差三条现场闭环", "决赛现场只演三条链：成功、失败、人工批准"],
  ["sh/mxorahsn", "P0 · 六阶段修复", "成功 · 六阶段"],
  ["sh/p4vatsbu", "P0 · 失败回传", "失败 · 红测回传"],
  ["sh/o3m90na9", "P0 · T4 人工门", "高风险 · T4"],
  ["sh/nehc3qpg", "同一项目跑完整链\nTriage→定位→修复→测试→审查→经验沉淀；保留原始失败、补丁、绿测与 canonical 未改证据。", "同一 task 完整闭环\n分类→定位→修复→测试→审查→沉淀；展示 Team Room、6/6 路由、terminal bundle 与 audit head。"],
  ["sh/md8va58v", "红测必须回 Coder\nTester 生成脱敏有界证据；Leader 校验后转 Coder，不得改写红测结论。", "红测只回 Coder\nTester 返回 FAILED + 红测证据；Leader 验证后只回 Coder，修复重试且不污染经验库。"],
  ["sh/8fqdcvq1", "先拒绝，再签名恢复\npaused→未批准恢复失败→精确摘要签名→resume+审计。完成后再录正式视频并冻结最终覆盖率。", "先拒绝，再恢复\nblocked→PAUSED；无批准恢复失败；外部精确签名一次消费后 resume，重放仍拒绝。"],

  ["sh/nqtcv6dw", "已验证｜六角色部署 / 两节点闭环\n已验证｜GitHub 三层负例 / 摘要回执\n待现场｜六阶段 / 红测闭环 / T4 真人恢复", "本地已验｜六阶段 / CI / 审计 / T4\n现场已验｜两节点 / GitHub 只读边界\n待补录｜集群闭环 / 真人批准 / 三仓基准"],
  ["sh/2pkvm1wb", "DEVFLOW · PRELIM", "DEVFLOW FINALS"],
];

for (const [id, before, after] of replacements) {
  replaceExact(id, before, after);
}

const evidenceTableRecord = inspectionRecords.find(
  (record) => record.kind === "table" && record.rows === 9 && record.cols === 5,
);
if (!evidenceTableRecord) {
  throw new Error("Could not locate the inherited 9x5 evidence table");
}
const evidenceTable = presentation.resolve(evidenceTableRecord.id);
const evidenceRows = [
  ["能力", "证据层级", "成功证据", "失败 / 恢复", "诚实口径"],
  ["六阶段协作", "本地实跑", "6/6 路由封存", "重复 / 冲突拒绝", "非集群现场"],
  ["路由权威", "跨进程测试", "SQLite 租约", "过期租约恢复", "外部副作用非恰一次"],
  ["测试完整性", "本地集成", "基线→候选转绿", "假 attestation 拒绝", "非真实仓库基准"],
  ["T4 审批", "本地集成", "精确签名后恢复", "错签名 / 重放拒绝", "集群恢复待录"],
  ["AgentTeams", "真实现场", "T2 completed", "无批准恢复拒绝", "目前仅两节点"],
  ["GitHub MCP", "真实现场", "固定 scope 读取", "错路径 / 身份 / 直连拒绝", "只读单范围"],
  ["RAG 隔离", "本地集成", "tenant/repo/revision", "篡改 / 跨租户拒绝", "Chroma 现场待补"],
  ["仓库基准", "清单验证", "3 仓 × 7 任务", "executed = 0", "不报成功率"],
];

for (let row = 0; row < evidenceRows.length; row += 1) {
  for (let column = 0; column < evidenceRows[row].length; column += 1) {
    evidenceTable.cells.set(row, column, evidenceRows[row][column]);
  }
}

const notes = [
  "开场：DevFlow 不以‘生成更多代码’为卖点，而是让多 Agent 研发协作可追责、可暂停、可复验。决赛版的核心是边界与证据。\n[Sources]\n- https://www.goaihz.com/tracks?track=infra（Agent Infra 官方赛道页，访问 2026-07-28）\n- README.md\n- docs/finals/ACCEPTANCE_MATRIX_CN.md",
  "问题：多 Agent 失败通常不是模型不会，而是责任漂移、证据丢失、权限越界。三个数字分别是 6 个自主 Agent、7 个可发布 Skill、3 个仓库各 7 个已冻结任务；任务尚未执行，所以不报解决率。\n[Sources]\n- benchmarks/repository_repair/tasks.yaml\n- docs/BENCHMARK.md\n- docs/finals/ACCEPTANCE_MATRIX_CN.md",
  "强调 Human Authority 不是第七个 Agent。所有 Worker 结果只回 Leader，避免点对点通信导致状态分叉；审批主体只授予精确目标的一次性授权。\n[Sources]\n- config/agents.yaml\n- agentteams/team.yaml\n- docs/BOUNDARIES_AND_MCP.md",
  "三层门：运行时身份决定‘是谁’，父子路由和摘要决定‘拿到什么’，Skill/MCP/scope/状态/批准的交集决定‘能做什么’。聊天内容本身不产生权限。\n[Sources]\n- src/devflow/collaboration/ledger.py\n- src/devflow/skills/contracts.py\n- docs/BOUNDARIES_AND_MCP.md",
  "这一页逐字对应官方五项核验：角色编排与任务拆解落在 Manager–Team–Worker 和 assignment；上下文传递与协同执行落在 Team Room、Worker Room、Handoff 与 Skill；状态追踪落在 taskflow、readback、retry 和 PAUSED。ready/SUCCESS 与 retry/blocked/FAILED 仍由 guard 强校验。\n[Sources]\n- https://www.goaihz.com/tracks?track=infra（AgentTeams 五项映射要求，访问 2026-07-28）\n- docs/submission/AGENTTEAMS_MAPPING_CN.md\n- agentteams/teamharness/guarded_server.py",
  "MCP 不靠提示词保护。Leader、Locator、Higress、Broker、GitHub API 每层都校验不同边界；错路径、错租户、错身份、直连、过期与重放都 fail closed。\n[Sources]\n- config/mcp_servers.yaml\n- agentteams/teamharness/guarded_server.py\n- tests/test_teamharness_github_capability.py",
  "每个 Skill 是版本化资产：合同、触发/拒绝条件、依赖失败、安全边界、正反例与独立验证器齐全。测试证据要签名，经验只从 VERIFIED 终态进入。\n[Sources]\n- skills/\n- evals/skill_behavior/cases.yaml\n- src/devflow/skills/catalog.py\n- tests/test_skill_validator_standalone.py",
  "这是本地确定性 Demo 的真实运行口径：六个阶段路由全部注册、租约与封存；18 条审计事件形成可重算哈希链；7 个 Skill 独立验证器通过。它不替代真实集群证据。\n[Sources]\n- src/devflow/demo.py\n- src/devflow/collaboration/ledger.py\n- tests/test_demo.py",
  "证据必须分层。真实 AgentTeams 两节点与 GitHub 边界、本地六阶段/T4/RAG 集成、以及仅建立清单的仓库任务不能拼成一个未发生的‘生产闭环’。\n[Sources]\n- docs/evidence/AGENTTEAMS_LIVE_20260727.md\n- docs/finals/ACCEPTANCE_MATRIX_CN.md\n- docs/evidence/REPOSITORY_REPAIR_BASELINE.md",
  "这是截至 2026-07-28 唯一公开可核验的评分权重。MCP、RAG、可观测推荐但不按数量计分；AgentTeams 与 Skill 是硬基线。\n[Sources]\n- https://www.goaihz.com/tracks?track=infra（访问 2026-07-28）\n- https://www.goaihz.com/faq（访问 2026-07-28）\n- docs/finals/ACCEPTANCE_MATRIX_CN.md",
  "现场脚本只演三条链：成功、失败、高风险。每条都展示原始状态、失败或拒绝、以及可重算证据；若网络不可用，切换本地隔离 Demo 与已冻结的真实现场证据包。\n[Sources]\n- docs/finals/DEMO_SCRIPT_CN.md\n- tests/test_agent_failure_recovery.py\n- tests/test_human_approval.py",
  "收束：已经验证什么、在哪里验证、还欠什么，全部明确。服务器指纹核验后补录集群六阶段、红测恢复、T4 真人批准和 3 仓真实基准，再冻结最终 tag 与交付哈希。\n[Sources]\n- docs/finals/ACCEPTANCE_MATRIX_CN.md\n- docs/evidence/AGENTTEAMS_LIVE_20260727.md\n- docs/BENCHMARK.md",
];

const slides = presentation.slides.items;
if (!Array.isArray(slides) || slides.length !== notes.length) {
  throw new Error(`Expected ${notes.length} slides, found ${slides?.length}`);
}

for (let index = 0; index < notes.length; index += 1) {
  const slide = slides[index];
  slide.speakerNotes.textFrame.setText(notes[index]);
  slide.speakerNotes.setVisible(true);
}

const pptx = await PresentationFile.exportPptx(presentation);
await pptx.save(finalPptxPath);
console.log(finalPptxPath);
