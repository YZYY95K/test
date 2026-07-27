# 初赛提交包构建与复验

构建器只接受一个干净且已打 Git tag 的提交，不提供 `allow-dirty`、跳过扫描或覆盖已有 ZIP 的参数。
源码、方案和提交文档必须全部由 Git 跟踪；生成物只能写成 `outputs/` 的直接子文件。

前置条件：Python 3.10–3.12、Git，以及用于抽取 PDF 文本的 Poppler `pdftotext`。

```powershell
python scripts/build_prelim_submission.py build `
  --tag goai-prelim-2026-07-27 `
  --output outputs/GOAI_2026_AgentInfra_DevFlow_初赛提交包_20260727.zip
```

脚本从显式 allowlist 构建源码 ZIP，验证 PPTX/PDF 内部内容，然后生成两层清单：源码层的
`SOURCE_MANIFEST.json`、`SOURCE_SHA256SUMS.txt`，以及外层的 `MANIFEST.json`、
`SHA256SUMS.txt`。所有 ZIP 条目固定顺序、时间、权限并使用无压缩存储，因而相同提交、tag
和输入会得到相同字节。

在新目录中取得 ZIP 后可独立复验：

```powershell
python scripts/build_prelim_submission.py verify `
  outputs/GOAI_2026_AgentInfra_DevFlow_初赛提交包_20260727.zip
```

复验会拒绝额外文件、哈希不一致、路径逃逸、重复或 Unicode 冲突路径、链接/非常规 ZIP 元数据、
超限内容、敏感凭据形态、公网 IP、本机用户绝对路径，以及带活动内容或嵌入对象的 PDF/PPTX。
`docs/submission/PRELIM_SUBMISSION_CHECKLIST_CN.md`、旧 ZIP、QA 渲染目录、缓存、`.devflow/`、
`dist/` 和 `agentteams/systemd/` 均不在 allowlist 中。
