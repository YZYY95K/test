# DevFlow 决赛路演材料 QA（2026-07-28）

本记录只冻结本轮决赛 PPT/PDF 的内容、模板和可重建性证据；不把仍在变化的全量测试数、覆盖率、commit 或 tag 写成最终值。

## 固化的生成源

- 生成脚本：`scripts/author_finals_deck.mjs`
- 模板输入：`docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx`
- 模板映射：`docs/finals/assets/finals_template_frame_map.json`
- 最终 PPTX：`outputs/DevFlow_GOAI_2026_决赛路演_20260728.pptx`
- 最终 PDF：`outputs/DevFlow_GOAI_2026_决赛路演_20260728.pdf`

在仓库根目录使用 Codex 随附的 Node.js 重建：

```powershell
$node = "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
& $node scripts\author_finals_deck.mjs
```

脚本默认从上面的正式模板输入生成 PPTX；可用 `--source` 和 `--out` 覆盖路径。它从 Codex runtime 定位 `@oai/artifact-tool`，不依赖 `.tmp` 中的脚本、模板或渲染缓存。

## QA 结果

| 检查项 | 结果 |
|---|---|
| PPTX 页数 | 12 |
| OOXML 关系图 | PASS：12 张 slide 与 12 张 notes 双向绑定且全部可达，无外部关系 |
| `slides_test.py` 越界检查 | PASS，0 页越界 |
| 模板忠实度 | PASS，`issueCount=0` |
| 逐页 PPTX 渲染检查 | 12/12 PASS |
| 讲稿 `[Sources]` | 12/12 |
| 本地来源路径 | 33/33 存在 |
| 第 8 页口径 | “六阶段 / 阶段路由”，无“六个 Worker” |
| PDF 页数 | 12 |
| PDF 安全属性 | pypdf 严格解析 PASS：未加密、无表单、无 JavaScript/Launch/嵌入文件 |
| 逐页 PDF 渲染检查 | 12/12 PASS |
| 正式脚本重建对照 | 130 条规范化 inspect 记录，差异 0；重建版越界检查 PASS |

PDF 由最终 PPTX 通过 PowerPoint 固定格式导出；随后用锁定版本 pypdf 解析真实页树与对象图，并逐页重新渲染检查。

本轮核心检查命令：

```powershell
& $python $slidesTest outputs\DevFlow_GOAI_2026_决赛路演_20260728.pptx
& $node $templateFidelity --workspace <qa-workspace> --starter-pptx <template-source> --final-pptx <final-pptx> --map <frame-map> --starter-layout-dir <starter-layouts> --final-layout-dir <final-layouts> --edit-dir <edit-dir>
& $pdfinfo outputs\DevFlow_GOAI_2026_决赛路演_20260728.pdf
& $pdftoppm -png -r 90 outputs\DevFlow_GOAI_2026_决赛路演_20260728.pdf <qa-pages>\page
```

## SHA-256

| 文件 | 字节 | SHA-256 |
|---|---:|---|
| `outputs/DevFlow_GOAI_2026_决赛路演_20260728.pptx` | 53,915 | `65D49007F3970A0779009B9BD778CD3A5A57C8DEB1277AFEC665CD2B18F210C7` |
| `outputs/DevFlow_GOAI_2026_决赛路演_20260728.pdf` | 1,236,340 | `7E3AB8F825F18FD4044A2452CD0E249394751AEAEB29CA505A56EE019F1585AB` |
| `docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx` | 51,883 | `3E6136FA24A4D41EC5564EC10991585E55F47AF9F6B5FFBF1F198FAB5AB14EFE` |

这些哈希只对应本轮材料版本。全量工程门完成后，如重新生成 PPTX/PDF，必须同步更新本记录与提交包清单。
