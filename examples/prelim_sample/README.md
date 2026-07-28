# 初赛代码包固定样例

`sample_input.json` 是随仓库提供的固定计算器回归请求；
`expected_output.json` 冻结可稳定复验的关键断言；
`actual_output.json` 是 2026-07-28 真实运行后提取的脱敏结果摘要。摘要不包含
模型凭据、主机身份、原始模型输出或运行时随机标识。

在 Python 3.10–3.12 环境中安装开发依赖后运行：

```powershell
python -m devflow.cli validate
python -m devflow.cli demo
python -m pytest tests/test_demo.py -q
```

演示会在 `.devflow/runs/` 生成完整本地报告。该目录是本地运行证据，不属于
提交包 allowlist；提交包只包含上述稳定、脱敏的样例文件。
