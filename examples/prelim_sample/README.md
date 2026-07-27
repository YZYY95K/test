# 初赛代码包固定样例

`sample_input.json` 是随仓库提供的固定计算器回归请求；
`expected_output.json` 只冻结可稳定复验的关键断言、事件集合和成功 MCP 调用，不包含模型凭据、主机信息或运行时生成的标识。

在 Python 3.10–3.12 环境中安装开发依赖后运行：

```powershell
python -m devflow.cli validate
python -m devflow.cli demo
python -m pytest tests/test_demo.py -q
```

演示会在 `.devflow/runs/` 生成完整报告。该目录是本地运行证据，不属于提交包 allowlist。
