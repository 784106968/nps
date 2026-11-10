# 贡献指南

## 分支与提交

- `main` 受保护，只能通过 PR 合入，且 CI 必须通过；
- 分支命名：`feat/<topic>`、`fix/<topic>`、`docs/<topic>`、`chore/<topic>`；
- 提交信息遵循 Conventional Commits：

```text
feat(capture): 支持 pcap_activate 告警分级
fix(filter): 修正 && 与 || 的优先级
docs(concepts): 补充抓包层次说明
```

## PR 要求

- 描述中关联 Issue（`Closes #12`），并写明验证方式（命令、截图或录屏）；
- 涉及捕获、解析、过滤、导出的改动**必须附带测试**；
- GUI 改动必须附截图；
- 每个 PR 至少完成一次自查（对照 Issue 验收标准逐条勾选）。

## 代码规范

- 格式与静态检查：`ruff format`、`ruff check`，行宽 100；
- 类型注解：`nps/core`、`nps/decode`、`nps/filters` 必须标注；
- GUI 线程内禁止阻塞调用与解析工作；
- 新增显示过滤字段必须同步更新 `docs/FILTER_SYNTAX.md` 并补测试。

## 测试

```bash
pytest -m "not requires_npcap"   # 无需真实网卡的用例（CI 运行）
pytest -m requires_npcap         # 需要 Npcap/libpcap 与权限（本地运行）
```

提交前请确保 `pytest` 与 `ruff check` 均通过。

## 数据合规

**禁止提交任何真实抓包文件**。测试数据一律通过 `scripts/make_fixtures.py` 生成合成 PCAP。
提交内容若被判定包含真实流量，将直接回退。

## 文档

- 架构与分层：`docs/ARCHITECTURE.md`
- 抓包层次与加密边界：`docs/CONCEPTS.md`
- 开发环境与故障排查：`docs/DEVELOPMENT.md`
- 过滤语法：`docs/FILTER_SYNTAX.md`
- 开发计划与验收标准：`NPS-Readme.md`
