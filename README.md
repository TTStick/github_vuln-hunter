# VulnHunter — AI 漏洞挖掘 Agent

一个本地运行的 AI 漏洞挖掘工具：在 Web 页面贴 GitHub 仓库地址，自动克隆、规划、扫描、自审、交叉复核，最终产出**可直接提交给上游项目**的详细漏洞报告。

---

## 它能做什么

- **Web 化操作**：填地址 → 选模型 → 入队 → 看仪表盘，全程不用碰命令行（除了启动）。
- **队列式批量挂机**：丢一堆项目进去，一个个跑，跑完看报告。
- **多 LLM 供应商**：
  - **Ollama**（本地）— 自动列出本机已安装模型
  - **Gemini**（在线）— 自动列出可用模型
  - **OpenAI 兼容**（硅基流动 / DeepSeek / Together / 自部署 vLLM 等）— 自动列出模型
- **7 阶段反幻觉流水线**（见下方）— 多层冗余，假阳性被显式标记为 `rejected` 并保留理由。
- **可提交的修复文档**：每个确认漏洞自动生成结构化 Markdown 报告，含 PoC、影响、修复建议、发现过程、推理链路，一键复制 / 下载。
- **实时仪表盘**：项目进度、API 调用次数、token 消耗、模型分布、24 小时时序图。
- **WebSocket 实时日志**：每个项目跑的时候可以打开详情看每一步在干嘛。

---

## 反幻觉策略（这是这个项目的核心价值）

LLM 找漏洞天生爱编造。本工具用**三层冗余**对抗：

### 第 1 层：机械校验（代码片段对齐）
模型在 `scan` 阶段输出的 `code_snippet` 会被**逐行**到真实文件里查找。
如果模型引用的代码在文件里根本不存在 —— 直接打 `_snippet_aligned=false`，在下一阶段自动 `rejected`，理由记为 *"code snippet not found in actual file (likely hallucination)"*。
**这一关砍掉绝大多数纯臆造。**

### 第 2 层：同模型怀疑式自审（self_verify）
同一个模型换一个 system prompt（`SELF_VERIFY_PROMPT`），角色变成**敌对审稿人**，被明确要求"寻找拒绝这个发现的理由"：
- source 真的用户可控吗？
- 中间是否有 sanitizer / 类型转换被忽略了？
- 行号是否真实存在？
- 攻击场景是否需要不切实际的前提？

返回 `confirmed | rejected | uncertain` 三态，低于 0.4 置信度直接砍。

### 第 3 层：跨模型交叉复核（cross_review）
用户可以为同一个项目配置**两套不同的 LLM**：一套做主扫描，一套做最终复核。比如用 DeepSeek 扫描、用 Gemini 复核，或者反过来。复核模型独立校验，不被前一阶段的"确信语气"带偏。

### 最终置信度
`final_confidence = mean(scan_conf, verify_conf, cross_conf)`
被拒绝的发现**不会删除**，而是以 `status=rejected` 入库，附带 `rejected_reason`，方便你人工反向检查"是不是误杀了"。

---

## 快速开始

### 环境要求
- Python 3.10+
- `git` 在 PATH 中（用于克隆仓库）
- 至少一个可用的 LLM 端点（本地 Ollama 或在线 API）

### 安装与启动

```bash
cd vuln-hunter
chmod +x start.sh
./start.sh
```

或者手动：

```bash
pip install -r backend/requirements.txt
cd backend
python main.py
```

启动后访问 **http://localhost:8765**

### 首次使用流程（5 分钟）

1. **添加模型配置** → 点左侧 `配置` → `新建配置`
   - **Ollama**：填 `http://localhost:11434` → 点 `列出模型` → 下拉选择 → 保存
   - **Gemini**：填 API Key → 点 `列出模型` → 选 `gemini-2.0-flash` 之类 → 保存
   - **OpenAI 兼容**（硅基流动示例）：
     - Base URL: `https://api.siliconflow.cn`
     - API Key: 你的 sk-xxx
     - 点 `列出模型` → 选 `deepseek-ai/DeepSeek-V3` → 保存
2. **建议配两套**：一套作为主扫描（侧重代码理解），一套作为复核（侧重批判性）。
3. **新建任务** → 点 `队列` → `新建任务`
   - 贴 GitHub 地址（公开仓库即可，例如 `https://github.com/some/repo`）
   - 选主扫描模型 + 复核模型
   - 加入队列
4. **看仪表盘** → 点 `仪表盘` 看总览，或点项目卡片看实时流水线（7 个进度点会一个个亮起）
5. **看报告** → 任务完成后点项目 → 找到确认漏洞 → 点 `查看完整报告` → `复制` 或 `下载 .md`

---

## 文件结构

```
vuln-hunter/
├── README.md              ← 你正在看
├── start.sh               ← 一键启动
├── backend/
│   ├── requirements.txt
│   ├── main.py            ← FastAPI 入口 + WebSocket + 队列 worker
│   ├── database.py        ← aiosqlite 数据层（5 张表）
│   ├── llm_providers.py   ← 统一 Ollama/Gemini/OpenAI 三种 provider
│   ├── prompts.py         ← 5 个核心提示词（triage/scan/verify/cross/report）
│   ├── git_handler.py     ← 克隆仓库 + 文件树构建 + 元数据探测
│   └── analyzer.py        ← 7 阶段流水线编排
├── frontend/
│   ├── index.html         ← 单页 SPA（4 视图 + 4 弹窗）
│   ├── styles.css         ← 暗色 "operator console" 风格
│   └── app.js             ← 纯 vanilla JS，无构建
└── data/                  ← 运行时创建
    ├── vulnhunter.db      ← SQLite 数据
    └── repos/             ← 克隆下来的仓库（扫完自动删）
```

---

## 🛠 7 阶段流水线详解

| # | 阶段          | 进度       | 做什么 |
|---|--------------|-----------|--------|
| 1 | `clone`      | 0 → 8%    | `git clone --depth=1` 浅克隆，限时 5 分钟 |
| 2 | `recon`      | 8 → 15%   | 探测语言/框架（看 package.json、requirements.txt、go.mod 等），构建文件树（跳过 node_modules、tests、vendor 等） |
| 3 | `triage`     | 15 → 25%  | **小仓库**（<300 文件）：单遍让模型挑高风险文件。**大仓库 / monorepo**：两遍 —— 先按目录摘要挑感兴趣的子目录，再在那些目录里挑文件。模型挑出 <3 个文件时启发式按关键词（auth/exec/upload/parse 等）兜底补到 25 个 |
| 4 | `scan`       | 25 → 45%  | 对每个高风险文件，主模型按 15+ 种漏洞类型扫描。严格要求 "source-to-sink 可追溯，不确定就空，宁缺勿滥" |
| 5 | `self_verify`| 50 → 70%  | 主模型扮演敌对审稿人重审每个发现。低于 0.4 confidence 砍掉 |
| 6 | `cross_review`| 72 → 90% | **复核模型**（可换不同模型）独立验证，输出 exploit_sketch 和 real_severity |
| 7 | `report`     | 92 → 100% | 复核模型生成可提交的 Markdown 报告（含 PoC、影响、修复、发现过程） |

### triage 的三层保险

1. **紧凑目录树**：按目录折叠展示，每个目录列出最多 15 个文件并按关键词预评分（`*risk=N`），让模型即使在大仓库下也能看到全貌的"轮廓"。
2. **两遍 triage**：超过 300 文件或检测到 monorepo 时，先让模型挑目录（看摘要），再在选中目录里挑文件，避免单次上下文塞不下。
3. **启发式兜底**：模型挑得 <3 个文件时，按内置关键词字典（auth/exec/shell/upload/oauth/sql 等共 70+ 词）评分自动补齐到 25 个目标。日志里会标注 `(heuristic match...)`。

---

## 重要提醒

- **本地工具，不要暴露到公网**：监听的是 0.0.0.0:8765，但你的 API Key 存在本地 SQLite 里，别开端口转发。
- **API 费用**：扫一个中等大小项目（~25 个文件）会调用 LLM 大概 50-100 次。在线 API 跑前先确认你的额度。建议先用 Ollama 本地模型测试流程，再换在线大模型跑正式扫描。
- **不是替代人工审计**：这工具是**初筛 + 报告生成器**。"已确认"的发现仍需你人工复核（看代码、跑 PoC）后再提交给上游。提交假漏洞会损害你的声誉，比不提交更糟。
- **挑项目有讲究**：
  - 太热门的项目（如 Linux、Django 核心）已经被审过无数遍，新洞难。
  - 找**中等热度、Star 500-5000、活跃维护、有 SECURITY.md** 的项目更有性价比。
  - 优先看 Web 后端、解析器、网关代理这类**输入面广**的项目。
- **关于残留仓库**：分析完成后 `data/repos/` 下的克隆会被自动清理。如果中途崩溃可能残留，手动删 `data/repos/*` 即可。
- **关于 Ollama 模型选择**：本地模型至少需要 14B 以上才有像样的代码理解能力（`qwen2.5-coder:14b`、`deepseek-coder-v2:16b` 起步），更小的模型幻觉率会很高。

---

## 故障排除

| 现象 | 可能原因 |
|------|---------|
| 启动报 `Address already in use` | 8765 端口被占，改 `backend/main.py` 末尾的 port |
| Ollama 列模型返回空 | Ollama 服务没启，或 base_url 写错（注意不要带 `/v1`） |
| Gemini 401/403 | API Key 失效，或在你所在地区不可用 |
| 扫描全是 0 发现 | 模型太小、项目语言不在主流支持范围、或文件都被 tree 过滤掉了。看日志里 `triage` 阶段的输出 |
| 进度卡在某一阶段 | LLM 端点超时。点项目详情看日志，里面会有 retry / error |

---

## 数据库表（如果你想 SQL 直查）

```
projects        — 任务主表（status, stage, progress, *_findings 计数）
scan_logs       — 每条流水线日志（level, stage, message）
findings        — 漏洞主表（status=confirmed/rejected，含完整推理链）
api_usage       — 每次 LLM 调用记录（tokens, latency, success）
llm_configs     — 你保存的模型配置
```

`sqlite3 data/vulnhunter.db` 可以直接连进去查。

---

## 提交漏洞的建议工作流

1. 仪表盘点开 `confirmed` 发现
2. 完整看一遍 Markdown 报告，重点核对：
   - `code_snippet` 是否真的在那个文件那个行号
   - `data_flow` 的 source 是不是真用户可控
   - `exploit_scenario` 你自己能不能复现
3. 在本地 checkout 那个 commit，尝试跑 PoC
4. 跑通了 → 给项目维护者发 security advisory（GitHub 上有 SECURITY.md 的按指引，没有的发邮件，**不要直接开 public issue**）
5. 收到回复 / CVE 编号后再写到简历里

祝你挖到第一个 CVE 

---

## 修订记录

**v0.2 — 大仓库 triage 修复 + 多处打磨**
- 修复 monorepo / 大仓库下 triage 选 0 文件的 bug：把单次文件树截断（12K 字符截死）改为两段式 triage（先目录再文件）+ 按目录折叠的紧凑树表示
- 启发式兜底：当模型挑出 <3 个文件时，按 70+ 安全关键词自动评分补足目标列表
- 扩展跳过列表：`evals/`、`integration-tests/`、`test-utils/`、`mocks/`、`*.test.ts`、`*.spec.js`、`*.d.ts`、`*-lock.json`、`*.eval.ts` 等都不再纳入扫描
- monorepo 检测：自动识别 `packages/*` / `apps/*` / `libs/*` / `services/*` / `crates/*` 子项目
- 改进路径匹配：处理 `\` / `./` / 大小写差异，避免 LLM 返回的路径被误丢
- 改进代码片段对齐：用空白折叠的子串匹配，比之前的简单 replace 鲁棒得多
- 新增 `重跑` 按钮：done/failed 的项目可以一键重新分析
- 启动时自动清理：上次崩溃残留的 cloning/analyzing 任务标记为 failed，data/repos/ 下的残留目录自动删除
- 详情页显示 `已扫描/总文件数` 和 `原始→确认/淘汰` 统计
- 框架探测扩展：新增 nestjs / koa / hapi / fastify / tornado / aiohttp / echo / fiber / graphql / grpc 等

**v0.1** — 首版发布。
