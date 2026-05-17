/* VulnHunter 前端逻辑 - 原生 JS SPA */
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const PIPELINE_STAGES = [
  { key: "clone", label: "克隆" },
  { key: "recon", label: "侦察" },
  { key: "triage", label: "分类" },
  { key: "scan", label: "扫描" },
  { key: "self_verify", label: "自验" },
  { key: "cross_review", label: "复核" },
  { key: "report", label: "报告" },
];

const state = {
  view: "dashboard",
  configs: [],
  projects: [],
  currentDetailProjectId: null,
  ws: null,
  pollingTimer: null,
};

// -------- API helpers --------
async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!r.ok) {
    let detail = "";
    try { detail = (await r.json()).detail || r.statusText; } catch (_) { detail = r.statusText; }
    throw new Error(detail);
  }
  return r.json();
}

function toast(msg, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toast-wrap").appendChild(el);
  setTimeout(() => { el.style.opacity = "0"; setTimeout(() => el.remove(), 300); }, 3500);
}

// -------- 路由 --------
function setView(v) {
  state.view = v;
  $$(".view").forEach((x) => x.classList.remove("active"));
  $(`.view-${v}`).classList.add("active");
  $$(".nav-item").forEach((x) => x.classList.toggle("active", x.dataset.view === v));
  if (v === "dashboard") loadDashboard();
  if (v === "queue") loadProjects();
  if (v === "configs") loadConfigs();
  if (v === "usage") loadUsage();
}

$$(".nav-item").forEach((n) => n.addEventListener("click", () => setView(n.dataset.view)));

// -------- 工具 --------
function fmtTime(unix) {
  if (!unix) return "—";
  const d = new Date(unix * 1000);
  return d.toLocaleString("zh-CN", { hour12: false });
}
function fmtDuration(p) {
  if (!p.started_at) return "—";
  const end = p.finished_at || Math.floor(Date.now() / 1000);
  const s = end - p.started_at;
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m${s % 60}s`;
  return `${Math.floor(s / 3600)}h${Math.floor((s % 3600) / 60)}m`;
}

function statusPill(s) {
  return `<span class="status-pill status-${s}">${s}</span>`;
}

function sevBadge(sev) {
  return `<span class="sev-badge sev-${sev || "medium"}">${sev || "med"}</span>`;
}

function openModal(id) { $("#" + id).classList.add("open"); }
function closeModal(id) { $("#" + id).classList.remove("open"); }
$$("[data-close]").forEach((b) => b.addEventListener("click", (e) => closeModal(e.target.dataset.close)));
$$(".modal").forEach((m) => {
  m.addEventListener("click", (e) => { if (e.target === m) m.classList.remove("open"); });
});

// -------- Dashboard --------
async function loadDashboard() {
  try {
    const d = await api("/api/dashboard");
    renderKPIs(d);
    renderActiveList(d.active);
    renderRecent(d);
    renderUsageChart(d.usage.timeseries);
    // worker 状态
    $("#worker-status").textContent = d.active.length > 0
      ? `worker · running (${d.active.length})`
      : "worker · idle";
  } catch (e) {
    toast("加载仪表盘失败：" + e.message, "error");
  }
}

function renderKPIs(d) {
  const t = d.usage.totals || {};
  const conf = d.projects_by_status.done
    ? state.projects.reduce((s, p) => s + (p.confirmed_findings || 0), 0)
    : "—";
  const grid = $("#kpi-grid");
  grid.innerHTML = `
    <div class="kpi amber">
      <div class="kpi-label">项目总数</div>
      <div class="kpi-value">${d.projects_total}<span class="unit">个</span></div>
      <div class="kpi-foot">${d.projects_by_status.done || 0} 完成 · ${d.projects_by_status.queued || 0} 排队</div>
    </div>
    <div class="kpi acid">
      <div class="kpi-label">已确认漏洞</div>
      <div class="kpi-value">${state.projects.reduce((s, p) => s + (p.confirmed_findings || 0), 0)}</div>
      <div class="kpi-foot">来自全部已完成项目</div>
    </div>
    <div class="kpi magenta">
      <div class="kpi-label">幻觉淘汰</div>
      <div class="kpi-value">${state.projects.reduce((s, p) => s + (p.rejected_findings || 0), 0)}</div>
      <div class="kpi-foot">被自验或交叉复核否决</div>
    </div>
    <div class="kpi cyan">
      <div class="kpi-label">24h API 调用</div>
      <div class="kpi-value">${t.total_calls || 0}</div>
      <div class="kpi-foot">${(t.total_prompt || 0).toLocaleString()} · ${(t.total_completion || 0).toLocaleString()} tok</div>
    </div>
  `;
}

function renderActiveList(active) {
  $("#active-count").textContent = `${active.length} 个`;
  const wrap = $("#active-list");
  if (active.length === 0) {
    wrap.innerHTML = `<div class="empty">空闲。提交一个 GitHub 项目开始分析。</div>`;
    return;
  }
  wrap.innerHTML = active.map((p) => `
    <div class="active-row" onclick="openProjectDetail(${p.id})">
      <div class="row-top">
        <div>
          <div class="row-name">${escapeHtml(p.repo_name || p.repo_url)}</div>
          <div class="row-meta">${escapeHtml(p.repo_url)}</div>
        </div>
        ${statusPill(p.status)}
      </div>
      <div class="row-stage">阶段：${p.stage || "—"}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${p.progress || 0}%"></div></div>
    </div>
  `).join("");
}

function renderRecent(d) {
  const recent = state.projects.filter((p) => p.status === "done" || p.status === "failed").slice(0, 6);
  if (recent.length === 0) {
    $("#recent-list").innerHTML = `<div class="empty">还没有已完成的项目。</div>`;
    return;
  }
  $("#recent-list").innerHTML = recent.map((p) => `
    <div class="recent-row" onclick="openProjectDetail(${p.id})">
      <div class="row-top">
        <div>
          <div class="row-name">${escapeHtml(p.repo_name)}</div>
          <div class="row-meta">${fmtTime(p.finished_at)} · ${fmtDuration(p)}</div>
        </div>
        <div>
          ${statusPill(p.status)}
          ${p.status === "done" ? `<span class="confidence-pill">${p.confirmed_findings} 漏洞 · ${p.rejected_findings} 淘汰</span>` : ""}
        </div>
      </div>
    </div>
  `).join("");
}

function renderUsageChart(timeseries) {
  const wrap = $("#usage-chart");
  if (!timeseries || timeseries.length === 0) {
    wrap.innerHTML = `<div class="empty" style="width:100%">尚无 API 调用数据。</div>`;
    return;
  }
  const max = Math.max(...timeseries.map((t) => t.tokens || 0)) || 1;
  // 凑齐 24 小时
  const now = Math.floor(Date.now() / 1000);
  const hourStart = Math.floor(now / 3600) * 3600;
  const series = [];
  for (let i = 23; i >= 0; i--) {
    const h = hourStart - i * 3600;
    const found = timeseries.find((t) => t.hour_ts === h);
    series.push({ h, tokens: found ? found.tokens : 0, calls: found ? found.calls : 0 });
  }
  wrap.innerHTML = series.map((s) => {
    const pct = (s.tokens / max) * 100;
    const tip = `${new Date(s.h * 1000).getHours()}:00 · ${s.calls}次 · ${(s.tokens || 0).toLocaleString()} tok`;
    return `<div class="chart-bar" style="height:${Math.max(2, pct)}%" data-tip="${tip}"></div>`;
  }).join("");
}

// -------- Queue / Projects --------
async function loadProjects() {
  state.projects = await api("/api/projects");
  renderProjectsTable();
}

function renderProjectsTable() {
  const tbody = $("#projects-table tbody");
  if (state.projects.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty">空空如也。点击右上角"添加"创建第一个分析任务。</td></tr>`;
    return;
  }
  tbody.innerHTML = state.projects.map((p) => `
    <tr>
      <td>${p.id}</td>
      <td><strong>${escapeHtml(p.repo_name)}</strong><br><span class="row-meta">${escapeHtml(p.repo_url)}</span></td>
      <td>${statusPill(p.status)}</td>
      <td>${p.stage || "—"}</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px;">
          <div class="bar-track" style="flex:1;min-width:80px;"><div class="bar-fill" style="width:${p.progress || 0}%"></div></div>
          <span class="row-meta">${Math.round(p.progress || 0)}%</span>
        </div>
      </td>
      <td>${p.raw_findings || 0} / <span style="color:var(--acid)">${p.confirmed_findings || 0}</span> / <span class="danger">${p.rejected_findings || 0}</span></td>
      <td>${fmtDuration(p)}</td>
      <td>
        <a class="row-action" onclick="openProjectDetail(${p.id})">详情</a>
        &nbsp;
        ${["done", "failed"].includes(p.status) ? `<a class="row-action" onclick="rerunProject(${p.id})">重跑</a>&nbsp;` : ""}
        <a class="row-action" onclick="delProject(${p.id})">删</a>
      </td>
    </tr>
  `).join("");
}

async function delProject(id) {
  if (!confirm("删除该项目记录？")) return;
  await api(`/api/projects/${id}`, { method: "DELETE" });
  toast("已删除", "success");
  loadProjects();
}
window.delProject = delProject;

async function rerunProject(id) {
  if (!confirm("重新分析该项目？现有的发现和日志会被清空。")) return;
  try {
    await api(`/api/projects/${id}/requeue`, { method: "POST" });
    toast("已加入队列", "success");
    loadProjects();
  } catch (e) {
    toast("重跑失败：" + e.message, "error");
  }
}
window.rerunProject = rerunProject;

// -------- New project modal --------
$("#add-btn").addEventListener("click", openNewProject);
$("#quick-add-btn").addEventListener("click", openNewProject);
async function openNewProject() {
  if (state.configs.length === 0) {
    state.configs = await api("/api/llm-configs");
  }
  if (state.configs.length === 0) {
    toast("请先在「模型配置」页添加至少一个 LLM", "error");
    setView("configs");
    return;
  }
  const opts = state.configs.map((c) => `<option value="${c.id}">${escapeHtml(c.name)} · ${c.provider} · ${escapeHtml(c.model)}</option>`).join("");
  $("#primary-config").innerHTML = opts;
  $("#review-config").innerHTML = opts;
  $("#repo-url").value = "";
  openModal("project-modal");
}

$("#submit-project").addEventListener("click", async () => {
  const url = $("#repo-url").value.trim();
  if (!url) { toast("请输入仓库 URL", "error"); return; }
  if (!/^https?:\/\/(github\.com|.+)\/.+\/.+/.test(url)) {
    toast("URL 看起来不像 GitHub 仓库", "error"); return;
  }
  try {
    await api("/api/projects", {
      method: "POST",
      body: {
        repo_url: url,
        llm_config_id: Number($("#primary-config").value),
        review_config_id: Number($("#review-config").value),
      },
    });
    toast("已加入队列", "success");
    closeModal("project-modal");
    loadProjects();
    if (state.view === "dashboard") loadDashboard();
  } catch (e) {
    toast("失败：" + e.message, "error");
  }
});

// -------- Project detail --------
async function openProjectDetail(id) {
  state.currentDetailProjectId = id;
  if (state.ws) { state.ws.close(); state.ws = null; }

  openModal("detail-modal");
  $("#pane-logs").querySelector("#log-pane").textContent = "";
  await refreshDetail();

  // 实时跟踪
  const proto = location.protocol === "https:" ? "wss" : "ws";
  state.ws = new WebSocket(`${proto}://${location.host}/ws/project/${id}`);
  state.ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.project) {
      renderProjectDetail(msg.project);
    }
    if (msg.new_logs && msg.new_logs.length > 0) {
      appendLogs(msg.new_logs);
    }
    if (msg.final_findings) {
      renderFindings(msg.final_findings, "confirmed");
      refreshDetail();
    }
  };
  state.ws.onerror = () => { /* 静默 */ };
}
window.openProjectDetail = openProjectDetail;

async function refreshDetail() {
  const id = state.currentDetailProjectId;
  if (!id) return;
  const p = await api(`/api/projects/${id}`);
  renderProjectDetail(p);

  const findings = await api(`/api/projects/${id}/findings?status=confirmed`);
  const rejected = await api(`/api/projects/${id}/findings?status=rejected`);
  renderFindings(findings, "confirmed");
  renderFindings(rejected, "rejected");
  $("#cnt-findings").textContent = findings.length;
  $("#cnt-rejected").textContent = rejected.length;

  const logs = await api(`/api/projects/${id}/logs`);
  $("#log-pane").textContent = "";
  appendLogs(logs);
}

function renderProjectDetail(p) {
  $("#detail-title").textContent = p.repo_name || "项目";
  const fileStats = (p.files_total > 0 || p.files_scanned > 0)
    ? ` · 文件 <strong>${p.files_scanned || 0}/${p.files_total || 0}</strong>`
    : "";
  const findingStats = (p.raw_findings > 0)
    ? ` · 原始 ${p.raw_findings} → 确认 <strong style="color:var(--acid)">${p.confirmed_findings || 0}</strong> / 淘汰 <strong style="color:var(--magenta)">${p.rejected_findings || 0}</strong>`
    : "";
  $("#detail-sub").innerHTML = `${escapeHtml(p.repo_url)} · ${statusPill(p.status)} · 当前阶段：<strong>${p.stage || "—"}</strong> · ${Math.round(p.progress || 0)}%${fileStats}${findingStats}`;

  // Rerun 按钮：仅 done/failed 时显示
  const rerunBtn = $("#detail-rerun-btn");
  if (rerunBtn) {
    if (["done", "failed"].includes(p.status)) {
      rerunBtn.style.display = "";
      rerunBtn.onclick = async () => {
        if (!confirm("重新分析该项目？现有的发现和日志会被清空。")) return;
        try {
          await api(`/api/projects/${p.id}/requeue`, { method: "POST" });
          toast("已加入队列", "success");
          closeModal("detail-modal");
          loadProjects();
        } catch (e) {
          toast("重跑失败：" + e.message, "error");
        }
      };
    } else {
      rerunBtn.style.display = "none";
    }
  }

  // 流水线圆点
  const progress = $("#pipeline-progress");
  progress.innerHTML = PIPELINE_STAGES.map((s) => {
    let cls = "";
    const stageIdx = PIPELINE_STAGES.findIndex((x) => x.key === p.stage);
    const myIdx = PIPELINE_STAGES.findIndex((x) => x.key === s.key);
    if (p.status === "done" || stageIdx > myIdx) cls = "done";
    else if (s.key === p.stage) cls = "active";
    return `<div class="pipe-step ${cls}">
      <div class="pipe-dot"></div>
      <div class="pipe-label">${s.label}</div>
    </div>`;
  }).join("");
}

function renderFindings(findings, kind) {
  const pane = kind === "confirmed" ? $("#pane-findings") : $("#pane-rejected");
  if (findings.length === 0) {
    pane.innerHTML = `<div class="empty">${kind === "confirmed" ? "尚无确认漏洞。流水线还在跑或确实没漏洞。" : "尚无淘汰条目。"}</div>`;
    return;
  }
  pane.innerHTML = findings.map((f) => `
    <div class="finding-card" onclick="openFindingDetail(${f.id})">
      <div class="finding-card-head">
        <div>
          <div class="finding-card-title">${escapeHtml(f.title || "(未命名)")}</div>
          <div class="finding-card-meta">${escapeHtml(f.file_path)} · L${f.line_start || "?"} · ${f.vuln_type}</div>
        </div>
        <div>
          ${sevBadge(f.severity)}
          <span class="confidence-pill">置信 ${((f.confidence || 0) * 100).toFixed(0)}%</span>
        </div>
      </div>
      ${kind === "rejected" ? `<div class="finding-card-summary">淘汰原因：${escapeHtml(f.rejected_reason || "—")}</div>` : ""}
    </div>
  `).join("");
}

function appendLogs(logs) {
  const pane = $("#log-pane");
  for (const l of logs) {
    const span = document.createElement("span");
    span.className = "log-" + (l.level === "stage" ? "stage" : l.level);
    const ts = new Date(l.ts * 1000).toLocaleTimeString("zh-CN", { hour12: false });
    span.textContent = `[${ts}] [${(l.stage || "-").padEnd(12)}] ${l.message}\n`;
    pane.appendChild(span);
  }
  pane.scrollTop = pane.scrollHeight;
}

// detail tab 切换
$$(".tab").forEach((t) => t.addEventListener("click", () => {
  $$(".tab").forEach((x) => x.classList.remove("active"));
  $$(".detail-pane").forEach((x) => x.classList.remove("active"));
  t.classList.add("active");
  $(".pane-" + t.dataset.tab).classList.add("active");
}));

// -------- Finding detail --------
async function openFindingDetail(id) {
  const f = await api(`/api/findings/${id}`);
  $("#finding-title").textContent = f.title || "漏洞";
  $("#finding-sub").innerHTML = `${escapeHtml(f.file_path)} · L${f.line_start || "?"}–${f.line_end || "?"} · ${f.vuln_type} ${sevBadge(f.severity)} <span class="confidence-pill">置信 ${((f.confidence || 0) * 100).toFixed(0)}%</span>`;
  const md = f.full_report_md || "(no report)";
  $("#finding-report").innerHTML = renderMarkdown(md);
  $("#finding-report").dataset.raw = md;
  $("#finding-report").dataset.title = f.title || "finding";
  openModal("finding-modal");
}
window.openFindingDetail = openFindingDetail;

$("#copy-report").addEventListener("click", () => {
  const raw = $("#finding-report").dataset.raw;
  navigator.clipboard.writeText(raw);
  toast("已复制到剪贴板", "success");
});
$("#download-report").addEventListener("click", () => {
  const raw = $("#finding-report").dataset.raw;
  const title = ($("#finding-report").dataset.title || "finding").replace(/[^a-z0-9-_]/gi, "_");
  const blob = new Blob([raw], { type: "text/markdown" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `${title}.md`;
  a.click();
});

// -------- LLM configs --------
async function loadConfigs() {
  state.configs = await api("/api/llm-configs");
  const tbody = $("#configs-table tbody");
  if (state.configs.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">还没配置任何模型，先加一个吧。</td></tr>`;
    return;
  }
  tbody.innerHTML = state.configs.map((c) => `
    <tr>
      <td>${c.id}</td>
      <td><strong>${escapeHtml(c.name)}</strong></td>
      <td>${c.provider}</td>
      <td>${escapeHtml(c.base_url || "—")}</td>
      <td>${escapeHtml(c.model)}</td>
      <td>${escapeHtml(c.api_key_masked || "—")}</td>
      <td><a class="row-action" onclick="delConfig(${c.id})">删</a></td>
    </tr>
  `).join("");
}

async function delConfig(id) {
  if (!confirm("删除该配置？")) return;
  await api(`/api/llm-configs/${id}`, { method: "DELETE" });
  toast("已删除", "success");
  loadConfigs();
}
window.delConfig = delConfig;

// 新增模型 modal
$("#add-config-btn").addEventListener("click", () => {
  $("#cfg-name").value = "";
  $("#cfg-provider").value = "ollama";
  $("#cfg-model-manual").value = "";
  $("#cfg-model-select").innerHTML = '<option value="">—— 先点上方"列模型"或手填 ——</option>';
  $("#cfg-test-result").className = "test-result";
  $("#cfg-test-result").textContent = "";
  renderProviderFields("ollama");
  openModal("config-modal");
});

$("#cfg-provider").addEventListener("change", (e) => renderProviderFields(e.target.value));

function renderProviderFields(prov) {
  const wrap = $("#provider-fields");
  if (prov === "ollama") {
    wrap.innerHTML = `
      <label>Ollama base URL</label>
      <div class="inline-row">
        <input type="text" id="cfg-base-url" class="grow" value="http://localhost:11434" placeholder="http://localhost:11434">
        <button class="btn-ghost" onclick="discoverOllama()">列模型</button>
      </div>
    `;
  } else if (prov === "gemini") {
    wrap.innerHTML = `
      <label>API key（Google AI Studio）</label>
      <input type="password" id="cfg-api-key" placeholder="AIza...">
      <label>Base URL（一般不改）</label>
      <div class="inline-row">
        <input type="text" id="cfg-base-url" class="grow" value="https://generativelanguage.googleapis.com">
        <button class="btn-ghost" onclick="discoverGemini()">列模型</button>
      </div>
    `;
  } else {
    wrap.innerHTML = `
      <label>Base URL（不含 /v1，例如 <code>https://api.siliconflow.cn</code>）</label>
      <input type="text" id="cfg-base-url" placeholder="https://api.siliconflow.cn">
      <label>API key（Bearer token）</label>
      <div class="inline-row">
        <input type="password" id="cfg-api-key" class="grow" placeholder="sk-...">
        <button class="btn-ghost" onclick="discoverOpenAI()">列模型</button>
      </div>
    `;
  }
}

async function discoverOllama() {
  const base = $("#cfg-base-url").value.trim() || "http://localhost:11434";
  try {
    const r = await api(`/api/llm-configs/discover-ollama?base_url=${encodeURIComponent(base)}`);
    if (!r.ok) throw new Error(r.error);
    populateModelSelect(r.models);
    toast(`发现 ${r.models.length} 个本地模型`, "success");
  } catch (e) { toast("列模型失败：" + e.message, "error"); }
}
window.discoverOllama = discoverOllama;

async function discoverGemini() {
  const key = $("#cfg-api-key").value.trim();
  const base = $("#cfg-base-url").value.trim();
  if (!key) { toast("先填 API key", "error"); return; }
  try {
    const r = await api(`/api/llm-configs/discover-gemini?api_key=${encodeURIComponent(key)}&base_url=${encodeURIComponent(base)}`);
    if (!r.ok) throw new Error(r.error);
    populateModelSelect(r.models);
    toast(`Gemini 支持 ${r.models.length} 个模型`, "success");
  } catch (e) { toast("列模型失败：" + e.message, "error"); }
}
window.discoverGemini = discoverGemini;

async function discoverOpenAI() {
  const base = $("#cfg-base-url").value.trim();
  const key = $("#cfg-api-key").value.trim();
  if (!base) { toast("先填 base URL", "error"); return; }
  try {
    const r = await api(`/api/llm-configs/discover-openai?base_url=${encodeURIComponent(base)}&api_key=${encodeURIComponent(key)}`);
    if (!r.ok) throw new Error(r.error);
    populateModelSelect(r.models);
    toast(`端点提供 ${r.models.length} 个模型`, "success");
  } catch (e) { toast("列模型失败：" + e.message, "error"); }
}
window.discoverOpenAI = discoverOpenAI;

function populateModelSelect(models) {
  const sel = $("#cfg-model-select");
  sel.innerHTML = '<option value="">—— 选一个 ——</option>' +
    models.map((m) => `<option value="${escapeHtml(m)}">${escapeHtml(m)}</option>`).join("");
  sel.addEventListener("change", () => {
    if (sel.value) $("#cfg-model-manual").value = sel.value;
  }, { once: true });
}

$("#cfg-test").addEventListener("click", async () => {
  const payload = collectConfigForm();
  if (!payload) return;
  const el = $("#cfg-test-result");
  el.className = "test-result";
  el.textContent = "测试中...";
  el.style.display = "block";
  try {
    const r = await api("/api/llm-configs/test", {
      method: "POST",
      body: {
        provider: payload.provider,
        base_url: payload.base_url,
        api_key: payload.api_key,
        model: payload.model,
      },
    });
    if (r.ok) {
      el.className = "test-result ok";
      el.textContent = "✓ 通了。模型回复：" + (r.reply || "");
    } else {
      el.className = "test-result fail";
      el.textContent = "✗ 失败：" + (r.error || "");
    }
  } catch (e) {
    el.className = "test-result fail";
    el.textContent = "✗ 错误：" + e.message;
  }
});

$("#cfg-save").addEventListener("click", async () => {
  const payload = collectConfigForm();
  if (!payload) return;
  try {
    await api("/api/llm-configs", { method: "POST", body: payload });
    toast("已保存", "success");
    closeModal("config-modal");
    loadConfigs();
  } catch (e) { toast("保存失败：" + e.message, "error"); }
});

function collectConfigForm() {
  const name = $("#cfg-name").value.trim();
  const provider = $("#cfg-provider").value;
  const model = ($("#cfg-model-manual").value || $("#cfg-model-select").value || "").trim();
  if (!name) { toast("起个名字", "error"); return null; }
  if (!model) { toast("选/填模型名", "error"); return null; }
  const payload = {
    name, provider, model,
    temperature: parseFloat($("#cfg-temp").value) || 0.2,
    max_tokens: parseInt($("#cfg-max").value) || 4096,
    base_url: $("#cfg-base-url") ? $("#cfg-base-url").value.trim() : null,
    api_key: $("#cfg-api-key") ? $("#cfg-api-key").value.trim() || null : null,
  };
  return payload;
}

// -------- Usage --------
async function loadUsage() {
  const d = await api("/api/dashboard?hours=720"); // 30 天
  const tbody = $("#usage-table tbody");
  if (!d.usage.per_model || d.usage.per_model.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="empty">尚无调用记录。</td></tr>`;
    return;
  }
  const cfgMap = Object.fromEntries(state.configs.map((c) => [c.id, c.name]));
  tbody.innerHTML = d.usage.per_model.map((u) => `
    <tr>
      <td>${escapeHtml(cfgMap[u.config_id] || `#${u.config_id}`)}</td>
      <td>${u.provider}</td>
      <td>${u.calls}</td>
      <td>${(u.prompt_tokens || 0).toLocaleString()}</td>
      <td>${(u.completion_tokens || 0).toLocaleString()}</td>
      <td>${u.calls ? Math.round((u.total_latency_ms || 0) / u.calls) : 0}ms</td>
      <td>${u.errors > 0 ? `<span class="danger">${u.errors}</span>` : "0"}</td>
    </tr>
  `).join("");
}

// -------- 工具：转义 + 极简 markdown 渲染 --------
function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function renderMarkdown(md) {
  // 非常轻量的 md 渲染，够用就行
  let h = md;
  // 代码块
  h = h.replace(/```([a-z]*)\n([\s\S]*?)```/g, (_, lang, code) =>
    `<pre><code>${escapeHtml(code)}</code></pre>`);
  // 行内 code
  h = h.replace(/`([^`\n]+)`/g, (_, t) => `<code>${escapeHtml(t)}</code>`);
  // 标题
  h = h.replace(/^### (.*)$/gm, "<h3>$1</h3>");
  h = h.replace(/^## (.*)$/gm, "<h2>$1</h2>");
  h = h.replace(/^# (.*)$/gm, "<h1>$1</h1>");
  // 加粗
  h = h.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  // 列表
  h = h.replace(/(^|\n)- (.+)/g, "$1<li>$2</li>");
  h = h.replace(/(<li>[\s\S]+?<\/li>\n?)+/g, (m) => `<ul>${m}</ul>`);
  // 段落
  h = h.split(/\n\n+/).map((p) => {
    if (/^<(h\d|ul|pre|blockquote)/.test(p.trim())) return p;
    return `<p>${p.replace(/\n/g, "<br>")}</p>`;
  }).join("\n");
  // 引用
  h = h.replace(/^> (.*)$/gm, "<blockquote>$1</blockquote>");
  return h;
}

// -------- init --------
async function init() {
  state.projects = await api("/api/projects");
  state.configs = await api("/api/llm-configs");
  loadDashboard();

  // 仪表盘自动刷新
  state.pollingTimer = setInterval(async () => {
    if (state.view === "dashboard") {
      state.projects = await api("/api/projects");
      loadDashboard();
    } else if (state.view === "queue") {
      loadProjects();
    }
  }, 4000);
}
init();
