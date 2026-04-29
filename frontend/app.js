const state = {
  source: "",
  severity: "",
  q: "",
  alertQ: "",
  alertStatus: "new",
  alertSource: "",
  alertOffset: 0,
  alertExpanded: false,
  analysisQ: "",
  productQ: "",
  productOffset: 0,
  productExpanded: false,
  sourceArchiveQ: "",
  sourceArchiveVersionRole: "",
  graphQuery: "",
  graphKind: "auto",
  graphDepth: 1,
  graphResult: null,
  graphSelectedId: "",
  graphViewport: null,
  graphDrag: null,
  graphAvailable: false,
  modelSettings: null,
  modelPickerResolve: null,
  vulnOffset: 0,
  vulnExpanded: false,
  messagePanelOpen: false,
  activeView: "dashboard",
};

const OVERVIEW_LIMIT = 10;
const LIST_LIMIT = 30;
const ALERT_PAGE_LIMIT = 10;
const FRONTEND_BUILD_VERSION = "20260428-analysis-source";
const intelDetails = new Map();
let analysisRefreshTimer = null;

const $ = (selector) => document.querySelector(selector);

function loginRedirectUrl() {
  return `/login?next=${encodeURIComponent(`/app${location.hash || ""}`)}&v=${FRONTEND_BUILD_VERSION}`;
}

const VIEW_PANELS = {
  dashboard: ["dashboardPanel"],
  alerts: ["rulesPanel", "alertCenter", "vulnCenter"],
  products: ["followedPanel", "productCenter"],
  analysis: ["analysisCenter"],
  source: ["sourceArchivePanel"],
  graph: ["graphPanel"],
  updates: ["updatePanel"],
  config: ["deepseekPanel", "sessionPanel", "sourcesPanel"],
};

const HASH_TO_VIEW = {
  dashboardPanel: "dashboard",
  deepseekPanel: "config",
  sessionPanel: "config",
  productCenter: "products",
  followedPanel: "products",
  sourceArchivePanel: "source",
  graphPanel: "graph",
  updatePanel: "updates",
  analysisCenter: "analysis",
  alertCenter: "alerts",
  rulesPanel: "alerts",
  sourcesPanel: "config",
  vulnCenter: "alerts",
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (response.status === 401) {
    location.href = loginRedirectUrl();
    return null;
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
}

function esc(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function viewFromHash() {
  const hash = decodeURIComponent(location.hash || "").replace(/^#/, "");
  if (VIEW_PANELS[hash]) return hash;
  return HASH_TO_VIEW[hash] || "dashboard";
}

function setActiveView(view, options = {}) {
  const next = VIEW_PANELS[view] ? view : "dashboard";
  state.activeView = next;
  const visible = new Set(VIEW_PANELS[next]);
  document.querySelectorAll("main > .panel").forEach((panel) => {
    panel.hidden = !visible.has(panel.id);
  });
  document.querySelectorAll("[data-view-link]").forEach((link) => {
    link.classList.toggle("active", link.dataset.viewLink === next);
  });
  if (options.updateHash && location.hash !== `#${next}`) {
    history.replaceState(null, "", `#${next}`);
  }
  updateDashboardJump();
}

async function loadActiveView() {
  const view = state.activeView;
  if (view === "dashboard") {
    await loadSummary();
    return;
  }
  if (view === "alerts") {
    await Promise.all([loadRules(), loadSources(), loadAlerts(), loadVulns(), loadSummary()]);
    return;
  }
  if (view === "products") {
    await Promise.all([loadFollowedProducts(), loadProducts(), loadSummary()]);
    return;
  }
  if (view === "analysis") {
    await Promise.all([loadModelSettings(), loadAnalysis(), loadSummary()]);
    return;
  }
  if (view === "source") {
    await Promise.all([loadSourceArchives(), loadSummary()]);
    return;
  }
  if (view === "graph") {
    await loadGraphStatus();
    return;
  }
  if (view === "updates") {
    await Promise.all([loadUpdates(), loadSummary()]);
    return;
  }
  if (view === "config") {
    await Promise.all([loadDeepSeek(), loadSourceSessions(), loadSources(), loadSummary()]);
  }
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(date);
}

function durationSince(value) {
  if (!value) return "-";
  const started = new Date(value).getTime();
  if (!started || Number.isNaN(started)) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - started) / 1000));
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分 ${seconds % 60} 秒`;
  const hours = Math.floor(minutes / 60);
  return `${hours} 小时 ${minutes % 60} 分`;
}

function relativeTime(value) {
  if (!value) return "-";
  const time = new Date(value).getTime();
  if (!time || Number.isNaN(time)) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - time) / 1000));
  if (seconds < 60) return "刚刚";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  return formatTime(value);
}

function balanceLabel(balance) {
  if (!balance) return "-";
  if (balance.status === "failed") return "failed";
  if (!balance.total_balance) return balance.status || "-";
  return `${balance.currency || ""} ${balance.total_balance}`.trim();
}

function rangeLabel(offset, count, total) {
  if (!total) return "0 条";
  const start = offset + 1;
  const end = offset + count;
  return `${start}-${end} / ${total} 条`;
}

function bytesLabel(value) {
  const bytes = Number(value || 0);
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function updateSourceArchiveFileName() {
  const input = $("#sourceArchiveFile");
  const label = $("#sourceArchiveUploadForm .source-file-picker");
  const nameNode = $("#sourceArchiveFileName");
  if (!input || !label || !nameNode) return;
  const file = input.files?.[0];
  label.classList.toggle("has-file", Boolean(file));
  nameNode.textContent = file ? `${file.name} · ${bytesLabel(file.size)}` : "未选择文件";
}

function updateUpdateFileName() {
  const input = $("#updateFile");
  const label = $("#updateUploadForm .source-file-picker");
  const nameNode = $("#updateFileName");
  if (!input || !label || !nameNode) return;
  const file = input.files?.[0];
  label.classList.toggle("has-file", Boolean(file));
  nameNode.textContent = file ? `${file.name} · ${bytesLabel(file.size)}` : "未选择文件";
}

function severityClass(value) {
  const text = String(value || "unknown").trim().toLowerCase();
  const allowed = new Set(["critical", "high", "medium", "low", "none", "unknown"]);
  return `severity-${allowed.has(text) ? text : "unknown"}`;
}

function messageLevelClass(value) {
  const text = String(value || "info").trim().toLowerCase();
  const allowed = new Set(["info", "success", "warning", "error"]);
  return `message-${allowed.has(text) ? text : "info"}`;
}

function analysisStatusLabel(value) {
  const labels = {
    idle: "未分析",
    queued: "排队中",
    running: "正在分析",
    finished: "已分析",
    failed: "失败",
  };
  return labels[value || "idle"] || value || "未分析";
}

function textPreview(value, length = 180) {
  const text = String(value || "").trim();
  if (!text) return "";
  return text.length > length ? `${text.slice(0, length)}...` : text;
}

function initPanelControls() {
  document.querySelectorAll("main > .panel").forEach((panel, index) => {
    const head = panel.querySelector(":scope > .panel-head");
    if (!head || head.querySelector(".panel-tools")) return;
    const tools = document.createElement("div");
    tools.className = "panel-tools";
    tools.innerHTML = `
      <button type="button" class="panel-tool" data-panel-collapse="${index}">收起</button>
      <button type="button" class="panel-tool" data-panel-zoom="${index}">放大</button>
    `;
    head.appendChild(tools);
  });

  document.querySelectorAll("[data-panel-collapse]").forEach((button) => {
    button.addEventListener("click", () => {
      const panel = button.closest(".panel");
      if (!panel) return;
      const collapsed = panel.classList.toggle("panel-collapsed");
      button.textContent = collapsed ? "展开" : "收起";
    });
  });

  document.querySelectorAll("[data-panel-zoom]").forEach((button) => {
    button.addEventListener("click", () => {
      const panel = button.closest(".panel");
      if (!panel) return;
      const zoomed = panel.classList.toggle("panel-zoomed");
      document.querySelectorAll(".panel.panel-zoomed").forEach((node) => {
        if (node !== panel) {
          node.classList.remove("panel-zoomed");
          const otherButton = node.querySelector("[data-panel-zoom]");
          if (otherButton) otherButton.textContent = "放大";
        }
      });
      button.textContent = zoomed ? "还原" : "放大";
      document.body.classList.toggle("panel-is-zoomed", Boolean(document.querySelector(".panel.panel-zoomed")));
      updateDashboardJump();
    });
  });
}

function initDashboardJump() {
  const button = $("#dashboardJump");
  if (!button) return;
  button.addEventListener("click", () => {
    const zoomed = document.querySelector(".panel.panel-zoomed");
    if (zoomed) {
      zoomed.scrollTo({ top: 0, behavior: "smooth" });
      return;
    }
    window.scrollTo({ top: 0, behavior: "smooth" });
    if (VIEW_PANELS[state.activeView] && location.hash !== `#${state.activeView}`) {
      history.replaceState(null, "", `#${state.activeView}`);
    }
  });
  window.addEventListener("scroll", updateDashboardJump, { passive: true });
  document.addEventListener("scroll", updateDashboardJump, { passive: true, capture: true });
  updateDashboardJump();
}

function updateDashboardJump() {
  const button = $("#dashboardJump");
  if (!button) return;
  const zoomed = document.querySelector(".panel.panel-zoomed");
  const offset = zoomed ? zoomed.scrollTop : window.scrollY;
  button.hidden = offset < 420;
}

function bindAckButtons() {
  document.querySelectorAll("[data-ack]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      await api(`/api/alerts/${button.dataset.ack}/ack`, { method: "POST" });
      await Promise.all([loadAlerts(), loadSummary()]);
    });
  });
}

function bindReadButtons() {
  document.querySelectorAll("[data-read]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      await api(`/api/alerts/${button.dataset.read}/read`, { method: "POST" });
      await Promise.all([loadAlerts(), loadSummary()]);
    });
  });
}

function bindFollowButtons() {
  document.querySelectorAll("[data-follow-id]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/vulnerabilities/${button.dataset.followId}/follow`, { method: "POST" });
        await Promise.all([loadFollowedProducts(), loadMessages(), loadAlerts(), loadVulns()]);
      } catch (error) {
        showModal("关注失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindProductFollowButtons() {
  document.querySelectorAll("[data-product-follow]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("/api/products/follow", {
          method: "POST",
          body: JSON.stringify({ product: button.dataset.productFollow }),
        });
        await Promise.all([loadFollowedProducts(), loadProducts(), loadMessages()]);
      } catch (error) {
        showModal("关注失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindProductDetailButtons() {
  document.querySelectorAll("[data-product-detail]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await showProductDetail(button.dataset.productDetail);
      } catch (error) {
        showModal("产品详情加载失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindAnalysisButtons() {
  document.querySelectorAll("[data-analysis-id]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const redTeam = button.dataset.analysisMode === "red_team_enhanced";
      const modelChoice = await chooseAnalysisModel(button.dataset.analysisLabel || (redTeam ? "红队增强" : "漏洞分析"));
      if (!modelChoice) return;
      button.disabled = true;
      button.textContent = redTeam ? "红队已排队" : "已排队";
      try {
        await api(`/api/vulnerabilities/${button.dataset.analysisId}/analysis/run`, {
          method: "POST",
          body: JSON.stringify({
            force: button.dataset.force === "1",
            mode: redTeam ? "red_team_enhanced" : "standard",
            red_team_enhanced: redTeam,
            model_choice: modelChoice,
          }),
        });
        await Promise.all([loadMessages(), loadAlerts(), loadAnalysis(), loadVulns(), loadSummary()]);
        scheduleAnalysisRefresh(3000);
      } catch (error) {
        showModal(redTeam ? "红队增强失败" : "分析失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindAnalysisTabButtons() {
  document.querySelectorAll("[data-analysis-tab]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", () => {
      const container = button.closest(".analysis-tabs");
      if (!container) return;
      const target = button.dataset.analysisTab;
      container.querySelectorAll("[data-analysis-tab]").forEach((node) => {
        node.classList.toggle("active", node === button);
      });
      container.querySelectorAll("[data-analysis-panel]").forEach((panel) => {
        panel.hidden = panel.dataset.analysisPanel !== target;
      });
    });
  });
}

function bindAnalysisFeedbackButtons() {
  document.querySelectorAll("[data-analysis-feedback]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/vulnerabilities/${button.dataset.feedbackId}/analysis/feedback`, {
          method: "POST",
          body: JSON.stringify({ rating: button.dataset.analysisFeedback }),
        });
        await loadAnalysis();
      } catch (error) {
        showModal("反馈提交失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindAnalysisDeleteButtons() {
  document.querySelectorAll("[data-analysis-delete-id]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      if (!confirm("确认删除该漏洞的分析报告、过程输出和生成的 POC/EXP？漏洞本身不会删除。")) {
        return;
      }
      button.disabled = true;
      try {
        await api(`/api/vulnerabilities/${button.dataset.analysisDeleteId}/analysis`, {
          method: "DELETE",
        });
        await Promise.all([loadMessages(), loadAlerts(), loadAnalysis(), loadVulns(), loadSummary()]);
      } catch (error) {
        showModal("删除分析失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindAnalysisLogButtons() {
  document.querySelectorAll("[data-analysis-log-id]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "加载中";
      try {
        const id = button.dataset.analysisLogId;
        const params = new URLSearchParams({ limit: "200" });
        if (button.dataset.analysisRunId) params.set("run_id", button.dataset.analysisRunId);
        const data = await api(`/api/vulnerabilities/${encodeURIComponent(id)}/analysis/events?${params}`);
        const events = data?.data || [];
        const body = analysisEventsText(events);
        showModal("模型对话过程与分析日志", `<pre class="analysis-output modal-log-output">${esc(body)}</pre>`, { html: true });
      } catch (error) {
        showModal("日志加载失败", error.message);
      } finally {
        button.disabled = false;
        button.textContent = originalText;
      }
    });
  });
}

function bindGitHubEvidenceButtons() {
  document.querySelectorAll("[data-github-refresh-id]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const id = button.dataset.githubRefreshId;
      if (!id) return;
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "刷新中";
      try {
        await api(`/api/vulnerabilities/${encodeURIComponent(id)}/github-evidence/refresh`, {
          method: "POST",
        });
        await Promise.all([loadAnalysis(), loadVulns(), loadAlerts()]);
      } catch (error) {
        showModal("GitHub 证据刷新失败", error.message);
      } finally {
        button.disabled = false;
        button.textContent = originalText;
      }
    });
  });
}

function scheduleAnalysisRefresh(delay = 5000) {
  if (analysisRefreshTimer) return;
  analysisRefreshTimer = setTimeout(async () => {
    analysisRefreshTimer = null;
    try {
      await refresh();
    } catch (error) {
      console.error(error);
    }
  }, delay);
}

function watchAnalysisRefresh(items) {
  if ((items || []).some((item) => ["queued", "running"].includes(item.analysis_status))) {
    scheduleAnalysisRefresh();
  }
}

function bindUnfollowButtons() {
  document.querySelectorAll("[data-unfollow-key]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/followed-products/${encodeURIComponent(button.dataset.unfollowKey)}`, { method: "DELETE" });
        await Promise.all([loadFollowedProducts(), loadMessages(), loadAlerts(), loadVulns()]);
      } catch (error) {
        showModal("取消关注失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindMessageButtons() {
  document.querySelectorAll("[data-message-read]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/messages/${button.dataset.messageRead}/read`, { method: "POST" });
        await loadMessages();
      } catch (error) {
        showModal("消息操作失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
  document.querySelectorAll("[data-message-unread]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/messages/${button.dataset.messageUnread}/unread`, { method: "POST" });
        await loadMessages();
      } catch (error) {
        showModal("消息操作失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function bindIntelButtons() {
  document.querySelectorAll("[data-intel-detail]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", () => showIntelDetail(button.dataset.intelDetail));
  });
}

function showIntelDetail(key) {
  const detail = intelDetails.get(key);
  if (!detail) return;
  showModal(detail.title, detail.html || detail.body, { html: Boolean(detail.html) });
}

function showModal(title, body, options = {}) {
  $("#intelModalTitle").textContent = title;
  const bodyNode = $("#intelModalBody");
  bodyNode.className = `modal-content ${options.html ? "rich" : "plain"}`;
  if (options.html) {
    bodyNode.innerHTML = body;
  } else {
    bodyNode.textContent = body;
  }
  $("#intelModal").hidden = false;
}

function closeIntelModal() {
  if (state.modelPickerResolve) {
    const resolve = state.modelPickerResolve;
    state.modelPickerResolve = null;
    resolve(null);
  }
  $("#intelModal").hidden = true;
}

function detailKey(item, kind) {
  return `${item.source || "source"}:${item.id || item.source_uid || item.cve_id || item.title}:${kind}`;
}

function intelActions(item) {
  const score = item.cvss_score;
  const hasCvss = score !== null && score !== undefined && score !== "";
  const cvssLabel = hasCvss
    ? `CVSS ${Number(score).toFixed(1)}${item.cvss_version ? ` v${item.cvss_version}` : ""}`
    : "CVSS -";
  const cvssKey = detailKey(item, "cvss");
  intelDetails.set(cvssKey, {
    title: `${item.cve_id || item.title || "漏洞"} · CVSS`,
    body: hasCvss
      ? [`评分：${cvssLabel}`, item.cvss_vector ? `向量：${item.cvss_vector}` : ""].filter(Boolean).join("\n")
      : "当前条目没有 CVSS 评分。",
  });
  const cvssButton = `<button type="button" class="intel-button ${hasCvss ? "active" : ""}" ${hasCvss ? `data-intel-detail="${esc(cvssKey)}"` : "disabled"}>${esc(cvssLabel)}</button>`;
  const pocButton = artifactButton(item, "poc", "POC");
  const expButton = artifactButton(item, "exp", "EXP");
  const githubButton = githubEvidenceButton(item);
  const reportButton = analysisReportButton(item);
  const sourceError = analysisSourceLabelAndError(item);
  return `<div class="intel-actions">${cvssButton}${pocButton}${expButton}${githubButton}${reportButton}${sourceError}</div>`;
}

function artifactButton(item, kind, label) {
  const available = Boolean(item[`${kind}_available`]);
  if (!available) {
    return `<button type="button" class="intel-button" disabled>${label} -</button>`;
  }
  const key = detailKey(item, kind);
  const url = item[`${kind}_url`] || "";
  const content = item[`${kind}_content`] || `源数据标记存在 ${label}，但未提供公开内容。`;
  intelDetails.set(key, {
    title: `${item.cve_id || item.title || "漏洞"} · ${label}`,
    body: [content, url ? `\n链接：${url}` : ""].filter(Boolean).join("\n"),
  });
  return `<button type="button" class="intel-button active ${kind}" data-intel-detail="${esc(key)}">${label}</button>`;
}

function githubEvidenceSummary(item) {
  return item.github_evidence_summary || {};
}

function githubEvidenceItems(item, kind = "") {
  const evidence = Array.isArray(item.github_evidence) ? item.github_evidence : [];
  if (!kind) return evidence;
  return evidence.filter((entry) => {
    const artifact = String(entry.artifact_kind || "").toLowerCase();
    if (kind === "poc") return artifact === "poc";
    if (kind === "exp") return artifact === "exp";
    return artifact === kind;
  });
}

function githubEvidenceLabel(item) {
  const summary = githubEvidenceSummary(item);
  const count = Number(item.github_evidence_count || summary.total || 0);
  if (!count) return "GitHub -";
  const score = item.github_evidence_max_score ?? summary.max_score;
  const scoreText = score === null || score === undefined ? "-" : `${Math.round(Number(score || 0))}`;
  return `GitHub ${count} · ${scoreText}`;
}

function githubEvidenceButton(item) {
  const count = Number(item.github_evidence_count || 0);
  if (!count) {
    return `<button type="button" class="intel-button" disabled>GitHub -</button>`;
  }
  const key = detailKey(item, "github-evidence");
  intelDetails.set(key, {
    title: `${item.cve_id || item.title || "漏洞"} · GitHub 证据`,
    html: githubEvidenceListHtml(githubEvidenceItems(item)),
  });
  return `<button type="button" class="intel-button active github" data-intel-detail="${esc(key)}">${esc(githubEvidenceLabel(item))}</button>`;
}

function githubEvidencePill(item) {
  const count = Number(item.github_evidence_count || 0);
  if (!count) return "";
  const summary = githubEvidenceSummary(item);
  const score = item.github_evidence_max_score ?? summary.max_score ?? 0;
  const confidence = summary.confidence || (score >= 78 ? "high" : score >= 55 ? "medium" : "low");
  const label = confidence === "high" ? "高" : confidence === "medium" ? "中" : "低";
  return `<span class="github-evidence-pill">GitHub 证据 ${esc(String(count))} · 可信度 ${esc(label)} ${esc(String(Math.round(Number(score || 0))))}</span>`;
}

function githubEvidenceListHtml(evidence) {
  if (!evidence.length) return `<div class="empty inline">暂无 GitHub 证据</div>`;
  return `
    <div class="github-evidence-list">
      ${evidence.map((entry) => {
        const title = entry.title || entry.repository || entry.evidence_url || "GitHub 证据";
        const href = entry.evidence_url || entry.url || "";
        const confidence = entry.confidence === "high" ? "高" : entry.confidence === "medium" ? "中" : "低";
        const meta = [
          entry.artifact_kind || "unknown",
          entry.evidence_type || "",
          entry.repository || "",
          entry.evidence_path || "",
        ].filter(Boolean).join(" · ");
        return `
          <article class="github-evidence-card">
            <div>
              <strong>${href ? `<a href="${esc(href)}" target="_blank" rel="noreferrer">${esc(title)}</a>` : esc(title)}</strong>
              <small>${esc(meta)}</small>
            </div>
            <span>可信度 ${esc(confidence)} · ${esc(String(Math.round(Number(entry.score || 0))))}</span>
            ${entry.snippet ? `<p>${esc(textPreview(entry.snippet, 260))}</p>` : ""}
          </article>
        `;
      }).join("")}
    </div>
  `;
}

function githubEvidencePanel(item, kind) {
  const evidence = githubEvidenceItems(item, kind);
  return `
    <div class="github-evidence-panel">
      <div class="analysis-panel-tools">
        <span>${esc(kind.toUpperCase())} GitHub 证据</span>
        <button type="button" class="intel-button github" data-github-refresh-id="${esc(item.id || "")}">刷新 GitHub 证据</button>
      </div>
      ${githubEvidenceListHtml(evidence)}
    </div>
  `;
}

function analysisReportButton(item) {
  if (!item.analysis_summary) {
    return `<button type="button" class="intel-button" disabled>报告 -</button>`;
  }
  const key = detailKey(item, "analysis");
  const sources = (item.analysis_sources || [])
    .map((source) => {
      const title = source.title || source.url || source.local_path || "";
      const url = source.url ? ` ${source.url}` : "";
      const local = source.local_path ? ` ${source.local_path}` : "";
      return `- ${title}${url}${local}`.trim();
    })
    .filter(Boolean)
    .join("\n");
  intelDetails.set(key, {
    title: `${item.cve_id || item.title || "漏洞"} · 分析报告`,
    body: [item.analysis_summary, sources ? `\n参考与源码：\n${sources}` : ""].filter(Boolean).join("\n"),
  });
  return `<button type="button" class="intel-button active analysis-report" data-intel-detail="${esc(key)}">报告</button>`;
}

function analysisSourceLabelAndError(item) {
  const sourceFound = item.analysis_source_found;
  const error = String(item.analysis_error || "").trim();
  const parts = [];
  if (sourceFound === 1 || sourceFound === true) {
    parts.push(analysisSourcePill(item));
  } else if (item.analysis_status === "finished") {
    const key = detailKey(item, "analysis-nosource");
    intelDetails.set(key, {
      title: `${item.cve_id || item.title || "漏洞"} · 源码说明`,
      body: error || "未搜索到可下载的源码仓库；POC/EXP 基于公开情报分析生成。",
    });
    parts.push(`<button type="button" class="intel-button" data-intel-detail="${esc(key)}">源码未找到</button>`);
  }
  if (error) {
    const key = detailKey(item, "analysis-error");
    intelDetails.set(key, {
      title: `${item.cve_id || item.title || "漏洞"} · 分析异常`,
      body: [`状态：${item.analysis_status || "unknown"}`, error].filter(Boolean).join("\n\n"),
    });
    parts.push(`<button type="button" class="intel-button active analysis-error" data-intel-detail="${esc(key)}">异常</button>`);
  }
  return parts.join("");
}

function itemActionButtons(item, ackButton = "") {
  return `
    <div class="item-actions">
      ${analysisButton(item)}
      ${followButton(item)}
      ${ackButton}
    </div>
  `;
}

function analysisButton(item) {
  const status = item.analysis_status || "idle";
  const running = status === "queued" || status === "running";
  const failed = status === "failed";
  const finished = status === "finished";
  const redTeam = item.analysis_trigger === "red_team_enhanced";
  const labelMap = {
    idle: "漏洞分析",
    queued: "已排队",
    running: "分析中",
    finished: "重新分析",
    failed: "重新分析",
  };
  const label = labelMap[status] || "漏洞分析";
  const title = failed && item.analysis_error ? ` title="${esc(item.analysis_error)}"` : "";
  const force = finished || failed ? "1" : "0";
  const standard = `<button type="button" class="analysis-action ${finished && !redTeam ? "active" : ""} ${failed ? "failed" : ""}" data-analysis-id="${esc(item.id)}" data-analysis-mode="standard" data-analysis-label="${esc(label)}" data-force="${force}" ${running ? "disabled" : ""}${title}>${label}</button>`;
  const redTitle = ` title="${esc("以红队攻击视角重新分析，并基于公开 POC/EXP 与源码证据生成增强 EXP")}"`;
  const redLabel = running && redTeam ? "红队进行中" : finished && redTeam ? "重新红队" : "红队增强";
  const red = `<button type="button" class="analysis-action red-team ${redTeam && finished ? "active" : ""}" data-analysis-id="${esc(item.id)}" data-analysis-mode="red_team_enhanced" data-analysis-label="${esc(redLabel)}" data-force="1" ${running ? "disabled" : ""}${redTitle}>${redLabel}</button>`;
  return `${standard}${red}`;
}

function followButton(item) {
  if (!item.product_key || !item.id) {
    return `<button type="button" disabled>关注 -</button>`;
  }
  if (item.is_followed) {
    return `<button type="button" class="follow-action active" disabled>已关注</button>`;
  }
  return `<button type="button" class="follow-action" data-follow-id="${esc(item.id)}">关注产品</button>`;
}

function sourceLabel(sourceName) {
  const select = $("#alertSource");
  const option = select ? Array.from(select.options).find((node) => node.value === sourceName) : null;
  return option && option.value ? option.textContent : sourceName || "-";
}

function sourceJobHint(jobs = []) {
  const byId = Object.fromEntries((jobs || []).map((job) => [job.id, job]));
  const regular = byId.regular_sources;
  const slow = byId.slow_sources;
  if (!regular && !slow) return "自动调度未就绪；服务启动后会注册数据源任务。";
  return [
    "自动调度已开启",
    regular ? `30分钟源下次 ${formatTime(regular.next_run_time)}` : "",
    slow ? `低频源下次 ${formatTime(slow.next_run_time)}` : "",
    "手动运行只会立即补跑，不会关闭自动调度",
  ].filter(Boolean).join(" · ");
}

function alertWorkflowLabel(status) {
  const labels = {
    new: "新告警",
    read: "已读",
    acknowledged: "已确认",
  };
  return labels[status || "new"] || status || "新告警";
}

function alertWorkflowActions(alert) {
  const id = esc(alert.alert_id);
  const status = alert.alert_status || "new";
  if (status === "acknowledged") {
    return `<button type="button" disabled>已确认</button>`;
  }
  const readButton = status === "new" ? `<button type="button" data-read="${id}">已读</button>` : "";
  return `${readButton}<button type="button" data-ack="${id}">确认</button>`;
}

function alertMarkup(alert) {
  const item = alert.vulnerability || {};
  const workflow = alert.alert_status || "new";
  return `
    <article class="alert ${severityClass(item.severity)}">
      <div>
        <span class="badge ${severityClass(item.severity)}">${esc(item.severity || "unknown")}</span>
        <span class="alert-status ${esc(workflow)}">${esc(alertWorkflowLabel(workflow))}</span>
        <div class="source-chip">${esc(sourceLabel(item.source))}</div>
        <div class="meta">${esc(alert.reason || "")}</div>
      </div>
      <div>
        <h3>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(item.title)}</a>` : esc(item.title)}</h3>
        <p>${esc(item.product || item.description || item.cve_id || "")}</p>
        <div class="meta">${esc(item.source || "")} · ${esc(item.published_at || item.updated_at || "")} · ${esc(item.cve_id || alert.dedupe_key)}</div>
        ${intelActions(item)}
      </div>
      ${itemActionButtons(item, alertWorkflowActions(alert))}
    </article>
  `;
}

function vulnMarkup(item) {
  const aliases = (item.aliases || []).filter(Boolean).join(" · ");
  return `
    <article class="vuln ${severityClass(item.severity)}">
      <div><span class="badge ${severityClass(item.severity)}">${esc(item.severity || "unknown")}</span></div>
      <div>
        <h3>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(item.title)}</a>` : esc(item.title)}</h3>
        <p>${esc(item.product || item.description || aliases || "")}</p>
        ${intelActions(item)}
      </div>
      <div class="vuln-side">
        <div class="meta">
          <div>${esc(item.source)}</div>
          <div>${esc(item.published_at || item.updated_at || "")}</div>
          <div>${esc(item.cve_id || aliases)}</div>
        </div>
        ${itemActionButtons(item)}
      </div>
    </article>
  `;
}

async function loadSummary() {
  const [data, claude] = await Promise.all([
    api("/api/summary"),
    api("/api/claude-code/status"),
  ]);
  if (!data || !claude) return;
  $("#dashboardHint").textContent = claude.available ? "Claude Code ready" : `Claude Code ${claude.status}`;
  $("#metrics").innerHTML = [
    ["漏洞总数", data.vulnerabilities, "全部入库"],
    ["有效产品", data.products || 0, `${data.catalog_products || 0} 条目录`],
    ["源码库", data.source_archives || 0, `${data.source_archives_pending || 0} 待处理`],
    ["图谱", data.graph_nodes || 0, `${data.graph_relationships || 0} 关系`],
    ["今日公开", data.published_today, "按调度时区"],
    ["抓取运行", data.running_jobs, "数据源任务"],
    ["分析中", data.analysis_running, "Claude Code"],
    ["排队分析", data.analysis_queued, "等待执行"],
    ["已分析", data.analysis_finished, "完成报告"],
    ["新告警", data.new_alerts || 0, "待处理"],
    ["已读告警", data.read_alerts || 0, "待确认"],
    ["已确认告警", data.acknowledged_alerts, "人工确认"],
    ["POC", data.poc_available, "已有内容"],
    ["EXP", data.exp_available, "已有内容"],
  ]
    .map(([label, value, hint]) => `<article class="metric"><span>${label}</span><strong>${value}</strong><small>${hint}</small></article>`)
    .join("");
  renderDashboardBreakdown(data);
}

function renderDashboardBreakdown(data) {
  const severityRows = data.by_severity || [];
  const analysisRows = [
    ["排队中", data.analysis_queued || 0, "queued"],
    ["正在分析", data.analysis_running || 0, "running"],
    ["已分析", data.analysis_finished || 0, "finished"],
    ["失败", data.analysis_failed || 0, "failed"],
  ];
  const maxSeverity = Math.max(1, ...severityRows.map((item) => Number(item.count) || 0));
  const maxAnalysis = Math.max(1, ...analysisRows.map((item) => Number(item[1]) || 0));
  $("#dashboardBreakdown").innerHTML = `
    <section class="dashboard-block">
      <h3>漏洞等级</h3>
      ${severityRows.length ? severityRows.map((item) => dashboardBar(item.severity, item.count, maxSeverity, severityClass(item.severity))).join("") : `<div class="empty inline">暂无等级数据</div>`}
    </section>
    <section class="dashboard-block">
      <h3>分析状态</h3>
      ${analysisRows.map(([label, count, status]) => dashboardBar(label, count, maxAnalysis, `analysis-${status}`)).join("")}
    </section>
  `;
}

function dashboardBar(label, count, max, className) {
  const width = Math.max(4, Math.round((Number(count) || 0) / max * 100));
  return `
    <div class="dashboard-bar ${esc(className)}">
      <div class="dashboard-bar-line">
        <span>${esc(label)}</span>
        <strong>${esc(count)}</strong>
      </div>
      <div class="dashboard-track"><i style="--bar-width: ${width}%"></i></div>
    </div>
  `;
}

async function loadModelSettings() {
  const data = await api("/api/model/settings");
  if (!data) return;
  state.modelSettings = data;
  populateModelSettings(data);
  return data;
}

function populateModelSettings(settings) {
  if (!settings) return;
  const flashModel = settings.flash_model || settings.product_attribution_model || "";
  const proModel = settings.pro_model || settings.poc_generation_model || "";
  const flashInput = $("#flashModel");
  const proInput = $("#proModel");
  if (flashInput && document.activeElement !== flashInput) flashInput.value = flashModel;
  if (proInput && document.activeElement !== proInput) proInput.value = proModel;
}

async function ensureModelSettings() {
  if (state.modelSettings) return state.modelSettings;
  return (await loadModelSettings()) || {};
}

async function chooseAnalysisModel(actionLabel = "漏洞分析") {
  const settings = await ensureModelSettings();
  const flashModel = settings.flash_model || settings.product_attribution_model || "deepseek-v4-flash";
  const proModel = settings.pro_model || settings.poc_generation_model || "deepseek-v4-pro[1m]";
  return new Promise((resolve) => {
    state.modelPickerResolve = resolve;
    showModal(
      `选择${actionLabel}模型`,
      `
        <div class="model-picker">
          <p>本次任务会使用你选择的模型执行，结果会带上对应模型标签。</p>
          <div class="model-picker-options">
            <button type="button" class="model-choice pro" data-model-choice="pro">
              <strong>Pro</strong>
              <span>${esc(proModel)}</span>
            </button>
            <button type="button" class="model-choice flash" data-model-choice="flash">
              <strong>Flash</strong>
              <span>${esc(flashModel)}</span>
            </button>
          </div>
          <div class="model-picker-actions">
            <button type="button" data-model-choice-cancel>取消</button>
          </div>
        </div>
      `,
      { html: true },
    );
    $("#intelModalBody").querySelectorAll("[data-model-choice]").forEach((button) => {
      button.addEventListener("click", () => {
        const pickerResolve = state.modelPickerResolve;
        state.modelPickerResolve = null;
        if (pickerResolve) pickerResolve(button.dataset.modelChoice === "flash" ? "flash" : "pro");
        $("#intelModal").hidden = true;
      });
    });
    const cancelButton = $("#intelModalBody").querySelector("[data-model-choice-cancel]");
    if (cancelButton) {
      cancelButton.addEventListener("click", closeIntelModal);
    }
  });
}

async function loadDeepSeek() {
  const [data, modelSettings] = await Promise.all([
    api("/api/deepseek/status"),
    api("/api/model/settings"),
  ]);
  if (!data) return;
  state.modelSettings = modelSettings || state.modelSettings;
  populateModelSettings(state.modelSettings);
  const balance = data.latest_balance;
  const configured = data.configured ? "已配置" : "未配置";
  const baseUrlInput = $("#modelBaseUrl");
  if (baseUrlInput && document.activeElement !== baseUrlInput) {
    baseUrlInput.value = data.base_url || "";
  }
  $("#deepseekStatus").innerHTML = [
    ["Key", configured],
    ["来源", data.key_source],
    ["尾号", data.masked_api_key || "-"],
    ["模型 URL", data.base_url || "-"],
    ["URL 来源", data.base_url_source || "-"],
    ["Flash", state.modelSettings?.flash_model || "-"],
    ["Pro", state.modelSettings?.pro_model || "-"],
    ["余额", balanceLabel(balance)],
    ["可用", balance?.is_available === false ? "否" : balance?.is_available === true ? "是" : "-"],
    ["检查时间", formatTime(balance?.checked_at)],
  ]
    .map(([label, value]) => `<div class="kv"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`)
    .join("");
}

async function loadGraphStatus() {
  const data = await api("/api/graph/status");
  if (!data) return;
  state.graphAvailable = Boolean(data.available);
  const available = data.available ? "可用" : "不可用";
  const configured = data.configured ? "已配置" : "未配置";
  $("#graphStatus").innerHTML = [
    ["状态", available],
    ["配置", configured],
    ["节点", data.nodes || 0],
    ["关系", data.relationships || 0],
    ["URI", data.uri || "-"],
    ["数据库", data.database || "-"],
  ]
    .map(([label, value]) => `<div class="kv"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`)
    .join("");
  const unavailableMessage = data.available
    ? ""
    : data.configured
      ? `Neo4j 当前不可用：${data.error || "无法连接图数据库"}。请启动 Neo4j 后同步，或先在产品/告警列表查看关系。`
      : "Neo4j 未配置。请配置 NEO4J_URI/NEO4J_PASSWORD 后重启，或先使用产品/告警列表查看关系。";
  $("#graphSyncMessage").textContent = unavailableMessage;
  if (!data.available) {
    $("#graphCanvas").innerHTML = `<div class="empty">${esc(unavailableMessage)}</div>`;
    renderGraphLegend([], [], { trimmed: false });
    renderGraphInspector(null, [], []);
  }
  const syncButton = $("#graphSync");
  if (syncButton) {
    syncButton.disabled = !data.available;
    syncButton.title = data.available ? "同步 PostgreSQL 中的产品、漏洞、告警和源码关系" : unavailableMessage;
  }
  const searchButton = $("#graphSearch");
  if (searchButton) {
    searchButton.disabled = !data.available;
    searchButton.title = data.available ? "查询图谱关系" : unavailableMessage;
  }
}

function graphNodeKind(node) {
  const labels = node.labels || [];
  if (labels.includes("Vulnerability")) return "vulnerability";
  if (labels.includes("Product")) return "product";
  if (labels.includes("Alert")) return "alert";
  if (labels.includes("DataSource")) return "source";
  if (labels.includes("SourceArchive")) return "archive";
  if (labels.includes("Vendor")) return "vendor";
  return "unknown";
}

function graphKindLabel(kind) {
  return {
    vulnerability: "漏洞",
    product: "产品",
    alert: "告警",
    source: "数据源",
    archive: "源码",
    vendor: "厂商",
    unknown: "节点",
  }[kind] || "节点";
}

function graphNodeTitle(node) {
  const props = node.properties || {};
  const kind = graphNodeKind(node);
  if (kind === "vulnerability") return props.cve_id || props.title || `漏洞 ${props.id || ""}`.trim();
  if (kind === "product") return props.name || props.key || "产品";
  if (kind === "alert") return `告警 ${props.id || ""}`.trim();
  if (kind === "source") return props.name || "数据源";
  if (kind === "archive") return props.filename || props.product_name || "源码";
  if (kind === "vendor") return props.name || "厂商";
  return props.name || props.title || props.id || "节点";
}

function graphNodeMeta(node) {
  const props = node.properties || {};
  const kind = graphNodeKind(node);
  if (kind === "vulnerability") {
    return [props.severity, props.product, props.source].filter(Boolean).join(" · ");
  }
  if (kind === "product") {
    return [
      props.vendor,
      props.vulnerability_count !== undefined ? `${props.vulnerability_count} 漏洞` : "",
      props.poc_count ? `${props.poc_count} POC` : "",
    ].filter(Boolean).join(" · ");
  }
  if (kind === "alert") return [props.status, props.reason].filter(Boolean).join(" · ");
  if (kind === "archive") return [props.status, props.minio_status, props.origin].filter(Boolean).join(" · ");
  return "";
}

function graphNodeUrl(node) {
  const props = node.properties || {};
  return props.url || "";
}

function graphRelationLabel(type) {
  return {
    AFFECTS: "影响",
    REPORTED: "上报",
    FOR: "触发",
    EVIDENCES: "佐证",
    SOURCE_FOR: "源码",
    OWNS: "拥有",
  }[type] || type || "关系";
}

function shortText(value, length = 24) {
  const text = String(value ?? "").trim();
  if (text.length <= length) return text;
  return `${text.slice(0, length - 1)}…`;
}

function graphCenterNode(result) {
  const target = result?.target || {};
  const nodes = result?.graph?.nodes || [];
  if (target.kind === "vulnerability") {
    return nodes.find((node) => graphNodeKind(node) === "vulnerability" && Number(node.properties?.id) === Number(target.id));
  }
  if (target.kind === "product") {
    return nodes.find((node) => graphNodeKind(node) === "product" && node.properties?.key === target.product_key);
  }
  return nodes[0] || null;
}

function graphDepthMap(nodes, relationships, centerId) {
  const adjacency = new Map();
  nodes.forEach((node) => adjacency.set(node.id, []));
  relationships.forEach((rel) => {
    if (!adjacency.has(rel.source) || !adjacency.has(rel.target)) return;
    adjacency.get(rel.source).push(rel.target);
    adjacency.get(rel.target).push(rel.source);
  });
  const depthById = new Map([[centerId, 0]]);
  const queue = [centerId];
  while (queue.length) {
    const current = queue.shift();
    const nextDepth = (depthById.get(current) || 0) + 1;
    (adjacency.get(current) || []).forEach((next) => {
      if (depthById.has(next)) return;
      depthById.set(next, nextDepth);
      queue.push(next);
    });
  }
  nodes.forEach((node) => {
    if (!depthById.has(node.id)) depthById.set(node.id, 9);
  });
  return depthById;
}

function graphSeverityWeight(node) {
  const severity = String(node?.properties?.severity || "").toLowerCase();
  return {
    critical: 70,
    high: 55,
    medium: 34,
    low: 18,
    unknown: 8,
  }[severity] || 8;
}

function graphNodeWeight(node, degree = 0) {
  const kind = graphNodeKind(node);
  const props = node.properties || {};
  const kindWeight = {
    product: 80,
    vulnerability: graphSeverityWeight(node),
    alert: 52,
    archive: 48,
    source: 38,
    vendor: 34,
    unknown: 10,
  }[kind] || 10;
  const quality = Number(props.quality_score || 0);
  const productCount = Number(props.vulnerability_count || 0);
  return kindWeight + Math.min(18, degree * 2) + Math.min(16, quality / 7) + Math.min(10, productCount / 12);
}

function trimGraph(result, maxNodes = 56, maxRelationships = 96) {
  const graph = result?.graph || {};
  const nodes = graph.nodes || [];
  const relationships = graph.relationships || [];
  if (nodes.length <= maxNodes && relationships.length <= maxRelationships) {
    return { nodes, relationships, trimmed: false, originalNodes: nodes.length, originalRelationships: relationships.length };
  }
  const center = graphCenterNode(result) || nodes[0];
  const degree = new Map();
  relationships.forEach((rel) => {
    degree.set(rel.source, (degree.get(rel.source) || 0) + 1);
    degree.set(rel.target, (degree.get(rel.target) || 0) + 1);
  });
  const depthById = graphDepthMap(nodes, relationships, center?.id);
  const priority = {
    vulnerability: 1,
    product: 2,
    archive: 3,
    alert: 4,
    vendor: 5,
    source: 6,
    unknown: 7,
  };
  const kept = new Set(
    nodes
      .slice()
      .sort((a, b) => {
        if (a.id === center?.id) return -1;
        if (b.id === center?.id) return 1;
        const depthDiff = (depthById.get(a.id) || 9) - (depthById.get(b.id) || 9);
        if (depthDiff) return depthDiff;
        const kindDiff = (priority[graphNodeKind(a)] || 9) - (priority[graphNodeKind(b)] || 9);
        if (kindDiff) return kindDiff;
        return graphNodeWeight(b, degree.get(b.id) || 0) - graphNodeWeight(a, degree.get(a.id) || 0);
      })
      .slice(0, maxNodes)
      .map((node) => node.id)
  );
  const trimmedNodes = nodes.filter((node) => kept.has(node.id));
  const trimmedRelationships = relationships
    .filter((rel) => kept.has(rel.source) && kept.has(rel.target))
    .slice(0, maxRelationships);
  return {
    nodes: trimmedNodes,
    relationships: trimmedRelationships,
    trimmed: true,
    originalNodes: nodes.length,
    originalRelationships: relationships.length,
  };
}

function layoutGraphNodes(nodes, relationships, centerId) {
  const width = 1420;
  const height = 900;
  const centerX = width / 2;
  const centerY = height / 2;
  const depthById = graphDepthMap(nodes, relationships, centerId);
  const degree = new Map();
  relationships.forEach((rel) => {
    degree.set(rel.source, (degree.get(rel.source) || 0) + 1);
    degree.set(rel.target, (degree.get(rel.target) || 0) + 1);
  });
  const rings = new Map();
  nodes.forEach((node) => {
    const depth = Math.min(depthById.get(node.id) || 1, 4);
    if (!rings.has(depth)) rings.set(depth, []);
    rings.get(depth).push(node);
  });
  const positions = new Map();
  positions.set(centerId, { x: centerX, y: centerY });
  [...rings.entries()].forEach(([depth, ringNodes]) => {
    if (depth === 0) return;
    const sorted = ringNodes.slice().sort((a, b) => {
      const weightDiff = graphNodeWeight(b, degree.get(b.id) || 0) - graphNodeWeight(a, degree.get(a.id) || 0);
      if (weightDiff) return weightDiff;
      return graphNodeTitle(a).localeCompare(graphNodeTitle(b), "zh-CN");
    });
    const baseRadius = 150 + (depth - 1) * 150;
    const minGap = nodes.length > 42 ? 82 : 96;
    let cursor = 0;
    let layer = 0;
    while (cursor < sorted.length) {
      const radius = Math.min(392, baseRadius + layer * 82);
      const capacity = Math.max(8, Math.floor((Math.PI * 2 * radius) / minGap));
      const chunk = sorted.slice(cursor, cursor + capacity);
      const angleOffset = -Math.PI / 2 + depth * 0.34 + layer * 0.19;
      chunk.forEach((node, index) => {
        const angle = angleOffset + (Math.PI * 2 * index) / Math.max(1, chunk.length);
        const wobble = (index % 2 === 0 ? 1 : -1) * Math.min(18, layer * 5 + depth * 2);
        positions.set(node.id, {
          x: centerX + Math.cos(angle) * (radius + wobble),
          y: centerY + Math.sin(angle) * (radius + wobble),
        });
      });
      cursor += chunk.length;
      layer += 1;
    }
  });
  positions.set(centerId, { x: centerX, y: centerY });
  return { positions, width, height };
}

function graphLabelIds(nodes, relationships, centerId, selectedId) {
  const degree = new Map();
  relationships.forEach((rel) => {
    degree.set(rel.source, (degree.get(rel.source) || 0) + 1);
    degree.set(rel.target, (degree.get(rel.target) || 0) + 1);
  });
  const budget = nodes.length > 46 ? 10 : nodes.length > 28 ? 14 : nodes.length > 16 ? 10 : nodes.length;
  const ids = new Set([centerId, selectedId].filter(Boolean));
  nodes
    .slice()
    .sort((a, b) => graphNodeWeight(b, degree.get(b.id) || 0) - graphNodeWeight(a, degree.get(a.id) || 0))
    .slice(0, budget)
    .forEach((node) => ids.add(node.id));
  return ids;
}

function renderGraphLegend(nodes, relationships, trimmed) {
  const counts = nodes.reduce((acc, node) => {
    const kind = graphNodeKind(node);
    acc[kind] = (acc[kind] || 0) + 1;
    return acc;
  }, {});
  const kinds = ["vulnerability", "product", "alert", "source", "archive", "vendor"];
  $("#graphLegend").innerHTML = `
    ${kinds
      .filter((kind) => counts[kind])
      .map((kind) => `<span><i class="graph-dot ${kind}"></i>${graphKindLabel(kind)} ${counts[kind]}</span>`)
      .join("")}
    <span>关系 ${relationships.length}</span>
    ${nodes.length > 16 ? `<span class="graph-trimmed">已启用精简标签</span>` : ""}
    ${trimmed.trimmed ? `<span class="graph-trimmed">已精简 ${trimmed.originalNodes} 节点 / ${trimmed.originalRelationships} 关系</span>` : ""}
  `;
}

function renderGraphInspector(node, relationships, nodes = []) {
  if (!node) {
    $("#graphInspector").innerHTML = `<h3>节点详情</h3><div class="empty inline">选择图中的节点查看属性。</div>`;
    return;
  }
  const nodeById = new Map(nodes.map((item) => [item.id, item]));
  const props = node.properties || {};
  const kind = graphNodeKind(node);
  const related = relationships.filter((rel) => rel.source === node.id || rel.target === node.id).slice(0, 12);
  const fields = [
    ["类型", graphKindLabel(kind)],
    ["名称", graphNodeTitle(node)],
    ["ID", props.id || props.key || node.id],
    ["等级", props.severity],
    ["产品", props.product],
    ["来源", props.source || props.origin],
    ["状态", props.status || props.analysis_status],
    ["漏洞数", props.vulnerability_count],
    ["POC", props.poc_available === true ? "是" : props.poc_available === false ? "否" : props.poc_count],
    ["EXP", props.exp_available === true ? "是" : props.exp_available === false ? "否" : ""],
  ].filter(([, value]) => value !== undefined && value !== null && value !== "");
  const url = graphNodeUrl(node);
  $("#graphInspector").innerHTML = `
    <h3>${esc(graphNodeTitle(node))}</h3>
    <div class="graph-node-type"><span class="graph-dot ${esc(kind)}"></span>${esc(graphKindLabel(kind))}</div>
    <div class="graph-inspector-grid">
      ${fields.map(([label, value]) => `<div class="kv"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("")}
    </div>
    ${url ? `<a class="intel-button active graph-open-link" href="${esc(url)}" target="_blank" rel="noreferrer">打开来源</a>` : ""}
    <h4>关联关系</h4>
    ${
      related.length
        ? `<ul class="graph-related">${related
            .map((rel) => {
              const direction = rel.source === node.id ? "→" : "←";
              const otherId = rel.source === node.id ? rel.target : rel.source;
              const otherNode = nodeById.get(otherId);
              return `<li><span>${esc(graphRelationLabel(rel.type))}</span><small>${esc(direction)} ${esc(otherNode ? graphNodeTitle(otherNode) : otherId)}</small></li>`;
            })
            .join("")}</ul>`
        : `<div class="empty inline">暂无关系</div>`
    }
  `;
}

function resetGraphViewport(width, height) {
  state.graphViewport = {
    width,
    height,
    scale: 1,
    x: 0,
    y: 0,
    minScale: 0.45,
    maxScale: 4,
  };
}

function ensureGraphViewport(width, height) {
  const viewport = state.graphViewport;
  if (!viewport || viewport.width !== width || viewport.height !== height) {
    resetGraphViewport(width, height);
  }
}

function clampGraphViewport() {
  const viewport = state.graphViewport;
  if (!viewport) return;
  viewport.scale = Math.max(viewport.minScale, Math.min(viewport.maxScale, viewport.scale));
  const slackX = viewport.width * Math.max(0.65, viewport.scale);
  const slackY = viewport.height * Math.max(0.65, viewport.scale);
  viewport.x = Math.max(-slackX, Math.min(slackX, viewport.x));
  viewport.y = Math.max(-slackY, Math.min(slackY, viewport.y));
}

function updateGraphTransform() {
  const viewport = state.graphViewport;
  const layer = $("#graphViewportLayer");
  if (!viewport || !layer) {
    const label = $("#graphZoomLabel");
    if (label) label.textContent = "100%";
    return;
  }
  clampGraphViewport();
  layer.setAttribute("transform", `translate(${viewport.x.toFixed(1)} ${viewport.y.toFixed(1)}) scale(${viewport.scale.toFixed(3)})`);
  const label = $("#graphZoomLabel");
  if (label) label.textContent = `${Math.round(viewport.scale * 100)}%`;
}

function graphViewportPoint(svg, clientX, clientY) {
  const viewport = state.graphViewport;
  if (!viewport || !svg) return { x: 0, y: 0 };
  const rect = svg.getBoundingClientRect();
  if (!rect.width || !rect.height) return { x: viewport.width / 2, y: viewport.height / 2 };
  return {
    x: ((clientX - rect.left) / rect.width) * viewport.width,
    y: ((clientY - rect.top) / rect.height) * viewport.height,
  };
}

function setGraphZoom(nextScale, anchor = null) {
  const viewport = state.graphViewport;
  const svg = $("#graphCanvas .graph-svg");
  if (!viewport || !svg) return;
  const scale = Math.max(viewport.minScale, Math.min(viewport.maxScale, nextScale));
  const point = anchor || { x: viewport.width / 2, y: viewport.height / 2 };
  const worldX = (point.x - viewport.x) / viewport.scale;
  const worldY = (point.y - viewport.y) / viewport.scale;
  viewport.scale = scale;
  viewport.x = point.x - worldX * scale;
  viewport.y = point.y - worldY * scale;
  updateGraphTransform();
}

function zoomGraphBy(factor, anchor = null) {
  const viewport = state.graphViewport;
  if (!viewport) return;
  setGraphZoom(viewport.scale * factor, anchor);
}

function fitGraphViewport() {
  if (!state.graphViewport) return;
  state.graphViewport.scale = 1;
  state.graphViewport.x = 0;
  state.graphViewport.y = 0;
  updateGraphTransform();
}

function resetGraphZoom() {
  if (!state.graphViewport) return;
  fitGraphViewport();
}

function bindGraphViewportEvents() {
  const svg = $("#graphCanvas .graph-svg");
  if (!svg || svg.dataset.viewportBound) return;
  svg.dataset.viewportBound = "1";
  svg.addEventListener(
    "wheel",
    (event) => {
      if (!state.graphViewport) return;
      event.preventDefault();
      const factor = event.deltaY < 0 ? 1.14 : 0.88;
      zoomGraphBy(factor, graphViewportPoint(svg, event.clientX, event.clientY));
    },
    { passive: false }
  );
  svg.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    if (event.target.closest?.(".graph-node")) return;
    const viewport = state.graphViewport;
    if (!viewport) return;
    state.graphDrag = {
      pointerId: event.pointerId,
      startClientX: event.clientX,
      startClientY: event.clientY,
      startX: viewport.x,
      startY: viewport.y,
    };
    svg.classList.add("panning");
    svg.setPointerCapture?.(event.pointerId);
  });
  svg.addEventListener("pointermove", (event) => {
    const drag = state.graphDrag;
    const viewport = state.graphViewport;
    if (!drag || !viewport || drag.pointerId !== event.pointerId) return;
    const rect = svg.getBoundingClientRect();
    const dx = rect.width ? ((event.clientX - drag.startClientX) / rect.width) * viewport.width : 0;
    const dy = rect.height ? ((event.clientY - drag.startClientY) / rect.height) * viewport.height : 0;
    viewport.x = drag.startX + dx;
    viewport.y = drag.startY + dy;
    updateGraphTransform();
  });
  const endDrag = (event) => {
    const drag = state.graphDrag;
    if (drag && drag.pointerId === event.pointerId) {
      state.graphDrag = null;
      svg.classList.remove("panning");
      svg.releasePointerCapture?.(event.pointerId);
    }
  };
  svg.addEventListener("pointerup", endDrag);
  svg.addEventListener("pointercancel", endDrag);
  svg.addEventListener("dblclick", (event) => {
    if (event.target.closest?.(".graph-node")) return;
    zoomGraphBy(1.35, graphViewportPoint(svg, event.clientX, event.clientY));
  });
}

function renderGraphResult(result) {
  const canvas = $("#graphCanvas");
  const target = result?.target || {};
  const graph = result?.graph || {};
  const rawNodes = graph.nodes || [];
  const rawRelationships = graph.relationships || [];
  $("#graphTarget").textContent = target.label
    ? `${target.kind === "product" ? "产品" : "漏洞"}：${target.label}`
    : "未选择图谱目标";
  if (!rawNodes.length) {
    canvas.innerHTML = `<div class="empty">数据库中找到了目标，但 Neo4j 图谱里还没有对应节点。请先点击“同步图谱”。</div>`;
    renderGraphLegend([], [], { trimmed: false });
    renderGraphInspector(null, [], []);
    state.graphViewport = null;
    updateGraphTransform();
    return;
  }
  const trimmed = trimGraph(result);
  const nodes = trimmed.nodes;
  const relationships = trimmed.relationships;
  const center = graphCenterNode({ ...result, graph: { nodes, relationships } }) || nodes[0];
  const selected = nodes.find((node) => node.id === state.graphSelectedId) || center;
  state.graphSelectedId = selected?.id || "";
  const { positions, width, height } = layoutGraphNodes(nodes, relationships, center.id);
  ensureGraphViewport(width, height);
  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const labelIds = graphLabelIds(nodes, relationships, center.id, state.graphSelectedId);
  const showEdgeLabels = relationships.length <= 18;
  const edgeMarkup = relationships
    .filter((rel) => positions.has(rel.source) && positions.has(rel.target))
    .map((rel, index) => {
      const source = positions.get(rel.source);
      const targetPoint = positions.get(rel.target);
      const labelX = (source.x + targetPoint.x) / 2;
      const labelY = (source.y + targetPoint.y) / 2;
      return `
        <g class="graph-edge">
          <line x1="${source.x.toFixed(1)}" y1="${source.y.toFixed(1)}" x2="${targetPoint.x.toFixed(1)}" y2="${targetPoint.y.toFixed(1)}"></line>
          ${showEdgeLabels && index < 40 ? `<text x="${labelX.toFixed(1)}" y="${labelY.toFixed(1)}">${esc(graphRelationLabel(rel.type))}</text>` : ""}
        </g>
      `;
    })
    .join("");
  const nodeMarkup = nodes
    .map((node) => {
      const point = positions.get(node.id);
      const kind = graphNodeKind(node);
      const selectedClass = node.id === state.graphSelectedId ? " selected" : "";
      const centerClass = node.id === center.id ? " center" : "";
      const title = shortText(graphNodeTitle(node), kind === "vulnerability" ? 30 : 24);
      const meta = shortText(graphNodeMeta(node), 28);
      const dense = nodes.length > 34;
      const radius = node.id === center.id ? (dense ? 24 : 28) : kind === "vulnerability" ? (dense ? 15 : 22) : kind === "product" ? (dense ? 17 : 21) : dense ? 13 : 17;
      const showLabel = labelIds.has(node.id);
      const labelClass = showLabel ? "" : " label-hidden";
      const fullTitle = [graphNodeTitle(node), graphNodeMeta(node)].filter(Boolean).join(" · ");
      return `
        <g class="graph-node ${esc(kind)}${selectedClass}${centerClass}${labelClass}" data-graph-node="${esc(node.id)}" transform="translate(${point.x.toFixed(1)} ${point.y.toFixed(1)})" role="button" tabindex="0">
          <title>${esc(fullTitle)}</title>
          <circle r="${radius}"></circle>
          <text class="graph-node-title" y="${radius + 16}">${esc(title)}</text>
          ${meta ? `<text class="graph-node-meta" y="${radius + 31}">${esc(meta)}</text>` : ""}
        </g>
      `;
    })
    .join("");
  canvas.innerHTML = `
    <svg class="graph-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="漏洞关系图谱">
      <g id="graphViewportLayer">
        <g class="graph-grid">
          <circle cx="${width / 2}" cy="${height / 2}" r="112"></circle>
          <circle cx="${width / 2}" cy="${height / 2}" r="194"></circle>
          <circle cx="${width / 2}" cy="${height / 2}" r="276"></circle>
        </g>
        <g class="graph-edges">${edgeMarkup}</g>
        <g class="graph-nodes">${nodeMarkup}</g>
      </g>
    </svg>
  `;
  renderGraphLegend(nodes, relationships, trimmed);
  renderGraphInspector(nodeById.get(state.graphSelectedId), relationships, nodes);
  updateGraphTransform();
  bindGraphViewportEvents();
  bindGraphNodeEvents();
}

function bindGraphNodeEvents() {
  document.querySelectorAll("[data-graph-node]").forEach((node) => {
    if (node.dataset.bound) return;
    node.dataset.bound = "1";
    const select = () => {
      state.graphSelectedId = node.dataset.graphNode;
      renderGraphResult(state.graphResult);
    };
    node.addEventListener("click", select);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        select();
      }
    });
  });
}

async function searchGraph() {
  if (!state.graphAvailable) {
    showModal("图谱不可用", "Neo4j 当前不可用。请先启动 Neo4j 并同步图谱，或在产品/告警列表查看关系。");
    return;
  }
  const query = $("#graphQuery").value.trim();
  if (!query) {
    showModal("图谱查询", "请输入 CVE、漏洞 ID 或产品名。");
    return;
  }
  state.graphQuery = query;
  state.graphKind = $("#graphKind").value || "auto";
  state.graphDepth = Number($("#graphDepth").value || 2);
  const params = new URLSearchParams({
    q: state.graphQuery,
    kind: state.graphKind,
    depth: String(state.graphDepth),
  });
  const button = $("#graphSearch");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "查询中";
  $("#graphSyncMessage").textContent = "";
  try {
    const result = await api(`/api/graph/search?${params}`);
    if (!result) return;
    state.graphResult = result;
    state.graphSelectedId = "";
    state.graphViewport = null;
    renderGraphResult(result);
  } catch (error) {
    $("#graphCanvas").innerHTML = `<div class="empty">未找到匹配的图谱节点。</div>`;
    renderGraphInspector(null, [], []);
    state.graphViewport = null;
    updateGraphTransform();
    $("#graphSyncMessage").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

async function loadSourceSessions() {
  const [avd, cnvd] = await Promise.all([
    api("/api/source-sessions/avd"),
    api("/api/source-sessions/cnvd"),
  ]);
  if (!avd || !cnvd) return;
  renderSessionStatus("#avdSessionStatus", "AVD Cookie", avd);
  renderSessionStatus("#cnvdSessionStatus", "CNVD Cookie", cnvd, [
    ["抓取范围", (cnvd.keywords || []).join("、") || "最新列表"],
    ["分页", `${cnvd.max_pages || "-"} 页 / 每页 ${cnvd.page_size || "-"} 条`],
  ]);
  $("#avdSessionMessage").textContent = avd.error || "";
  $("#cnvdSessionMessage").textContent = cnvd.error || "";
}

function renderSessionStatus(selector, label, data, extra = []) {
  $(selector).innerHTML = [
    [label, data.configured ? "已配置" : "未配置"],
    ["来源", data.source],
    ["状态", data.status],
    ["Cookie", data.masked_cookie || "-"],
    ["更新时间", formatTime(data.updated_at)],
    ["浏览器", data.browser_executable ? "Chrome" : "-"],
    ...extra,
  ]
    .map(([key, value]) => `<div class="kv"><span>${esc(key)}</span><strong>${esc(value)}</strong></div>`)
    .join("");
}

async function loadFollowedProducts() {
  const data = await api("/api/followed-products");
  if (!data) return;
  const items = data.data || [];
  $("#followedCount").textContent = `${items.length} 个产品`;
  $("#followedProducts").innerHTML = items.length
    ? items
        .map((item) => `
          <article class="followed-item">
            <div>
              <strong>${esc(item.product)}</strong>
              <div class="meta">
                ${item.last_matched_at ? `最近触发：${esc(item.last_matched_at)}` : "等待高危/严重漏洞触发"}
              </div>
            </div>
            <button type="button" data-unfollow-key="${esc(item.product_key)}">取消关注</button>
          </article>
        `)
        .join("")
    : `<div class="empty">暂无关注产品；在告警中心或漏洞情报中点击“关注产品”。</div>`;
  bindUnfollowButtons();
}

function productMarkup(item) {
  const followed = Boolean(item.is_followed);
  const aliases = (item.aliases || []).filter(Boolean).slice(0, 4);
  const aliasText = aliases.map((alias) => alias.alias).filter(Boolean);
  return `
    <article class="product-item">
      <div class="product-main">
        <h3>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">${esc(item.name)}</a>` : esc(item.name)}</h3>
        <div class="meta product-meta">
          ${esc(item.source || "product")} · ${esc(item.vulnerability_count || 0)} 个漏洞
          ${item.local_vulnerability_count ? ` · 本地命中 ${esc(item.local_vulnerability_count)} 条` : ""}
          ${item.poc_count ? ` · ${esc(item.poc_count)} 个 POC` : ""}
          ${item.merged_count ? ` · 已合并 ${esc(item.merged_count)} 项` : ""}
          ${item.last_crawled_at ? ` · ${esc(formatTime(item.last_crawled_at))}` : ""}
        </div>
        ${aliasText.length ? `<div class="product-alias-line">${aliasText.map((alias) => `<span>${esc(alias)}</span>`).join("")}</div>` : ""}
        ${productLatestVulnerabilities(item)}
      </div>
      <div class="product-actions">
        ${item.url ? `<a class="intel-button active" href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">打开</a>` : ""}
        <button type="button" class="intel-button active" data-product-detail="${esc(item.product_key)}">详情</button>
        <button type="button" class="follow-action ${followed ? "active" : ""}" ${followed ? "disabled" : `data-product-follow="${esc(item.name)}"`}>${followed ? "已关注" : "关注产品"}</button>
      </div>
    </article>
  `;
}

async function showProductDetail(productKey) {
  const detail = await api(`/api/products/${encodeURIComponent(productKey)}`);
  if (!detail) return;
  showModal(detail.name || "产品详情", productDetailHtml(detail), { html: true });
  bindProductDetailForms(detail);
}

function productDetailHtml(detail) {
  const aliases = detail.aliases || [];
  const merged = detail.merged_products || [];
  const latest = detail.latest_vulnerabilities || [];
  const pocExp = detail.latest_poc_exp || [];
  const severity = detail.severity_distribution || [];
  const evidence = detail.evidence_summary || [];
  return `
    <div class="product-detail">
      <div class="product-detail-head">
        <div>
          <h3>${esc(detail.name || "-")}</h3>
          <div class="meta">${esc(detail.source || "product")} · ${esc(detail.vendor || "未标注厂商")} · ${esc(detail.product_key || "")}</div>
        </div>
        <span class="analysis-status ${detail.is_followed ? "finished" : ""}">${detail.is_followed ? "已关注" : "未关注"}</span>
      </div>
      <div class="detail-metrics">
        <div class="kv"><span>本地漏洞</span><strong>${esc(detail.local_vulnerability_count || 0)}</strong></div>
        <div class="kv"><span>产品库漏洞</span><strong>${esc(detail.vulnerability_count || 0)}</strong></div>
        <div class="kv"><span>POC</span><strong>${esc(detail.poc_count || 0)}</strong></div>
        <div class="kv"><span>最近采集</span><strong>${esc(formatTime(detail.last_crawled_at))}</strong></div>
      </div>
      <section>
        <h4>漏洞趋势</h4>
        ${trendBars(detail.trend || [])}
      </section>
      <section>
        <h4>严重等级分布</h4>
        ${severity.length ? `<div class="severity-pills">${severity.map((item) => `<span class="badge ${severityClass(item.severity)}">${esc(item.severity)} ${esc(item.count)}</span>`).join("")}</div>` : `<div class="empty inline">暂无显式关联漏洞</div>`}
      </section>
      <section>
        <h4>最新 POC / EXP</h4>
        ${pocExp.length ? `<ul class="detail-list">${pocExp.map((item) => productDetailVulnLink(item, true)).join("")}</ul>` : `<div class="empty inline">暂无 POC/EXP 产出</div>`}
      </section>
      <section>
        <h4>最新漏洞</h4>
        ${latest.length ? `<ul class="detail-list">${latest.map((item) => productDetailVulnLink(item)).join("")}</ul>` : `<div class="empty inline">暂无漏洞</div>`}
      </section>
      <section>
        <h4>别名字典</h4>
        ${aliases.length ? `<div class="alias-list">${aliases.map((item) => `<span>${esc(item.alias)}${item.vendor ? ` · ${esc(item.vendor)}` : ""}</span>`).join("")}</div>` : `<div class="empty inline">暂无别名</div>`}
        <form class="inline-form" data-product-alias-form="${esc(detail.product_key)}">
          <input name="alias" type="text" placeholder="新增别名，如 Yonyou NC" />
          <input name="vendor" type="text" placeholder="厂商，可选" />
          <button type="submit">添加</button>
        </form>
      </section>
      <section>
        <h4>产品合并</h4>
        ${merged.length ? `<div class="alias-list">${merged.map((item) => `<span>${esc(item.name)}</span>`).join("")}</div>` : `<div class="empty inline">暂无合并项</div>`}
        <form class="inline-form" data-product-merge-form="${esc(detail.product_key)}">
          <input name="sources" type="text" placeholder="输入要合并的产品名或 product_key，逗号分隔" />
          <button type="submit">合并</button>
        </form>
      </section>
      <section>
        <h4>关系证据</h4>
        ${evidence.length ? `<div class="evidence-list">${evidence.map((item) => `<div class="kv"><span>${esc(item.match_method || "unknown")} / ${esc(item.evidence_type || "direct")}</span><strong>${esc(item.count)} · ${Math.round(Number(item.avg_confidence || 0) * 100)}%</strong></div>`).join("")}</div>` : `<div class="empty inline">暂无证据统计</div>`}
      </section>
    </div>
  `;
}

function trendBars(rows) {
  if (!rows.length) return `<div class="empty inline">最近 30 天暂无趋势数据</div>`;
  const max = Math.max(1, ...rows.map((row) => Number(row.count) || 0));
  return `
    <div class="trend-bars">
      ${rows.map((row) => `<div title="${esc(row.day)} ${esc(row.count)}"><i style="height:${Math.max(8, Math.round((Number(row.count) || 0) / max * 56))}px"></i><span>${esc(String(row.day || "").slice(5))}</span></div>`).join("")}
    </div>
  `;
}

function productDetailVulnLink(item, showArtifact = false) {
  const label = item.title || item.cve_id || "未命名漏洞";
  const link = item.url
    ? `<a href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(label)}</a>`
    : `<span>${esc(label)}</span>`;
  const artifacts = showArtifact
    ? [item.poc_available ? "POC" : "", item.exp_available ? "EXP" : ""].filter(Boolean).join(" / ")
    : "";
  const meta = [item.severity || "", item.source || "", artifacts, item.published_at ? formatTime(item.published_at) : ""].filter(Boolean).join(" · ");
  return `<li>${link}${meta ? `<small>${esc(meta)}</small>` : ""}</li>`;
}

function bindProductDetailForms(detail) {
  document.querySelectorAll("[data-product-alias-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      await api("/api/products/aliases", {
        method: "POST",
        body: JSON.stringify({
          product_key: form.dataset.productAliasForm,
          alias: data.get("alias"),
          vendor: data.get("vendor"),
        }),
      });
      await Promise.all([loadProducts(), showProductDetail(form.dataset.productAliasForm)]);
    });
  });
  document.querySelectorAll("[data-product-merge-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      await api("/api/products/merge", {
        method: "POST",
        body: JSON.stringify({
          target_product_key: form.dataset.productMergeForm,
          sources: data.get("sources"),
          note: "前端手动合并",
        }),
      });
      await Promise.all([loadProducts(), showProductDetail(form.dataset.productMergeForm)]);
    });
  });
}

function bindSourceArchiveButtons() {
  document.querySelectorAll("[data-source-detail]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const archive = await api(`/api/source-archives/${button.dataset.sourceDetail}`);
        if (archive) {
          showModal(archive.filename || "源码详情", sourceArchiveDetailHtml(archive), { html: true });
        }
      } catch (error) {
        showModal("源码详情加载失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-cancel]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      if (!confirm("确认取消入库并删除该源码？这会删除源码库记录、本地源码文件，并尝试删除对象存储里的源码包。")) {
        return;
      }
      button.disabled = true;
      try {
        await api(`/api/source-archives/${button.dataset.sourceCancel}/cancel`, {
          method: "POST",
          body: JSON.stringify({ reason: "前端手动取消入库" }),
        });
        await Promise.all([loadSourceArchives(), loadMessages(), loadSummary()]);
      } catch (error) {
        showModal("取消入库失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-delete]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      if (!confirm("确认删除该源码？这会删除源码库记录、本地源码文件，并尝试删除对象存储里的源码包；已确认的产品不会自动删除。")) {
        return;
      }
      button.disabled = true;
      try {
        await api(`/api/source-archives/${button.dataset.sourceDelete}`, {
          method: "DELETE",
          body: JSON.stringify({ reason: "前端手动删除源码" }),
        });
        await Promise.all([loadSourceArchives(), loadMessages(), loadSummary()]);
      } catch (error) {
        showModal("删除源码失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-confirm]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const card = button.closest(".source-archive-item");
      if (!card) return;
      const productName = card.querySelector("[data-source-product-name]")?.value.trim() || "";
      const vendor = card.querySelector("[data-source-vendor]")?.value.trim() || "";
      const aliases = (card.querySelector("[data-source-aliases]")?.value || "")
        .split(/[,\n，、]/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (!productName) {
        showModal("确认失败", "请先填写产品名。");
        return;
      }
      button.disabled = true;
      try {
        await api(`/api/source-archives/${button.dataset.sourceConfirm}/confirm-product`, {
          method: "POST",
          body: JSON.stringify({ product_name: productName, vendor, aliases }),
        });
        await Promise.all([loadSourceArchives(), loadProducts(), loadMessages()]);
      } catch (error) {
        showModal("确认失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-reanalyze]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/source-archives/${button.dataset.sourceReanalyze}/reanalyze`, { method: "POST" });
        await loadSourceArchives();
        setTimeout(loadSourceArchives, 5000);
      } catch (error) {
        showModal("重新分析失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-retry-minio]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/source-archives/${button.dataset.sourceRetryMinio}/retry-minio`, { method: "POST" });
        await loadSourceArchives();
      } catch (error) {
        showModal("源码包上传失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-source-fetch-latest]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      const productName = button.dataset.sourceFetchLatest || "";
      if (!productName) {
        showModal("拉取失败", "请先确认产品名。");
        return;
      }
      button.disabled = true;
      const original = button.textContent;
      button.textContent = "拉取中";
      try {
        await fetchLatestSourceArchive({
          productName,
          productKey: button.dataset.sourceFetchProductKey || "",
        });
        await Promise.all([loadSourceArchives(), loadMessages(), loadSummary()]);
        setTimeout(loadSourceArchives, 5000);
      } catch (error) {
        showModal("拉取失败", error.message);
      } finally {
        button.disabled = false;
        button.textContent = original;
      }
    });
  });
}

function bindUpdateButtons() {
  document.querySelectorAll("[data-update-detail]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const update = await api(`/api/updates/${button.dataset.updateDetail}`);
        if (update) {
          showModal(update.filename || "更新报告", updateDetailHtml(update), { html: true });
        }
      } catch (error) {
        showModal("更新报告加载失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-update-reanalyze]").forEach((button) => {
    if (button.dataset.bound) return;
    button.dataset.bound = "1";
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/updates/${button.dataset.updateReanalyze}/reanalyze`, { method: "POST" });
        await Promise.all([loadUpdates(), loadMessages()]);
        setTimeout(loadUpdates, 5000);
      } catch (error) {
        showModal("重新分析失败", error.message);
      } finally {
        button.disabled = false;
      }
    });
  });
}

function productLatestVulnerabilities(item) {
  const vulnerabilities = item.latest_vulnerabilities || [];
  if (!vulnerabilities.length) {
    return `<div class="product-vulns product-vulns-empty">暂无匹配漏洞</div>`;
  }
  return `
    <div class="product-vulns">
      <div class="product-vulns-title">最新漏洞</div>
      <ul>
        ${vulnerabilities
          .map((vuln) => {
            const label = vuln.title || vuln.cve_id || "未命名漏洞";
            const title = vuln.url
              ? `<a href="${esc(vuln.url)}" target="_blank" rel="noopener noreferrer">${esc(label)}</a>`
              : `<span>${esc(label)}</span>`;
            const meta = [vuln.severity || "", vuln.source || "", vuln.published_at ? formatTime(vuln.published_at) : ""]
              .filter(Boolean)
              .join(" · ");
            return `<li>${title}${meta ? `<small>${esc(meta)}</small>` : ""}</li>`;
          })
          .join("")}
      </ul>
    </div>
  `;
}

async function loadProducts() {
  const limit = state.productExpanded ? LIST_LIMIT : OVERVIEW_LIMIT;
  const offset = state.productExpanded ? state.productOffset : 0;
  const params = new URLSearchParams({
    source: "biu_products",
    limit: String(limit),
    offset: String(offset),
  });
  if (state.productQ) params.set("q", state.productQ);
  const data = await api(`/api/products?${params}`);
  if (!data) return;
  const items = data.data || [];
  $("#productCount").textContent = state.productExpanded
    ? `${state.productQ ? "搜索结果" : "biu.life 产品库"}：${rangeLabel(offset, items.length, data.total)}`
    : `${state.productQ ? "搜索结果：" : ""}Top ${Math.min(items.length, OVERVIEW_LIMIT)} / ${data.total} 个产品`;
  $("#products").innerHTML = items.length
    ? items.map(productMarkup).join("")
    : `<div class="empty">暂无产品数据；运行 biu.life 产品库数据源后会自动入库。</div>`;
  $("#productToggleList").textContent = state.productExpanded ? "收起" : "展开清单";
  $("#productPager").hidden = !state.productExpanded || (offset <= 0 && data.total <= LIST_LIMIT);
  $("#productPrev").disabled = offset <= 0;
  $("#productNext").disabled = offset + LIST_LIMIT >= data.total;
  bindProductFollowButtons();
  bindProductDetailButtons();
}

function sourceArchiveStatusLabel(value) {
  const labels = {
    fetching: "拉取中",
    queued: "排队中",
    analyzing: "分析中",
    needs_confirmation: "待确认产品",
    ready: "已入库",
    canceled: "已取消",
    failed: "失败",
  };
  return labels[value] || value || "-";
}

function minioStatusLabel(value) {
  const labels = {
    pending: "待上传",
    uploaded: "已上传",
    skipped: "未配置",
    failed: "失败",
  };
  return labels[value] || value || "-";
}

function sourceVersionLabel(item) {
  const roleLabels = {
    uploaded: "上传版本",
    affected: "受影响版本",
    latest: "最新版本",
    unknown: "未知版本",
  };
  const role = roleLabels[item.version_role] || item.version_role || "版本";
  const version = item.source_version || "";
  return version ? `${role} ${version}` : role;
}

function sourceArchiveMarkup(item) {
  const aliases = (item.suggested_aliases || []).join("，");
  const productName = item.product_name || item.suggested_product_name || item.product_hint || "";
  const minioClass = item.minio_status === "uploaded" ? "found" : item.minio_status === "failed" ? "missing" : "pending";
  const minioAction = item.minio_download_url
    ? `<a class="intel-button active" href="${esc(item.minio_download_url)}" target="_blank" rel="noreferrer" title="通过后端代理下载源码包">下载</a>`
    : `<button type="button" class="intel-button" data-source-retry-minio="${esc(item.id)}">重试上传</button>`;
  const fetchLatestAction = productName
    ? `<button type="button" class="intel-button" data-source-fetch-latest="${esc(productName)}" data-source-fetch-product-key="${esc(item.product_key || "")}">拉取最新版本</button>`
    : "";
  return `
    <article class="source-archive-item ${esc(item.status || "")}">
      <div class="source-archive-head">
        <div>
          <h3>${esc(item.filename || "源码包")}</h3>
          <div class="meta">
            ${esc(item.origin || "upload")} · ${esc(bytesLabel(item.size_bytes))} · ${esc(formatTime(item.created_at))}
            ${item.source_version || item.version_role ? ` · ${esc(sourceVersionLabel(item))}` : ""}
            ${item.sha256 ? ` · ${esc(String(item.sha256).slice(0, 12))}` : ""}
          </div>
        </div>
        <div class="source-archive-badges">
          <span class="analysis-status ${esc(item.status || "")}">${esc(sourceArchiveStatusLabel(item.status))}</span>
          <span class="analysis-source-pill ${esc(minioClass)}">源码包 ${esc(minioStatusLabel(item.minio_status))}</span>
        </div>
      </div>
      <div class="source-archive-summary">
        <div class="kv"><span>建议产品</span><strong>${esc(item.suggested_product_name || item.product_hint || "-")}</strong></div>
        <div class="kv"><span>确认产品</span><strong>${esc(item.product_name || (item.product_confirmed ? "-" : "待确认"))}</strong></div>
        <div class="kv"><span>源码版本</span><strong>${esc(item.source_version || "-")}</strong></div>
        <div class="kv"><span>厂商</span><strong>${esc(item.suggested_vendor || "-")}</strong></div>
      </div>
      ${item.architecture_summary ? `<p><strong>架构</strong>${esc(textPreview(item.architecture_summary, 260))}</p>` : ""}
      ${item.function_summary ? `<p><strong>功能</strong>${esc(textPreview(item.function_summary, 260))}</p>` : ""}
      ${item.product_evidence ? `<p><strong>证据</strong>${esc(textPreview(item.product_evidence, 260))}</p>` : ""}
      ${item.error ? `<div class="analysis-error-text">${esc(item.error)}</div>` : ""}
      <div class="source-archive-actions">
        <button type="button" class="intel-button active" data-source-detail="${esc(item.id)}">查看详情</button>
        ${minioAction}
        ${fetchLatestAction}
        <button type="button" class="intel-button active" data-source-reanalyze="${esc(item.id)}">重新分析</button>
        ${item.product_confirmed ? `<button type="button" class="intel-button danger" data-source-delete="${esc(item.id)}">删除源码</button>` : ""}
      </div>
      ${item.product_confirmed || item.status === "canceled" ? "" : `
        <div class="source-confirm-box">
          <input data-source-product-name type="text" value="${esc(productName)}" placeholder="确认产品名或新建产品" />
          <input data-source-vendor type="text" value="${esc(item.suggested_vendor || "")}" placeholder="厂商，可选" />
          <input data-source-aliases type="text" value="${esc(aliases)}" placeholder="别名，逗号分隔" />
          <button type="button" class="primary" data-source-confirm="${esc(item.id)}">确认入库</button>
          <button type="button" class="danger-button" data-source-cancel="${esc(item.id)}">取消入库并删除</button>
        </div>
      `}
    </article>
  `;
}

function sourceArchiveDetailHtml(item) {
  const raw = item.analysis_raw || {};
  const manifest = raw.manifest || {};
  const languages = manifest.languages || [];
  const sampleFiles = manifest.sample_files || [];
  const manifestNames = Object.keys(manifest.manifests || {});
  const minio = item.minio_download_url
    ? `<a href="${esc(item.minio_download_url)}" target="_blank" rel="noreferrer">下载源码包</a>`
    : `<span>${esc(item.minio_error || minioStatusLabel(item.minio_status))}</span>`;
  return `
    <div class="source-detail">
      <div class="source-detail-grid">
        <div class="kv"><span>状态</span><strong>${esc(sourceArchiveStatusLabel(item.status))}</strong></div>
        <div class="kv"><span>源码包</span><strong>${esc(minioStatusLabel(item.minio_status))}</strong></div>
        <div class="kv"><span>源码版本</span><strong>${esc(item.source_version || "-")}</strong></div>
        <div class="kv"><span>版本类型</span><strong>${esc(sourceVersionLabel(item))}</strong></div>
        <div class="kv"><span>大小</span><strong>${esc(bytesLabel(item.size_bytes))}</strong></div>
        <div class="kv"><span>SHA256</span><strong>${esc(item.sha256 || "-")}</strong></div>
        <div class="kv"><span>来源</span><strong>${esc(item.origin || "-")}</strong></div>
        <div class="kv"><span>模型</span><strong>${esc(item.analysis_model || "-")}</strong></div>
      </div>
      <section>
        <h4>产品归属</h4>
        <div class="source-detail-grid">
          <div class="kv"><span>建议产品</span><strong>${esc(item.suggested_product_name || "-")}</strong></div>
          <div class="kv"><span>确认产品</span><strong>${esc(item.product_name || "-")}</strong></div>
          <div class="kv"><span>厂商</span><strong>${esc(item.suggested_vendor || "-")}</strong></div>
          <div class="kv"><span>别名</span><strong>${esc((item.suggested_aliases || []).join("，") || "-")}</strong></div>
        </div>
      </section>
      <section>
        <h4>架构与功能</h4>
        <pre>${esc([
          item.architecture_summary ? `架构：${item.architecture_summary}` : "",
          item.function_summary ? `功能：${item.function_summary}` : "",
          item.product_evidence ? `证据：${item.product_evidence}` : "",
        ].filter(Boolean).join("\\n\\n") || "暂无分析结果")}</pre>
      </section>
      <section>
        <h4>源码清单</h4>
        <div class="source-detail-grid">
          <div class="kv"><span>解压文件</span><strong>${esc(manifest.total_files ?? "-")}</strong></div>
          <div class="kv"><span>语言</span><strong>${esc(languages.map((item) => `${item.language} ${item.count}`).join("，") || "-")}</strong></div>
        </div>
        ${sampleFiles.length ? `<ul class="detail-list source-file-list">${sampleFiles.slice(0, 80).map((file) => `<li><span>${esc(file)}</span></li>`).join("")}</ul>` : `<div class="empty inline">暂无文件采样</div>`}
      </section>
      <section>
        <h4>清单文件</h4>
        ${manifestNames.length ? `<div class="alias-list">${manifestNames.map((name) => `<span>${esc(name)}</span>`).join("")}</div>` : `<div class="empty inline">暂无 package/README 等清单文件</div>`}
      </section>
      <section>
        <h4>存储位置</h4>
        <ul class="detail-list">
          <li><span>本地包</span><small>${esc(item.local_path || "-")}</small></li>
          <li><span>解压目录</span><small>${esc(item.extracted_path || "-")}</small></li>
          <li>${minio}<small>后端代理下载</small></li>
        </ul>
      </section>
    </div>
  `;
}

async function uploadSourceArchive(file, productHint, sourceVersion) {
  const response = await fetch("/api/source-archives/upload", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      "x-source-filename": encodeURIComponent(file.name || "source.zip"),
      "x-source-product": encodeURIComponent(productHint || ""),
      "x-source-version": encodeURIComponent(sourceVersion || ""),
    },
    body: file,
  });
  if (response.status === 401) {
    location.href = loginRedirectUrl();
    return null;
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
}

async function fetchLatestSourceArchive({ productName = "", productKey = "", repoUrl = "" } = {}) {
  return api("/api/source-archives/fetch-latest", {
    method: "POST",
    body: JSON.stringify({
      product_name: productName,
      product_key: productKey,
      repo_url: repoUrl,
    }),
  });
}

async function loadSourceArchives() {
  const params = new URLSearchParams({ limit: "30", offset: "0" });
  if (state.sourceArchiveQ) params.set("q", state.sourceArchiveQ);
  if (state.sourceArchiveVersionRole) params.set("version_role", state.sourceArchiveVersionRole);
  const data = await api(`/api/source-archives?${params}`);
  if (!data) return;
  const items = data.data || [];
  const counts = data.counts || {};
  $("#sourceArchiveCount").textContent = [
    `${items.length} / ${data.total || 0} 个源码包`,
    counts.fetching ? `拉取中 ${counts.fetching}` : "",
    counts.needs_confirmation ? `待确认 ${counts.needs_confirmation}` : "",
    counts.analyzing ? `分析中 ${counts.analyzing}` : "",
    counts.failed ? `失败 ${counts.failed}` : "",
  ].filter(Boolean).join(" · ");
  $("#sourceArchives").innerHTML = items.length
    ? items.map(sourceArchiveMarkup).join("")
    : `<div class="empty">暂无源码包；上传 zip/tar 源码后会异步分析并等待产品确认。</div>`;
  bindSourceArchiveButtons();
}

function updateStatusLabel(value) {
  const labels = {
    queued: "排队中",
    analyzing: "校验并应用中",
    finished: "已完成",
    failed: "失败",
  };
  return labels[value] || value || "-";
}

function updateMarkup(item) {
  const changedFiles = item.changed_files || [];
  const checks = item.checks || [];
  return `
    <article class="source-archive-item ${esc(item.status || "")}">
      <div class="source-archive-head">
        <div>
          <h3>${esc(item.filename || "更新包")}</h3>
          <div class="meta">
            ${esc(bytesLabel(item.size_bytes))} · ${esc(formatTime(item.created_at))}
            ${item.sha256 ? ` · ${esc(String(item.sha256).slice(0, 12))}` : ""}
          </div>
        </div>
        <div class="source-archive-badges">
          <span class="analysis-status ${esc(item.status || "")}">${esc(updateStatusLabel(item.status))}</span>
          ${item.needs_restart ? `<span class="analysis-source-pill pending">需重启</span>` : ""}
        </div>
      </div>
      <div class="source-archive-summary">
        <div class="kv"><span>返回码</span><strong>${esc(item.cli_returncode ?? "-")}</strong></div>
        <div class="kv"><span>变更文件</span><strong>${esc(changedFiles.length || "-")}</strong></div>
        <div class="kv"><span>校验</span><strong>${esc(checks.length || "-")}</strong></div>
      </div>
      ${item.summary ? `<p><strong>摘要</strong>${esc(textPreview(item.summary, 320))}</p>` : ""}
      ${item.error ? `<div class="analysis-error-text">${esc(item.error)}</div>` : ""}
      ${changedFiles.length ? `<div class="alias-list">${changedFiles.slice(0, 12).map((file) => `<span>${esc(file)}</span>`).join("")}</div>` : ""}
      <div class="source-archive-actions">
        <button type="button" class="intel-button active" data-update-detail="${esc(item.id)}">查看报告</button>
        <button type="button" class="intel-button active" data-update-reanalyze="${esc(item.id)}">重新分析</button>
      </div>
    </article>
  `;
}

function updateDetailHtml(item) {
  const changedFiles = item.changed_files || [];
  const checks = item.checks || [];
  const operations = Array.isArray(item.manifest?.operations) ? item.manifest.operations : [];
  const shortHash = (value) => {
    const text = String(value || "");
    return text.length > 18 ? `${text.slice(0, 12)}...${text.slice(-6)}` : text || "-";
  };
  return `
    <div class="source-detail">
      <div class="source-detail-grid">
        <div class="kv"><span>状态</span><strong>${esc(updateStatusLabel(item.status))}</strong></div>
        <div class="kv"><span>大小</span><strong>${esc(bytesLabel(item.size_bytes))}</strong></div>
        <div class="kv"><span>SHA256</span><strong>${esc(item.sha256 || "-")}</strong></div>
        <div class="kv"><span>需要重启</span><strong>${item.needs_restart ? "是" : "否"}</strong></div>
      </div>
      <section>
        <h4>更新报告</h4>
        <pre>${esc(item.report || item.summary || "暂无报告")}</pre>
      </section>
      <section>
        <h4>变更文件</h4>
        ${changedFiles.length ? `<ul class="detail-list">${changedFiles.map((file) => `<li><span>${esc(file)}</span></li>`).join("")}</ul>` : `<div class="empty inline">暂无记录</div>`}
      </section>
      <section>
        <h4>校验</h4>
        ${checks.length ? `<ul class="detail-list">${checks.map((check) => `<li><span>${esc(check)}</span></li>`).join("")}</ul>` : `<div class="empty inline">暂无记录</div>`}
      </section>
      <section>
        <h4>一致性约束</h4>
        ${operations.length ? `<ul class="detail-list">${operations.map((op) => `<li><span>${esc(op.action || "-")} · ${esc(op.path || "-")} · before ${esc(shortHash(op.before_sha256))} · after ${esc(shortHash(op.after_sha256))}</span></li>`).join("")}</ul>` : `<div class="empty inline">暂无记录</div>`}
      </section>
    </div>
  `;
}

async function uploadUpdate(file) {
  const response = await fetch("/api/updates/upload", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "Content-Type": file.type || "application/octet-stream",
      "x-update-filename": encodeURIComponent(file.name || "update.update"),
    },
    body: file,
  });
  if (response.status === 401) {
    location.href = loginRedirectUrl();
    return null;
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.json();
}

async function loadUpdates() {
  const data = await api("/api/updates?limit=30");
  if (!data) return;
  const items = data.data || [];
  const active = items.filter((item) => ["queued", "analyzing"].includes(item.status)).length;
  const failed = items.filter((item) => item.status === "failed").length;
  $("#updateCount").textContent = [
    `${items.length} / ${data.total || 0} 个更新包`,
    active ? `进行中 ${active}` : "",
    failed ? `失败 ${failed}` : "",
  ].filter(Boolean).join(" · ");
  $("#updates").innerHTML = items.length
    ? items.map(updateMarkup).join("")
    : `<div class="empty">暂无更新包；上传 .update 后会启动后台校验并应用声明变更。</div>`;
  bindUpdateButtons();
  if (active) {
    clearTimeout(window.__updateRefreshTimer);
    window.__updateRefreshTimer = setTimeout(loadUpdates, 5000);
  }
}

function messageMarkup(message) {
  const readClass = message.is_read ? "read" : "unread";
  const action = message.is_read
    ? `<button type="button" data-message-unread="${esc(message.id)}" title="标为未读">未读</button>`
    : `<button type="button" class="primary" data-message-read="${esc(message.id)}" title="标为已读">已读</button>`;
  const levelLabels = { info: "消息", success: "完成", warning: "警告", error: "错误" };
  const levelLabel = levelLabels[message.level] || "消息";
  return `
    <article class="message-item ${readClass} ${messageLevelClass(message.level)}">
      <div class="message-line">
        <span class="message-dot" aria-hidden="true"></span>
        <strong>${esc(message.title)}</strong>
        <span class="message-meta">
          <span class="msg-category">${esc(levelLabel)}</span>
          <span class="msg-time">${esc(formatTime(message.created_at))}</span>
        </span>
      </div>
      ${message.body ? `<p>${esc(message.body)}</p>` : ""}
      <div class="message-actions">${action}</div>
    </article>
  `;
}

async function loadMessages() {
  const data = await api("/api/messages?limit=20");
  if (!data) return;
  const badge = $("#messageBadge");
  badge.textContent = data.unread || 0;
  badge.hidden = !data.unread;
  $("#messageList").innerHTML = data.data.length
    ? data.data.map(messageMarkup).join("")
    : `<div class="empty">暂无消息</div>`;
  bindMessageButtons();
}

function analysisModelDisplay(item) {
  const raw = item.analysis_raw || {};
  const model = item.analysis_model || raw.analysis_model || "";
  if (!model) return "";
  const choice = raw.analysis_model_choice || inferAnalysisModelChoice(model);
  const label = raw.analysis_model_label || (choice === "flash" ? "Flash" : choice === "pro" ? "Pro" : "自定义");
  return `${label} · ${model}`;
}

function analysisModelPolicyNote(item) {
  const raw = item.analysis_raw || {};
  if (raw.task_model_policy !== "flash_for_light_tasks") return "";
  const light = raw.light_task_model || "";
  const deep = raw.deep_task_model || "";
  if (!light && !deep) return "";
  return `轻任务 ${light || "-"} · 深度分析 ${deep || "-"}`;
}

function inferAnalysisModelChoice(model) {
  const lower = String(model || "").toLowerCase();
  if (lower.includes("flash") || lower.includes("haiku")) return "flash";
  if (lower.includes("pro") || lower.includes("opus") || lower.includes("sonnet")) return "pro";
  return "custom";
}

function analysisItemMeta(item) {
  const sourceState = analysisSourceState(item);
  const modelLabel = analysisModelDisplay(item);
  const modelPolicy = analysisModelPolicyNote(item);
  return [
    item.cve_id || "",
    item.product || "",
    item.source || "",
    sourceState.showInMeta ? sourceState.label : "",
    modelLabel ? `模型 ${modelLabel}` : "",
    modelPolicy,
    item.analysis_trigger ? `触发 ${item.analysis_trigger}` : "",
  ].filter(Boolean).join(" · ");
}

function analysisSourceState(item) {
  if (item.analysis_source_found === 1 || item.analysis_source_found === true) {
    return { label: "源码已找到", className: "found", showInMeta: true };
  }
  if (item.analysis_status === "finished") {
    return { label: "源码未找到", className: "missing", showInMeta: true };
  }
  if (item.analysis_status === "running" || item.analysis_status === "queued") {
    return { label: "源码待检索", className: "pending", showInMeta: true };
  }
  return { label: "源码未分析", className: "pending", showInMeta: false };
}

function analysisSourceHref(item) {
  if (!(item.analysis_source_found === 1 || item.analysis_source_found === true)) return "";
  if (item.analysis_source_url) return item.analysis_source_url;
  if (item.analysis_source_archive_path || item.analysis_source_local_path) {
    return `/api/vulnerabilities/${encodeURIComponent(item.id)}/analysis/source`;
  }
  return "";
}

function analysisSourcePill(item, prefix = "") {
  const state = analysisSourceState(item);
  const label = `${prefix}${state.label}`;
  const className = `analysis-source-pill ${state.className}`;
  const href = analysisSourceHref(item);
  const title = item.analysis_source_title || item.analysis_source_url || item.analysis_source_archive_path || item.analysis_source_local_path || label;
  if (href) {
    return `<a class="${esc(className)}" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="${esc(title)}">${esc(label)}</a>`;
  }
  return `<span class="${esc(className)}" title="${esc(title)}">${esc(label)}</span>`;
}

function analysisEventsMarkup(item) {
  const events = [...(item.analysis_events || [])].sort((left, right) => {
    const leftTime = new Date(left.created_at || 0).getTime() || 0;
    const rightTime = new Date(right.created_at || 0).getTime() || 0;
    return rightTime - leftTime || Number(right.id || 0) - Number(left.id || 0);
  });
  return `<pre class="analysis-output">${esc(analysisEventsText(events))}</pre>`;
}

function analysisEventsText(events) {
  return events.length
    ? events.map((event) => {
      const raw = event.raw || {};
      const usage = raw.json_event?.usage;
      const usageText = usage
        ? `\n  tokens: input=${usage.input_tokens || 0} cache_create=${usage.cache_creation_input_tokens || 0} cache_read=${usage.cache_read_input_tokens || 0} output=${usage.output_tokens || 0}`
        : "";
      const models = raw.json_event?.model_usage_keys?.length ? `\n  models: ${raw.json_event.model_usage_keys.join(", ")}` : "";
      const result = raw.json_event?.result_preview ? `\n  result: ${textPreview(raw.json_event.result_preview, 500)}` : "";
      return `[${formatTime(event.created_at)}] ${event.stream || "stage"}: ${textPreview(event.message, 500)}${usageText}${models}${result}`;
    }).join("\n\n")
    : "等待模型输出过程信息。";
}

function analysisRunProgress(item) {
  const events = [...(item.analysis_events || [])].sort((left, right) => {
    const leftTime = new Date(left.created_at || 0).getTime() || 0;
    const rightTime = new Date(right.created_at || 0).getTime() || 0;
    return rightTime - leftTime || Number(right.id || 0) - Number(left.id || 0);
  });
  const newest = events[0] || {};
  const runId = item.analysis_run_id ? String(item.analysis_run_id).slice(0, 8) : "";
  const started = item.analysis_started_at || item.analysis_requested_at || "";
  const parts = [
    started ? `本轮 ${formatTime(started)} 启动` : "",
    started ? `已运行 ${durationSince(started)}` : "",
    newest.created_at ? `最近日志 ${relativeTime(newest.created_at)}` : "等待模型输出",
    runId ? `run ${runId}` : "",
  ].filter(Boolean);
  return `<div class="analysis-progress">${esc(parts.join(" · "))}</div>`;
}

function analysisLogButton(item, label = "模型日志") {
  if (!item.id) return "";
  return `<button type="button" class="intel-button analysis-log" data-analysis-log-id="${esc(item.id)}" data-analysis-run-id="${esc(item.analysis_run_id || "")}">${esc(label)}</button>`;
}

function analysisArtifactPane(item, kind, label) {
  const available = Boolean(item[`${kind}_available`]);
  const content = item[`${kind}_content`] || "";
  const url = item[`${kind}_url`] || "";
  const key = detailKey(item, `analysis-${kind}`);
  if (available || content || url) {
    intelDetails.set(key, {
      title: `${item.cve_id || item.title || "漏洞"} · ${label}`,
      body: [content || `${label} 标记存在，但当前数据源未给出正文。`, url ? `\n链接：${url}` : ""].filter(Boolean).join("\n"),
    });
  }
  return `
    <div class="analysis-artifact ${kind}">
      <div class="analysis-artifact-head">
        <strong>${label}</strong>
        <span>${available || content ? "已生成" : "未生成"}</span>
      </div>
      <p>${esc(textPreview(content || url || "暂无内容", 220))}</p>
      <button type="button" class="intel-button ${available || content || url ? `active ${kind}` : ""}" ${available || content || url ? `data-intel-detail="${esc(key)}"` : "disabled"}>查看${label}</button>
    </div>
  `;
}

function analysisOutput(item) {
  const raw = item.analysis_raw || {};
  const output = raw.claude_output || raw.parsed || raw || {};
  return output && typeof output === "object" ? output : {};
}

function analysisText(value, fallback = "暂无内容") {
  if (Array.isArray(value)) {
    return value.filter(Boolean).join("\n");
  }
  if (value && typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }
  return String(value || "").trim() || fallback;
}

function analysisSourcesHtml(item) {
  const sources = item.analysis_sources || [];
  if (!sources.length) return `<div class="empty inline">暂无参考来源</div>`;
  return `
    <ul class="detail-list">
      ${sources.map((source) => {
        const title = source.title || source.url || source.local_path || "参考来源";
        const href = source.url ? `<a href="${esc(source.url)}" target="_blank" rel="noreferrer">${esc(title)}</a>` : `<span>${esc(title)}</span>`;
        const meta = [source.local_path || "", source.kind || ""].filter(Boolean).join(" · ");
        return `<li>${href}${meta ? `<small>${esc(meta)}</small>` : ""}</li>`;
      }).join("")}
    </ul>
  `;
}

function analysisTabs(item) {
  const output = analysisOutput(item);
  const confidence = item.analysis_confidence === null || item.analysis_confidence === undefined
    ? "-"
    : `${Math.round(Number(item.analysis_confidence || 0) * 100)}%`;
  const credibility = item.source_credibility || {};
  const sourceState = analysisSourceState(item);
  const fixAdvice = output.remediation || output.fix_advice || output.fix || output.mitigation || output.recommendations;
  const rootCause = output.root_cause ? `\n\n根因分析：\n${analysisText(output.root_cause, "")}` : "";
  const attackSurface = output.attack_surface ? `\n\n攻击面：\n${analysisText(output.attack_surface, "")}` : "";
  const feedback = item.analysis_feedback || {};
  const modelLabel = analysisModelDisplay(item) || "-";
  const logButton = analysisLogButton(item);
  return `
    <div class="analysis-confidence">
      <span>分析置信度 ${esc(confidence)}</span>
      <span>来源可信度 ${esc(credibility.label || "-")} · ${Math.round(Number(credibility.score || 0) * 100)}%</span>
      <span>模型 ${esc(modelLabel)}</span>
      ${analysisSourcePill(item, "源码状态 ")}
      ${githubEvidencePill(item)}
    </div>
    <div class="analysis-tabs">
      <div class="analysis-tab-buttons">
        <button type="button" class="active" data-analysis-tab="summary">摘要</button>
        <button type="button" data-analysis-tab="poc">POC</button>
        <button type="button" data-analysis-tab="exp">EXP</button>
        <button type="button" data-analysis-tab="fix">修复建议</button>
        <button type="button" data-analysis-tab="sources">参考来源</button>
        <button type="button" data-analysis-tab="logs">模型日志</button>
      </div>
      <section data-analysis-panel="summary">
        <pre>${esc(analysisText(item.analysis_summary, "暂无分析摘要") + rootCause + attackSurface)}</pre>
      </section>
      <section data-analysis-panel="poc" hidden>
        <div class="analysis-panel-tools">${logButton}</div>
        <pre>${esc(analysisText(item.poc_content || output.poc_content || output.poc, item.poc_available ? "标记存在 POC，但暂无正文。" : "暂无 POC"))}</pre>
        ${item.poc_url ? `<a href="${esc(item.poc_url)}" target="_blank" rel="noreferrer">打开 POC 链接</a>` : ""}
        ${githubEvidencePanel(item, "poc")}
      </section>
      <section data-analysis-panel="exp" hidden>
        <div class="analysis-panel-tools">${logButton}</div>
        <pre>${esc(analysisText(item.exp_content || output.exp_content || output.exp, item.exp_available ? "标记存在 EXP，但暂无正文。" : "暂无 EXP"))}</pre>
        ${item.exp_url ? `<a href="${esc(item.exp_url)}" target="_blank" rel="noreferrer">打开 EXP 链接</a>` : ""}
        ${githubEvidencePanel(item, "exp")}
      </section>
      <section data-analysis-panel="fix" hidden>
        <div class="analysis-panel-tools">${logButton}</div>
        <pre>${esc(analysisText(fixAdvice, "暂无单独修复建议；可重新分析生成更完整的处置建议。"))}</pre>
      </section>
      <section data-analysis-panel="sources" hidden>
        ${analysisSourcesHtml(item)}
      </section>
      <section data-analysis-panel="logs" hidden>
        <div class="analysis-panel-tools">${analysisLogButton(item, "刷新模型日志")}</div>
        <pre class="analysis-output">点击上方按钮查看模型对话过程、stdout/stderr 与阶段日志。</pre>
      </section>
    </div>
    <div class="analysis-feedback">
      <button type="button" class="${feedback.rating === "useful" ? "active" : ""}" data-feedback-id="${esc(item.id)}" data-analysis-feedback="useful">有用</button>
      <button type="button" class="${feedback.rating === "not_useful" ? "active" : ""}" data-feedback-id="${esc(item.id)}" data-analysis-feedback="not_useful">无用</button>
    </div>
  `;
}

function analysisCard(item, mode = "finished") {
  const status = item.analysis_status || "idle";
  const time = item.analysis_finished_at || item.analysis_started_at || item.analysis_requested_at || item.first_seen_at;
  return `
    <article class="analysis-card ${esc(status)}">
      <div class="analysis-card-head">
        <span class="badge ${severityClass(item.severity)}">${esc(item.severity || "unknown")}</span>
        <span class="analysis-status ${esc(status)}">${esc(analysisStatusLabel(status))}</span>
        ${analysisSourcePill(item)}
        ${githubEvidencePill(item)}
      </div>
      <h3>${item.url ? `<a href="${esc(item.url)}" target="_blank" rel="noreferrer">${esc(item.title)}</a>` : esc(item.title)}</h3>
      <div class="meta">${esc(analysisItemMeta(item))}</div>
      <div class="meta">${esc(formatTime(time))}</div>
      ${item.analysis_error ? `<div class="analysis-error-text">${esc(item.analysis_error)}</div>` : ""}
      ${mode === "running" ? analysisRunProgress(item) : ""}
      ${mode === "running" ? analysisEventsMarkup(item) : ""}
      ${mode === "finished" ? analysisTabs(item) : ""}
      ${mode === "finished" ? `<button type="button" class="analysis-delete" data-analysis-delete-id="${esc(item.id)}">删除分析</button>` : ""}
      ${itemActionButtons(item)}
    </article>
  `;
}

function registerAnalysisSummary(item) {
  const key = detailKey(item, "analysis-center-summary");
  const sources = (item.analysis_sources || [])
    .map((source) => {
      const title = source.title || source.url || source.local_path || "";
      const url = source.url ? ` ${source.url}` : "";
      const local = source.local_path ? ` ${source.local_path}` : "";
      return `- ${title}${url}${local}`.trim();
    })
    .filter(Boolean)
    .join("\n");
  intelDetails.set(key, {
    title: `${item.cve_id || item.title || "漏洞"} · 分析报告`,
    body: [item.analysis_summary || "暂无报告正文", sources ? `\n参考与源码：\n${sources}` : ""].filter(Boolean).join("\n"),
  });
  return key;
}

async function loadAnalysis() {
  const params = new URLSearchParams({ limit: "8" });
  if (state.analysisQ) params.set("q", state.analysisQ);
  const data = await api(`/api/analysis?${params}`);
  if (!data) return;
  const queued = data.queued || [];
  const running = data.running || [];
  const finished = data.finished || [];
  const counts = data.counts || {};
  $("#analysisQueuedCount").textContent = counts.queued || 0;
  $("#analysisRunningCount").textContent = counts.running || 0;
  $("#analysisFinishedCount").textContent = `${counts.finished || 0}${counts.failed ? ` / 失败 ${counts.failed}` : ""}`;
  $("#analysisCount").textContent = state.analysisQ
    ? `搜索结果：排队 ${queued.length} · 进行中 ${running.length} · 已分析 ${finished.length}`
    : `排队 ${counts.queued || 0} · 进行中 ${counts.running || 0} · 已分析 ${counts.finished || 0} · 失败 ${counts.failed || 0}`;
  $("#analysisQueued").innerHTML = queued.length
    ? queued.map((item) => analysisCard(item, "queued")).join("")
    : `<div class="empty compact">暂无排队任务</div>`;
  $("#analysisRunning").innerHTML = running.length
    ? running.map((item) => analysisCard(item, "running")).join("")
    : `<div class="empty compact">暂无正在分析的漏洞</div>`;
  $("#analysisFinished").innerHTML = finished.length
    ? finished.map((item) => analysisCard(item, "finished")).join("")
    : `<div class="empty compact">暂无已分析漏洞</div>`;
  bindIntelButtons();
  bindAnalysisTabButtons();
  bindAnalysisFeedbackButtons();
  bindAnalysisLogButtons();
  bindGitHubEvidenceButtons();
  bindAnalysisButtons();
  bindAnalysisDeleteButtons();
  bindFollowButtons();
  watchAnalysisRefresh([...queued, ...running]);
}

async function loadSources() {
  const data = await api("/api/sources");
  if (!data) return;
  populateAlertSourceOptions(data.data);
  $("#sourceCount").textContent = `${data.data.length} 个源`;
  $("#jobLine").textContent = data.jobs
    .map((job) => `${job.name}: ${formatTime(job.next_run_time)}`)
    .join(" · ");
  $("#sourceScheduleHint").textContent = sourceJobHint(data.jobs);
  $("#sources").innerHTML = data.data
    .map((source) => {
      const displayStatus = source.display_status || source.last_status || "pending";
      const displayError = source.display_error ?? source.last_error ?? "";
      const displayErrorPreview = textPreview(displayError, 160);
      const statusClass = displayStatus === "success" ? "success" : displayStatus === "failed" ? "failed" : displayStatus === "disabled" ? "disabled" : "";
      return `
        <tr>
          <td><strong>${esc(source.title)}</strong><br><span class="meta">${esc(source.name)}</span></td>
          <td><span class="badge ${esc(source.category)}">${esc(source.category)}</span></td>
          <td>${esc(source.schedule)}</td>
          <td><span class="badge ${statusClass}">${esc(displayStatus)}</span>${displayError ? `<br><span class="meta" title="${esc(displayError)}">${esc(displayErrorPreview)}</span>` : ""}</td>
          <td>${source.last_item_count ?? 0}</td>
          <td>${formatTime(source.last_run_at)}</td>
          <td><button class="primary" data-run="${esc(source.name)}" ${source.enabled ? "" : "disabled"}>${source.enabled ? "运行" : "已停用"}</button></td>
        </tr>
      `;
    })
    .join("");
  document.querySelectorAll("[data-run]").forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api(`/api/sources/${button.dataset.run}/run`, { method: "POST" });
        await refresh();
      } finally {
        button.disabled = false;
      }
    });
  });
}

function populateAlertSourceOptions(sources) {
  const select = $("#alertSource");
  if (!select) return;
  const current = state.alertSource;
  select.innerHTML = [
    `<option value="">全部来源</option>`,
    ...(sources || []).map((source) => {
      const selected = source.name === current ? " selected" : "";
      return `<option value="${esc(source.name)}"${selected}>${esc(source.title || source.name)}</option>`;
    }),
  ].join("");
}

async function loadRules() {
  const rules = await api("/api/monitor/rules");
  if (!rules) return;
  $("#minSeverity").value = rules.min_severity || "high";
  $("#enableCveDedup").checked = Boolean(rules.enable_cve_dedup);
  $("#noFilter").checked = Boolean(rules.no_filter);
  $("#maxAlertAgeDays").value = rules.max_age_days || 30;
  $("#whiteKeywords").value = (rules.white_keywords || []).join("\n");
  $("#blackKeywords").value = (rules.black_keywords || []).join("\n");
}

async function loadAlerts() {
  const limit = ALERT_PAGE_LIMIT;
  const offset = state.alertExpanded ? state.alertOffset : 0;
  const params = new URLSearchParams({
    status: state.alertStatus,
    limit: String(limit),
    offset: String(offset),
  });
  if (state.alertQ) params.set("q", state.alertQ);
  if (state.alertSource) params.set("source", state.alertSource);
  const data = await api(`/api/alerts?${params}`);
  if (!data) return;
  const statusLabel = state.alertStatus ? alertWorkflowLabel(state.alertStatus) : "全部";
  const sourceText = state.alertSource ? sourceLabel(state.alertSource) : "";
  const prefix = [statusLabel, sourceText, state.alertQ ? "搜索结果" : ""].filter(Boolean).join(" · ");
  const label = state.alertExpanded
    ? `${prefix}：${rangeLabel(offset, data.data.length, data.total)}`
    : `${prefix}：最新 ${Math.min(data.data.length, OVERVIEW_LIMIT)} / ${data.total} 条告警`;
  $("#alertCount").textContent = label;
  const emptyText = state.alertStatus === "new"
    ? "暂无新告警"
    : state.alertStatus
      ? `暂无${alertWorkflowLabel(state.alertStatus)}告警`
      : "暂无匹配告警";
  $("#alerts").innerHTML = data.data.length
    ? data.data.map(alertMarkup).join("")
    : `<div class="empty">${esc(emptyText)}</div>`;
  $("#alertToggleList").textContent = state.alertExpanded ? "收起" : "展开清单";
  const currentPage = Math.floor(offset / ALERT_PAGE_LIMIT) + 1;
  const totalPages = Math.max(1, Math.ceil(data.total / ALERT_PAGE_LIMIT));
  $("#alertPageInfo").textContent = `${currentPage} / ${totalPages} 页`;
  $("#alertPageJump").value = String(currentPage);
  $("#alertPageJump").max = String(totalPages);
  $("#alertPager").hidden = !state.alertExpanded || (offset <= 0 && data.total <= ALERT_PAGE_LIMIT);
  $("#alertPrev").disabled = offset <= 0;
  $("#alertNext").disabled = offset + ALERT_PAGE_LIMIT >= data.total;
  bindReadButtons();
  bindAckButtons();
  bindIntelButtons();
  bindGitHubEvidenceButtons();
  bindAnalysisButtons();
  bindFollowButtons();
  watchAnalysisRefresh(data.data.map((alert) => alert.vulnerability || {}));
}

async function loadVulns() {
  const limit = state.vulnExpanded ? LIST_LIMIT : OVERVIEW_LIMIT;
  const offset = state.vulnExpanded ? state.vulnOffset : 0;
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  if (state.severity) params.set("severity", state.severity);
  if (state.q) params.set("q", state.q);
  const data = await api(`/api/vulnerabilities?${params}`);
  if (!data) return;
  const items = data.data || [];
  const filters = [state.severity ? state.severity : "", state.q ? "搜索结果" : ""].filter(Boolean).join(" · ");
  $("#vulnCount").textContent = state.vulnExpanded
    ? `${filters || "全部漏洞"}：${rangeLabel(offset, items.length, data.total)}`
    : `${filters ? `${filters}：` : ""}最新 ${Math.min(items.length, OVERVIEW_LIMIT)} / ${data.total} 条漏洞`;
  $("#vulns").innerHTML = items.length
    ? items.map(vulnMarkup).join("")
    : `<div class="empty">暂无数据</div>`;
  $("#vulnToggleList").textContent = state.vulnExpanded ? "收起" : "展开清单";
  $("#vulnPager").hidden = !state.vulnExpanded || (offset <= 0 && data.total <= LIST_LIMIT);
  $("#vulnPrev").disabled = offset <= 0;
  $("#vulnNext").disabled = offset + LIST_LIMIT >= data.total;
  bindIntelButtons();
  bindGitHubEvidenceButtons();
  bindAnalysisButtons();
  bindFollowButtons();
  watchAnalysisRefresh(items);
}

async function refresh() {
  await Promise.all([loadMessages(), loadActiveView()]);
}

$("#analysisQuery").addEventListener("input", (event) => {
  state.analysisQ = event.target.value.trim();
  clearTimeout(window.__analysisQueryTimer);
  window.__analysisQueryTimer = setTimeout(loadAnalysis, 250);
});

$("#analysisRefresh").addEventListener("click", loadAnalysis);

$("#productQuery").addEventListener("input", (event) => {
  state.productQ = event.target.value.trim();
  state.productOffset = 0;
  if (state.productQ) state.productExpanded = true;
  clearTimeout(window.__productQueryTimer);
  window.__productQueryTimer = setTimeout(loadProducts, 250);
});

$("#productToggleList").addEventListener("click", () => {
  state.productExpanded = !state.productExpanded;
  state.productOffset = 0;
  loadProducts();
});

$("#productAlign").addEventListener("click", async () => {
  const button = $("#productAlign");
  button.disabled = true;
  button.textContent = "对齐中";
  try {
    await api("/api/products/align-vulnerabilities", {
      method: "POST",
      body: JSON.stringify({ only_unlinked: true, deepseek_flash: true, ai_limit: 5 }),
    });
    await refresh();
  } finally {
    button.disabled = false;
    button.textContent = "对齐漏洞";
  }
});

$("#productNormalize").addEventListener("click", async () => {
  const button = $("#productNormalize");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "规范中";
  try {
    const result = await api("/api/products/normalize", {
      method: "POST",
      body: JSON.stringify({ auto_merge: true, merge_limit: 200 }),
    });
    const normalized = result?.normalized_products ?? 0;
    const mergedCount = result?.merged_products ?? 0;
    $("#productCount").textContent = `已规范 ${normalized} 个产品，合并 ${mergedCount} 个重复项`;
    await Promise.all([loadProducts(), loadFollowedProducts(), loadSummary()]);
  } catch (error) {
    showModal("产品规范化失败", error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

$("#productPrev").addEventListener("click", () => {
  state.productOffset = Math.max(0, state.productOffset - LIST_LIMIT);
  loadProducts();
});

$("#productNext").addEventListener("click", () => {
  state.productOffset += LIST_LIMIT;
  loadProducts();
});

$("#sourceArchiveQuery").addEventListener("input", (event) => {
  state.sourceArchiveQ = event.target.value.trim();
  clearTimeout(window.__sourceArchiveQueryTimer);
  window.__sourceArchiveQueryTimer = setTimeout(loadSourceArchives, 250);
});

$("#sourceArchiveRefresh").addEventListener("click", loadSourceArchives);

$("#sourceArchiveVersionRole").addEventListener("change", (event) => {
  state.sourceArchiveVersionRole = event.target.value;
  loadSourceArchives();
});

$("#sourceArchiveFile").addEventListener("change", updateSourceArchiveFileName);

$("#sourceArchiveFetchLatest").addEventListener("click", async () => {
  const button = $("#sourceArchiveFetchLatest");
  const productName = $("#sourceArchiveProduct").value.trim() || state.sourceArchiveQ;
  if (!productName) {
    showModal("拉取失败", "请先在产品提示或搜索框里填写产品名。");
    return;
  }
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "拉取中";
  try {
    await fetchLatestSourceArchive({ productName });
    await Promise.all([loadSourceArchives(), loadMessages(), loadSummary()]);
    setTimeout(loadSourceArchives, 5000);
  } catch (error) {
    showModal("拉取失败", error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

$("#sourceArchiveUploadForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#sourceArchiveFile").files?.[0];
  if (!file) {
    showModal("上传失败", "请选择 zip、tar 或源码文件。");
    return;
  }
  const button = $("#sourceArchiveUpload");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "上传中";
  try {
    await uploadSourceArchive(file, $("#sourceArchiveProduct").value.trim(), $("#sourceArchiveVersion").value.trim());
    $("#sourceArchiveFile").value = "";
    $("#sourceArchiveVersion").value = "";
    updateSourceArchiveFileName();
    await Promise.all([loadSourceArchives(), loadMessages()]);
    setTimeout(loadSourceArchives, 5000);
  } catch (error) {
    showModal("上传失败", error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

$("#updateRefresh").addEventListener("click", loadUpdates);

$("#updateFile").addEventListener("change", updateUpdateFileName);

$("#updateUploadForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#updateFile").files?.[0];
  if (!file) {
    showModal("上传失败", "请选择 .update 文件。");
    return;
  }
  if (!file.name.toLowerCase().endsWith(".update")) {
    showModal("上传失败", "只允许上传 .update 文件。");
    return;
  }
  const button = $("#updateUpload");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "上传中";
  try {
    await uploadUpdate(file);
    $("#updateFile").value = "";
    updateUpdateFileName();
    await Promise.all([loadUpdates(), loadMessages()]);
    setTimeout(loadUpdates, 5000);
  } catch (error) {
    showModal("上传失败", error.message);
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

$("#graphSearchForm").addEventListener("submit", (event) => {
  event.preventDefault();
  searchGraph();
});

$("#graphSearch").addEventListener("click", (event) => {
  event.preventDefault();
  searchGraph();
});

$("#graphQuery").addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  searchGraph();
});

$("#graphZoomOut").addEventListener("click", () => zoomGraphBy(0.82));

$("#graphZoomIn").addEventListener("click", () => zoomGraphBy(1.22));

$("#graphZoomFit").addEventListener("click", fitGraphViewport);

$("#graphZoomReset").addEventListener("click", resetGraphZoom);

$("#graphDepth").addEventListener("change", () => {
  if (state.graphQuery) searchGraph();
});

$("#graphKind").addEventListener("change", () => {
  state.graphKind = $("#graphKind").value || "auto";
});

$("#graphSync").addEventListener("click", async () => {
  if (!state.graphAvailable) {
    showModal("图谱不可用", "Neo4j 当前不可用。请先启动 Neo4j 后再同步。");
    return;
  }
  const button = $("#graphSync");
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "同步中";
  $("#graphSyncMessage").textContent = "";
  try {
    const result = await api("/api/graph/sync", {
      method: "POST",
      body: JSON.stringify({ limit: 800 }),
    });
    const synced = result?.synced || {};
    $("#graphSyncMessage").textContent = `已同步：产品 ${synced.products || 0}，漏洞 ${synced.vulnerabilities || 0}，关系 ${synced.product_vulnerabilities || 0}`;
    await loadGraphStatus();
    if (state.graphQuery) {
      await searchGraph();
      $("#graphSyncMessage").textContent = `已同步并刷新当前图谱：产品 ${synced.products || 0}，漏洞 ${synced.vulnerabilities || 0}，关系 ${synced.product_vulnerabilities || 0}`;
    }
  } catch (error) {
    showModal("图谱同步失败", error.message);
    $("#graphSyncMessage").textContent = error.message;
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
});

$("#query").addEventListener("input", (event) => {
  state.q = event.target.value.trim();
  state.vulnOffset = 0;
  if (state.q) state.vulnExpanded = true;
  clearTimeout(window.__queryTimer);
  window.__queryTimer = setTimeout(loadVulns, 250);
});

$("#severity").addEventListener("change", (event) => {
  state.severity = event.target.value;
  state.vulnOffset = 0;
  if (state.severity) state.vulnExpanded = true;
  loadVulns();
});

$("#alertQuery").addEventListener("input", (event) => {
  state.alertQ = event.target.value.trim();
  state.alertOffset = 0;
  if (state.alertQ) state.alertExpanded = true;
  clearTimeout(window.__alertQueryTimer);
  window.__alertQueryTimer = setTimeout(loadAlerts, 250);
});

$("#alertStatus").addEventListener("change", (event) => {
  state.alertStatus = event.target.value;
  state.alertOffset = 0;
  if (state.alertStatus !== "new") state.alertExpanded = true;
  loadAlerts();
});

$("#alertSource").addEventListener("change", (event) => {
  state.alertSource = event.target.value;
  state.alertOffset = 0;
  if (state.alertSource) state.alertExpanded = true;
  loadAlerts();
});

$("#alertToggleList").addEventListener("click", () => {
  state.alertExpanded = !state.alertExpanded;
  state.alertOffset = 0;
  loadAlerts();
});

$("#alertPrev").addEventListener("click", () => {
  state.alertOffset = Math.max(0, state.alertOffset - ALERT_PAGE_LIMIT);
  loadAlerts();
});

$("#alertNext").addEventListener("click", () => {
  state.alertOffset += ALERT_PAGE_LIMIT;
  loadAlerts();
});

function jumpAlertPage() {
  const input = $("#alertPageJump");
  const totalPages = Math.max(1, Number(input.max) || 1);
  const page = Math.max(1, Math.min(totalPages, Number(input.value) || 1));
  state.alertExpanded = true;
  state.alertOffset = (page - 1) * ALERT_PAGE_LIMIT;
  loadAlerts();
}

$("#alertPageGo").addEventListener("click", jumpAlertPage);

$("#alertPageJump").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    jumpAlertPage();
  }
});

$("#vulnToggleList").addEventListener("click", () => {
  state.vulnExpanded = !state.vulnExpanded;
  state.vulnOffset = 0;
  loadVulns();
});

$("#vulnPrev").addEventListener("click", () => {
  state.vulnOffset = Math.max(0, state.vulnOffset - LIST_LIMIT);
  loadVulns();
});

$("#vulnNext").addEventListener("click", () => {
  state.vulnOffset += LIST_LIMIT;
  loadVulns();
});

document.querySelectorAll("[data-close-intel]").forEach((node) => {
  node.addEventListener("click", closeIntelModal);
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("#intelModal").hidden) {
    closeIntelModal();
    return;
  }
  if (event.key === "Escape") {
    document.querySelectorAll(".panel.panel-zoomed").forEach((panel) => {
      panel.classList.remove("panel-zoomed");
      const button = panel.querySelector("[data-panel-zoom]");
      if (button) button.textContent = "放大";
    });
    document.body.classList.remove("panel-is-zoomed");
  }
});

$("#runRegular").addEventListener("click", async () => {
  await api("/api/jobs/regular/run", { method: "POST" });
  await refresh();
});

$("#runSlow").addEventListener("click", async () => {
  await api("/api/jobs/slow/run", { method: "POST" });
  await refresh();
});

$("#messageToggle").addEventListener("click", async (event) => {
  event.stopPropagation();
  state.messagePanelOpen = !state.messagePanelOpen;
  $("#messagePanel").hidden = !state.messagePanelOpen;
  if (state.messagePanelOpen) {
    await loadMessages();
  }
});

$("#messagePanel").addEventListener("click", (event) => {
  event.stopPropagation();
});

$("#markAllMessagesRead").addEventListener("click", async () => {
  const button = $("#markAllMessagesRead");
  button.disabled = true;
  try {
    await api("/api/messages/read-all", { method: "POST" });
    await loadMessages();
  } catch (error) {
    showModal("消息操作失败", error.message);
  } finally {
    button.disabled = false;
  }
});

document.addEventListener("click", () => {
  if (!state.messagePanelOpen) return;
  state.messagePanelOpen = false;
  $("#messagePanel").hidden = true;
});

$("#rulesForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("#rulesMessage").textContent = "";
  await api("/api/monitor/rules", {
    method: "PUT",
    body: JSON.stringify({
      min_severity: $("#minSeverity").value,
      enable_cve_dedup: $("#enableCveDedup").checked,
      no_filter: $("#noFilter").checked,
      max_age_days: Number($("#maxAlertAgeDays").value) || 30,
      white_keywords: $("#whiteKeywords").value,
      black_keywords: $("#blackKeywords").value,
    }),
  });
  $("#rulesMessage").textContent = "已保存";
  state.alertOffset = 0;
  await Promise.all([loadRules(), loadAlerts(), loadSummary()]);
});

$("#deepseekForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const keyInput = $("#deepseekKey");
  const baseUrlInput = $("#modelBaseUrl");
  const flashInput = $("#flashModel");
  const proInput = $("#proModel");
  const message = $("#deepseekMessage");
  message.textContent = "";
  try {
    const current = state.modelSettings || {};
    const baseUrl = baseUrlInput.value.trim();
    const apiKey = keyInput.value.trim();
    const flashModel = flashInput.value.trim() || current.flash_model || current.product_attribution_model || "";
    const proModel = proInput.value.trim() || current.pro_model || current.poc_generation_model || "";
    if (apiKey || baseUrl) {
      await api("/api/deepseek/config", {
        method: "PUT",
        body: JSON.stringify({ api_key: apiKey, base_url: baseUrl }),
      });
    }
    state.modelSettings = await api("/api/model/settings", {
      method: "PUT",
      body: JSON.stringify({
        flash_model: flashModel,
        pro_model: proModel,
        product_attribution_model: flashModel,
        source_triage_model: flashModel,
        root_cause_model: proModel,
        poc_generation_model: proModel,
        fix_advice_model: proModel,
      }),
    });
    keyInput.value = "";
    message.textContent = "已保存";
    await Promise.all([loadDeepSeek(), loadSummary()]);
  } catch (error) {
    message.textContent = error.message;
  }
});

$("#refreshDeepSeek").addEventListener("click", async () => {
  const button = $("#refreshDeepSeek");
  const message = $("#deepseekMessage");
  button.disabled = true;
  message.textContent = "";
  try {
    const data = await api("/api/deepseek/balance/run", { method: "POST" });
    message.textContent = data?.balance_status === "success" ? "余额已更新" : data?.balance_status || "";
    await Promise.all([loadDeepSeek(), loadSummary()]);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#clearDeepSeek").addEventListener("click", async () => {
  const message = $("#deepseekMessage");
  message.textContent = "";
  try {
    await api("/api/deepseek/config", { method: "DELETE" });
    message.textContent = "密钥已清除，模型 URL 和模型名保留";
    await Promise.all([loadDeepSeek(), loadSummary()]);
  } catch (error) {
    message.textContent = error.message;
  }
});

$("#refreshAvdSession").addEventListener("click", async () => {
  const button = $("#refreshAvdSession");
  const message = $("#avdSessionMessage");
  button.disabled = true;
  message.textContent = "刷新中";
  try {
    await api("/api/source-sessions/avd/refresh", {
      method: "POST",
      body: JSON.stringify({ headless: false }),
    });
    message.textContent = "已刷新";
    await Promise.all([loadSourceSessions(), loadSources()]);
  } catch (error) {
    message.textContent = error.message;
    await loadSourceSessions();
  } finally {
    button.disabled = false;
  }
});

$("#clearAvdSession").addEventListener("click", async () => {
  const message = $("#avdSessionMessage");
  message.textContent = "";
  try {
    await api("/api/source-sessions/avd", { method: "DELETE" });
    message.textContent = "已清除";
    await loadSourceSessions();
  } catch (error) {
    message.textContent = error.message;
  }
});

$("#runAvdAfterSession").addEventListener("click", async () => {
  const button = $("#runAvdAfterSession");
  const message = $("#avdSessionMessage");
  button.disabled = true;
  message.textContent = "";
  try {
    const data = await api("/api/sources/avd_high_risk/run", { method: "POST" });
    message.textContent = data?.status === "success" ? `AVD 已入库 ${data.item_count} 条` : data?.error || "";
    await refresh();
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#refreshCnvdSession").addEventListener("click", async () => {
  const button = $("#refreshCnvdSession");
  const message = $("#cnvdSessionMessage");
  button.disabled = true;
  message.textContent = "刷新中";
  try {
    await api("/api/source-sessions/cnvd/refresh", {
      method: "POST",
      body: JSON.stringify({ headless: false }),
    });
    message.textContent = "已刷新";
    await Promise.all([loadSourceSessions(), loadSources()]);
  } catch (error) {
    message.textContent = error.message;
    await loadSourceSessions();
  } finally {
    button.disabled = false;
  }
});

$("#clearCnvdSession").addEventListener("click", async () => {
  const message = $("#cnvdSessionMessage");
  message.textContent = "";
  try {
    await api("/api/source-sessions/cnvd", { method: "DELETE" });
    message.textContent = "已清除";
    await loadSourceSessions();
  } catch (error) {
    message.textContent = error.message;
  }
});

$("#captureCnvdProxy").addEventListener("click", async () => {
  const button = $("#captureCnvdProxy");
  const message = $("#cnvdSessionMessage");
  button.disabled = true;
  message.textContent = "正在读取容器浏览器 Cookie";
  try {
    const data = await api("/api/browser-proxy/cnvd/capture", { method: "POST" });
    message.textContent = data?.session?.status === "success" ? "CNVD 会话已保存" : data?.session?.error || "已保存";
    await Promise.all([loadSourceSessions(), loadSources()]);
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#runCnvdAfterSession").addEventListener("click", async () => {
  const button = $("#runCnvdAfterSession");
  const message = $("#cnvdSessionMessage");
  button.disabled = true;
  message.textContent = "";
  try {
    const data = await api("/api/sources/cnvd_list/run", { method: "POST" });
    message.textContent = data?.status === "success" ? `CNVD 已入库 ${data.item_count} 条` : data?.error || "";
    await refresh();
  } catch (error) {
    message.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$("#cnvdCookieForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = $("#cnvdCookie");
  const message = $("#cnvdSessionMessage");
  message.textContent = "校验中";
  try {
    const data = await api("/api/source-sessions/cnvd", {
      method: "PUT",
      body: JSON.stringify({ cookie: input.value }),
    });
    input.value = "";
    message.textContent = data?.status === "success" ? "Cookie 已保存并通过校验" : data?.error || data?.status || "已保存";
    await loadSourceSessions();
  } catch (error) {
    message.textContent = error.message;
  }
});

$("#logout").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  location.href = "/login";
});

initPanelControls();
initDashboardJump();
setActiveView(viewFromHash(), { updateHash: true });
window.addEventListener("hashchange", async () => {
  setActiveView(viewFromHash());
  await refresh();
});
refresh();
setInterval(refresh, 60_000);
