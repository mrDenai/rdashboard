"use strict";

import {
  evaluateHostObservation,
  formatHistoryCoverage,
  formatSampleAge,
  notificationKindLabel,
  notificationStatePresentation,
  operationKindLabel,
  operationResultPresentation,
  projectConditionPresentation,
  repositorySizeChange,
  validWorkflowOverview,
  workflowAttemptPresentation,
  workflowCurrentStepLabel,
} from "./status.js";

const elements = Object.freeze({
  connection: document.querySelector("#connection-status"),
  sampleAge: document.querySelector("#sample-age"),
  sequence: document.querySelector("#event-sequence"),
  retry: document.querySelector("#retry-connection"),
  historyStatus: document.querySelector("#host-history-status"),
  historyCoverage: Object.freeze({
    hour: document.querySelector("#history-hour-coverage"),
    day: document.querySelector("#history-day-coverage"),
    week: document.querySelector("#history-week-coverage"),
    month: document.querySelector("#history-month-coverage"),
  }),
  historyCells: document.querySelectorAll("[data-history-window][data-history-metric]"),
  cpu: document.querySelector("#metric-cpu"),
  load: document.querySelector("#metric-load"),
  memory: document.querySelector("#metric-memory"),
  memoryDetail: document.querySelector("#metric-memory-detail"),
  disk: document.querySelector("#metric-disk"),
  diskDetail: document.querySelector("#metric-disk-detail"),
  network: document.querySelector("#metric-network"),
  networkDetail: document.querySelector("#metric-network-detail"),
  partialPanel: document.querySelector("#partial-panel"),
  partialReasons: document.querySelector("#partial-reasons"),
  projectCount: document.querySelector("#project-count"),
  projectList: document.querySelector("#project-list"),
  workflowSummary: document.querySelector("#workflow-summary"),
  workflowStatus: document.querySelector("#workflow-status"),
  workflowList: document.querySelector("#workflow-list"),
  workflowRefresh: document.querySelector("#workflow-refresh"),
  sqliteVersion: document.querySelector("#sqlite-version"),
  observationOperation: document.querySelector("#observation-operation"),
  sampleInterval: document.querySelector("#sample-interval"),
  streamDetail: document.querySelector("#stream-detail"),
  polite: document.querySelector("#polite-announcer"),
  assertive: document.querySelector("#assertive-announcer"),
});

const runtime = {
  source: null,
  reconnectTimer: null,
  reconnectDelayMs: 1_000,
  lastSequence: null,
  latestSnapshot: null,
  snapshotBaseAgeMs: null,
  snapshotReceivedAtMonotonicMs: null,
  acceptingResyncSnapshot: false,
  initializing: false,
  historyLoading: false,
  historyFailed: false,
  projectOperations: new Map(),
  projectOperationsLoading: new Set(),
  projectResources: new Map(),
  projectResourcesLoading: new Set(),
  projectRepositories: new Map(),
  projectRepositoriesLoading: new Set(),
  projectUpdates: new Map(),
  projectUpdatesLoading: new Set(),
  projectErrors: new Map(),
  projectErrorsLoading: new Set(),
  projectNotifications: new Map(),
  projectNotificationsLoading: new Set(),
  workflowOverview: null,
  workflowLoading: false,
  workflowFailed: false,
};

const HOST_HISTORY_REFRESH_MS = 60_000;
const PROJECT_OPERATIONS_REFRESH_MS = 30_000;
const PROJECT_RESOURCES_REFRESH_MS = 60_000;
const PROJECT_REPOSITORY_REFRESH_MS = 5 * 60_000;
const PROJECT_INTEGRATIONS_REFRESH_MS = 60_000;
const PROJECT_NOTIFICATIONS_REFRESH_MS = 30_000;
const WORKFLOW_OVERVIEW_REFRESH_MS = 5_000;
const PROJECT_INTEGRATIONS_STALE_MS = 15 * 60_000;
const HOST_HISTORY_WINDOWS = Object.freeze(["hour", "day", "week", "month"]);
const REPOSITORY_PERIODS = Object.freeze([
  ["1 ч", 60 * 60_000],
  ["1 день", 24 * 60 * 60_000],
  ["7 дней", 7 * 24 * 60 * 60_000],
  ["30 дней", 30 * 24 * 60 * 60_000],
]);

const byteFormatter = new Intl.NumberFormat("ru-RU", {
  maximumFractionDigits: 1,
});
const percentFormatter = new Intl.NumberFormat("ru-RU", {
  minimumFractionDigits: 1,
  maximumFractionDigits: 1,
});
function setConnection(state, visibleText, detail, announcement = null) {
  elements.connection.dataset.state = state;
  elements.connection.textContent = visibleText;
  elements.streamDetail.textContent = detail;
  elements.retry.hidden = !["retrying", "disconnected", "error"].includes(state);
  if (announcement) announce(announcement, state === "error" || state === "disconnected");
}

function announce(message, assertive = false) {
  const target = assertive ? elements.assertive : elements.polite;
  target.textContent = "";
  window.setTimeout(() => {
    target.textContent = message;
  }, 50);
}

async function loadHostHistory(announceFailure = false) {
  if (runtime.historyLoading) return;
  runtime.historyLoading = true;
  try {
    const response = await fetch("/api/v1/host-history", {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "История ресурсов недоступна.");
    }
    renderHostHistory(await response.json());
    runtime.historyFailed = false;
  } catch (error) {
    elements.historyStatus.hidden = false;
    elements.historyStatus.dataset.state = "error";
    elements.historyStatus.textContent = error.message;
    for (const cell of elements.historyCells) {
      cell.dataset.state = "unknown";
      cell.textContent = "Недоступно";
    }
    if (announceFailure || !runtime.historyFailed) {
      announce("Историю ресурсов получить не удалось.", true);
    }
    runtime.historyFailed = true;
  } finally {
    runtime.historyLoading = false;
  }
}

function renderHostHistory(history) {
  if (
    history?.schema_version !== 2
    || !Number.isFinite(history.complete_through_ms)
    || !Array.isArray(history.windows)
  ) {
    throw new Error("Сервер вернул неподдерживаемый контракт истории ресурсов.");
  }
  const windows = new Map(history.windows.map((window) => [window.window, window]));
  if (HOST_HISTORY_WINDOWS.some((name) => !validHistoryWindow(windows.get(name), name))) {
    throw new Error("Сервер вернул неполную историю ресурсов.");
  }
  for (const name of HOST_HISTORY_WINDOWS) {
    const window = windows.get(name);
    elements.historyCoverage[name].textContent = formatHistoryCoverage(window);
  }
  for (const cell of elements.historyCells) {
    renderHistoryCell(cell, windows.get(cell.dataset.historyWindow));
  }
  elements.historyStatus.hidden = true;
  elements.historyStatus.textContent = "";
}

function validHistoryWindow(window, expectedName) {
  return window?.window === expectedName
    && Number.isSafeInteger(window.sample_count)
    && window.sample_count >= 0
    && Number.isSafeInteger(window.covered_minutes)
    && window.covered_minutes >= 0
    && Number.isSafeInteger(window.expected_minutes)
    && window.expected_minutes > 0
    && window.covered_minutes <= window.expected_minutes
    && typeof window.complete === "boolean"
    && window.complete === (window.covered_minutes === window.expected_minutes)
    && typeof window.medians === "object"
    && window.medians !== null
    && validTrafficTotals(window.totals);
}

function validTrafficTotals(totals) {
  return totals !== null
    && typeof totals === "object"
    && [totals.network_rx_bytes, totals.network_tx_bytes].every(
      (value) => value === null || (Number.isSafeInteger(value) && value >= 0),
    )
    && Number.isSafeInteger(totals.network_rx_covered_ms)
    && totals.network_rx_covered_ms >= 0
    && Number.isSafeInteger(totals.network_tx_covered_ms)
    && totals.network_tx_covered_ms >= 0;
}

async function loadWorkflowOverview(announceResult = false) {
  if (runtime.workflowLoading) return;
  runtime.workflowLoading = true;
  elements.workflowRefresh.disabled = true;
  if (!runtime.workflowOverview) {
    elements.workflowStatus.hidden = false;
    elements.workflowStatus.dataset.state = "loading";
    elements.workflowStatus.textContent = "Загружается журнал workflow…";
  }
  try {
    const response = await fetch("/api/v1/workflows?limit=50", {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "Журнал workflow недоступен.");
    }
    const overview = await response.json();
    if (!validWorkflowOverview(overview)) {
      throw new Error("Сервер вернул неподдерживаемый контракт workflow.");
    }
    runtime.workflowOverview = overview;
    renderWorkflowOverview(overview);
    if (announceResult) announce("Журнал workflow обновлён.");
    runtime.workflowFailed = false;
  } catch (error) {
    elements.workflowStatus.hidden = false;
    elements.workflowStatus.dataset.state = "error";
    elements.workflowStatus.textContent = runtime.workflowOverview
      ? `${error.message} Показаны последние полученные данные.`
      : error.message;
    if (!runtime.workflowOverview) {
      renderWorkflowPlaceholder("Журнал workflow получить не удалось.");
      elements.workflowSummary.textContent = "Данные недоступны";
    }
    if (announceResult || !runtime.workflowFailed) {
      announce("Журнал workflow получить не удалось.", true);
    }
    runtime.workflowFailed = true;
  } finally {
    runtime.workflowLoading = false;
    elements.workflowRefresh.disabled = false;
  }
}

function renderWorkflowOverview(overview) {
  const count = overview.deployments.length;
  const projectCount = new Set(overview.deployments.map((deployment) => deployment.project_id)).size;
  const generated = new Date(overview.generated_at_ms).toLocaleString("ru-RU");
  elements.workflowSummary.textContent = `${projectCount} ${workflowProjectCountLabel(projectCount)} · ${generated}`;
  elements.workflowStatus.hidden = !overview.truncated;
  elements.workflowStatus.dataset.state = overview.truncated ? "partial" : "fresh";
  elements.workflowStatus.textContent = overview.truncated
    ? "Показаны только 50 актуальных записей. Полная история остаётся в durable journal."
    : "";
  elements.workflowList.replaceChildren();
  if (count === 0) {
    renderWorkflowPlaceholder("Попытки workflow ещё не зафиксированы.");
    return;
  }
  for (const deployment of overview.deployments) {
    elements.workflowList.append(createWorkflowRow(deployment));
  }
}

function createWorkflowRow(deployment) {
  const row = document.createElement("tr");
  row.className = "workflow-row";

  const project = document.createElement("th");
  project.scope = "row";
  project.textContent = deployment.project_id;
  appendProjectCellDetail(project, `SHA ${deployment.source_sha.slice(0, 10)}`);

  const state = workflowAttemptPresentation(deployment.state);
  const stateCell = workflowStateCell(state);
  if (deployment.attempt_number > 1) {
    appendProjectCellDetail(stateCell, `Попытка № ${deployment.attempt_number}`);
  }

  const stepCell = document.createElement("td");
  stepCell.textContent = workflowCurrentStepLabel(deployment);
  appendProjectCellDetail(
    stepCell,
    `${deployment.completed_stages} из ${deployment.total_stages} этапов завершено`,
  );

  const durationCell = document.createElement("td");
  durationCell.textContent = formatDuration(deployment.duration_ms);

  const testsCell = document.createElement("td");
  testsCell.textContent = deployment.test_duration_ms === null
    ? "—"
    : formatDuration(deployment.test_duration_ms);

  const releaseCell = document.createElement("td");
  releaseCell.textContent = deployment.release_size_bytes === null
    ? "—"
    : formatBytes(deployment.release_size_bytes);

  const updatedCell = document.createElement("td");
  updatedCell.textContent = new Date(deployment.updated_at_ms).toLocaleString("ru-RU");

  row.append(
    project,
    stateCell,
    stepCell,
    durationCell,
    testsCell,
    releaseCell,
    updatedCell,
  );
  return row;
}

function workflowStateCell(value) {
  const cell = document.createElement("td");
  cell.dataset.state = value.state;
  const label = document.createElement("strong");
  label.className = "state-label";
  label.textContent = value.label;
  cell.append(label);
  return cell;
}

function renderWorkflowPlaceholder(message) {
  elements.workflowList.replaceChildren();
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.className = "empty-state";
  cell.colSpan = 7;
  cell.textContent = message;
  row.append(cell);
  elements.workflowList.append(row);
}

function workflowProjectCountLabel(count) {
  const modulo100 = count % 100;
  const modulo10 = count % 10;
  if (modulo100 >= 11 && modulo100 <= 14) return "проектов";
  if (modulo10 === 1) return "проект";
  if (modulo10 >= 2 && modulo10 <= 4) return "проекта";
  return "проектов";
}

function formatDuration(value) {
  if (!Number.isSafeInteger(value) || value < 0) return "—";
  const totalSeconds = Math.round(value / 1_000);
  if (totalSeconds < 60) return `${totalSeconds} с`;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (totalMinutes < 60) return seconds === 0
    ? `${totalMinutes} мин`
    : `${totalMinutes} мин ${seconds} с`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes === 0 ? `${hours} ч` : `${hours} ч ${minutes} мин`;
}

function renderHistoryCell(cell, window) {
  cell.replaceChildren();
  cell.dataset.state = window.complete ? "fresh" : "partial";
  if (window.sample_count === 0) {
    cell.dataset.state = "unknown";
    cell.textContent = "Нет данных";
    return;
  }
  const metric = cell.dataset.historyMetric;
  const primary = document.createElement("strong");
  const secondary = document.createElement("small");
  if (metric === "cpu_percent") {
    primary.textContent = formatPercent(window.medians.cpu_percent);
    secondary.textContent = Number.isFinite(window.medians.load_1)
      ? `Load 1: ${window.medians.load_1.toFixed(2)}`
      : "Load 1: —";
  } else if (metric === "memory_used_percent" || metric === "disk_used_percent") {
    primary.textContent = formatPercent(window.medians[metric]);
  } else if (metric === "network") {
    primary.textContent = `↓ ${formatBytes(window.totals.network_rx_bytes)}`;
    secondary.textContent = `↑ ${formatBytes(window.totals.network_tx_bytes)}`;
  }
  cell.append(primary);
  if (secondary.textContent) cell.append(secondary);
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) return "Нет данных";
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${byteFormatter.format(scaled)} ${units[unit]}`;
}

function formatPercent(value) {
  return Number.isFinite(value) ? `${percentFormatter.format(value)} %` : "—";
}

function usedPercent(total, available) {
  if (!Number.isFinite(total) || !Number.isFinite(available) || total <= 0 || available > total) {
    return null;
  }
  return ((total - available) / total) * 100;
}

function renderSnapshot(snapshot, serverReferenceMs) {
  runtime.latestSnapshot = snapshot;
  const baseAgeMs = serverReferenceMs - snapshot.generated_at_ms;
  runtime.snapshotBaseAgeMs = Number.isFinite(baseAgeMs) && baseAgeMs >= 0
    ? baseAgeMs
    : null;
  runtime.snapshotReceivedAtMonotonicMs = performance.now();
  const host = snapshot.host;

  elements.cpu.textContent = formatPercent(host.cpu_percent);
  const loads = [host.load_1, host.load_5, host.load_15]
    .map((value) => (Number.isFinite(value) ? value.toFixed(2) : "—"))
    .join(" / ");
  elements.load.textContent = `Load ${loads}`;

  const memoryPercent = usedPercent(host.memory_total_bytes, host.memory_available_bytes);
  elements.memory.textContent = formatPercent(memoryPercent);
  elements.memoryDetail.textContent = memoryPercent !== null
    ? `${formatBytes(host.memory_total_bytes - host.memory_available_bytes)} из ${formatBytes(host.memory_total_bytes)}`
    : "Нет данных";

  const diskPercent = usedPercent(host.disk_total_bytes, host.disk_available_bytes);
  elements.disk.textContent = formatPercent(diskPercent);
  elements.diskDetail.textContent = diskPercent !== null
    ? `${formatBytes(host.disk_available_bytes)} свободно из ${formatBytes(host.disk_total_bytes)}`
    : "Нет данных";

  elements.network.textContent = `↓ ${formatBytes(host.network_rx_bytes)}`;
  elements.networkDetail.textContent = `↑ ${formatBytes(host.network_tx_bytes)}`;

  renderPartialReasons(host.partial_reasons);
  renderProjects(snapshot.projects);
  elements.sqliteVersion.textContent = snapshot.control.sqlite_version;
  elements.observationOperation.textContent = snapshot.control.observation_operation_id;
  elements.sampleInterval.textContent = `${snapshot.control.sample_interval_seconds} с`;
  updateSampleAge();
}

function renderPartialReasons(reasons) {
  const visible = Array.isArray(reasons) && reasons.length > 0;
  elements.partialPanel.hidden = !visible;
  elements.partialReasons.replaceChildren();
  if (!visible) return;
  for (const reason of reasons) {
    const item = document.createElement("li");
    item.textContent = String(reason);
    elements.partialReasons.append(item);
  }
}

function renderProjects(projects) {
  elements.projectList.replaceChildren();
  const connectedProjects = Array.isArray(projects) ? projects : [];
  const count = connectedProjects.length;
  elements.projectCount.textContent = formatProjectCount(count);
  if (count === 0) {
    const row = document.createElement("tr");
    const empty = document.createElement("td");
    empty.className = "empty-state";
    empty.colSpan = 9;
    empty.textContent = "Проекты ещё не подключены.";
    row.append(empty);
    elements.projectList.append(row);
    return;
  }
  for (const project of connectedProjects) {
    elements.projectList.append(createProjectRow(project, true));
  }
}

function formatProjectCount(count) {
  const ending = count % 10 === 1 && count % 100 !== 11
    ? "проект"
    : count % 10 >= 2 && count % 10 <= 4 && !(count % 100 >= 12 && count % 100 <= 14)
      ? "проекта"
      : "проектов";
  return `${count} ${ending}`;
}

function createProjectRow(project, loadIntegrations) {
  const projectId = String(project.project_id);
  const row = document.createElement("tr");
  row.className = "project-row";
  row.dataset.projectId = projectId;

  const identity = document.createElement("th");
  identity.scope = "row";
  const name = document.createElement("strong");
  name.textContent = String(project.display_name);
  identity.append(name);
  if (String(project.display_name) !== projectId) {
    const identifier = document.createElement("code");
    identifier.textContent = projectId;
    identity.append(identifier);
  }

  const condition = String(project.condition);
  const presentation = projectConditionPresentation(condition, "fresh");
  const conditionCell = document.createElement("td");
  const conditionLabel = document.createElement("p");
  conditionLabel.className = "project-condition";
  conditionLabel.dataset.condition = condition;
  conditionLabel.dataset.state = presentation.state;
  conditionLabel.textContent = presentation.label;
  conditionCell.append(conditionLabel);

  const operations = runtime.projectOperations.get(projectId);
  const resources = runtime.projectResources.get(projectId);
  const repository = runtime.projectRepositories.get(projectId);
  const updates = runtime.projectUpdates.get(projectId);
  const errors = runtime.projectErrors.get(projectId);
  const notifications = runtime.projectNotifications.get(projectId);
  row.append(
    identity,
    conditionCell,
    createProjectResourceCell(project.resources, resources),
    createOperationCell(
      operations,
      (operation) => ["deploy", "code_rollback"].includes(operation.operation_kind),
    ),
    createOperationCell(
      operations,
      (operation) => operation.operation_kind === "backup_only",
    ),
    createRepositoryCell(repository),
    createUpdatesCell(updates),
    createErrorsCell(errors),
    createNotificationsCell(notifications),
  );

  if (loadIntegrations) {
    loadProjectOperations(projectId, false);
    loadProjectResources(projectId, false);
    loadProjectRepository(projectId, false);
    loadProjectUpdates(projectId, false);
    loadProjectErrors(projectId, false);
    loadProjectNotifications(projectId, false);
  }
  return row;
}

function createProjectResourceCell(current, history) {
  if (!validCurrentProjectResources(current)) {
    return createSummaryCell("Недоступно", "error");
  }
  const hasCurrent = Number.isFinite(current.cpu_percent)
    && Number.isSafeInteger(current.memory_used_bytes)
    && Number.isSafeInteger(current.memory_limit_bytes);
  if (!hasCurrent) {
    const unconfigured = current.status === "unknown" || current.status === "unsupported";
    return createSummaryCell(unconfigured ? "Не настроено" : "Недоступно", current.status);
  }

  const cell = createSummaryCell(
    `CPU ${formatPercent(current.cpu_percent)}`,
    current.status,
    `RAM ${formatBytes(current.memory_used_bytes)} из ${formatBytes(current.memory_limit_bytes)}`,
  );
  if (!history) {
    appendResourceGroup(cell, "История", "Загружается…");
    return cell;
  }
  if (history.error && history.windows.length === 0) {
    appendResourceGroup(cell, "История", "Недоступна");
    return cell;
  }

  const windows = new Map(history.windows.map((window) => [window.window, window]));
  const labels = { hour: "1 ч", day: "1 д", week: "7 д", month: "30 д" };
  const medians = HOST_HISTORY_WINDOWS.map((name) => {
    const window = windows.get(name);
    const cpu = formatPercent(window?.medians?.cpu_percent);
    const memory = formatBytes(window?.medians?.memory_used_bytes);
    return `${labels[name]}: ${cpu} / ${memory}`;
  });
  appendResourceGroup(cell, "Медиана CPU / RAM", medians.join(" · "));

  const hour = windows.get("hour");
  if (hour?.totals) {
    appendResourceGroup(
      cell,
      "Трафик за 1 час",
      `↓ ${formatBytes(hour.totals.network_rx_bytes)} · ↑ ${formatBytes(hour.totals.network_tx_bytes)}`,
    );
  }
  if (history.error) appendResourceGroup(cell, "Актуальность", "Последние сохранённые данные");
  return cell;
}

function appendResourceGroup(cell, label, value) {
  const group = document.createElement("div");
  group.className = "project-resource-group";
  const term = document.createElement("span");
  term.className = "project-resource-label";
  term.textContent = label;
  const detail = document.createElement("span");
  detail.className = "project-resource-value";
  detail.textContent = value;
  group.append(term, detail);
  cell.append(group);
}

function appendProjectCellDetail(cell, text, extraClass = null) {
  const detail = document.createElement("small");
  detail.className = "project-cell-detail";
  if (extraClass) detail.classList.add(extraClass);
  detail.textContent = text;
  cell.append(detail);
}

function validCurrentProjectResources(resources) {
  if (!resources || typeof resources !== "object") return false;
  const statuses = ["fresh", "stale", "signal_lost", "partial", "unsupported", "unknown"];
  const optionalByteValues = [
    resources.memory_used_bytes,
    resources.memory_limit_bytes,
    resources.network_rx_bytes,
    resources.network_tx_bytes,
    resources.block_read_bytes,
    resources.block_write_bytes,
  ];
  const memoryIsCoherent = resources.memory_used_bytes === null
    || resources.memory_limit_bytes === null
    || (resources.memory_limit_bytes > 0
      && resources.memory_used_bytes <= resources.memory_limit_bytes);
  return statuses.includes(resources.status)
    && typeof resources.detail === "string"
    && (resources.observed_at_ms === null
      || (Number.isSafeInteger(resources.observed_at_ms) && resources.observed_at_ms >= 0))
    && (resources.cpu_percent === null
      || (Number.isFinite(resources.cpu_percent) && resources.cpu_percent >= 0))
    && optionalByteValues.every((value) => value === null
      || (Number.isSafeInteger(value) && value >= 0))
    && memoryIsCoherent;
}

function refreshProjectOverview(projectId) {
  const project = runtime.latestSnapshot?.projects?.find(
    (candidate) => String(candidate.project_id) === projectId,
  );
  if (!project) return;
  const current = Array.from(elements.projectList.querySelectorAll(".project-row"))
    .find((row) => row.dataset.projectId === projectId);
  if (!current) return;
  current.replaceWith(createProjectRow(project, false));
  updateSampleAge();
}

function createRepositoryCell(cached) {
  if (!cached) {
    return createSummaryCell("Загрузка…", "loading");
  }
  if (cached.error && cached.samples.length === 0) {
    return createSummaryCell("Недоступно", "unknown");
  }
  if (cached.samples.length === 0) {
    return createSummaryCell("Нет данных", "unknown");
  }

  const latest = cached.samples.at(-1);
  const cell = createSummaryCell(
    formatBytes(latest.total_bytes),
    cached.error ? "partial" : "fresh",
    `${latest.file_count.toLocaleString("ru-RU")} файлов · ${latest.head.slice(0, 8)}`,
  );
  const changes = document.createElement("small");
  changes.className = "project-cell-detail repository-changes";
  const values = [];
  for (const [label, periodMs] of REPOSITORY_PERIODS) {
    const change = repositorySizeChange(cached.samples, periodMs);
    values.push(`${label}: ${formatByteChange(change)}`);
  }
  changes.textContent = values.join(" · ");
  cell.append(changes);
  if (cached.error) {
    const stale = document.createElement("small");
    stale.className = "project-cell-detail";
    stale.textContent = "Последние сохранённые данные";
    cell.append(stale);
  }
  return cell;
}

function formatByteChange(value) {
  if (!Number.isSafeInteger(value)) return "—";
  if (value === 0) return "0 Б";
  return `${value > 0 ? "+" : "−"}${formatBytes(Math.abs(value))}`;
}

function createUpdatesCell(cached) {
  if (!cached) return createSummaryCell("Загрузка…", "loading");
  if (!cached.record) {
    return createSummaryCell("Недоступно", "error", cached.fetchError || "Нет данных");
  }
  const { record } = cached;
  if (record.data === null) {
    const unconfigured = record.collection_error?.code === "github_not_configured";
    return createSummaryCell(
      unconfigured ? "Не настроено" : "Недоступно",
      unconfigured ? "unknown" : "error",
      record.collection_error?.detail || "Данные ещё не собраны",
    );
  }
  const updates = record.data.updates;
  const counts = { passing: 0, pending: 0, failing: 0, unknown: 0 };
  for (const update of updates) counts[update.check_state] += 1;
  let state = "fresh";
  if (counts.failing > 0) state = "error";
  else if (counts.pending > 0) state = "partial";
  else if (counts.unknown > 0) state = "unknown";
  if (record.collection_error || integrationRecordIsStale(record)) state = "stale";
  const suffix = record.data.truncated ? "+" : "";
  const cell = createSummaryCell(`${updates.length}${suffix} обновлений`, state);
  const checkParts = [];
  if (counts.passing) checkParts.push(`✓ ${counts.passing}`);
  if (counts.pending) checkParts.push(`… ${counts.pending}`);
  if (counts.failing) checkParts.push(`× ${counts.failing}`);
  if (counts.unknown) checkParts.push(`? ${counts.unknown}`);
  appendProjectCellDetail(cell, checkParts.length > 0 ? checkParts.join(" · ") : "Открытых нет");
  if (updates.length > 0) {
    appendProjectCellLink(cell, `#${updates[0].number} ${updates[0].title}`, updates[0].deep_link);
  }
  appendIntegrationFreshness(cell, record);
  if (record.collection_error) appendProjectCellDetail(cell, record.collection_error.detail);
  if (cached.fetchError) appendProjectCellDetail(cell, "API дашборда временно недоступен");
  return cell;
}

function createErrorsCell(cached) {
  if (!cached) return createSummaryCell("Загрузка…", "loading");
  if (!cached.record) {
    return createSummaryCell("Недоступно", "error", cached.fetchError || "Нет данных");
  }
  const { record } = cached;
  if (record.data === null) {
    const unconfigured = record.collection_error?.code === "glitchtip_not_configured";
    return createSummaryCell(
      unconfigured ? "Не настроено" : "Недоступно",
      unconfigured ? "unknown" : "error",
      record.collection_error?.detail || "Данные ещё не собраны",
    );
  }
  const data = record.data;
  if (data.unresolved_groups === 0) {
    const state = record.collection_error || integrationRecordIsStale(record) ? "stale" : "fresh";
    const cell = createSummaryCell("Нет открытых", state, "Проверено без вызова модели");
    appendIntegrationFreshness(cell, record);
    if (record.collection_error) appendProjectCellDetail(cell, record.collection_error.detail);
    return cell;
  }
  let state = {
    none: "fresh",
    low: "fresh",
    medium: "partial",
    high: "error",
    critical: "error",
  }[data.insight.priority] || "unknown";
  if (record.collection_error || integrationRecordIsStale(record)) state = "stale";
  if (data.analysis_error && state === "fresh") state = "partial";
  const suffix = data.truncated ? "+" : "";
  const cell = createSummaryCell(
    `${data.unresolved_groups}${suffix} групп · ${data.total_events} событий`,
    state,
    data.insight.summary,
  );
  const model = data.insight.source === "deepseek_v4_flash_free"
    ? "DeepSeek Free"
    : "Локальная сводка";
  appendProjectCellDetail(cell, `${model} · приоритет ${data.insight.priority}`);
  if (data.groups.length > 0) {
    appendProjectCellLink(cell, data.groups[0].safe_label, data.groups[0].deep_link);
  }
  appendIntegrationFreshness(cell, record);
  if (data.analysis_error) appendProjectCellDetail(cell, data.analysis_error.detail);
  if (record.collection_error) appendProjectCellDetail(cell, record.collection_error.detail);
  if (cached.fetchError) appendProjectCellDetail(cell, "API дашборда временно недоступен");
  return cell;
}

function createNotificationsCell(cached) {
  if (!cached) return createSummaryCell("Загрузка…", "loading");
  if (!cached.payload) {
    return createSummaryCell("Недоступно", "error", cached.fetchError || "Нет данных");
  }
  if (!cached.payload.configured) {
    return createSummaryCell("Не настроено", "unknown", "Доставка отключена");
  }
  if (cached.payload.records.length === 0) {
    return createSummaryCell("Нет событий", "fresh", "Очередь пуста");
  }
  const latest = cached.payload.records[0];
  const presentation = notificationStatePresentation(latest.state);
  const cell = createSummaryCell(
    presentation.label,
    presentation.state,
    notificationKindLabel(latest.event.kind),
  );
  appendProjectTimestamp(cell, latest.updated_at_ms);
  if (latest.state === "delivered_possible_duplicate") {
    appendProjectCellDetail(cell, "Повтор сохранил исходную неопределённость");
  } else if (latest.last_error_code !== null) {
    appendProjectCellDetail(cell, latest.last_error_code);
  }
  if (cached.fetchError) appendProjectCellDetail(cell, "Показан последний сохранённый статус");
  return cell;
}

function appendProjectTimestamp(cell, timestampMs) {
  const date = new Date(timestampMs);
  if (!Number.isFinite(date.getTime())) {
    appendProjectCellDetail(cell, "Время события недоступно");
    return;
  }
  const timestamp = document.createElement("time");
  timestamp.className = "notification-timestamp";
  timestamp.dateTime = date.toISOString();
  timestamp.title = date.toLocaleString("ru-RU");
  timestamp.textContent = date.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
  cell.append(timestamp);
}

function appendProjectCellLink(cell, text, href) {
  const link = document.createElement("a");
  link.className = "project-cell-detail project-cell-link";
  link.href = href;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  link.referrerPolicy = "no-referrer";
  link.textContent = text;
  cell.append(link);
}

function appendIntegrationFreshness(cell, record) {
  if (!Number.isSafeInteger(record.successful_at_ms)) return;
  const label = record.collection_error || integrationRecordIsStale(record)
    ? "Последние данные"
    : "Обновлено";
  appendProjectCellDetail(cell, `${label}: ${new Date(record.successful_at_ms).toLocaleString("ru-RU")}`);
}

function integrationRecordIsStale(record) {
  const serverReferenceMs = currentServerReferenceMs();
  return Number.isSafeInteger(record.successful_at_ms)
    && Number.isFinite(serverReferenceMs)
    && serverReferenceMs - record.successful_at_ms > PROJECT_INTEGRATIONS_STALE_MS;
}

function createOperationCell(cached, predicate) {
  if (!cached) {
    return createSummaryCell("Загрузка…", "loading");
  }
  if (cached.error) {
    return createSummaryCell("Недоступно", "error");
  }
  const matching = cached.operations.filter(predicate);
  if (matching.length === 0) {
    return createSummaryCell("Нет", "unknown");
  }
  const latest = matching.reduce((selected, operation) => (
    Number(operation.updated_at_ms) > Number(selected.updated_at_ms) ? operation : selected
  ));
  const result = operationResultPresentation(latest.result);
  const kind = latest.operation_kind === "code_rollback"
    ? `${operationKindLabel(latest.operation_kind)} · `
    : "";
  const updated = Number.isFinite(latest.updated_at_ms)
    ? new Date(latest.updated_at_ms).toLocaleString("ru-RU")
    : "Время неизвестно";
  return createSummaryCell(`${kind}${result.label}`, result.state, updated);
}

function createSummaryCell(primaryText, state, detailText = null) {
  const cell = document.createElement("td");
  cell.className = "project-summary-cell";
  cell.dataset.state = state;
  const primary = document.createElement("strong");
  primary.textContent = primaryText;
  cell.append(primary);
  if (detailText) {
    const detail = document.createElement("small");
    detail.className = "project-cell-detail";
    detail.textContent = detailText;
    cell.append(detail);
  }
  return cell;
}

async function loadProjectOperations(projectId, refresh) {
  if (runtime.projectOperationsLoading.has(projectId)) return;
  if (!refresh && runtime.projectOperations.has(projectId)) return;
  runtime.projectOperationsLoading.add(projectId);
  try {
    const response = await fetch(
      `/api/v1/projects/${encodeURIComponent(projectId)}/operations?limit=10`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    );
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "История операций недоступна.");
    }
    const payload = await response.json();
    if (
      payload?.schema_version !== 1
      || payload.project_id !== projectId
      || !Array.isArray(payload.operations)
    ) {
      throw new Error("Сервер вернул неподдерживаемую историю операций.");
    }
    runtime.projectOperations.set(projectId, { operations: payload.operations });
  } catch (error) {
    runtime.projectOperations.set(projectId, { error: error.message, operations: [] });
  } finally {
    runtime.projectOperationsLoading.delete(projectId);
    refreshProjectOverview(projectId);
  }
}

async function loadProjectResources(projectId, refresh) {
  if (runtime.projectResourcesLoading.has(projectId)) return;
  if (!refresh && runtime.projectResources.has(projectId)) return;
  runtime.projectResourcesLoading.add(projectId);
  try {
    const response = await fetch(
      `/api/v1/projects/${encodeURIComponent(projectId)}/resource-history`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    );
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "История ресурсов проекта недоступна.");
    }
    const payload = await response.json();
    if (!validProjectResourceHistory(payload, projectId)) {
      throw new Error("Сервер вернул неподдерживаемую историю ресурсов проекта.");
    }
    runtime.projectResources.set(projectId, { windows: payload.windows });
  } catch (error) {
    const previous = runtime.projectResources.get(projectId);
    runtime.projectResources.set(projectId, {
      error: error.message,
      windows: previous?.windows ?? [],
    });
  } finally {
    runtime.projectResourcesLoading.delete(projectId);
    refreshProjectOverview(projectId);
  }
}

function validProjectResourceHistory(payload, projectId) {
  if (
    payload?.schema_version !== 1
    || payload.project_id !== projectId
    || !Number.isSafeInteger(payload.complete_through_ms)
    || !Array.isArray(payload.windows)
    || payload.windows.length !== HOST_HISTORY_WINDOWS.length
  ) return false;
  const windows = new Map(payload.windows.map((window) => [window?.window, window]));
  return HOST_HISTORY_WINDOWS.every((name) => validProjectResourceWindow(windows.get(name), name));
}

function validProjectResourceWindow(window, name) {
  if (
    window?.window !== name
    || !Number.isSafeInteger(window.sample_count)
    || window.sample_count < 0
    || !Number.isSafeInteger(window.covered_minutes)
    || window.covered_minutes < 0
    || !Number.isSafeInteger(window.expected_minutes)
    || window.expected_minutes <= 0
    || window.covered_minutes > window.expected_minutes
    || typeof window.complete !== "boolean"
    || window.complete !== (window.covered_minutes === window.expected_minutes)
  ) return false;
  const medians = [
    window.medians?.cpu_percent,
    window.medians?.memory_used_bytes,
    window.medians?.memory_used_percent,
  ];
  const totals = [
    window.totals?.network_rx_bytes,
    window.totals?.network_tx_bytes,
    window.totals?.block_read_bytes,
    window.totals?.block_write_bytes,
  ];
  const coverage = [
    window.totals?.network_rx_covered_ms,
    window.totals?.network_tx_covered_ms,
    window.totals?.block_read_covered_ms,
    window.totals?.block_write_covered_ms,
  ];
  return medians.every((value) => value === null || (Number.isFinite(value) && value >= 0))
    && totals.every((value) => value === null || (Number.isSafeInteger(value) && value >= 0))
    && coverage.every((value) => Number.isSafeInteger(value) && value >= 0);
}

async function loadProjectRepository(projectId, refresh) {
  if (runtime.projectRepositoriesLoading.has(projectId)) return;
  if (!refresh && runtime.projectRepositories.has(projectId)) return;
  runtime.projectRepositoriesLoading.add(projectId);
  try {
    const response = await fetch(
      `/api/v1/projects/${encodeURIComponent(projectId)}/repository-history`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    );
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "История репозитория недоступна.");
    }
    const payload = await response.json();
    if (!validRepositoryHistory(payload, projectId)) {
      throw new Error("Сервер вернул неподдерживаемую историю репозитория.");
    }
    runtime.projectRepositories.set(projectId, {
      error: payload.last_collection_error,
      samples: payload.samples,
    });
  } catch (error) {
    const previous = runtime.projectRepositories.get(projectId);
    runtime.projectRepositories.set(projectId, {
      error: error.message,
      samples: previous?.samples ?? [],
    });
  } finally {
    runtime.projectRepositoriesLoading.delete(projectId);
    refreshProjectOverview(projectId);
  }
}

function validRepositoryHistory(payload, projectId) {
  if (
    payload?.schema_version !== 1
    || payload.project_id !== projectId
    || payload.collection_interval_seconds !== 3_600
    || !(payload.last_collection_error === null || typeof payload.last_collection_error === "string")
    || !Array.isArray(payload.samples)
    || payload.samples.length > 24 * 31 + 1
  ) return false;
  let previousTime = -1;
  for (const sample of payload.samples) {
    if (
      !Number.isSafeInteger(sample?.observed_at_ms)
      || sample.observed_at_ms < 0
      || sample.observed_at_ms <= previousTime
      || typeof sample.head !== "string"
      || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sample.head)
      || !Number.isSafeInteger(sample.file_count)
      || sample.file_count < 0
      || !Number.isSafeInteger(sample.total_bytes)
      || sample.total_bytes < 0
    ) return false;
    previousTime = sample.observed_at_ms;
  }
  return true;
}

async function loadProjectUpdates(projectId, refresh) {
  await loadProjectIntegration(
    projectId,
    refresh,
    "updates",
    runtime.projectUpdates,
    runtime.projectUpdatesLoading,
    validProjectUpdatesRecord,
  );
}

async function loadProjectErrors(projectId, refresh) {
  await loadProjectIntegration(
    projectId,
    refresh,
    "errors",
    runtime.projectErrors,
    runtime.projectErrorsLoading,
    validProjectErrorsRecord,
  );
}

async function loadProjectNotifications(projectId, refresh) {
  if (runtime.projectNotificationsLoading.has(projectId)) return;
  if (!refresh && runtime.projectNotifications.has(projectId)) return;
  runtime.projectNotificationsLoading.add(projectId);
  try {
    const response = await fetch(
      `/api/v1/projects/${encodeURIComponent(projectId)}/notifications`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    );
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "Статус уведомлений недоступен.");
    }
    const payload = await response.json();
    if (!validProjectNotifications(payload, projectId)) {
      throw new Error("Сервер вернул неподдерживаемый контракт уведомлений.");
    }
    runtime.projectNotifications.set(projectId, { payload });
  } catch (error) {
    const previous = runtime.projectNotifications.get(projectId);
    runtime.projectNotifications.set(projectId, {
      payload: previous?.payload ?? null,
      fetchError: error.message,
    });
  } finally {
    runtime.projectNotificationsLoading.delete(projectId);
    refreshProjectOverview(projectId);
  }
}

async function loadProjectIntegration(projectId, refresh, route, cache, loading, validator) {
  if (loading.has(projectId)) return;
  if (!refresh && cache.has(projectId)) return;
  loading.add(projectId);
  try {
    const response = await fetch(
      `/api/v1/projects/${encodeURIComponent(projectId)}/${route}`,
      { headers: { Accept: "application/json" }, cache: "no-store" },
    );
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "Интеграция проекта недоступна.");
    }
    const record = await response.json();
    if (!validator(record, projectId)) {
      throw new Error("Сервер вернул неподдерживаемый контракт интеграции.");
    }
    cache.set(projectId, { record });
  } catch (error) {
    const previous = cache.get(projectId);
    cache.set(projectId, {
      record: previous?.record ?? null,
      fetchError: error.message,
    });
  } finally {
    loading.delete(projectId);
    refreshProjectOverview(projectId);
  }
}

function validProjectErrorsRecord(record, projectId) {
  if (!validIntegrationRecord(record, projectId, validProjectErrorsData)) return false;
  return record.data === null || record.data.project_id === projectId;
}

function validProjectUpdatesRecord(record, projectId) {
  if (!validIntegrationRecord(record, projectId, validProjectUpdatesData)) return false;
  return record.data === null || record.data.project_id === projectId;
}

function validProjectNotifications(payload, projectId) {
  if (!exactKeys(payload, [
    "schema_version",
    "generated_at_ms",
    "project_id",
    "configured",
    "records",
  ])) return false;
  if (
    payload.schema_version !== 1
    || !safeNonnegativeInteger(payload.generated_at_ms)
    || payload.project_id !== projectId
    || typeof payload.configured !== "boolean"
    || !Array.isArray(payload.records)
    || payload.records.length > 20
    || (!payload.configured && payload.records.length !== 0)
  ) return false;
  let previousUpdated = Number.MAX_SAFE_INTEGER;
  for (const record of payload.records) {
    if (!validNotificationRecord(record, projectId) || record.updated_at_ms > previousUpdated) {
      return false;
    }
    previousUpdated = record.updated_at_ms;
  }
  return true;
}

function validNotificationRecord(record, projectId) {
  if (!exactKeys(record, [
    "schema_version",
    "event",
    "state",
    "attempt_count",
    "route",
    "provider_message_id",
    "last_error_code",
    "retry_at_ms",
    "updated_at_ms",
  ])) return false;
  const states = [
    "pending",
    "sending",
    "delivery_unknown",
    "retry_scheduled",
    "delivered",
    "delivered_possible_duplicate",
    "permanently_failed",
  ];
  if (
    record.schema_version !== 1
    || !validNotificationEvent(record.event, projectId)
    || !states.includes(record.state)
    || !safeNonnegativeInteger(record.attempt_count)
    || !(record.route === null || record.route === "telegram_gateway")
    || !(record.provider_message_id === null || validUuid(record.provider_message_id))
    || !(record.last_error_code === null
      || (typeof record.last_error_code === "string"
        && /^[a-z0-9_]{1,64}$/.test(record.last_error_code)))
    || !safeNonnegativeInteger(record.retry_at_ms)
    || !safeNonnegativeInteger(record.updated_at_ms)
    || record.updated_at_ms < record.event.created_at_ms
  ) return false;
  const attempted = record.attempt_count > 0 && record.route === "telegram_gateway";
  if (record.state === "pending") {
    return record.attempt_count === 0
      && record.route === null
      && record.provider_message_id === null
      && record.last_error_code === null
      && record.retry_at_ms === record.updated_at_ms;
  }
  if (!attempted) return false;
  if (record.state === "sending") return record.last_error_code === null;
  if (["delivered", "delivered_possible_duplicate"].includes(record.state)) {
    return record.provider_message_id !== null
      && record.last_error_code === null
      && record.retry_at_ms === record.updated_at_ms;
  }
  if (["delivery_unknown", "retry_scheduled", "permanently_failed"].includes(record.state)) {
    return record.last_error_code !== null
      && (record.state !== "delivery_unknown" || record.provider_message_id === null)
      && (record.state === "permanently_failed"
        ? record.retry_at_ms === record.updated_at_ms
        : record.retry_at_ms > record.updated_at_ms);
  }
  return false;
}

function validNotificationEvent(event, projectId) {
  const kinds = [
    "error_priority_changed",
    "error_collection_failed",
    "error_collection_recovered",
    "dependency_update_changed",
    "dependency_checks_failed",
    "dependency_checks_recovered",
    "dependency_collection_failed",
    "dependency_collection_recovered",
    "operation_started",
    "operation_succeeded",
    "operation_failed",
    "backup_verified",
    "backup_failed",
    "deploy_succeeded",
    "deploy_rolled_back",
    "deploy_failed",
    "source_signal_lost",
    "source_recovered",
    "controller_failed",
  ];
  return exactKeys(event, [
    "schema_version",
    "project_id",
    "kind",
    "event_key",
    "occurrence_digest",
    "dedup_key",
    "text",
    "created_at_ms",
  ])
    && event.schema_version === 1
    && event.project_id === projectId
    && kinds.includes(event.kind)
    && typeof event.event_key === "string"
    && /^[a-z0-9._:-]{1,128}$/.test(event.event_key)
    && typeof event.occurrence_digest === "string"
    && /^[0-9a-f]{64}$/.test(event.occurrence_digest)
    && typeof event.dedup_key === "string"
    && /^[0-9a-f]{64}$/.test(event.dedup_key)
    && boundedNotificationText(event.text)
    && safeNonnegativeInteger(event.created_at_ms);
}

function boundedNotificationText(value) {
  return typeof value === "string"
    && value.length > 0
    && value === value.trim()
    && new TextEncoder().encode(value).length <= 3_500
    && !/[\u0000-\u0009\u000b-\u001f\u007f]/.test(value);
}

function validUuid(value) {
  return typeof value === "string"
    && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}

function validIntegrationRecord(record, projectId, validateData) {
  if (!exactKeys(record, [
    "schema_version",
    "project_id",
    "attempted_at_ms",
    "successful_at_ms",
    "collection_error",
    "data",
  ])) return false;
  if (
    record.schema_version !== 1
    || record.project_id !== projectId
    || !safeNonnegativeInteger(record.attempted_at_ms)
    || !(record.successful_at_ms === null || safeNonnegativeInteger(record.successful_at_ms))
    || (Number.isSafeInteger(record.successful_at_ms)
      && record.successful_at_ms > record.attempted_at_ms)
    || !(record.collection_error === null || validIntegrationFailure(record.collection_error))
    || !(record.data === null || validateData(record.data, projectId))
    || (record.successful_at_ms !== null) !== (record.data !== null)
    || (record.collection_error === null && record.successful_at_ms !== record.attempted_at_ms)
  ) return false;
  return true;
}

function validProjectErrorsData(data, projectId) {
  if (!exactKeys(data, [
    "schema_version",
    "project_id",
    "unresolved_groups",
    "truncated",
    "total_events",
    "affected_users",
    "highest_level",
    "groups",
    "insight",
    "analysis_error",
  ])) return false;
  if (
    data.schema_version !== 1
    || data.project_id !== projectId
    || !safeNonnegativeInteger(data.unresolved_groups)
    || typeof data.truncated !== "boolean"
    || !safeNonnegativeInteger(data.total_events)
    || !safeNonnegativeInteger(data.affected_users)
    || !["debug", "info", "warning", "error", "fatal", "unknown"].includes(data.highest_level)
    || !Array.isArray(data.groups)
    || data.groups.length > 20
    || data.unresolved_groups !== data.groups.length
    || !data.groups.every(validErrorGroup)
    || !validErrorInsight(data.insight)
    || !(data.analysis_error === null || validIntegrationFailure(data.analysis_error))
  ) return false;
  const eventTotal = safeSum(data.groups.map((group) => group.event_count));
  const userTotal = safeSum(data.groups.map((group) => group.affected_users));
  if (eventTotal !== data.total_events || userTotal !== data.affected_users) return false;
  if (data.unresolved_groups === 0) {
    return data.truncated === false
      && data.total_events === 0
      && data.affected_users === 0
      && data.highest_level === "unknown"
      && data.insight.source === "deterministic"
      && data.insight.priority === "none"
      && data.analysis_error === null;
  }
  return true;
}

function validErrorGroup(group) {
  return exactKeys(group, [
    "safe_label",
    "level",
    "event_count",
    "affected_users",
    "first_seen",
    "last_seen",
    "deep_link",
  ])
    && typeof group.safe_label === "string"
    && /^[A-Za-z0-9:_.$#]{1,96}$/.test(group.safe_label)
    && ["debug", "info", "warning", "error", "fatal", "unknown"].includes(group.level)
    && Number.isSafeInteger(group.event_count)
    && group.event_count > 0
    && safeNonnegativeInteger(group.affected_users)
    && validProviderTimestamp(group.first_seen)
    && validProviderTimestamp(group.last_seen)
    && validHttpsLink(group.deep_link, "glitchtip.4u.ge");
}

function validErrorInsight(insight) {
  return exactKeys(insight, [
    "source",
    "priority",
    "summary",
    "actions",
    "generated_at_ms",
    "input_digest",
  ])
    && ["deterministic", "deepseek_v4_flash_free"].includes(insight.source)
    && ["none", "low", "medium", "high", "critical"].includes(insight.priority)
    && boundedDisplayText(insight.summary, 512)
    && Array.isArray(insight.actions)
    && insight.actions.length <= 3
    && insight.actions.every((action) => boundedDisplayText(action, 240))
    && safeNonnegativeInteger(insight.generated_at_ms)
    && typeof insight.input_digest === "string"
    && /^[0-9a-f]{64}$/.test(insight.input_digest);
}

function validProjectUpdatesData(data, projectId) {
  return exactKeys(data, ["schema_version", "project_id", "truncated", "updates"])
    && data.schema_version === 1
    && data.project_id === projectId
    && typeof data.truncated === "boolean"
    && Array.isArray(data.updates)
    && data.updates.length <= 50
    && data.updates.every(validDependencyUpdate);
}

function validDependencyUpdate(update) {
  return exactKeys(update, [
    "number",
    "title",
    "head_ref",
    "head",
    "updated_at",
    "deep_link",
    "check_state",
  ])
    && Number.isSafeInteger(update.number)
    && update.number > 0
    && boundedDisplayText(update.title, 240)
    && typeof update.head_ref === "string"
    && /^(?!\/)(?!.*\.\.)(?!.*\/$)[A-Za-z0-9/_.-]{1,160}$/.test(update.head_ref)
    && typeof update.head === "string"
    && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(update.head)
    && validProviderTimestamp(update.updated_at)
    && validHttpsLink(update.deep_link, "github.com")
    && ["passing", "pending", "failing", "unknown"].includes(update.check_state);
}

function validIntegrationFailure(failure) {
  return exactKeys(failure, ["code", "detail"])
    && typeof failure.code === "string"
    && /^[a-z0-9_]{1,64}$/.test(failure.code)
    && boundedDisplayText(failure.detail, 240);
}

function validProviderTimestamp(value) {
  return typeof value === "string"
    && value.length > 0
    && value.length <= 48
    && value.includes("T")
    && (value.endsWith("Z") || value.includes("+"));
}

function validHttpsLink(value, requiredHost) {
  if (typeof value !== "string") return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && url.hostname === requiredHost
      && url.username === ""
      && url.password === ""
      && url.hash === "";
  } catch (_error) {
    return false;
  }
}

function exactKeys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function safeNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function safeSum(values) {
  let total = 0;
  for (const value of values) {
    if (!safeNonnegativeInteger(value) || !Number.isSafeInteger(total + value)) return null;
    total += value;
  }
  return total;
}

function boundedDisplayText(value, maximumBytes) {
  return typeof value === "string"
    && value.length > 0
    && value === value.trim()
    && new TextEncoder().encode(value).length <= maximumBytes
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function updateSampleAge() {
  if (!runtime.latestSnapshot) {
    elements.sampleAge.textContent = "Нет данных";
    return;
  }
  const ageMs = currentSnapshotAgeMs();
  const observation = evaluateHostObservation(runtime.latestSnapshot, ageMs);
  elements.sampleAge.textContent = formatSampleAge(observation.ageSeconds);
  refreshProjectConditions(observation.status);
}

function currentSnapshotAgeMs() {
  const elapsedMs = performance.now() - runtime.snapshotReceivedAtMonotonicMs;
  return Number.isFinite(runtime.snapshotBaseAgeMs) && Number.isFinite(elapsedMs)
    ? runtime.snapshotBaseAgeMs + Math.max(0, elapsedMs)
    : null;
}

function currentServerReferenceMs() {
  const generatedAtMs = runtime.latestSnapshot?.generated_at_ms;
  const ageMs = currentSnapshotAgeMs();
  if (!Number.isSafeInteger(generatedAtMs) || !Number.isFinite(ageMs)) return null;
  const serverReferenceMs = generatedAtMs + ageMs;
  return Number.isFinite(serverReferenceMs) && serverReferenceMs <= Number.MAX_SAFE_INTEGER
    ? serverReferenceMs
    : null;
}

function refreshProjectConditions(hostObservationStatus) {
  for (const cell of elements.projectList.querySelectorAll(".project-condition")) {
    const presentation = projectConditionPresentation(
      cell.dataset.condition,
      hostObservationStatus,
    );
    cell.dataset.state = presentation.state;
    cell.textContent = presentation.label;
  }
}

async function loadInitialSnapshot() {
  const response = await fetch("/api/v1/snapshot", {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) {
    const problem = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(problem.detail || "Первоначальный снимок недоступен");
  }
  const serverTimeHeader = response.headers.get("x-rdashboard-server-time-ms");
  const serverReferenceMs = serverTimeHeader === null ? null : Number(serverTimeHeader);
  renderSnapshot(await response.json(), serverReferenceMs);
}

function connect() {
  clearReconnectTimer();
  if (runtime.source) runtime.source.close();
  if (navigator.onLine === false) {
    setConnection(
      "disconnected",
      "× Нет сети",
      "Браузер находится offline; показан последний снимок.",
    );
    return;
  }
  const after = runtime.lastSequence === null ? "" : `?after=${encodeURIComponent(runtime.lastSequence)}`;
  const source = new EventSource(`/api/v1/events${after}`);
  runtime.source = source;
  setConnection("loading", "Подключение…", "Открывается поток серверных событий.");

  source.addEventListener("open", () => {
    runtime.reconnectDelayMs = 1_000;
    setConnection("connected", "● Подключён", "SSE подключён; обновления поступают автоматически.", "Поток обновлений подключён.");
  });

  source.addEventListener("snapshot", (event) => {
    handleSnapshotEnvelope(event.data);
  });

  source.addEventListener("resync_required", (event) => {
    const envelope = parseEnvelope(event.data);
    if (!envelope) return;
    runtime.acceptingResyncSnapshot = true;
    elements.sequence.textContent = String(envelope.sequence);
    setConnection(
      "retrying",
      "△ Синхронизация",
      "История событий имеет разрыв; сервер передаёт свежий полный снимок.",
      "Обнаружен разрыв обновлений. Загружается полный снимок.",
    );
  });

  source.addEventListener("error", () => {
    if (source !== runtime.source) return;
    source.close();
    setConnection(
      navigator.onLine ? "retrying" : "disconnected",
      navigator.onLine ? "△ Переподключение" : "× Нет сети",
      "Поток прерван; текущие значения остаются видимыми с растущим возрастом снимка.",
      "Поток обновлений прерван.",
    );
    scheduleReconnect();
  });
}

function handleSnapshotEnvelope(raw) {
  const envelope = parseEnvelope(raw);
  if (!envelope || envelope.event.kind !== "snapshot") return;
  const sequence = Number(envelope.sequence);
  if (!Number.isSafeInteger(sequence) || sequence <= 0) {
    forceResync("Сервер передал некорректную последовательность событий.");
    return;
  }
  if (
    !runtime.acceptingResyncSnapshot &&
    runtime.lastSequence !== null &&
    sequence > runtime.lastSequence + 1
  ) {
    forceResync("Обнаружен необъявленный разрыв последовательности событий.");
    return;
  }
  if (!runtime.acceptingResyncSnapshot && runtime.lastSequence !== null && sequence <= runtime.lastSequence) {
    return;
  }
  runtime.acceptingResyncSnapshot = false;
  runtime.lastSequence = sequence;
  elements.sequence.textContent = String(sequence);
  renderSnapshot(envelope.event.payload, Number(envelope.delivered_at_ms));
}

function parseEnvelope(raw) {
  try {
    const envelope = JSON.parse(raw);
    if (envelope.version !== 1 || !envelope.event) throw new Error("unsupported envelope");
    return envelope;
  } catch (error) {
    forceResync(`Некорректное событие: ${error.message}`);
    return null;
  }
}

function forceResync(reason) {
  runtime.acceptingResyncSnapshot = true;
  runtime.lastSequence = 0;
  announce(reason, true);
  if (runtime.source) runtime.source.close();
  scheduleReconnect(0);
}

function scheduleReconnect(delay = runtime.reconnectDelayMs) {
  clearReconnectTimer();
  runtime.reconnectTimer = window.setTimeout(connect, delay);
  runtime.reconnectDelayMs = Math.min(runtime.reconnectDelayMs * 2, 30_000);
}

function clearReconnectTimer() {
  if (runtime.reconnectTimer !== null) {
    window.clearTimeout(runtime.reconnectTimer);
    runtime.reconnectTimer = null;
  }
}

elements.retry.addEventListener("click", async () => {
  if (runtime.initializing) return;
  runtime.initializing = true;
  runtime.reconnectDelayMs = 1_000;
  setConnection("loading", "Подключение…", "Повторно загружается актуальный снимок.");
  if (!runtime.latestSnapshot) {
    try {
      await loadInitialSnapshot();
    } catch (error) {
      runtime.initializing = false;
      setConnection(
        "error",
        "× Ошибка",
        error.message,
        "Первоначальный снимок получить не удалось.",
      );
      return;
    }
  }
  runtime.initializing = false;
  loadHostHistory(false);
  connect();
});

elements.workflowRefresh.addEventListener("click", () => {
  loadWorkflowOverview(true);
});

window.addEventListener("online", () => {
  runtime.reconnectDelayMs = 1_000;
  connect();
});
window.addEventListener("offline", () => {
  if (runtime.source) runtime.source.close();
  clearReconnectTimer();
  setConnection("disconnected", "× Нет сети", "Браузер находится offline; показан последний снимок.", "Сетевое подключение потеряно.");
});

window.setInterval(updateSampleAge, 1_000);
window.setInterval(() => loadHostHistory(false), HOST_HISTORY_REFRESH_MS);
window.setInterval(() => loadWorkflowOverview(false), WORKFLOW_OVERVIEW_REFRESH_MS);
window.setInterval(() => {
  if (!runtime.latestSnapshot?.projects) return;
  for (const project of runtime.latestSnapshot.projects) {
    loadProjectOperations(String(project.project_id), true);
  }
}, PROJECT_OPERATIONS_REFRESH_MS);
window.setInterval(() => {
  if (!runtime.latestSnapshot?.projects) return;
  for (const project of runtime.latestSnapshot.projects) {
    loadProjectResources(String(project.project_id), true);
  }
}, PROJECT_RESOURCES_REFRESH_MS);
window.setInterval(() => {
  if (!runtime.latestSnapshot?.projects) return;
  for (const project of runtime.latestSnapshot.projects) {
    loadProjectRepository(String(project.project_id), true);
  }
}, PROJECT_REPOSITORY_REFRESH_MS);
window.setInterval(() => {
  if (!runtime.latestSnapshot?.projects) return;
  for (const project of runtime.latestSnapshot.projects) {
    const projectId = String(project.project_id);
    loadProjectUpdates(projectId, true);
    loadProjectErrors(projectId, true);
  }
}, PROJECT_INTEGRATIONS_REFRESH_MS);
window.setInterval(() => {
  if (!runtime.latestSnapshot?.projects) return;
  for (const project of runtime.latestSnapshot.projects) {
    loadProjectNotifications(String(project.project_id), true);
  }
}, PROJECT_NOTIFICATIONS_REFRESH_MS);

loadHostHistory(true);
loadWorkflowOverview(false);

loadInitialSnapshot()
  .then(connect)
  .catch((error) => {
    setConnection("error", "× Ошибка", error.message, "Первоначальный снимок получить не удалось.");
  });
