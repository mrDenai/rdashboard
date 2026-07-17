"use strict";

import {
  evaluateHostObservation,
  formatHistoryCoverage,
  formatSampleAge,
  operationKindLabel,
  operationResultPresentation,
  projectConditionPresentation,
  repositorySizeChange,
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
};

const HOST_HISTORY_REFRESH_MS = 60_000;
const PROJECT_OPERATIONS_REFRESH_MS = 30_000;
const PROJECT_RESOURCES_REFRESH_MS = 60_000;
const PROJECT_REPOSITORY_REFRESH_MS = 5 * 60_000;
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
    empty.colSpan = 8;
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
    createUnavailableCell(),
    createUnavailableCell(),
  );

  if (loadIntegrations) {
    loadProjectOperations(projectId, false);
    loadProjectResources(projectId, false);
    loadProjectRepository(projectId, false);
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
    `${formatPercent(current.cpu_percent)} · ${formatBytes(current.memory_used_bytes)}`,
    current.status,
    `RAM из ${formatBytes(current.memory_limit_bytes)}`,
  );
  if (!history) {
    appendProjectCellDetail(cell, "История загружается…");
    return cell;
  }
  if (history.error && history.windows.length === 0) {
    appendProjectCellDetail(cell, "История недоступна");
    return cell;
  }

  const windows = new Map(history.windows.map((window) => [window.window, window]));
  const labels = { hour: "1ч", day: "1д", week: "7д", month: "30д" };
  const medians = HOST_HISTORY_WINDOWS.map((name) => {
    const window = windows.get(name);
    const cpu = formatPercent(window?.medians?.cpu_percent);
    const memory = formatBytes(window?.medians?.memory_used_bytes);
    return `${labels[name]} ${cpu}/${memory}`;
  });
  appendProjectCellDetail(cell, medians.join(" · "), "resource-history");

  const hour = windows.get("hour");
  if (hour?.totals) {
    appendProjectCellDetail(
      cell,
      `трафик 1ч ↓ ${formatBytes(hour.totals.network_rx_bytes)} · ↑ ${formatBytes(hour.totals.network_tx_bytes)}`,
      "resource-history",
    );
  }
  if (history.error) appendProjectCellDetail(cell, "Последняя сохранённая история");
  return cell;
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

function createUnavailableCell() {
  return createSummaryCell("Не настроено", "unknown");
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

function updateSampleAge() {
  if (!runtime.latestSnapshot) {
    elements.sampleAge.textContent = "Нет данных";
    return;
  }
  const elapsedMs = performance.now() - runtime.snapshotReceivedAtMonotonicMs;
  const ageMs = Number.isFinite(runtime.snapshotBaseAgeMs) && Number.isFinite(elapsedMs)
    ? runtime.snapshotBaseAgeMs + Math.max(0, elapsedMs)
    : null;
  const observation = evaluateHostObservation(runtime.latestSnapshot, ageMs);
  elements.sampleAge.textContent = formatSampleAge(observation.ageSeconds);
  refreshProjectConditions(observation.status);
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

loadHostHistory(true);

loadInitialSnapshot()
  .then(connect)
  .catch((error) => {
    setConnection("error", "× Ошибка", error.message, "Первоначальный снимок получить не удалось.");
  });
