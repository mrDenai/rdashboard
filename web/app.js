"use strict";

import {
  evaluateHostObservation,
  formatSampleAge,
  mutationStatePresentation,
  operationKindLabel,
  operationPhaseLabel,
  projectConditionPresentation,
} from "./status.js";

const elements = Object.freeze({
  connection: document.querySelector("#connection-status"),
  sampleAge: document.querySelector("#sample-age"),
  sequence: document.querySelector("#event-sequence"),
  retry: document.querySelector("#retry-connection"),
  hostStatus: document.querySelector("#host-observation-status"),
  cpu: document.querySelector("#metric-cpu"),
  load: document.querySelector("#metric-load"),
  memory: document.querySelector("#metric-memory"),
  memoryDetail: document.querySelector("#metric-memory-detail"),
  disk: document.querySelector("#metric-disk"),
  diskDetail: document.querySelector("#metric-disk-detail"),
  network: document.querySelector("#metric-network"),
  networkDetail: document.querySelector("#metric-network-detail"),
  psi: document.querySelector("#metric-psi"),
  partialPanel: document.querySelector("#partial-panel"),
  partialReasons: document.querySelector("#partial-reasons"),
  projectCount: document.querySelector("#project-count"),
  projectRows: document.querySelector("#project-rows"),
  sqliteVersion: document.querySelector("#sqlite-version"),
  observationOperation: document.querySelector("#observation-operation"),
  sampleInterval: document.querySelector("#sample-interval"),
  streamDetail: document.querySelector("#stream-detail"),
  mutationCapability: document.querySelector("#mutation-capability"),
  mutationStartReason: document.querySelector("#mutation-start-reason"),
  mutationStatusForm: document.querySelector("#mutation-status-form"),
  mutationIntentId: document.querySelector("#mutation-intent-id"),
  mutationIntentError: document.querySelector("#mutation-intent-error"),
  mutationAttemptId: document.querySelector("#mutation-attempt-id"),
  mutationAttemptError: document.querySelector("#mutation-attempt-error"),
  mutationStatusSubmit: document.querySelector("#mutation-status-submit"),
  mutationStatusMessage: document.querySelector("#mutation-status-message"),
  mutationStatusDetail: document.querySelector("#mutation-status-detail"),
  mutationState: document.querySelector("#mutation-state"),
  mutationOperation: document.querySelector("#mutation-operation"),
  mutationPhase: document.querySelector("#mutation-phase"),
  mutationCompletedPhases: document.querySelector("#mutation-completed-phases"),
  mutationUpdatedAt: document.querySelector("#mutation-updated-at"),
  mutationStatusRetry: document.querySelector("#mutation-status-retry"),
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
  mutationCapabilities: null,
  mutationStatusTimer: null,
  mutationStatusLoading: false,
  lastMutationState: null,
};

const MUTATION_STATUS_STORAGE_KEY = "rdashboard.mutation-status.v1";
const MUTATION_STATUS_POLL_MS = 2_000;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

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

async function initializeMutationControls() {
  restoreMutationIdentity();
  const response = await fetch("/api/v1/mutations/capabilities", {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  if (!response.ok) throw new Error("Конфигурацию контура операций получить не удалось.");
  const capabilities = await response.json();
  if (
    capabilities.schema_version !== 1
    || typeof capabilities.executor_socket_configured !== "boolean"
    || typeof capabilities.authorization_handoff_available !== "boolean"
  ) {
    throw new Error("Сервер вернул неподдерживаемый контракт контура операций.");
  }
  runtime.mutationCapabilities = capabilities;
  const executorReady = capabilities.executor_socket_configured;
  elements.mutationStatusSubmit.disabled = !executorReady;
  if (executorReady) {
    elements.mutationCapability.dataset.state = "partial";
    elements.mutationCapability.textContent = "△ Доступно наблюдение";
    elements.mutationStatusMessage.textContent =
      "Введите идентификаторы операции; состояние будет обновляться автоматически.";
  } else {
    elements.mutationCapability.dataset.state = "error";
    elements.mutationCapability.textContent = "× Executor не подключён";
    elements.mutationStatusMessage.textContent =
      "Наблюдение недоступно: сервер не настроен на root executor.";
  }
  if (capabilities.authorization_handoff_available) {
    elements.mutationStartReason.textContent =
      "Авторизатор объявлен сервером, но запуск из этого интерфейса ещё не разрешён.";
  }
  if (executorReady && restoredMutationIdentityIsComplete()) {
    await requestMutationStatus(false);
  }
}

function renderMutationControlsUnavailable(error) {
  runtime.mutationCapabilities = null;
  elements.mutationCapability.dataset.state = "error";
  elements.mutationCapability.textContent = "× Конфигурация недоступна";
  elements.mutationStatusSubmit.disabled = true;
  elements.mutationStatusMessage.textContent = error.message;
  announce(error.message, true);
}

function restoreMutationIdentity() {
  try {
    const stored = JSON.parse(window.sessionStorage.getItem(MUTATION_STATUS_STORAGE_KEY));
    if (stored && normalizeUuid(stored.intent_id) && normalizeUuid(stored.attempt_id)) {
      elements.mutationIntentId.value = normalizeUuid(stored.intent_id);
      elements.mutationAttemptId.value = normalizeUuid(stored.attempt_id);
    }
  } catch {
    // Session state is an optional convenience; an unavailable store must not block observation.
  }
}

function restoredMutationIdentityIsComplete() {
  return Boolean(
    normalizeUuid(elements.mutationIntentId.value)
    && normalizeUuid(elements.mutationAttemptId.value),
  );
}

function persistMutationIdentity(intentId, attemptId) {
  try {
    window.sessionStorage.setItem(MUTATION_STATUS_STORAGE_KEY, JSON.stringify({
      intent_id: intentId,
      attempt_id: attemptId,
    }));
  } catch {
    // Polling remains functional when storage is disabled or full.
  }
}

function normalizeUuid(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  if (!UUID_PATTERN.test(normalized) || normalized === "00000000-0000-0000-0000-000000000000") {
    return null;
  }
  return normalized;
}

function validateMutationIdentity() {
  clearFieldError(elements.mutationIntentId, elements.mutationIntentError);
  clearFieldError(elements.mutationAttemptId, elements.mutationAttemptError);
  const intentId = normalizeUuid(elements.mutationIntentId.value);
  const attemptId = normalizeUuid(elements.mutationAttemptId.value);
  let firstInvalid = null;
  if (!intentId) {
    showFieldError(
      elements.mutationIntentId,
      elements.mutationIntentError,
      "Укажите ненулевой UUID intent.",
    );
    firstInvalid = elements.mutationIntentId;
  }
  if (!attemptId) {
    showFieldError(
      elements.mutationAttemptId,
      elements.mutationAttemptError,
      "Укажите ненулевой UUID попытки.",
    );
    firstInvalid ??= elements.mutationAttemptId;
  }
  if (firstInvalid) {
    firstInvalid.focus();
    announce("Проверьте идентификаторы операции.", true);
    return null;
  }
  elements.mutationIntentId.value = intentId;
  elements.mutationAttemptId.value = attemptId;
  return { intentId, attemptId };
}

function showFieldError(input, errorElement, message) {
  input.setAttribute("aria-invalid", "true");
  errorElement.textContent = message;
  errorElement.hidden = false;
}

function clearFieldError(input, errorElement) {
  input.removeAttribute("aria-invalid");
  errorElement.textContent = "";
  errorElement.hidden = true;
}

async function requestMutationStatus(announceFailure = true) {
  if (runtime.mutationStatusLoading || !runtime.mutationCapabilities?.executor_socket_configured) {
    return;
  }
  const identity = validateMutationIdentity();
  if (!identity) return;
  persistMutationIdentity(identity.intentId, identity.attemptId);
  clearMutationStatusTimer();
  runtime.mutationStatusLoading = true;
  elements.mutationStatusSubmit.disabled = true;
  elements.mutationStatusRetry.hidden = true;
  elements.mutationStatusMessage.textContent = "Запрашивается состояние операции…";
  try {
    const query = new URLSearchParams({
      intent_id: identity.intentId,
      attempt_id: identity.attemptId,
    });
    const response = await fetch(`/api/v1/mutations/status?${query}`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!response.ok) {
      const problem = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(problem.detail || "Состояние операции недоступно.");
    }
    const status = await response.json();
    if (status.intent_id !== identity.intentId || status.attempt_id !== identity.attemptId) {
      throw new Error("Ответ executor не совпал с запрошенной операцией.");
    }
    renderMutationStatus(status);
    if (status.state !== "succeeded") {
      runtime.mutationStatusTimer = window.setTimeout(
        () => requestMutationStatus(false),
        MUTATION_STATUS_POLL_MS,
      );
    }
  } catch (error) {
    elements.mutationStatusMessage.textContent = error.message;
    elements.mutationStatusRetry.hidden = false;
    if (announceFailure) announce(error.message, true);
  } finally {
    runtime.mutationStatusLoading = false;
    elements.mutationStatusSubmit.disabled = false;
  }
}

function renderMutationStatus(status) {
  const state = mutationStatePresentation(status.state);
  const phase = operationPhaseLabel(status.current_phase);
  const completed = Array.isArray(status.completed_phases)
    ? status.completed_phases.map(operationPhaseLabel)
    : [];
  elements.mutationStatusDetail.hidden = false;
  elements.mutationState.dataset.state = state.state;
  elements.mutationState.textContent = state.label;
  elements.mutationOperation.textContent = `${status.project_id} · ${operationKindLabel(status.operation_kind)}`;
  elements.mutationPhase.textContent = phase;
  elements.mutationCompletedPhases.textContent = completed.length > 0 ? completed.join(" → ") : "Нет";
  elements.mutationUpdatedAt.textContent = Number.isFinite(status.updated_at_ms)
    ? new Date(status.updated_at_ms).toLocaleString("ru-RU")
    : "Некорректное время";
  elements.mutationStatusMessage.textContent = status.state === "succeeded"
    ? "Операция завершена; автоматическое обновление остановлено."
    : "Состояние обновляется автоматически каждые 2 секунды.";
  if (runtime.lastMutationState !== status.state) {
    announce(`Состояние операции: ${state.label}. Текущая фаза: ${phase}.`);
    runtime.lastMutationState = status.state;
  }
}

function clearMutationStatusTimer() {
  if (runtime.mutationStatusTimer !== null) {
    window.clearTimeout(runtime.mutationStatusTimer);
    runtime.mutationStatusTimer = null;
  }
}

function formatBytes(value) {
  if (!Number.isFinite(value) || value < 0) return "Нет данных";
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${byteFormatter.format(scaled)} ${units[unit]}`;
}

function formatRate(value) {
  return Number.isFinite(value) ? `${formatBytes(value)}/с` : "Нет данных";
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

  elements.network.textContent = `↓ ${formatRate(host.network_rx_bytes_per_second)}`;
  elements.networkDetail.textContent = `↑ ${formatRate(host.network_tx_bytes_per_second)}`;
  elements.psi.textContent = [
    host.psi.cpu_some_avg10,
    host.psi.memory_some_avg10,
    host.psi.io_some_avg10,
  ]
    .map((value) => (Number.isFinite(value) ? percentFormatter.format(value) : "—"))
    .join(" / ");

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
  elements.projectRows.replaceChildren();
  const count = Array.isArray(projects) ? projects.length : 0;
  elements.projectCount.textContent = `${count} подключено`;
  if (count === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-cell";
    cell.textContent = "Проекты ещё не подключены.";
    row.append(cell);
    elements.projectRows.append(row);
    return;
  }
  for (const project of projects) {
    const row = document.createElement("tr");
    appendCell(row, project.display_name);
    const condition = String(project.condition);
    const presentation = projectConditionPresentation(condition, "fresh");
    const conditionCell = appendCell(row, presentation.label);
    conditionCell.className = "project-condition";
    conditionCell.dataset.condition = condition;
    conditionCell.dataset.state = presentation.state;
    appendCell(
      row,
      Number.isFinite(project.observed_at_ms)
        ? new Date(project.observed_at_ms).toLocaleString("ru-RU")
        : "Нет данных",
    );
    appendCell(row, project.detail);
    elements.projectRows.append(row);
  }
}

function appendCell(row, value) {
  const cell = document.createElement("td");
  cell.textContent = String(value);
  row.append(cell);
  return cell;
}

function updateSampleAge() {
  if (!runtime.latestSnapshot) {
    elements.sampleAge.textContent = "Нет данных";
    elements.hostStatus.dataset.state = "unknown";
    elements.hostStatus.textContent = "? Состояние неизвестно";
    return;
  }
  const elapsedMs = performance.now() - runtime.snapshotReceivedAtMonotonicMs;
  const ageMs = Number.isFinite(runtime.snapshotBaseAgeMs) && Number.isFinite(elapsedMs)
    ? runtime.snapshotBaseAgeMs + Math.max(0, elapsedMs)
    : null;
  const observation = evaluateHostObservation(runtime.latestSnapshot, ageMs);
  elements.hostStatus.dataset.state = observation.status;
  elements.hostStatus.textContent = observation.label;
  elements.sampleAge.textContent = formatSampleAge(observation.ageSeconds);
  refreshProjectConditions(observation.status);
}

function refreshProjectConditions(hostObservationStatus) {
  for (const cell of elements.projectRows.querySelectorAll(".project-condition")) {
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
  connect();
});

elements.mutationStatusForm.addEventListener("submit", (event) => {
  event.preventDefault();
  requestMutationStatus(true);
});

elements.mutationStatusRetry.addEventListener("click", () => {
  requestMutationStatus(true);
});

for (const [input, errorElement] of [
  [elements.mutationIntentId, elements.mutationIntentError],
  [elements.mutationAttemptId, elements.mutationAttemptError],
]) {
  input.addEventListener("input", () => clearFieldError(input, errorElement));
}

window.addEventListener("online", () => {
  runtime.reconnectDelayMs = 1_000;
  connect();
});
window.addEventListener("offline", () => {
  if (runtime.source) runtime.source.close();
  clearReconnectTimer();
  setConnection("disconnected", "× Нет сети", "Браузер находится offline; показан последний снимок.", "Сетевое подключение потеряно.");
});

window.addEventListener("pagehide", clearMutationStatusTimer);

window.setInterval(updateSampleAge, 1_000);

initializeMutationControls().catch(renderMutationControlsUnavailable);

loadInitialSnapshot()
  .then(connect)
  .catch((error) => {
    setConnection("error", "× Ошибка", error.message, "Первоначальный снимок получить не удалось.");
  });
