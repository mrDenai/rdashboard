"use strict";

const hostStatusLabels = Object.freeze({
  fresh: "● Данные свежие",
  stale: "△ Данные устарели",
  signal_lost: "× Сигнал потерян",
  partial: "△ Неполные данные",
  unsupported: "◇ Не поддерживается",
  unknown: "? Состояние неизвестно",
});

const knownHostStatuses = new Set(Object.keys(hostStatusLabels));

const projectConditionLabels = Object.freeze({
  healthy: "● Работает",
  degraded: "△ Деградация",
  down: "× Недоступен",
  maintenance: "◇ Обслуживание",
  migrating: "↻ Миграция",
  unknown: "? Неизвестно",
  signal_lost: "× Сигнал потерян",
});

const mutationStateLabels = Object.freeze({
  accepted: "◌ Принята",
  running: "↻ Выполняется",
  needs_reconcile: "△ Требует сверки",
  succeeded: "● Завершена",
  rolled_back: "△ Выполнен откат",
});

const operationKindLabels = Object.freeze({
  deploy: "деплой",
  code_rollback: "откат кода",
  backup_only: "резервная копия",
});

const operationResultLabels = Object.freeze({
  running: { state: "running", label: "↻ Выполняется" },
  succeeded: { state: "succeeded", label: "● Завершено" },
  failed: { state: "error", label: "× Ошибка" },
  rolled_back: { state: "partial", label: "△ Выполнен откат" },
  rollback_failed: { state: "error", label: "× Откат не удался" },
  cancelled: { state: "unknown", label: "◇ Отменено" },
  superseded: { state: "unknown", label: "◇ Заменено новым" },
  manual_recovery_required: { state: "error", label: "× Требуется восстановление" },
});

const operationPhaseLabels = Object.freeze({
  queued: "В очереди",
  syncing_source: "Синхронизация исходников",
  verifying_source: "Проверка исходников",
  testing: "Тестирование",
  building: "Сборка",
  preflight: "Предварительная проверка",
  backing_up: "Резервное копирование",
  draining: "Остановка записи",
  cutover_snapshotting: "Снимок перед переключением",
  migrating: "Миграция",
  deploying: "Развёртывание",
  health_checking: "Проверка здоровья",
  soaking: "Контрольный период",
  rollback: "Откат",
  reconciliation: "Сверка состояния",
});

const workflowAttemptLabels = Object.freeze({
  queued: { state: "partial", label: "◌ В очереди" },
  waiting_for_mutation: { state: "partial", label: "◇ Ждёт завершения мутации" },
  running: { state: "running", label: "↻ Выполняется" },
  succeeded: { state: "succeeded", label: "● Завершён" },
  failed: { state: "error", label: "× Ошибка" },
  superseded: { state: "unknown", label: "◇ Заменён новым" },
  needs_reconcile: { state: "needs_reconcile", label: "△ Требует сверки" },
});

const workflowMutationLabels = Object.freeze({
  not_started: { state: "unknown", label: "Не начата" },
  owned: { state: "running", label: "Выполняется" },
  needs_reconcile: { state: "needs_reconcile", label: "Требует сверки" },
  complete: { state: "succeeded", label: "Завершена" },
});

const workflowCleanupLabels = Object.freeze({
  complete: { state: "succeeded", label: "Завершён" },
  pending: { state: "error", label: "Требуется" },
});

const workflowNodeKindLabels = Object.freeze({
  source_admission: "Приём исходников",
  host_prepare: "Подготовка окружения",
  verification: "Проверки",
  release_build: "Сборка релиза",
  deterministic_reduce: "Сверка доказательств",
  resource_reservation: "Резерв ресурсов",
  backup: "Резервная копия",
  migration: "Миграция",
  candidate_health: "Проверка кандидата",
  cutover: "Переключение трафика",
  released_observation: "Наблюдение релиза",
  rollback: "Откат",
});

const workflowNodeStates = new Set([
  "dormant",
  "blocked",
  "ready",
  "leased",
  "succeeded",
  "failed",
  "cancelled",
  "needs_reconcile",
]);
const workflowWorkerPools = new Set([
  "controller",
  "vps_required",
  "build_compute",
  "privileged_executor",
]);
const workflowIdentifierPattern = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const commitPattern = /^[0-9a-f]{40}$/;
const digestPattern = /^[0-9a-f]{64}$/;

export function evaluateHostObservation(snapshot, ageMs) {
  if (
    !snapshot
    || !snapshot.host
    || !Number.isFinite(snapshot.generated_at_ms)
    || !Number.isFinite(ageMs)
    || ageMs < 0
    || !Number.isFinite(snapshot.control?.sample_interval_seconds)
    || snapshot.control.sample_interval_seconds <= 0
  ) {
    return observation("unknown", null);
  }

  const ageSeconds = Math.floor(ageMs / 1_000);
  const intervalMs = snapshot.control.sample_interval_seconds * 1_000;
  if (ageMs > intervalMs * 3) return observation("signal_lost", ageSeconds);
  if (ageMs > intervalMs * 2) return observation("stale", ageSeconds);

  const sourceStatus = knownHostStatuses.has(snapshot.host.status)
    ? snapshot.host.status
    : "unknown";
  return observation(sourceStatus, ageSeconds);
}

export function projectConditionPresentation(condition, hostObservationStatus) {
  const projectCondition = Object.hasOwn(projectConditionLabels, condition)
    ? condition
    : "unknown";
  const baseLabel = projectConditionLabels[projectCondition];
  if (hostObservationStatus === "stale") {
    return presentation("stale", `${baseLabel} · данные устарели`);
  }
  if (hostObservationStatus === "signal_lost") {
    return presentation("signal_lost", `${baseLabel} · нет свежего сигнала`);
  }
  if (hostObservationStatus === "unknown") {
    return presentation("unknown", `${baseLabel} · актуальность неизвестна`);
  }
  return presentation(projectCondition, baseLabel);
}

export function formatSampleAge(ageSeconds) {
  if (!Number.isSafeInteger(ageSeconds) || ageSeconds < 0) {
    return "Время снимка некорректно";
  }
  return ageSeconds < 60
    ? `${ageSeconds} с назад`
    : `${Math.floor(ageSeconds / 60)} мин назад`;
}

export function formatHistoryCoverage(window) {
  if (
    !window
    || !Number.isSafeInteger(window.sample_count)
    || window.sample_count < 0
    || !Number.isSafeInteger(window.covered_minutes)
    || window.covered_minutes < 0
    || !Number.isSafeInteger(window.expected_minutes)
    || window.expected_minutes <= 0
    || window.covered_minutes > window.expected_minutes
    || typeof window.complete !== "boolean"
    || window.complete !== (window.covered_minutes === window.expected_minutes)
  ) {
    return "история некорректна";
  }
  if (window.sample_count === 0) return "нет данных";
  if (window.complete) return "полная история";
  const percent = Math.floor((window.covered_minutes / window.expected_minutes) * 100);
  return `${percent} % истории`;
}

export function mutationStatePresentation(state) {
  const normalized = Object.hasOwn(mutationStateLabels, state) ? state : "unknown";
  return presentation(normalized, mutationStateLabels[normalized] ?? "? Неизвестно");
}

export function operationKindLabel(kind) {
  return operationKindLabels[kind] ?? "неизвестная операция";
}

export function operationResultPresentation(result) {
  const value = operationResultLabels[result];
  return value ? presentation(value.state, value.label) : presentation("unknown", "? Неизвестно");
}

export function operationPhaseLabel(phase) {
  return operationPhaseLabels[phase] ?? "Неизвестная фаза";
}

export function workflowAttemptPresentation(state) {
  const value = workflowAttemptLabels[state];
  return value ? presentation(value.state, value.label) : presentation("unknown", "? Неизвестно");
}

export function workflowMutationPresentation(state) {
  const value = workflowMutationLabels[state];
  return value ? presentation(value.state, value.label) : presentation("unknown", "Неизвестно");
}

export function workflowCleanupPresentation(state) {
  const value = workflowCleanupLabels[state];
  return value ? presentation(value.state, value.label) : presentation("unknown", "Неизвестно");
}

export function workflowCurrentStepLabel(attempt) {
  if (!Array.isArray(attempt?.nodes)) return "Неизвестный этап";
  const priorities = ["needs_reconcile", "failed", "leased", "ready", "blocked"];
  for (const state of priorities) {
    const matching = attempt.nodes.filter((node) => node.state === state);
    if (matching.length > 0) {
      const labels = matching.slice(0, 2).map(
        (node) => workflowNodeKindLabels[node.kind] ?? "Неизвестный этап",
      );
      if (matching.length > labels.length) labels.push(`ещё ${matching.length - labels.length}`);
      return labels.join(" · ");
    }
  }
  return attempt.state === "succeeded" ? "Все этапы завершены" : "Нет активного этапа";
}

export function validWorkflowOverview(payload) {
  if (
    !hasExactKeys(payload, ["schema_version", "generated_at_ms", "truncated", "attempts"])
    || payload.schema_version !== 1
    || !safeNonnegativeInteger(payload.generated_at_ms)
    || typeof payload.truncated !== "boolean"
    || !Array.isArray(payload.attempts)
    || payload.attempts.length > 50
  ) return false;
  const attemptIds = new Set();
  let previousUpdatedAt = Number.MAX_SAFE_INTEGER;
  for (const attempt of payload.attempts) {
    if (
      !validWorkflowAttempt(attempt, payload.generated_at_ms)
      || attemptIds.has(attempt.attempt_id)
      || attempt.updated_at_ms > previousUpdatedAt
    ) return false;
    attemptIds.add(attempt.attempt_id);
    previousUpdatedAt = attempt.updated_at_ms;
  }
  return true;
}

function validWorkflowAttempt(attempt, generatedAtMs) {
  if (!hasExactKeys(attempt, [
    "request_id",
    "attempt_id",
    "attempt_number",
    "project_id",
    "source_sha",
    "source_sequence",
    "workflow_policy_digest",
    "source_attestation_digest",
    "preparation_key",
    "priority",
    "state",
    "mutation_state",
    "cleanup_state",
    "created_at_ms",
    "updated_at_ms",
    "terminal_at_ms",
    "nodes",
  ])) return false;
  if (
    !uuidPattern.test(attempt.request_id)
    || !uuidPattern.test(attempt.attempt_id)
    || !safePositiveInteger(attempt.attempt_number)
    || !workflowIdentifierPattern.test(attempt.project_id)
    || !commitPattern.test(attempt.source_sha)
    || !safePositiveInteger(attempt.source_sequence)
    || !digestPattern.test(attempt.workflow_policy_digest)
    || !digestPattern.test(attempt.source_attestation_digest)
    || !digestPattern.test(attempt.preparation_key)
    || !safeNonnegativeInteger(attempt.priority)
    || attempt.priority > 3
    || !Object.hasOwn(workflowAttemptLabels, attempt.state)
    || !Object.hasOwn(workflowMutationLabels, attempt.mutation_state)
    || !Object.hasOwn(workflowCleanupLabels, attempt.cleanup_state)
    || !safeNonnegativeInteger(attempt.created_at_ms)
    || !safeNonnegativeInteger(attempt.updated_at_ms)
    || attempt.updated_at_ms < attempt.created_at_ms
    || attempt.updated_at_ms > generatedAtMs
    || !(attempt.terminal_at_ms === null
      || (safeNonnegativeInteger(attempt.terminal_at_ms)
        && attempt.terminal_at_ms >= attempt.created_at_ms
        && attempt.terminal_at_ms <= attempt.updated_at_ms))
    || !Array.isArray(attempt.nodes)
    || attempt.nodes.length === 0
    || attempt.nodes.length > 64
  ) return false;
  const nodeIds = new Set();
  for (const node of attempt.nodes) {
    if (!validWorkflowNode(node) || nodeIds.has(node.node_id)) return false;
    nodeIds.add(node.node_id);
  }
  return true;
}

function validWorkflowNode(node) {
  return hasExactKeys(node, [
    "node_id",
    "kind",
    "profile_id",
    "worker_pool",
    "state",
    "lease_generation",
    "output_digest",
    "receipt_digest",
    "completed_at_ms",
  ])
    && workflowIdentifierPattern.test(node.node_id)
    && Object.hasOwn(workflowNodeKindLabels, node.kind)
    && workflowIdentifierPattern.test(node.profile_id)
    && workflowWorkerPools.has(node.worker_pool)
    && workflowNodeStates.has(node.state)
    && safeNonnegativeInteger(node.lease_generation)
    && (node.output_digest === null || digestPattern.test(node.output_digest))
    && (node.receipt_digest === null || digestPattern.test(node.receipt_digest))
    && (node.completed_at_ms === null || safeNonnegativeInteger(node.completed_at_ms));
}

export function repositorySizeChange(samples, periodMs) {
  if (!Array.isArray(samples) || samples.length < 2 || !Number.isFinite(periodMs) || periodMs <= 0) {
    return null;
  }
  const latest = samples.at(-1);
  if (!validRepositoryPoint(latest)) return null;
  const targetMs = latest.observed_at_ms - periodMs;
  let baseline = null;
  let previousTime = -1;
  for (const sample of samples) {
    if (
      !validRepositoryPoint(sample)
      || sample.observed_at_ms <= previousTime
      || sample.observed_at_ms > latest.observed_at_ms
    ) return null;
    if (sample.observed_at_ms <= targetMs) baseline = sample;
    previousTime = sample.observed_at_ms;
  }
  return baseline ? latest.total_bytes - baseline.total_bytes : null;
}

function validRepositoryPoint(sample) {
  return Number.isSafeInteger(sample?.observed_at_ms)
    && sample.observed_at_ms >= 0
    && Number.isSafeInteger(sample.total_bytes)
    && sample.total_bytes >= 0;
}

function hasExactKeys(value, keys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function safeNonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function safePositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function observation(status, ageSeconds) {
  return Object.freeze({
    status,
    label: hostStatusLabels[status],
    ageSeconds,
  });
}

function presentation(state, label) {
  return Object.freeze({ state, label });
}
