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
