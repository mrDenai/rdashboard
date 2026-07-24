import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateHostObservation,
  formatHistoryCoverage,
  formatSampleAge,
  mutationStatePresentation,
  notificationKindLabel,
  notificationStatePresentation,
  operationKindLabel,
  operationPhaseLabel,
  operationResultPresentation,
  projectConditionPresentation,
  repositorySizeChange,
  validWorkflowOverview,
  workflowAttemptPresentation,
  workflowCurrentStepLabel,
} from "../web/status.js";

function snapshot(status = "fresh") {
  return {
    generated_at_ms: 1_000_000,
    host: { status },
    control: { sample_interval_seconds: 5 },
  };
}

test("host observation ages from fresh through stale to signal loss", () => {
  assert.deepEqual(evaluateHostObservation(snapshot(), 5_000), {
    status: "fresh",
    label: "● Данные свежие",
    ageSeconds: 5,
  });
  assert.deepEqual(evaluateHostObservation(snapshot(), 11_000), {
    status: "stale",
    label: "△ Данные устарели",
    ageSeconds: 11,
  });
  assert.deepEqual(evaluateHostObservation(snapshot(), 16_000), {
    status: "signal_lost",
    label: "× Сигнал потерян",
    ageSeconds: 16,
  });
});

test("source states remain truthful while the sample is current", () => {
  for (const status of ["partial", "signal_lost", "unsupported", "unknown"]) {
    assert.equal(evaluateHostObservation(snapshot(status), 1_000).status, status);
  }
  assert.equal(evaluateHostObservation(snapshot("invented"), 1_000).status, "unknown");
});

test("missing or malformed server age never renders as fresh", () => {
  assert.equal(evaluateHostObservation(snapshot(), -1).status, "unknown");
  assert.equal(evaluateHostObservation(null, 0).status, "unknown");
  assert.equal(formatSampleAge(null), "Время снимка некорректно");
  assert.equal(formatSampleAge(125), "2 мин назад");
});

test("historical coverage distinguishes absent, partial, complete, and corrupt windows", () => {
  assert.equal(formatHistoryCoverage({
    sample_count: 0,
    covered_minutes: 0,
    expected_minutes: 60,
    complete: false,
  }), "нет данных");
  assert.equal(formatHistoryCoverage({
    sample_count: 120,
    covered_minutes: 30,
    expected_minutes: 60,
    complete: false,
  }), "50 % истории");
  assert.equal(formatHistoryCoverage({
    sample_count: 720,
    covered_minutes: 60,
    expected_minutes: 60,
    complete: true,
  }), "полная история");
  assert.equal(formatHistoryCoverage({
    sample_count: 1,
    covered_minutes: 61,
    expected_minutes: 60,
    complete: false,
  }), "история некорректна");
});

test("project conditions retain last-known meaning without staying green when stale", () => {
  assert.deepEqual(projectConditionPresentation("healthy", "fresh"), {
    state: "healthy",
    label: "● Работает",
  });
  assert.deepEqual(projectConditionPresentation("healthy", "stale"), {
    state: "stale",
    label: "● Работает · данные устарели",
  });
  assert.deepEqual(projectConditionPresentation("down", "signal_lost"), {
    state: "signal_lost",
    label: "× Недоступен · нет свежего сигнала",
  });
});

test("mutation status labels stay explicit for recovery and unknown states", () => {
  assert.deepEqual(mutationStatePresentation("running"), {
    state: "running",
    label: "↻ Выполняется",
  });
  assert.deepEqual(mutationStatePresentation("needs_reconcile"), {
    state: "needs_reconcile",
    label: "△ Требует сверки",
  });
  assert.deepEqual(mutationStatePresentation("rolled_back"), {
    state: "rolled_back",
    label: "△ Выполнен откат",
  });
  assert.deepEqual(mutationStatePresentation("invented"), {
    state: "unknown",
    label: "? Неизвестно",
  });
  assert.equal(operationKindLabel("backup_only"), "резервная копия");
  assert.equal(operationPhaseLabel("health_checking"), "Проверка здоровья");
  assert.equal(operationPhaseLabel("invented"), "Неизвестная фаза");
  assert.deepEqual(operationResultPresentation("failed"), {
    state: "error",
    label: "× Ошибка",
  });
  assert.deepEqual(operationResultPresentation("manual_recovery_required"), {
    state: "error",
    label: "× Требуется восстановление",
  });
});

test("repository history reports only fully covered size changes", () => {
  const hour = 60 * 60_000;
  const samples = [
    { observed_at_ms: 0, total_bytes: 100 },
    { observed_at_ms: hour, total_bytes: 120 },
    { observed_at_ms: hour * 2, total_bytes: 90 },
  ];
  assert.equal(repositorySizeChange(samples, hour), -30);
  assert.equal(repositorySizeChange(samples, hour * 2), -10);
  assert.equal(repositorySizeChange(samples, hour * 3), null);
  assert.equal(repositorySizeChange([{ observed_at_ms: 0, total_bytes: 100 }], hour), null);
  assert.equal(repositorySizeChange([{ observed_at_ms: 0, total_bytes: -1 }], hour), null);
  assert.equal(repositorySizeChange([samples[1], samples[0], samples[2]], hour), null);
});

test("notification delivery preserves ambiguous and terminal outcomes", () => {
  assert.deepEqual(notificationStatePresentation("delivered"), {
    state: "fresh",
    label: "Доставлено",
  });
  assert.deepEqual(notificationStatePresentation("delivery_unknown"), {
    state: "error",
    label: "Исход неизвестен",
  });
  assert.deepEqual(notificationStatePresentation("delivered_possible_duplicate"), {
    state: "partial",
    label: "Возможен дубль",
  });
  assert.deepEqual(notificationStatePresentation("invented"), {
    state: "unknown",
    label: "Неизвестно",
  });
  assert.equal(notificationKindLabel("dependency_checks_failed"), "Проверки зависимостей упали");
  assert.equal(
    notificationKindLabel("dependency_checks_recovered"),
    "Проверки зависимостей восстановлены",
  );
  assert.equal(notificationKindLabel("invented"), "Неизвестное событие");
});

test("workflow overview accepts only compact deployment summaries", () => {
  const deployment = {
    project_id: "rimg",
    source_sha: "a".repeat(40),
    attempt_number: 1,
    state: "needs_reconcile",
    current_stage: "cutover",
    completed_stages: 3,
    total_stages: 5,
    duration_ms: 12_000,
    test_duration_ms: 4_000,
    release_size_bytes: 1_048_576,
    updated_at_ms: 20,
  };
  const overview = {
    schema_version: 2,
    generated_at_ms: 30,
    truncated: false,
    deployments: [deployment],
  };
  assert.equal(validWorkflowOverview(overview), true);
  assert.deepEqual(workflowAttemptPresentation("needs_reconcile"), {
    state: "needs_reconcile",
    label: "△ Требует сверки",
  });
  assert.equal(workflowCurrentStepLabel(deployment), "Переключение трафика");
  assert.equal(workflowCurrentStepLabel({
    ...deployment,
    state: "failed",
    current_stage: "candidate_health",
  }), "Проверка кандидата");

  assert.equal(validWorkflowOverview({ ...overview, unexpected: true }), false);
  assert.equal(validWorkflowOverview({ ...overview, generated_at_ms: 19 }), false);
  assert.equal(validWorkflowOverview({
    ...overview,
    deployments: [{ ...deployment, current_stage: "invented" }],
  }), false);
  assert.equal(validWorkflowOverview({
    ...overview,
    deployments: [deployment, { ...deployment }],
  }), false);
  assert.deepEqual(workflowAttemptPresentation("invented"), {
    state: "unknown",
    label: "? Неизвестно",
  });
});
