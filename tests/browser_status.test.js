import assert from "node:assert/strict";
import test from "node:test";

import {
  evaluateHostObservation,
  formatSampleAge,
  mutationStatePresentation,
  operationKindLabel,
  operationPhaseLabel,
  projectConditionPresentation,
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
  assert.deepEqual(mutationStatePresentation("invented"), {
    state: "unknown",
    label: "? Неизвестно",
  });
  assert.equal(operationKindLabel("backup_only"), "резервная копия");
  assert.equal(operationPhaseLabel("health_checking"), "Проверка здоровья");
  assert.equal(operationPhaseLabel("invented"), "Неизвестная фаза");
});
