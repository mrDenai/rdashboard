use std::{convert::Infallible, pin::Pin, sync::Arc};

use axum::response::sse::Event;
use futures_util::Stream;
use serde::Serialize;
use tokio::sync::{Semaphore, broadcast};

use crate::{
    domain::{DashboardEvent, EVENT_PROTOCOL_VERSION, EventEnvelope, ResyncReason},
    store::{ControlStore, EventHistoryWindow, StoreError},
};

const SSE_BROADCAST_CAPACITY: usize = 512;
const SSE_HISTORY_LIMIT: usize = 512;
const SSE_GLOBAL_CONNECTION_LIMIT: usize = 32;

pub type EventStream = Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send + 'static>>;

#[derive(Clone, Debug)]
pub struct EventHub {
    store: ControlStore,
    sender: broadcast::Sender<EventEnvelope>,
    permits: Arc<Semaphore>,
}

impl EventHub {
    pub fn new(store: ControlStore) -> Self {
        let (sender, _) = broadcast::channel(SSE_BROADCAST_CAPACITY);
        Self {
            store,
            sender,
            permits: Arc::new(Semaphore::new(SSE_GLOBAL_CONNECTION_LIMIT)),
        }
    }

    pub fn publish(
        &self,
        emitted_at_ms: i64,
        event: DashboardEvent,
    ) -> Result<EventEnvelope, StoreError> {
        let envelope = self.store.append_event(emitted_at_ms, event)?;
        let _subscriber_count = self.sender.send(envelope.clone());
        Ok(envelope)
    }

    pub fn subscribe(&self, requested_after: RequestedAfter) -> Result<EventStream, HubError> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| HubError::Capacity)?;
        // Subscribe before reading persisted history. Publications racing with the
        // history query are then queued and de-duplicated by the sequence cursor.
        let mut receiver = self.sender.subscribe();
        let initial = self.initial_events(requested_after)?;
        let hub = self.clone();

        let stream = async_stream::stream! {
            let _permit = permit;
            let mut cursor = initial
                .events
                .iter()
                .map(|envelope| envelope.sequence)
                .max();
            if let Some(reset) = initial.empty_history_resync {
                let Ok(event) = to_empty_history_resync_sse(reset) else {
                    return;
                };
                cursor = Some(0);
                yield Ok(event);
            }
            for envelope in initial.events {
                let Ok(event) = to_sse_event(&envelope) else {
                    return;
                };
                yield Ok(event);
            }
            loop {
                match receiver.recv().await {
                    Ok(envelope) => {
                        if cursor.is_some_and(|sequence| envelope.sequence <= sequence) {
                            continue;
                        }
                        if let Some(sequence) = cursor
                            && envelope.sequence > sequence.saturating_add(1)
                        {
                            let Ok(events) = hub.resync_events(
                                Some(sequence),
                                ResyncReason::HistoryUnavailable,
                            ) else {
                                break;
                            };
                            cursor = events.iter().map(|event| event.sequence).max();
                            for envelope in events {
                                let Ok(event) = to_sse_event(&envelope) else {
                                    return;
                                };
                                yield Ok(event);
                            }
                            continue;
                        }
                        let Ok(event) = to_sse_event(&envelope) else {
                            return;
                        };
                        cursor = Some(envelope.sequence);
                        yield Ok(event);
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let Ok(events) = hub.resync_events(cursor, ResyncReason::SubscriberLagged) else {
                            break;
                        };
                        cursor = events.iter().map(|event| event.sequence).max();
                        for envelope in events {
                            let Ok(event) = to_sse_event(&envelope) else {
                                return;
                            };
                            yield Ok(event);
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        };
        Ok(Box::pin(stream))
    }

    fn initial_events(&self, requested: RequestedAfter) -> Result<InitialEvents, HubError> {
        let after = match requested {
            RequestedAfter::Absent | RequestedAfter::Invalid => None,
            RequestedAfter::Sequence(sequence) => Some(sequence),
        };
        let window = self.store.event_history_window(after, SSE_HISTORY_LIMIT)?;
        let Some((oldest, latest)) = window.bounds else {
            let empty_history_resync = match requested {
                RequestedAfter::Absent | RequestedAfter::Sequence(0) => None,
                RequestedAfter::Invalid => Some(EmptyHistoryResync {
                    requested_after: None,
                    reason: ResyncReason::InvalidLastEventId,
                }),
                RequestedAfter::Sequence(sequence) => Some(EmptyHistoryResync {
                    requested_after: Some(sequence),
                    reason: ResyncReason::HistoryUnavailable,
                }),
            };
            return Ok(InitialEvents {
                events: Vec::new(),
                empty_history_resync,
            });
        };
        let events = match requested {
            RequestedAfter::Absent => window.latest_event.into_iter().collect(),
            RequestedAfter::Invalid => {
                Self::resync_from_window(&window, None, ResyncReason::InvalidLastEventId)?
            }
            RequestedAfter::Sequence(after)
                if after > latest || after.saturating_add(1) < oldest =>
            {
                Self::resync_from_window(&window, Some(after), ResyncReason::HistoryUnavailable)?
            }
            RequestedAfter::Sequence(after) => {
                let starts_at_requested_successor = after == latest
                    || window
                        .events_after
                        .first()
                        .is_some_and(|event| event.sequence == after.saturating_add(1));
                let reaches_latest = after == latest
                    || window
                        .events_after
                        .last()
                        .is_some_and(|event| event.sequence == latest);
                let is_contiguous = window
                    .events_after
                    .windows(2)
                    .all(|events| events[1].sequence == events[0].sequence.saturating_add(1));
                if starts_at_requested_successor && reaches_latest && is_contiguous {
                    window.events_after
                } else {
                    Self::resync_from_window(
                        &window,
                        Some(after),
                        ResyncReason::HistoryUnavailable,
                    )?
                }
            }
        };
        Ok(InitialEvents {
            events,
            empty_history_resync: None,
        })
    }

    fn resync_events(
        &self,
        requested_after: Option<u64>,
        reason: ResyncReason,
    ) -> Result<Vec<EventEnvelope>, HubError> {
        let window = self.store.event_history_window(None, SSE_HISTORY_LIMIT)?;
        if window.bounds.is_none() {
            return Ok(Vec::new());
        }
        Self::resync_from_window(&window, requested_after, reason)
    }

    fn resync_from_window(
        window: &EventHistoryWindow,
        requested_after: Option<u64>,
        reason: ResyncReason,
    ) -> Result<Vec<EventEnvelope>, HubError> {
        let (oldest, latest) = window.bounds.ok_or(HubError::EmptyHistoryWindow)?;
        let resync = EventEnvelope {
            version: EVENT_PROTOCOL_VERSION,
            sequence: latest,
            emitted_at_ms: crate::unix_time_ms().map_err(HubError::Clock)?,
            event: DashboardEvent::ResyncRequired {
                requested_after,
                oldest_available: oldest,
                latest_available: latest,
                reason,
            },
        };
        let mut events = vec![resync];
        if let Some(latest) = window.latest_event.clone() {
            events.push(latest);
        }
        Ok(events)
    }
}

struct InitialEvents {
    events: Vec<EventEnvelope>,
    empty_history_resync: Option<EmptyHistoryResync>,
}

#[derive(Clone, Copy)]
struct EmptyHistoryResync {
    requested_after: Option<u64>,
    reason: ResyncReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestedAfter {
    Absent,
    Invalid,
    Sequence(u64),
}

impl RequestedAfter {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Absent,
            Some(value) => value.parse().map_or(Self::Invalid, Self::Sequence),
        }
    }
}

fn to_sse_event(envelope: &EventEnvelope) -> Result<Event, SseEventError> {
    let delivered = DeliveredEventEnvelope {
        version: envelope.version,
        sequence: envelope.sequence,
        emitted_at_ms: envelope.emitted_at_ms,
        delivered_at_ms: crate::unix_time_ms()?,
        event: &envelope.event,
    };
    Ok(Event::default()
        .event(envelope.event.event_name())
        .id(envelope.sequence.to_string())
        .data(serde_json::to_string(&delivered)?))
}

fn to_empty_history_resync_sse(reset: EmptyHistoryResync) -> Result<Event, SseEventError> {
    let event = DashboardEvent::ResyncRequired {
        requested_after: reset.requested_after,
        oldest_available: 0,
        latest_available: 0,
        reason: reset.reason,
    };
    let delivered = DeliveredEventEnvelope {
        version: EVENT_PROTOCOL_VERSION,
        sequence: 0,
        emitted_at_ms: crate::unix_time_ms()?,
        delivered_at_ms: crate::unix_time_ms()?,
        event: &event,
    };
    Ok(Event::default()
        .event(event.event_name())
        .id("0")
        .data(serde_json::to_string(&delivered)?))
}

#[derive(Serialize)]
struct DeliveredEventEnvelope<'a> {
    version: u16,
    sequence: u64,
    emitted_at_ms: i64,
    delivered_at_ms: i64,
    event: &'a DashboardEvent,
}

#[derive(Debug, thiserror::Error)]
enum SseEventError {
    #[error("host clock is before the Unix epoch: {0}")]
    Clock(#[from] std::time::SystemTimeError),
    #[error("SSE event JSON encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("SSE connection capacity is exhausted")]
    Capacity,
    #[error("event store failed: {0}")]
    Store(#[from] StoreError),
    #[error("host clock is before the Unix epoch: {0}")]
    Clock(std::time::SystemTimeError),
    #[error("event history window unexpectedly became empty")]
    EmptyHistoryWindow,
}
