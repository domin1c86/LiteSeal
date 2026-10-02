//! Per-identity bounded round-robin lanes. Intent/pause is persisted in media
//! jobs; retry timing is transient and resets when a task revision changes.
use super::*;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
#[derive(Default)]
pub(super) struct State {
    cursors: [Option<String>; 2],
    retries: [HashMap<String, Retry>; 2],
}
struct Retry {
    revision: (u64, u64),
    failures: u32,
    due: Instant,
}
struct Candidate {
    id: String,
    revision: (u64, u64),
    cancel: bool,
    blob: bool,
}
#[derive(Default, Debug, Serialize)]
pub struct Drive {
    pub task: Option<Progress>,
    pub media: Option<MediaProgress>,
}
impl State {
    fn pick(&mut self, lane: usize, rows: &[Candidate], now: Instant) -> Option<usize> {
        self.retries[lane].retain(|id, _| rows.iter().any(|r| r.id == *id));
        let eligible = |row: &Candidate| {
            self.retries[lane]
                .get(&row.id)
                .is_none_or(|r| r.revision != row.revision || r.due <= now)
        };
        let has_cancel = rows.iter().any(|r| r.cancel && eligible(r));
        let mut ready: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, r)| eligible(r) && (!has_cancel || r.cancel))
            .map(|(i, _)| i)
            .collect();
        ready.sort_by(|a, b| rows[*a].id.cmp(&rows[*b].id));
        let index = ready
            .iter()
            .copied()
            .find(|i| {
                self.cursors[lane]
                    .as_ref()
                    .is_none_or(|last| rows[*i].id > *last)
            })
            .or_else(|| ready.first().copied())?;
        self.cursors[lane] = Some(rows[index].id.clone());
        Some(index)
    }
    fn result(&mut self, lane: usize, row: &Candidate, progress: bool, now: Instant) {
        if progress {
            self.retries[lane].remove(&row.id);
            return;
        }
        let failures = self.retries[lane]
            .get(&row.id)
            .filter(|r| r.revision == row.revision)
            .map_or(1, |r| r.failures.saturating_add(1));
        let seconds = 2u64.saturating_pow(failures.min(6)).min(60);
        self.retries[lane].insert(
            row.id.clone(),
            Retry {
                revision: row.revision,
                failures,
                due: now + Duration::from_secs(seconds),
            },
        );
    }
}
impl MessageCoordinator {
    /// Text lane advances text and cancellation fences. Media lane advances
    /// only explicit send/download intent, or an already prepared original.
    pub async fn drive(&self, media_lane: bool, keys: &KeyPair) -> Result<Drive> {
        let lease = self.lease(keys)?;
        let tasks = self.with(&lease, |s| s.tasks(keys))?;
        let jobs = self.with(&lease, |s| s.media_tasks(keys))?;
        let mut rows = Vec::new();
        for task in &tasks {
            if !matches!(
                task.state,
                TaskState::Prepared | TaskState::Publishing | TaskState::Conflict
            ) {
                continue;
            }
            let job = jobs.iter().find(|j| j.id == task.id);
            let allowed = if media_lane {
                task.kind != Kind::Text && !task.cancel_requested && job.is_some_and(|j| !j.paused)
            } else {
                task.cancel_requested || task.kind == Kind::Text
            };
            if allowed {
                rows.push(Candidate {
                    id: task.id.clone(),
                    revision: (task.revision, job.map_or(0, |j| j.revision)),
                    cancel: task.cancel_requested,
                    blob: false,
                });
            }
        }
        if media_lane {
            for job in &jobs {
                if job.requested
                    && !job.paused
                    && matches!(
                        job.phase,
                        media::Phase::Staged | media::Phase::Uploaded | media::Phase::Downloading
                    )
                {
                    rows.push(Candidate {
                        id: job.id.clone(),
                        revision: (0, job.revision),
                        cancel: false,
                        blob: true,
                    });
                }
            }
        }
        let picked = self
            .schedule
            .lock()
            .map_err(|_| local("schedule".into()))?
            .pick(usize::from(media_lane), &rows, Instant::now());
        let Some(index) = picked else {
            return Ok(Drive::default());
        };
        let row = &rows[index];
        let result = if row.blob {
            let job = self.with(&lease, |s| s.media_task(&row.id, keys))?;
            if job.phase == media::Phase::Uploaded {
                self.prepare_media(&row.id, keys).await.map(|p| Drive {
                    task: None,
                    media: Some(MediaProgress {
                        task: job,
                        condition: p.condition,
                        http_status: p.http_status,
                    }),
                })
            } else {
                self.media_step(&row.id, keys).await.map(|p| Drive {
                    task: None,
                    media: Some(p),
                })
            }
        } else {
            self.step(&row.id, keys).await.map(|p| Drive {
                task: Some(p),
                media: None,
            })
        };
        let result = match result {
            Err(error) => match self.with(&lease, |s| s.media_task(&row.id, keys)) {
                Ok(job) if job.paused => Ok(Drive {
                    task: None,
                    media: Some(MediaProgress {
                        task: job,
                        condition: Condition::Paused,
                        http_status: None,
                    }),
                }),
                _ => Err(error),
            },
            ok => ok,
        };
        let progress = result.as_ref().is_ok_and(|r| {
            let condition = r
                .task
                .as_ref()
                .map(|p| &p.condition)
                .or_else(|| r.media.as_ref().map(|p| &p.condition));
            matches!(
                condition,
                Some(
                    Condition::Uploading
                        | Condition::Uploaded
                        | Condition::Downloading
                        | Condition::Cached
                        | Condition::Prepared
                        | Condition::Accepted
                        | Condition::Cancelled
                )
            )
        });
        self.schedule
            .lock()
            .map_err(|_| local("schedule".into()))?
            .result(usize::from(media_lane), row, progress, Instant::now());
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_backoff_and_cancel_revision_do_not_starve_another_task() {
        let mut state = State::default();
        let now = Instant::now();
        let mut rows = vec![
            Candidate {
                id: "a".into(),
                revision: (1, 1),
                cancel: false,
                blob: false,
            },
            Candidate {
                id: "b".into(),
                revision: (1, 1),
                cancel: false,
                blob: false,
            },
        ];
        assert_eq!(state.pick(0, &rows, now), Some(0));
        state.result(0, &rows[0], false, now);
        assert_eq!(state.pick(0, &rows, now), Some(1));
        state.result(0, &rows[1], false, now);
        assert_eq!(state.pick(0, &rows, now), None);
        rows[0].revision.0 += 1;
        rows[0].cancel = true;
        assert_eq!(state.pick(0, &rows, now), Some(0));
        assert_eq!(state.pick(0, &rows, now + Duration::from_secs(2)), Some(0));
        rows[0].cancel = false;
        state.result(0, &rows[0], true, now);
        assert_eq!(state.pick(0, &rows, now + Duration::from_secs(2)), Some(1));
    }
    #[test]
    fn lanes_keep_independent_retry_state_and_backoff_is_bounded() {
        let now = Instant::now();
        let mut state = State::default();
        let row = Candidate {
            id: "text".into(),
            revision: (1, 0),
            cancel: false,
            blob: false,
        };
        for _ in 0..10 {
            state.result(0, &row, false, now);
        }
        assert_eq!(
            state.retries[0]["text"].due.duration_since(now),
            Duration::from_secs(60)
        );
        assert_eq!(state.pick(1, &[], now), None);
        assert_eq!(state.pick(0, &[row], now + Duration::from_secs(59)), None);
    }
}
