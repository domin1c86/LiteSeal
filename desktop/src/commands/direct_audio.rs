//! Scoped audio business commands; no secret capability or wire is public.
use super::*;
use liteseal_core::trusted_devices::messages::coordinator::{AudioPoll, AudioTarget, AudioView};
use liteseal_shared::voice_call::{Kind as AudioKind, Signal};

fn scoped(state: &AppState, scope: &str) -> Result<Context, String> {
    let ctx = context(state)?;
    if ctx.key != scope || ctx.selected.identity.token.is_empty() {
        return Err(bad());
    }
    Ok(ctx)
}
pub async fn targets(
    state: &AppState,
    scope: String,
    peer: String,
) -> Result<Vec<AudioTarget>, String> {
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.audio_targets(&peer, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub async fn begin(
    state: &AppState,
    scope: String,
    peer: String,
    device: String,
) -> Result<AudioView, String> {
    let ctx = scoped(state, &scope)?;
    let result = bounded(ctx.actor.begin_audio(&peer, &device, &ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(result)
}
pub fn prepare(
    state: &AppState,
    scope: String,
    id: String,
    kind: AudioKind,
    sdp: Option<String>,
) -> Result<String, String> {
    let ctx = scoped(state, &scope)?;
    let handle = ctx
        .actor
        .prepare_audio_signal(&id, kind, sdp, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(handle)
}
pub async fn publish(state: &AppState, scope: String, handle: String) -> Result<(), String> {
    let ctx = scoped(state, &scope)?;
    bounded(ctx.actor.publish_audio_signal(&handle, &ctx.keys)).await?;
    current(state, &ctx)
}
pub fn open(state: &AppState, scope: String, handle: String) -> Result<Signal, String> {
    let ctx = scoped(state, &scope)?;
    let signal = ctx
        .actor
        .open_audio_signal(&handle, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)?;
    Ok(signal)
}
pub fn retire(state: &AppState, scope: String, id: String) -> Result<(), String> {
    let ctx = scoped(state, &scope)?;
    ctx.actor
        .retire_audio(&id, &ctx.keys)
        .map_err(|e| e.to_string())?;
    current(state, &ctx)
}
#[derive(Serialize, Default)]
pub struct Report {
    pub scope: Option<String>,
    #[serde(flatten)]
    pub audio: AudioPoll,
}
pub async fn process(state: &AppState) -> Result<Report, String> {
    let Some(selected) = normal::capture(state)? else {
        return Ok(Report::default());
    };
    if selected.protocol != "v3" || selected.identity.token.is_empty() {
        return Ok(Report::default());
    }
    let ctx = context(state)?;
    let audio = bounded(ctx.actor.poll_audio(&ctx.keys)).await?;
    current(state, &ctx)?;
    Ok(Report {
        scope: Some(ctx.key),
        audio,
    })
}
