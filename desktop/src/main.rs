use liteseal_desktop::{
    protocol::{self, Request, Response},
    AppState,
};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

async fn read_frame(
    reader: &mut (impl AsyncBufReadExt + Unpin),
) -> Result<Option<Vec<u8>>, String> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|e| e.to_string())?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err("Incomplete request frame".into())
            };
        }
        let end = available.iter().position(|b| *b == b'\n');
        let count = end.map_or(available.len(), |i| i + 1);
        if frame.len() + count > protocol::MAX_FRAME_BYTES {
            return Err("Request frame exceeds limit".into());
        }
        frame.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(frame));
        }
    }
}

async fn run() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    // This override is only accepted on the executable command line, never via renderer IPC.
    let mut args = std::env::args().skip(1);
    let db_path = match args.next().as_deref() {
        Some("--db-path") => PathBuf::from(args.next().ok_or("Missing database path")?),
        None => dirs::data_dir()
            .ok_or("Cannot find data directory")?
            .join("liteseal")
            .join("data.db"),
        _ => return Err("Unknown desktop argument".into()),
    };
    if args.next().is_some() {
        return Err("Unexpected desktop argument".into());
    }
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let state = Arc::new(AppState::new(
        db_path.to_str().ok_or("Invalid database path")?,
    )?);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(128);
    let mut writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        stdout
            .write_all(format!("{{\"ready\":true,\"version\":{}}}\n", protocol::VERSION).as_bytes())
            .await?;
        stdout.flush().await?;
        while let Some(mut bytes) = rx.recv().await {
            bytes.push(b'\n');
            stdout.write_all(&bytes).await?;
            stdout.flush().await?;
        }
        Ok::<_, std::io::Error>(())
    });
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut jobs = tokio::task::JoinSet::new();
    let slots = Arc::new(tokio::sync::Semaphore::new(128));
    loop {
        let frame = tokio::select! {
            frame = read_frame(&mut reader) => frame?,
            _ = &mut writer => return Err("Desktop output pipe closed".into()),
        };
        let Some(frame) = frame else { break };
        while jobs.try_join_next().is_some() {}
        match serde_json::from_slice::<Request>(&frame) {
            Ok(request) => {
                let permit = slots.clone().try_acquire_owned();
                if let Ok(permit) = permit {
                    let state = state.clone();
                    let tx = tx.clone();
                    jobs.spawn(async move {
                        let _permit = permit;
                        let result = tokio::time::timeout(Duration::from_secs(60), protocol::dispatch(request.command, &state))
                            .await.unwrap_or_else(|_| Err("Operation timed out; its outcome may be unknown. Do not automatically retry.".into()));
                        let response = Response::from_result(Some(request.id), result);
                        let _ = tx.send(serde_json::to_vec(&response).expect("Serializable response")).await;
                    });
                } else {
                    let response = Response::from_result(
                        Some(request.id),
                        Err("Too many pending requests".into()),
                    );
                    tx.send(serde_json::to_vec(&response).unwrap())
                        .await
                        .map_err(|e| e.to_string())?;
                }
            }
            Err(_) => {
                // Never echo invalid input: requests may contain passwords or secret keys.
                let id = serde_json::from_slice::<serde_json::Value>(&frame)
                    .ok()
                    .and_then(|v| v.get("id")?.as_u64());
                let response =
                    Response::from_result(id, Err("Invalid command or arguments".into()));
                tx.send(serde_json::to_vec(&response).unwrap())
                    .await
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    jobs.abort_all();
    while jobs.join_next().await.is_some() {}
    let _ = tokio::time::timeout(Duration::from_secs(2), state.client.disconnect()).await;
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    Ok(())
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().expect("Cannot start desktop runtime");
    let result = runtime.block_on(run());
    if let Err(ref error) = result {
        eprintln!("Desktop service: {error}");
    }
    // stdin is a blocking OS read on Tokio's pool. Never wait indefinitely for it
    // during a broken-pipe shutdown; no business work survives the desktop process.
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}
