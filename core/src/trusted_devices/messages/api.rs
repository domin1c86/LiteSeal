//! Bound HTTP receipts, no redirect/credential forwarding or unbounded JSON.
use super::Acceptance;
use liteseal_shared::{
    direct_media::{Reference, Submission},
    direct_message::{self as d, Ack, Batch},
    direct_transport::{self as t, Page, Result as Outcome},
    trusted_device::canonical_origin,
};
use reqwest::{Method, RequestBuilder};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
#[path = "history_api.rs"]
mod history_api;
pub use history_api::HistoryAction;
#[derive(Debug)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: &'static str,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ApiError {}
fn invalid() -> ApiError {
    ApiError {
        status: None,
        message: "单聊 v3 参数、范围或响应无法验证",
    }
}
fn network() -> ApiError {
    ApiError {
        status: None,
        message: "单聊 v3 结果未确认，请保留原批次",
    }
}
fn id(value: &str) -> Result<(), ApiError> {
    if uuid::Uuid::parse_str(value)
        .ok()
        .is_none_or(|id| id.to_string() != value)
    {
        Err(invalid())
    } else {
        Ok(())
    }
}
#[derive(Debug, PartialEq, Eq)]
pub enum RemoteState {
    Unknown,
    Cancelled,
    Accepted,
}
/// Only this client can construct a response bound to the request/origin. This
/// wrapper proves the transport binding, not local persistence or a server signature.
pub struct AuthenticatedResult {
    pub(super) outcome: Outcome,
}
impl AuthenticatedResult {
    pub fn state(&self) -> RemoteState {
        match self.outcome {
            Outcome::Unknown { .. } => RemoteState::Unknown,
            Outcome::Cancelled { .. } => RemoteState::Cancelled,
            Outcome::Accepted { .. } => RemoteState::Accepted,
        }
    }
}
pub struct AuthenticatedPage {
    pub(super) page: Page,
}
/// Private page contents bind this response to the requested account/device and
/// origin. The store still verifies signatures, historical evidence and bodies.
pub struct AuthenticatedOperations {
    pub(super) page: liteseal_shared::direct_operation::Page,
    pub(super) origin: String,
    pub(super) account: String,
    pub(super) device: String,
    pub(super) after: i64,
}
pub struct AuthenticatedOperationResult {
    pub(super) outcome: liteseal_shared::direct_operation::Outcome,
    pub(super) origin: String,
    pub(super) account: String,
    pub(super) device: String,
    pub(super) digest: [u8; 32],
}
impl AuthenticatedOperationResult {
    pub fn state(&self) -> RemoteState {
        match self.outcome {
            liteseal_shared::direct_operation::Outcome::Unknown { .. } => RemoteState::Unknown,
            liteseal_shared::direct_operation::Outcome::Cancelled { .. } => RemoteState::Cancelled,
            liteseal_shared::direct_operation::Outcome::Accepted { .. } => RemoteState::Accepted,
        }
    }
}
impl AuthenticatedOperations {
    pub fn len(&self) -> usize {
        self.page.events.len()
    }
    pub fn is_empty(&self) -> bool {
        self.page.events.is_empty()
    }
    pub fn through(&self) -> i64 {
        self.page.through
    }
    pub fn has_more(&self) -> bool {
        self.page.has_more
    }
}
impl AuthenticatedPage {
    pub fn len(&self) -> usize {
        self.page.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.page.items.is_empty()
    }
    pub fn has_more(&self) -> bool {
        self.page.has_more
    }
}
#[derive(Clone)]
pub struct DirectApi {
    origin: String,
    client: reqwest::Client,
}
/// Rust-only routing and public ciphertext reference; no file key or name.
pub struct MediaObject<'a> {
    pub device: &'a str,
    pub id: &'a str,
    pub reference: &'a Reference,
}
impl DirectApi {
    pub(super) async fn audio_reserve(
        &self,
        token: &str,
        admission: &liteseal_shared::voice_call::Admission,
    ) -> Result<liteseal_shared::voice_call::Reservation, ApiError> {
        let result: liteseal_shared::voice_call::Reservation = self
            .json(
                self.request(Method::POST, "/audio/v1/admit", token)?
                    .timeout(std::time::Duration::from_secs(5))
                    .json(admission),
                4096,
            )
            .await?;
        if result.id != admission.header.id
            || result.ticket.len() != 64
            || !result
                .ticket
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        Ok(result)
    }
    pub(super) async fn audio_signal(
        &self,
        token: &str,
        input: &liteseal_shared::voice_call::Submission,
    ) -> Result<(), ApiError> {
        let result: liteseal_shared::voice_call::Receipt = self
            .json(
                self.request(Method::POST, "/audio/v1/signal", token)?
                    .timeout(std::time::Duration::from_secs(5))
                    .json(input),
                4096,
            )
            .await?;
        if result.id != input.envelope.header.id
            || result.sequence != input.envelope.header.sequence
            || result.digest != input.envelope.digest().map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) async fn audio_pending(
        &self,
        token: &str,
        device: &str,
        active: Option<&str>,
    ) -> Result<liteseal_shared::voice_call::Pending, ApiError> {
        let mut request = self
            .request(Method::GET, "/audio/v1/pending", token)?
            .timeout(std::time::Duration::from_secs(5))
            .query(&[("device", device)]);
        if let Some(active) = active {
            request = request.query(&[("active", active)]);
        }
        let result: liteseal_shared::voice_call::Pending = self.json(request, 1024 * 1024).await?;
        if result
            .closed
            .as_deref()
            .is_some_and(|id| Some(id) != active)
        {
            return Err(invalid());
        }
        if let Some(delivery) = &result.delivery {
            if delivery.envelope.header.target.device.device_id != device
                || delivery.admission.header.origin != self.origin
                || delivery.ticket.len() != 64
                || !delivery
                    .ticket
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(invalid());
            }
        }
        Ok(result)
    }
    pub(super) async fn audio_ack(
        &self,
        token: &str,
        input: &liteseal_shared::voice_call::Acknowledge,
    ) -> Result<(), ApiError> {
        let result: liteseal_shared::voice_call::Receipt = self
            .json(
                self.request(Method::POST, "/audio/v1/ack", token)?
                    .timeout(std::time::Duration::from_secs(5))
                    .json(input),
                4096,
            )
            .await?;
        if result.id != input.receipt.id
            || result.sequence != input.receipt.sequence
            || result.digest != input.receipt.digest
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub(super) async fn audio_stop(
        &self,
        token: &str,
        input: &liteseal_shared::voice_call::Stop,
    ) -> Result<(), ApiError> {
        let id: String = self
            .json(
                self.request(Method::POST, "/audio/v1/stop", token)?
                    .timeout(std::time::Duration::from_secs(5))
                    .json(input),
                4096,
            )
            .await?;
        if id != input.admission.header.id {
            return Err(invalid());
        }
        Ok(())
    }
    fn bind_operation(
        &self,
        operation: &liteseal_shared::direct_operation::Operation,
        outcome: liteseal_shared::direct_operation::Outcome,
        allow_unknown: bool,
    ) -> Result<AuthenticatedOperationResult, ApiError> {
        use liteseal_shared::direct_operation::Outcome;
        self.bound_batch(&operation.original)?;
        id(&operation.header.id)?;
        let digest = operation.digest().map_err(|_| invalid())?;
        match &outcome {
            Outcome::Unknown { id, digest: other }
                if allow_unknown && *id == operation.header.id && *other == digest => {}
            Outcome::Cancelled { id, digest: other }
                if *id == operation.header.id && *other == digest => {}
            Outcome::Accepted { receipt }
                if receipt.id == operation.header.id
                    && receipt.digest == digest
                    && receipt.revision == operation.header.revision
                    && receipt.order > 0
                    && (1..=8_640_000_000_000_000).contains(&receipt.accepted_at) => {}
            _ => return Err(invalid()),
        }
        Ok(AuthenticatedOperationResult {
            outcome,
            origin: self.origin.clone(),
            account: operation.original.header.sender.clone(),
            device: operation.original.header.sender_device.clone(),
            digest,
        })
    }
    pub async fn operation_lookup(
        &self,
        token: &str,
        operation: &liteseal_shared::direct_operation::Operation,
    ) -> Result<AuthenticatedOperationResult, ApiError> {
        self.bound_batch(&operation.original)?;
        id(&operation.header.id)?;
        let result = self
            .json(
                self.request(
                    Method::GET,
                    &format!("/direct/v3/operations/{}/outcome", operation.header.id),
                    token,
                )?
                .query(&[
                    (
                        "device_id",
                        operation.original.header.sender_device.as_str(),
                    ),
                    (
                        "digest",
                        &hex::encode(operation.digest().map_err(|_| invalid())?),
                    ),
                ]),
                4096,
            )
            .await?;
        self.bind_operation(operation, result, true)
    }
    pub async fn operation_publish(
        &self,
        token: &str,
        operation: &liteseal_shared::direct_operation::Operation,
    ) -> Result<AuthenticatedOperationResult, ApiError> {
        self.bound_batch(&operation.original)?;
        id(&operation.header.id)?;
        let wire = operation.to_wire().map_err(|_| invalid())?;
        let receipt = self
            .json(
                self.request(Method::POST, "/direct/v3/operations", token)?
                    .header("content-type", "application/json")
                    .body(wire),
                4096,
            )
            .await?;
        self.bind_operation(
            operation,
            liteseal_shared::direct_operation::Outcome::Accepted { receipt },
            false,
        )
    }
    pub async fn operation_cancel(
        &self,
        token: &str,
        operation: &liteseal_shared::direct_operation::Operation,
    ) -> Result<AuthenticatedOperationResult, ApiError> {
        self.bound_batch(&operation.original)?;
        id(&operation.header.id)?;
        let wire = operation.to_wire().map_err(|_| invalid())?;
        let result = self
            .json(
                self.request(
                    Method::POST,
                    &format!("/direct/v3/operations/{}/cancel", operation.header.id),
                    token,
                )?
                .header("content-type", "application/json")
                .body(wire),
                4096,
            )
            .await?;
        self.bind_operation(operation, result, false)
    }
    pub async fn operations(
        &self,
        token: &str,
        account: &str,
        device: &str,
        after: i64,
        limit: usize,
    ) -> Result<AuthenticatedOperations, ApiError> {
        use liteseal_shared::direct_operation as op;
        id(account)?;
        id(device)?;
        if after < 0 || !(1..=op::MAX_PAGE).contains(&limit) {
            return Err(invalid());
        }
        let page: op::Page = self
            .json(
                self.request(Method::GET, "/direct/v3/operations", token)?
                    .query(&[
                        ("device_id", device),
                        ("after", &after.to_string()),
                        ("limit", &limit.to_string()),
                    ]),
                op::MAX_PAGE_BYTES,
            )
            .await?;
        if page.events.len() > limit
            || page.events.is_empty() && (page.has_more || page.through != after)
            || page.events.last().is_some_and(|e| e.order != page.through)
        {
            return Err(invalid());
        }
        let mut previous = after;
        let mut ids = HashSet::new();
        for event in &page.events {
            self.bound_batch(&event.operation.original)?;
            id(&event.operation.header.id)?;
            event.operation.to_wire().map_err(|_| invalid())?;
            if event.order <= previous
                || !ids.insert(&event.operation.header.id)
                || !(1..=8_640_000_000_000_000).contains(&event.accepted_at)
                || !event
                    .operation
                    .payloads
                    .iter()
                    .any(|p| p.account == account && p.device == device)
            {
                return Err(invalid());
            }
            previous = event.order;
        }
        Ok(AuthenticatedOperations {
            page,
            origin: self.origin.clone(),
            account: account.into(),
            device: device.into(),
            after,
        })
    }
    pub fn new(server: &str) -> Result<Self, ApiError> {
        let origin = canonical_origin(server).map_err(|_| invalid())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| network())?;
        Ok(Self { origin, client })
    }
    fn request(&self, method: Method, path: &str, token: &str) -> Result<RequestBuilder, ApiError> {
        if token.is_empty() || token.len() > 256 || token.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(invalid());
        }
        Ok(self
            .client
            .request(method, format!("{}{path}", self.origin))
            .bearer_auth(token))
    }
    async fn json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        max: usize,
    ) -> Result<T, ApiError> {
        let mut response = request.send().await.map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "单聊 v3 请求被拒绝，请查询原结果",
            });
        }
        if response.content_length().is_some_and(|n| n > max as u64) {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len().saturating_add(chunk.len()) > max {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
    fn bound_batch(&self, batch: &Batch) -> Result<Vec<u8>, ApiError> {
        if batch.header.origin != self.origin {
            return Err(invalid());
        }
        for value in [
            &batch.header.id,
            &batch.header.sender,
            &batch.header.peer,
            &batch.header.sender_device,
        ] {
            id(value)?;
        }
        batch.to_wire().map_err(|_| invalid())
    }
    fn bind_result(
        &self,
        batch: &Batch,
        outcome: Outcome,
        allow_unknown: bool,
    ) -> Result<AuthenticatedResult, ApiError> {
        let digest = batch.digest().map_err(|_| invalid())?;
        match &outcome {
            Outcome::Unknown {
                id,
                digest: digest_,
            } if allow_unknown && *id == batch.header.id && *digest_ == digest => {}
            Outcome::Cancelled {
                id,
                digest: digest_,
            } if *id == batch.header.id && *digest_ == digest => {}
            Outcome::Accepted {
                receipt,
                acknowledgements,
            } => {
                Acceptance::from_authenticated_response(
                    batch,
                    &receipt.id,
                    receipt.digest,
                    receipt.accepted_at,
                )
                .map_err(|_| invalid())?;
                if acknowledgements.len() > d::MAX_TARGETS {
                    return Err(invalid());
                }
                let mut targets = HashSet::new();
                for ack in acknowledgements {
                    if ack.to_wire().is_err()
                        || ack.origin != self.origin
                        || ack.id != batch.header.id
                        || ack.batch != digest
                        || !targets.insert((&ack.account, &ack.device))
                        || !batch
                            .payloads
                            .iter()
                            .any(|p| p.account == ack.account && p.device == ack.device)
                    {
                        return Err(invalid());
                    }
                }
            }
            _ => return Err(invalid()),
        }
        Ok(AuthenticatedResult { outcome })
    }
    pub async fn lookup(
        &self,
        token: &str,
        batch: &Batch,
    ) -> Result<AuthenticatedResult, ApiError> {
        self.bound_batch(batch)?;
        let outcome = self
            .json(
                self.request(
                    Method::GET,
                    &format!("/direct/v3/batches/{}", batch.header.id),
                    token,
                )?
                .query(&[
                    ("device_id", batch.header.sender_device.as_str()),
                    (
                        "digest",
                        &hex::encode(batch.digest().map_err(|_| invalid())?),
                    ),
                ]),
                32 * 1024,
            )
            .await?;
        self.bind_result(batch, outcome, true)
    }
    async fn submit(
        &self,
        token: &str,
        batch: &Batch,
        path: &str,
    ) -> Result<AuthenticatedResult, ApiError> {
        let wire = self.bound_batch(batch)?;
        let outcome = self
            .json(
                self.request(Method::POST, path, token)?
                    .header("content-type", "application/json")
                    .body(wire),
                32 * 1024,
            )
            .await?;
        self.bind_result(batch, outcome, false)
    }
    pub async fn publish(
        &self,
        token: &str,
        batch: &Batch,
    ) -> Result<AuthenticatedResult, ApiError> {
        self.submit(token, batch, "/direct/v3/batches").await
    }
    /// The immutable media wrapper binds the original batch and ciphertext.
    /// It contains no plaintext file metadata or file key.
    pub async fn publish_media(
        &self,
        token: &str,
        submission: &Submission,
    ) -> Result<AuthenticatedResult, ApiError> {
        self.bound_batch(&submission.batch)?;
        submission.verify_binding().map_err(|_| invalid())?;
        let wire = submission.to_wire().map_err(|_| invalid())?;
        let outcome = self
            .json(
                self.request(Method::POST, "/direct/v3/media/batches", token)?
                    .header("content-type", "application/json")
                    .body(wire),
                32 * 1024,
            )
            .await?;
        self.bind_result(&submission.batch, outcome, false)
    }
    pub async fn create_media(
        &self,
        token: &str,
        device: &str,
        object: &str,
        peer: &str,
        reference: &Reference,
    ) -> Result<(), ApiError> {
        id(device)?;
        id(object)?;
        id(peer)?;
        reference
            .validate(d::Kind::Attachment)
            .map_err(|_| invalid())?;
        let returned: String = self
            .json(
                self.request(Method::POST, "/direct/v3/media/objects", token)?
                    .json(&serde_json::json!({
                        "device_id": device, "id": object, "peer": peer,
                        "size": reference.size, "hash": reference.hash,
                    })),
                128,
            )
            .await?;
        if returned != object {
            return Err(invalid());
        }
        Ok(())
    }
    fn media_request(
        &self,
        method: Method,
        token: &str,
        object: &MediaObject<'_>,
        part: i32,
    ) -> Result<(RequestBuilder, usize), ApiError> {
        id(object.device)?;
        id(object.id)?;
        object
            .reference
            .validate(d::Kind::Attachment)
            .map_err(|_| invalid())?;
        let len = object.reference.chunk_len(part).map_err(|_| invalid())?;
        Ok((
            self.request(
                method,
                &format!("/direct/v3/media/objects/{}/{part}", object.id),
                token,
            )?
            .query(&[("device_id", object.device)]),
            len,
        ))
    }
    /// A response loss leaves this exact chunk safe to retry under the same id.
    pub async fn upload_media_chunk(
        &self,
        token: &str,
        object: &MediaObject<'_>,
        part: i32,
        bytes: Vec<u8>,
    ) -> Result<(), ApiError> {
        let (request, len) = self.media_request(Method::PUT, token, object, part)?;
        if bytes.len() != len {
            return Err(invalid());
        }
        let response = request
            .header("content-type", "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "单聊 v3 分块尚未确认，保留原编号和密文",
            });
        }
        Ok(())
    }
    /// Exact bounded ciphertext only. The caller must authenticate the complete
    /// object against the descriptor before caching or exposing plaintext.
    pub async fn download_media_chunk(
        &self,
        token: &str,
        object: &MediaObject<'_>,
        part: i32,
    ) -> Result<Vec<u8>, ApiError> {
        let (request, len) = self.media_request(Method::GET, token, object, part)?;
        let mut response = request.send().await.map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "单聊 v3 原附件不可用或请求被拒绝",
            });
        }
        if response.content_length().is_some_and(|n| n != len as u64) {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(len);
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len().saturating_add(chunk.len()) > len {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != len {
            return Err(invalid());
        }
        Ok(bytes)
    }
    pub async fn cancel(
        &self,
        token: &str,
        batch: &Batch,
    ) -> Result<AuthenticatedResult, ApiError> {
        self.submit(token, batch, "/direct/v3/cancel").await
    }
    pub async fn pending(
        &self,
        token: &str,
        account: &str,
        device: &str,
        limit: usize,
    ) -> Result<AuthenticatedPage, ApiError> {
        id(account)?;
        id(device)?;
        if !(1..=t::MAX_PAGE_ITEMS).contains(&limit) {
            return Err(invalid());
        }
        let page: Page = self
            .json(
                self.request(Method::GET, "/direct/v3/pending", token)?
                    .query(&[("device_id", device), ("limit", &limit.to_string())]),
                t::MAX_PAGE_BYTES,
            )
            .await?;
        if page.items.len() > limit || page.items.is_empty() && page.has_more {
            return Err(invalid());
        }
        let mut previous = 0;
        let mut ids = HashSet::new();
        for item in &page.items {
            self.bound_batch(&item.batch)?;
            if item.order <= previous
                || !ids.insert(&item.batch.header.id)
                || !item
                    .batch
                    .payloads
                    .iter()
                    .any(|p| p.account == account && p.device == device)
            {
                return Err(invalid());
            }
            previous = item.order;
            Acceptance::from_authenticated_response(
                &item.batch,
                &item.receipt.id,
                item.receipt.digest,
                item.receipt.accepted_at,
            )
            .map_err(|_| invalid())?;
        }
        Ok(AuthenticatedPage { page })
    }
    pub async fn ack(&self, token: &str, ack: &Ack) -> Result<(), ApiError> {
        id(&ack.id)?;
        id(&ack.account)?;
        id(&ack.device)?;
        if ack.origin != self.origin {
            return Err(invalid());
        }
        let wire = ack.to_wire().map_err(|_| invalid())?;
        let response = self
            .request(Method::POST, "/direct/v3/ack", token)?
            .header("content-type", "application/json")
            .body(wire)
            .send()
            .await
            .map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "单聊 v3 ACK 尚未确认，保留原签名",
            });
        }
        Ok(())
    }
}
