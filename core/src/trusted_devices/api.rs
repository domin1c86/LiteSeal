//! Bounded, typed control requests. Credentials remain in Rust and redirects
//! are rejected, so a response cannot redirect an authorization to another origin.
use liteseal_shared::trusted_device::*;
use reqwest::{Method, RequestBuilder};
use serde::{de::DeserializeOwned, Serialize};
#[derive(Debug)]
pub struct ControlError {
    pub status: Option<u16>,
    pub message: &'static str,
}
impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for ControlError {}
fn invalid() -> ControlError {
    ControlError {
        status: None,
        message: "无效设备授权参数或响应",
    }
}
fn network() -> ControlError {
    ControlError {
        status: None,
        message: "设备请求未确认，请保留原编号后查询或重试",
    }
}
fn id(value: &str) -> Result<(), ControlError> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| invalid())
}
pub struct DeviceControlApi {
    origin: String,
    client: reqwest::Client,
}
impl DeviceControlApi {
    pub fn new(server: &str) -> Result<Self, ControlError> {
        let origin = canonical_origin(server).map_err(|_| invalid())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(20))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| network())?;
        Ok(Self { origin, client })
    }
    fn request(
        &self,
        method: Method,
        path: &str,
        token: &str,
    ) -> Result<RequestBuilder, ControlError> {
        if token.is_empty() || token.len() > 256 {
            return Err(invalid());
        }
        Ok(self
            .client
            .request(method, format!("{}{path}", self.origin))
            .bearer_auth(token))
    }
    async fn send<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T, ControlError> {
        let mut response = request.send().await.map_err(|_| network())?;
        if !response.status().is_success() {
            return Err(ControlError {
                status: Some(response.status().as_u16()),
                message: "设备请求被拒绝，请查询原申请或授权状态",
            });
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_DEVICE_PAGE_BYTES as u64)
        {
            return Err(invalid());
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len().saturating_add(chunk.len()) > MAX_DEVICE_PAGE_BYTES {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| invalid())
    }
    fn body<T: Serialize>(
        &self,
        request: RequestBuilder,
        input: &T,
    ) -> Result<RequestBuilder, ControlError> {
        let body = serde_json::to_vec(input).map_err(|_| invalid())?;
        if body.len() > MAX_DEVICE_EVENT_BYTES {
            return Err(invalid());
        }
        Ok(request
            .header("content-type", "application/json")
            .body(body))
    }
    fn status_origin(&self, status: JoinStatus, id: &str) -> Result<JoinStatus, ControlError> {
        if status.ticket.id != id
            || status.ticket.anchor.origin != self.origin
            || status.ticket.anchor.validate().is_err()
        {
            return Err(invalid());
        }
        Ok(status)
    }
    pub async fn begin(&self, input: &JoinStartRequest) -> Result<JoinStatus, ControlError> {
        id(&input.request_id)?;
        let status: JoinStatus = self
            .send(
                self.body(
                    self.client
                        .post(format!("{}/devices/join_requests", self.origin)),
                    input,
                )?,
            )
            .await?;
        let status = self.status_origin(status, &input.request_id)?;
        if status.ticket.device.encryption_key != input.encryption_key
            || status.ticket.device.signing_key != input.signing_key
            || status.ticket.device_name != input.device_name
        {
            return Err(invalid());
        }
        Ok(status)
    }
    pub async fn status(
        &self,
        token: &str,
        request_id: &str,
        root_device: Option<&str>,
    ) -> Result<JoinStatus, ControlError> {
        id(request_id)?;
        let mut request = self.request(
            Method::GET,
            &format!("/devices/join_requests/{request_id}"),
            token,
        )?;
        if let Some(device) = root_device {
            id(device)?;
            request = request.query(&[("device_id", device)]);
        }
        let response = self.send(request).await?;
        self.status_origin(response, request_id)
    }
    pub async fn list(
        &self,
        token: &str,
        root_device: &str,
    ) -> Result<Vec<JoinStatus>, ControlError> {
        id(root_device)?;
        let statuses: Vec<JoinStatus> = self
            .send(
                self.request(Method::GET, "/devices/join_requests", token)?
                    .query(&[("device_id", root_device)]),
            )
            .await?;
        if statuses.len() > 1 {
            return Err(invalid());
        }
        for status in &statuses {
            self.status_origin(status.clone(), &status.ticket.id)?;
        }
        Ok(statuses)
    }
    pub async fn intent(
        &self,
        token: &str,
        intent: &JoinIntent,
    ) -> Result<JoinStatus, ControlError> {
        id(&intent.id)?;
        let response = self
            .send(self.body(
                self.request(
                    Method::POST,
                    &format!("/devices/join_requests/{}/intent", intent.id),
                    token,
                )?,
                intent,
            )?)
            .await?;
        self.status_origin(response, &intent.id)
    }
    pub async fn challenge(
        &self,
        token: &str,
        request_id: &str,
        device: &str,
        challenge: &Challenge,
    ) -> Result<JoinStatus, ControlError> {
        id(request_id)?;
        id(device)?;
        let response = self
            .send(self.body(
                self.request(
                    Method::POST,
                    &format!("/devices/join_requests/{request_id}/challenge"),
                    token,
                )?,
                &ChallengeSubmission {
                    device_id: device.into(),
                    challenge: challenge.clone(),
                },
            )?)
            .await?;
        self.status_origin(response, request_id)
    }
    pub async fn proof(
        &self,
        token: &str,
        request_id: &str,
        proof: &DeviceProof,
    ) -> Result<JoinStatus, ControlError> {
        id(request_id)?;
        let response = self
            .send(self.body(
                self.request(
                    Method::POST,
                    &format!("/devices/join_requests/{request_id}/proof"),
                    token,
                )?,
                proof,
            )?)
            .await?;
        self.status_origin(response, request_id)
    }
    pub async fn cancel(
        &self,
        token: &str,
        request_id: &str,
        root_device: Option<&str>,
    ) -> Result<JoinStatus, ControlError> {
        id(request_id)?;
        let mut request = self.request(
            Method::DELETE,
            &format!("/devices/join_requests/{request_id}"),
            token,
        )?;
        if let Some(device) = root_device {
            id(device)?;
            request = request.query(&[("device_id", device)]);
        }
        let response = self.send(request).await?;
        self.status_origin(response, request_id)
    }
    pub async fn submit(
        &self,
        token: &str,
        root_device: &str,
        event: &DeviceEvent,
    ) -> Result<DeviceReceipt, ControlError> {
        id(root_device)?;
        let route = if matches!(event.action, DeviceAction::Grant { .. }) {
            "grants"
        } else {
            "revoke"
        };
        let receipt: DeviceReceipt = self
            .send(self.body(
                self.request(Method::POST, &format!("/devices/{route}"), token)?,
                &DeviceEventSubmission {
                    device_id: root_device.into(),
                    event: event.clone(),
                },
            )?)
            .await?;
        if receipt.event_id != event.id
            || receipt.event_hash != event.hash()
            || receipt.accepted_revision != event.revision
            || receipt.current_revision < event.revision
            || receipt.current_revision > MAX_DEVICE_EVENTS
            || receipt.current_hash.len() != 32
            || receipt.current_revision == event.revision && receipt.current_hash != event.hash()
        {
            return Err(invalid());
        }
        Ok(receipt)
    }
    pub async fn manifest(
        &self,
        token: &str,
        account: &str,
        after: u64,
    ) -> Result<DeviceManifestPage, ControlError> {
        id(account)?;
        self.manifest_request(token, &format!("/users/{account}/device_manifest"), after)
            .await
    }
    /// Join-only access to this applicant's own account authorization evidence.
    /// It cannot retrieve message history or another account's directory.
    pub async fn join_manifest(
        &self,
        token: &str,
        request_id: &str,
        after: u64,
    ) -> Result<DeviceManifestPage, ControlError> {
        id(request_id)?;
        self.manifest_request(
            token,
            &format!("/devices/join_requests/{request_id}/manifest"),
            after,
        )
        .await
    }
    async fn manifest_request(
        &self,
        token: &str,
        path: &str,
        after: u64,
    ) -> Result<DeviceManifestPage, ControlError> {
        if after > MAX_DEVICE_EVENTS {
            return Err(invalid());
        }
        let page: DeviceManifestPage = self
            .send(
                self.request(Method::GET, path, token)?
                    .query(&[("after_revision", after)]),
            )
            .await?;
        if page.anchor.origin != self.origin || page.events.len() > 100 {
            return Err(invalid());
        }
        Ok(page) // DeviceTrustStore::import_page validates against the independently pinned anchor.
    }
}
