use liteseal_shared::group::*;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Debug)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: String,
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for ApiError {}
fn network() -> ApiError {
    ApiError {
        status: None,
        message: "群请求失败，请保留原任务后重试".into(),
    }
}
fn valid_id(value: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ApiError {
            status: None,
            message: "无效群或消息编号".into(),
        })
}
pub(super) fn canonical_origin(server: &str) -> Result<String, String> {
    let mut origin = url::Url::parse(&crate::api::normalize_server_url(server)?)
        .map_err(|_| "无效服务器地址")?;
    if !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err("服务器地址不能含凭据、查询或片段".into());
    }
    let path = origin.path().trim_end_matches('/').to_string();
    origin.set_path(&path);
    Ok(origin.to_string().trim_end_matches('/').to_string())
}

/// Credentials remain in Rust memory; never serialize or log this object.
pub struct GroupApi {
    pub(super) origin: String,
    token: String,
    device: String,
    client: reqwest::Client,
}
impl GroupApi {
    pub fn new(server: &str, token: String, device: String) -> Result<Self, String> {
        let origin = canonical_origin(server)?;
        if device.is_empty() || token.is_empty() {
            return Err("群请求需要账号会话和设备".into());
        }
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "无法创建群请求客户端")?;
        Ok(Self {
            origin,
            token,
            device,
            client,
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.origin))
            .bearer_auth(&self.token)
    }
    async fn decode<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, ApiError> {
        let status = response.status();
        if !status.is_success() {
            return Err(ApiError {
                status: Some(status.as_u16()),
                message: format!(
                    "群请求被拒绝（{}），请检查会话、成员版本或待收限额",
                    status.as_u16()
                ),
            });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                return Err(ApiError {
                    status: None,
                    message: "群响应超出大小限制".into(),
                });
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|_| ApiError {
            status: None,
            message: "群响应格式无效".into(),
        })
    }
    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, ApiError> {
        Self::decode(
            self.request(reqwest::Method::POST, path)
                .json(body)
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn list(&self, after: Option<&str>) -> Result<GroupListPage, ApiError> {
        if let Some(id) = after {
            valid_id(id)?;
        }
        let mut query = vec![("device_id", self.device.as_str())];
        if let Some(id) = after {
            query.push(("after_id", id));
        }
        Self::decode(
            self.request(reqwest::Method::GET, "/groups")
                .query(&query)
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn invites(&self, after: Option<&str>) -> Result<GroupInvitePage, ApiError> {
        if let Some(id) = after {
            valid_id(id)?;
        }
        let mut query = vec![("device_id", self.device.as_str())];
        if let Some(id) = after {
            query.push(("after_id", id));
        }
        Self::decode(
            self.request(reqwest::Method::GET, "/group-invites")
                .query(&query)
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn changes(&self, group: &str, after: u64) -> Result<GroupEventPage, ApiError> {
        valid_id(group)?;
        Self::decode(
            self.request(reqwest::Method::GET, &format!("/groups/{group}/changes"))
                .query(&[
                    ("device_id", self.device.clone()),
                    ("after_epoch", after.to_string()),
                ])
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn change(
        &self,
        change: &GroupChange,
        create: bool,
    ) -> Result<GroupChange, ApiError> {
        valid_id(&change.group_id)?;
        let path = if create {
            "/groups".into()
        } else {
            format!("/groups/{}/changes", change.group_id)
        };
        self.post(
            &path,
            &GroupChangeRequest {
                device_id: self.device.clone(),
                change: change.clone(),
            },
        )
        .await
    }
    pub async fn invite(&self, invite: &GroupInvite) -> Result<GroupInviteStatus, ApiError> {
        valid_id(&invite.group_id)?;
        valid_id(&invite.id)?;
        self.post(
            &format!("/groups/{}/invites", invite.group_id),
            &GroupInviteRequest {
                device_id: self.device.clone(),
                invite: invite.clone(),
            },
        )
        .await
    }
    pub async fn cancel_invite(&self, id: &str) -> Result<(), ApiError> {
        valid_id(id)?;
        let response = self
            .request(reqwest::Method::DELETE, &format!("/group-invites/{id}"))
            .query(&[("device_id", &self.device)])
            .send()
            .await
            .map_err(|_| network())?;
        empty(response)
    }
    pub async fn send(
        &self,
        group: &str,
        envelopes: &[GroupEnvelope],
    ) -> Result<GroupMessageReceipt, ApiError> {
        valid_id(group)?;
        self.post(
            &format!("/groups/{group}/messages"),
            &GroupSendRequest {
                device_id: self.device.clone(),
                envelopes: envelopes.to_vec(),
            },
        )
        .await
    }
    pub async fn pending(&self, group: &str) -> Result<GroupMessagePage, ApiError> {
        valid_id(group)?;
        Self::decode(
            self.request(reqwest::Method::GET, &format!("/groups/{group}/messages"))
                .query(&[("device_id", &self.device)])
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn ack(&self, group: &str, joined: u64, ids: &[String]) -> Result<(), ApiError> {
        valid_id(group)?;
        for id in ids {
            valid_id(id)?;
        }
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/groups/{group}/messages/ack"),
            )
            .json(&GroupAckRequest {
                device_id: self.device.clone(),
                recipient_join_epoch: joined,
                message_ids: ids.to_vec(),
            })
            .send()
            .await
            .map_err(|_| network())?;
        empty(response)
    }
    pub async fn receipt(
        &self,
        group: &str,
        message: &str,
    ) -> Result<GroupMessageReceipt, ApiError> {
        valid_id(group)?;
        valid_id(message)?;
        Self::decode(
            self.request(
                reqwest::Method::GET,
                &format!("/groups/{group}/messages/{message}/receipt"),
            )
            .query(&[("device_id", &self.device)])
            .send()
            .await
            .map_err(|_| network())?,
        )
        .await
    }
    pub async fn cancel_message(
        &self,
        group: &str,
        message: &str,
    ) -> Result<GroupCancelResult, ApiError> {
        valid_id(group)?;
        valid_id(message)?;
        self.post(
            &format!("/groups/{group}/messages/{message}/cancel"),
            &GroupCancelRequest {
                device_id: self.device.clone(),
            },
        )
        .await
    }
}
fn empty(response: reqwest::Response) -> Result<(), ApiError> {
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(ApiError {
            status: Some(response.status().as_u16()),
            message: "群确认请求失败，保留原确认任务".into(),
        })
    }
}
