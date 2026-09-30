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
pub fn canonical_origin(server: &str) -> Result<String, String> {
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
    token: std::sync::RwLock<String>,
    device: String,
    client: reqwest::Client,
}
impl GroupApi {
    pub async fn media_create(
        &self,
        id: &str,
        blob: &str,
        size: usize,
    ) -> Result<String, ApiError> {
        valid_id(id)?;
        valid_id(blob)?;
        self.post(
            &format!("/groups/{id}/attachments"),
            &serde_json::json!({"device_id":self.device,"id":blob,"size":size}),
        )
        .await
    }
    pub async fn media_upload(
        &self,
        id: &str,
        blob: &str,
        part: usize,
        bytes: Vec<u8>,
    ) -> Result<(), ApiError> {
        valid_id(id)?;
        valid_id(blob)?;
        let response = self
            .request(
                reqwest::Method::PUT,
                &format!("/groups/{id}/attachments/{blob}/{part}"),
            )
            .query(&[("device_id", &self.device)])
            .body(bytes)
            .send()
            .await
            .map_err(|_| network())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "群附件上传失败，保留原任务".into(),
            })
        }
    }
    pub async fn media_download(
        &self,
        id: &str,
        blob: &str,
        part: usize,
    ) -> Result<Vec<u8>, ApiError> {
        valid_id(id)?;
        valid_id(blob)?;
        let mut response = self
            .request(
                reqwest::Method::GET,
                &format!("/groups/{id}/attachments/{blob}/{part}"),
            )
            .query(&[("device_id", &self.device)])
            .send()
            .await
            .map_err(|_| network())?;
        if !response.status().is_success() {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "群附件不可下载，可能过期或权限已变化".into(),
            });
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len() + chunk.len() > 1024 * 1024 {
                return Err(network());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    pub async fn extension_capability(&self, id: &str) -> Result<u8, ApiError> {
        valid_id(id)?;
        Self::decode(
            self.request(
                reqwest::Method::GET,
                &format!("/groups/{id}/extensions/capabilities"),
            )
            .query(&[("device_id", &self.device)])
            .send()
            .await
            .map_err(|_| network())?,
        )
        .await
    }
    pub async fn extension_submit(
        &self,
        id: &str,
        submission: &liteseal_shared::group_extension::Submission,
    ) -> Result<liteseal_shared::group_extension::Receipt, ApiError> {
        valid_id(id)?;
        self.post(
            &format!("/groups/{id}/extensions"),
            &serde_json::json!({"device_id":self.device,"submission":submission}),
        )
        .await
    }
    pub async fn extension_page(
        &self,
        id: &str,
        after: i64,
    ) -> Result<liteseal_shared::group_extension::Page, ApiError> {
        valid_id(id)?;
        let mut response = self
            .request(reqwest::Method::GET, &format!("/groups/{id}/extensions"))
            .query(&[
                ("device_id", self.device.clone()),
                ("after", after.to_string()),
            ])
            .send()
            .await
            .map_err(|_| network())?;
        Self::decode_bounded(&mut response, 512 * 1024).await
    }
    pub async fn extension_cancel(
        &self,
        id: &str,
        event: &str,
        root: Option<&str>,
    ) -> Result<liteseal_shared::group_extension::CancelResult, ApiError> {
        valid_id(id)?;
        valid_id(event)?;
        self.post(
            &format!("/groups/{id}/extensions/{event}/cancel"),
            &serde_json::json!({"device_id":self.device,"root":root}),
        )
        .await
    }
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
            token: std::sync::RwLock::new(token),
            device,
            client,
        })
    }
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{path}", self.origin))
            .bearer_auth(
                self.token
                    .read()
                    .map(|token| token.clone())
                    .unwrap_or_default(),
            )
    }
    pub(super) fn update_token(&self, token: String) -> Result<(), String> {
        if token.is_empty() {
            return Err("群会话已退出".into());
        }
        *self.token.write().map_err(|_| "群会话锁不可用")? = token;
        Ok(())
    }
    pub(super) fn token_matches(&self, token: &str) -> bool {
        self.token.read().is_ok_and(|current| *current == token)
    }
    pub(super) fn invalidate_token_if(&self, expected: &str) {
        if let Ok(mut token) = self.token.write() {
            if *token == expected {
                token.clear();
            }
        }
    }
    async fn decode<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T, ApiError> {
        Self::decode_bounded(&mut response, 4 * 1024 * 1024).await
    }
    async fn decode_bounded<T: DeserializeOwned>(
        response: &mut reqwest::Response,
        limit: usize,
    ) -> Result<T, ApiError> {
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
            if bytes.len() + chunk.len() > limit {
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
    pub async fn collaboration_capability(&self, id: &str) -> Result<u8, ApiError> {
        valid_id(id)?;
        Self::decode(
            self.request(
                reqwest::Method::GET,
                &format!("/groups/{id}/collaboration/capabilities"),
            )
            .query(&[("device_id", &self.device)])
            .send()
            .await
            .map_err(|_| network())?,
        )
        .await
    }
    pub async fn collaboration_submit(
        &self,
        id: &str,
        body: &liteseal_shared::collaboration::Submission,
    ) -> Result<i64, ApiError> {
        valid_id(id)?;
        self.post(&format!("/groups/{id}/collaboration"), body)
            .await
    }
    pub async fn collaboration_page(
        &self,
        id: &str,
        after: i64,
    ) -> Result<liteseal_shared::collaboration::Page, ApiError> {
        valid_id(id)?;
        Self::decode(
            self.request(reqwest::Method::GET, &format!("/groups/{id}/collaboration"))
                .query(&[
                    ("device_id", self.device.clone()),
                    ("after", after.to_string()),
                ])
                .send()
                .await
                .map_err(|_| network())?,
        )
        .await
    }
    pub async fn collaboration_ack(&self, id: &str, ids: &[String]) -> Result<(), ApiError> {
        valid_id(id)?;
        let response = self
            .request(
                reqwest::Method::POST,
                &format!("/groups/{id}/collaboration/ack"),
            )
            .json(&serde_json::json!({"device_id":self.device,"ids":ids}))
            .send()
            .await
            .map_err(|_| network())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "群协作确认失败，稍后重试".into(),
            })
        }
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
    pub async fn sent_invites(
        &self,
        group: &str,
        after: Option<&str>,
    ) -> Result<GroupSentInvitePage, ApiError> {
        valid_id(group)?;
        if let Some(id) = after {
            valid_id(id)?;
        }
        let mut query = vec![("device_id", self.device.as_str())];
        if let Some(id) = after {
            query.push(("after_id", id));
        }
        Self::decode(
            self.request(reqwest::Method::GET, &format!("/groups/{group}/invites"))
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn renewing_and_invalidating_tokens_changes_only_future_request_capability() {
        let api = GroupApi::new("http://localhost:3000", "old".into(), "device".into()).unwrap();
        api.update_token("fresh".into()).unwrap();
        api.invalidate_token_if("old");
        assert_eq!(
            api.request(reqwest::Method::GET, "/groups")
                .build()
                .unwrap()
                .headers()[reqwest::header::AUTHORIZATION],
            "Bearer fresh"
        );
        api.invalidate_token_if("fresh");
        assert!(!api.token_matches("fresh"));
        assert!(api.update_token(String::new()).is_err());
        api.update_token("next".into()).unwrap();
        assert_eq!(
            api.request(reqwest::Method::GET, "/groups")
                .build()
                .unwrap()
                .headers()[reqwest::header::AUTHORIZATION],
            "Bearer next"
        );
        assert_eq!(api.origin, "http://localhost:3000");
    }
}
