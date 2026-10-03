use super::*;
use liteseal_shared::history_transfer::{self as h, Offer, RelayStatus};
pub enum HistoryAction {
    Publish,
    Cancel,
    Permit,
}
impl DirectApi {
    pub async fn history_received(
        &self,
        token: &str,
        offer: &Offer,
        receipt: &h::Received,
    ) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        receipt.verify(offer).map_err(|_| invalid())?;
        let value = self
            .json(
                self.request(
                    Method::POST,
                    &format!("/direct/v3/history/{}/received", offer.header.id),
                    token,
                )?
                .json(receipt),
                4096,
            )
            .await?;
        let value = self.history_result(offer, value)?;
        if value.state != h::RelayState::Received {
            return Err(invalid());
        }
        Ok(value)
    }
    fn history_bound(&self, offer: &Offer) -> Result<(), ApiError> {
        if offer.header.origin != self.origin
            || serde_json::to_vec(offer).map_err(|_| invalid())?.len() > h::MAX_METADATA
        {
            return Err(invalid());
        }
        for value in [
            &offer.header.id,
            &offer.header.account,
            &offer.header.peer,
            &offer.header.source.device_id,
            &offer.header.target.device.device_id,
        ] {
            id(value)?;
        }
        offer.digest().map_err(|_| invalid())?;
        Ok(())
    }
    fn history_result(&self, offer: &Offer, value: RelayStatus) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        if value.id != offer.header.id
            || value.digest != offer.digest().map_err(|_| invalid())?
            || value.next > offer.size.div_ceil(h::CHUNK)
        {
            return Err(invalid());
        }
        if matches!(value.state, h::RelayState::Ready | h::RelayState::Permitted)
            && value.next != offer.size.div_ceil(h::CHUNK)
        {
            return Err(invalid());
        }
        Ok(value)
    }
    pub async fn register_history(
        &self,
        token: &str,
        offer: &Offer,
    ) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        let result = self
            .json(
                self.request(Method::POST, "/direct/v3/history", token)?
                    .json(offer),
                4096,
            )
            .await?;
        self.history_result(offer, result)
    }
    pub async fn history_status(
        &self,
        token: &str,
        offer: &Offer,
    ) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        let result = self
            .json(
                self.request(
                    Method::GET,
                    &format!("/direct/v3/history/{}", offer.header.id),
                    token,
                )?
                .query(&[
                    ("device_id", offer.header.source.device_id.clone()),
                    (
                        "digest",
                        hex::encode(offer.digest().map_err(|_| invalid())?),
                    ),
                ]),
                4096,
            )
            .await?;
        self.history_result(offer, result)
    }
    pub async fn history_action(
        &self,
        token: &str,
        offer: &Offer,
        action: HistoryAction,
    ) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        let (path, device) = match action {
            HistoryAction::Publish => ("publish", &offer.header.source.device_id),
            HistoryAction::Cancel => ("cancel", &offer.header.source.device_id),
            HistoryAction::Permit => ("permit", &offer.header.target.device.device_id),
        };
        let result=self.json(self.request(Method::POST,&format!("/direct/v3/history/{}/{}",offer.header.id,path),token)?.json(&serde_json::json!({"device_id":device,"digest":hex::encode(offer.digest().map_err(|_|invalid())?)})),4096).await?;
        self.history_result(offer, result)
    }
    pub async fn upload_history_chunk(
        &self,
        token: &str,
        offer: &Offer,
        part: usize,
        bytes: Vec<u8>,
    ) -> Result<RelayStatus, ApiError> {
        self.history_bound(offer)?;
        if bytes.len() != offer.chunk_len(part).map_err(|_| invalid())? {
            return Err(invalid());
        }
        let result = self
            .json(
                self.request(
                    Method::PUT,
                    &format!("/direct/v3/history/{}/chunks/{part}", offer.header.id),
                    token,
                )?
                .query(&[
                    ("device_id", offer.header.source.device_id.clone()),
                    (
                        "digest",
                        hex::encode(offer.digest().map_err(|_| invalid())?),
                    ),
                ])
                .body(bytes),
                4096,
            )
            .await?;
        let result = self.history_result(offer, result)?;
        if result.next < part + 1 {
            return Err(invalid());
        }
        Ok(result)
    }
    pub async fn pending_history(
        &self,
        token: &str,
        account: &str,
        device: &str,
    ) -> Result<Vec<Offer>, ApiError> {
        id(account)?;
        id(device)?;
        let offers: Vec<Offer> = self
            .json(
                self.request(Method::GET, "/direct/v3/history/pending", token)?
                    .query(&[("device_id", device)]),
                8 * h::MAX_METADATA + 64,
            )
            .await?;
        if offers.len() > 8 {
            return Err(invalid());
        }
        let mut ids = HashSet::new();
        for offer in &offers {
            self.history_bound(offer)?;
            if offer.header.account != account
                || offer.header.target.device.device_id != device
                || !ids.insert(&offer.header.id)
            {
                return Err(invalid());
            }
        }
        Ok(offers)
    }
    pub async fn download_history_chunk(
        &self,
        token: &str,
        offer: &Offer,
        part: usize,
    ) -> Result<Vec<u8>, ApiError> {
        self.history_bound(offer)?;
        let length = offer.chunk_len(part).map_err(|_| invalid())?;
        let mut response = self
            .request(
                Method::GET,
                &format!("/direct/v3/history/{}/chunks/{part}", offer.header.id),
                token,
            )?
            .query(&[
                ("device_id", offer.header.target.device.device_id.clone()),
                (
                    "digest",
                    hex::encode(offer.digest().map_err(|_| invalid())?),
                ),
            ])
            .send()
            .await
            .map_err(|_| network())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(ApiError {
                status: Some(response.status().as_u16()),
                message: "授权历史分块尚未确认，请沿原编号继续",
            });
        }
        if response
            .content_length()
            .is_some_and(|n| n != length as u64)
        {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(length);
        while let Some(chunk) = response.chunk().await.map_err(|_| network())? {
            if bytes.len().saturating_add(chunk.len()) > length {
                return Err(invalid());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != length {
            return Err(invalid());
        }
        Ok(bytes)
    }
}
