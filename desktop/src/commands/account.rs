use crate::AppState;
use liteseal_core::api::normalize_server_url;
use serde_json::{json,Value};
fn client()->Result<reqwest::Client,String>{reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e|e.to_string())}
async fn response(response:reqwest::Response)->Result<Value,String>{
    if !response.status().is_success(){return Err(format!("账号操作失败：{}",response.status()));}
    if response.status()==reqwest::StatusCode::NO_CONTENT {Ok(Value::Null)}else{response.json().await.map_err(|_|"无法读取账号响应".into())}
}
pub async fn policies(state:&AppState)->Result<Value,String>{
    let saved=state.identity()?;
    response(client()?.get(format!("{}/contact-policy",normalize_server_url(&saved.server_url)?)).bearer_auth(saved.token).query(&[("device_id",saved.device_id)]).send().await.map_err(|e|e.to_string())?).await
}
pub async fn policy(state:&AppState,peer:String,status:String)->Result<(),String>{
    if !["accepted","blocked","rejected","pending"].contains(&status.as_str()){return Err("无效联系请求状态".into());}
    let saved=state.identity()?;
    if status=="accepted" {
        let info=response(client()?.get(format!("{}/users/{peer}/key",normalize_server_url(&saved.server_url)?)).bearer_auth(&saved.token).send().await.map_err(|e|e.to_string())?).await?;
        let username=info["username"].as_str().ok_or("缺少用户名")?.to_string();
        let pk:Vec<u8>=serde_json::from_value(info["public_key"].clone()).map_err(|_|"缺少公钥")?;
        let signing:Vec<u8>=serde_json::from_value(info["ed25519_pk"].clone()).map_err(|_|"缺少签名公钥")?;
        state.client.add_contact(peer.clone(),username,pk,Some(signing))?;
    }
    response(client()?.post(format!("{}/contact-policy",normalize_server_url(&saved.server_url)?)).bearer_auth(saved.token).json(&json!({"device_id":saved.device_id,"peer_id":peer,"status":status})).send().await.map_err(|e|e.to_string())?).await?;
    Ok(())
}
pub async fn sessions(state:&AppState)->Result<Value,String>{
    let saved=state.identity()?;
    response(client()?.get(format!("{}/auth/sessions",normalize_server_url(&saved.server_url)?)).bearer_auth(saved.token).send().await.map_err(|e|e.to_string())?).await
}
pub async fn logout_all(state:&AppState)->Result<(),String>{
    let mut saved=state.identity()?;
    response(client()?.post(format!("{}/auth/logout_all",normalize_server_url(&saved.server_url)?)).json(&json!({"access_token":saved.token})).send().await.map_err(|e|e.to_string())?).await?;
    state.client.disconnect().await;saved.token.clear();saved.refresh_token.clear();state.save_identity(saved)
}
