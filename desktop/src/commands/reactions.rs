use crate::AppState;
use liteseal_shared::{crypto,reaction::{Reaction,ReactionDelivery,EMOJI}};
use liteseal_core::{api::normalize_server_url,chat::canonical_conversation_id};
use std::sync::OnceLock;
static GATE:OnceLock<tokio::sync::Mutex<()>>=OnceLock::new();
fn client()->Result<reqwest::Client,String>{reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build().map_err(|e|e.to_string())}
fn rows(state:&AppState)->Result<Vec<(i64,Reaction)>,String>{
    let user=state.identity()?.user_id;
    state.client.db.lock().map_err(|e|e.to_string())?.reaction_rows(&user).map_err(|e|e.to_string())?.into_iter().map(|(seq,body)|Ok((seq,serde_json::from_str(&body).map_err(|_|"回应数据损坏")?))).collect()
}
fn store(state:&AppState,event:&Reaction,seq:i64)->Result<(),String>{
    state.client.db.lock().map_err(|e|e.to_string())?.save_reaction(&state.identity()?.user_id,&event.id,seq,&serde_json::to_string(event).map_err(|e|e.to_string())?).map_err(|e|e.to_string())
}
async fn publish(state:&AppState,event:&Reaction)->Result<(),String>{
    let saved=state.identity()?;
    let response=client()?.post(format!("{}/reactions",normalize_server_url(&saved.server_url)?)).bearer_auth(saved.token).json(event).send().await.map_err(|_|"回应发送中断，已保存待重试")?;
    if !response.status().is_success(){
        if response.status().is_client_error() && response.status()!=reqwest::StatusCode::TOO_MANY_REQUESTS && response.status()!=reqwest::StatusCode::UNAUTHORIZED {store(state,event,-1)?;}
        return Err(format!("回应未被接受：{}",response.status()));
    }
    let delivery:ReactionDelivery=response.json().await.map_err(|_|"回应确认格式无效")?;
    if delivery.event.signing_bytes()!=event.signing_bytes(){return Err("回应确认内容不一致".into());}
    // Cursor is advanced only by ordered sync, never by a submit response.
    store(state,event,-2)
}
pub async fn submit(state:&AppState,target:String,peer_id:String,emoji:String)->Result<(),String>{
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    if !EMOJI.contains(&emoji.as_str()){return Err("不支持的回应".into());}
    let saved=state.identity()?;
    let (message,peer)={let db=state.client.db.lock().map_err(|e|e.to_string())?;(db.get_message(&target).map_err(|e|e.to_string())?.ok_or("原消息不存在")?,db.get_contact(&peer_id).map_err(|e|e.to_string())?.ok_or("联系人不存在")?)};
    if message.conversation_id!=canonical_conversation_id(&saved.user_id,&peer_id){return Err("回应会话不匹配".into());}
    let history=rows(state)?;
    if history.iter().any(|(seq,e)|*seq==0&&e.actor==saved.user_id&&e.target_id==target){return Err("上一回应尚未确认，请先同步或重试".into());}
    let revision=history.iter().filter(|(seq,e)|*seq!=-1&&e.actor==saved.user_id&&e.target_id==target).map(|(_,e)|e.revision).max().unwrap_or(0)+1;
    let ciphertext=liteseal_core::chat::encrypt_message(emoji.into_bytes(),peer.public_key,saved.secret_key)?;
    let mut event=Reaction{id:uuid::Uuid::new_v4().to_string(),target_id:target,conversation_id:message.conversation_id,actor:saved.user_id,device:saved.device_id,peer:peer_id,revision,ciphertext,signature:Vec::new()};
    event.signature=liteseal_core::chat::sign_message(event.signing_bytes(),saved.ed25519_sk)?;
    store(state,&event,0)?;publish(state,&event).await
}
pub async fn sync(state:&AppState)->Result<usize,String>{
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    let saved=state.identity()?;let history=rows(state)?;
    for (seq,event) in &history{if *seq==0{publish(state,event).await?;}}
    let after=history.iter().map(|(seq,_)|*seq).max().unwrap_or(0).max(0);
    let response=client()?.get(format!("{}/reactions",normalize_server_url(&saved.server_url)?)).bearer_auth(&saved.token).query(&[("device_id",saved.device_id.clone()),("after",after.to_string())]).send().await.map_err(|_|"回应同步失败")?;
    if !response.status().is_success(){return Err(format!("回应同步失败：{}",response.status()));}
    let deliveries:Vec<ReactionDelivery>=response.json().await.map_err(|_|"回应同步数据无效")?;
    for delivery in &deliveries{if delivery.event.actor!=saved.user_id&&delivery.event.peer!=saved.user_id{return Err("回应账号不匹配".into());}store(state,&delivery.event,delivery.seq)?;}
    Ok(deliveries.len())
}
pub fn views(state:&AppState,conversation:String)->Result<serde_json::Value,String>{
    let saved=state.identity()?;let mut latest=std::collections::HashMap::new();
    for (seq,event) in rows(state)?{
        if seq==0||seq == -1||event.conversation_id!=conversation{continue;}
        let peer_id=if event.actor==saved.user_id{&event.peer}else{&event.actor};
        if event.conversation_id!=canonical_conversation_id(&saved.user_id,peer_id){continue;}
        let peer=state.client.db.lock().map_err(|e|e.to_string())?.get_contact(peer_id).map_err(|e|e.to_string())?;
        let Some(peer)=peer else{continue};
        let signing: [u8;32]=if event.actor==saved.user_id{saved.ed25519_pk.clone()}else{peer.ed25519_pk.clone().unwrap_or_default()}.try_into().map_err(|_|"回应者签名密钥无效")?;
        if !crypto::verify_with_public_key(&event.signing_bytes(),&event.signature,&signing).map_err(|e|e.to_string())?{continue;}
        let plain=liteseal_core::chat::decrypt_message(event.ciphertext.clone(),peer.public_key,saved.secret_key.clone())?;
        let emoji=String::from_utf8(plain).map_err(|_|"回应编码无效")?;
        if !EMOJI.contains(&emoji.as_str()){continue;}
        let key=(event.target_id.clone(),event.actor.clone());
        let old=latest.entry(key).or_insert((0,String::new()));if event.revision>old.0{*old=(event.revision,emoji);}
    }
    Ok(serde_json::Value::Array(latest.into_iter().filter(|(_,(_,emoji))|!emoji.is_empty()).map(|((target_id,actor),(_,emoji))|serde_json::json!({"target_id":target_id,"actor":actor,"emoji":emoji})).collect()))
}
