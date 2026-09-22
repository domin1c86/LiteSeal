use crate::AppState;
use liteseal_core::{api, db::repository::AttachmentTransfer};
use liteseal_shared::{crypto, protocol::EncryptedPayload};
use serde::{Deserialize, Serialize};
use std::{io::{Read, Write}, sync::OnceLock};
const LIMIT: usize = 20 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;
const PREFIX: &str = "\u{1e}LiteSeal:2:";
static GATE: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
#[derive(Clone, Serialize, Deserialize)]
struct Descriptor { version: u8, id: String, name: String, size: usize, mime: String, key: Vec<u8> }
#[derive(Serialize)]
pub struct View { id: String, peer_id: String, message_id: String, name: String, size: usize, mime: String, offset: i64, total: usize, direction: String }
fn client() -> Result<reqwest::Client,String> { reqwest::Client::builder().timeout(std::time::Duration::from_secs(25)).build().map_err(|e|e.to_string()) }
fn descriptor(state:&AppState,item:&AttachmentTransfer)->Result<Descriptor,String> {
    let saved=state.identity()?;
    serde_json::from_slice(&liteseal_core::chat::decrypt_message(item.metadata.clone(),saved.public_key,saved.secret_key)?).map_err(|_|"附件任务元数据损坏".into())
}
fn view(state:&AppState,item:&AttachmentTransfer)->Result<View,String> {
    let d=descriptor(state,item)?;
    Ok(View{id:item.id.clone(),peer_id:item.peer_id.clone(),message_id:item.message_id.clone(),name:d.name,size:d.size,mime:d.mime,offset:item.offset,total:d.size+40,direction:item.direction.clone()})
}
fn load(state:&AppState,id:&str)->Result<AttachmentTransfer,String> {
    let user=state.identity()?.user_id;
    state.client.db.lock().map_err(|e|e.to_string())?.attachment_transfer(&user,id).map_err(|e|e.to_string())
}
fn save(state:&AppState,item:&AttachmentTransfer)->Result<(),String> {
    state.client.db.lock().map_err(|e|e.to_string())?.save_attachment_transfer(item).map_err(|e|e.to_string())
}
fn media(bytes:&[u8])->&'static str {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") { "image/png" }
    else if bytes.starts_with(&[255,216,255]) { "image/jpeg" }
    else if bytes.len()>=12 && &bytes[..4]==b"RIFF" && &bytes[8..12]==b"WEBP" { "image/webp" }
    else { "application/octet-stream" }
}
fn safe_name(path:&std::path::Path)->String {
    path.file_name().unwrap_or_default().to_string_lossy().chars().filter(|c| !c.is_control() && !"<>:\"/\\|?*".contains(*c)).take(160).collect::<String>().trim_matches(['.',' ']).to_string()
}
pub async fn stage(state:&AppState,path:String,peer_id:String)->Result<View,String> {
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    let saved=state.identity()?;
    {
        let db=state.client.db.lock().map_err(|e|e.to_string())?;
        if db.get_contact(&peer_id).map_err(|e|e.to_string())?.is_none(){return Err("请先添加联系人".into());}
        if db.attachment_cache_bytes(&saved.user_id).map_err(|e|e.to_string())? > 256*1024*1024-LIMIT as i64 { return Err("附件缓存上限 256 MiB，请清理已下载缓存或取消待发任务".into()); }
    }
    let path=std::path::Path::new(&path);
    let file=std::fs::File::open(path).map_err(|_|"无法读取所选文件")?;
    if !file.metadata().map_err(|e|e.to_string())?.is_file(){return Err("请选择普通文件".into());}
    let mut bytes=Vec::new();file.take((LIMIT+1) as u64).read_to_end(&mut bytes).map_err(|_|"读取文件失败")?;
    if bytes.len()>LIMIT {return Err("单文件不能超过 20 MiB".into());}
    let mime=media(&bytes).to_string();
    let (ciphertext,key)=crypto::encrypt_attachment(&bytes).map_err(|e|e.to_string())?;
    let id=uuid::Uuid::new_v4().to_string();
    let d=Descriptor{version:1,id:id.clone(),name:safe_name(path),size:bytes.len(),mime,key};
    let metadata=liteseal_core::chat::encrypt_message(serde_json::to_vec(&d).map_err(|e|e.to_string())?,saved.public_key,saved.secret_key)?;
    let item=AttachmentTransfer{id,user_id:saved.user_id,peer_id,message_id:uuid::Uuid::new_v4().to_string(),metadata,ciphertext,offset:0,direction:"upload".into()};
    save(state,&item)?;view(state,&item)
}
pub fn pending(state:&AppState)->Result<Vec<View>,String> {
    let user=state.identity()?.user_id;
    let ids=state.client.db.lock().map_err(|e|e.to_string())?.attachment_transfer_ids(&user).map_err(|e|e.to_string())?;
    ids.iter().map(|id|view(state,&load(state,id)?)).collect()
}
pub async fn step(state:&AppState,id:String)->Result<View,String> {
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    let saved=state.identity()?;
    let mut item=load(state,&id)?;
    let d=descriptor(state,&item)?;
    let base=api::normalize_server_url(&saved.server_url)?;
    let http=client()?;
    if item.direction=="upload" {
        if item.offset==0 {
            let response=http.post(format!("{base}/attachments")).bearer_auth(&saved.token).json(&serde_json::json!({"device_id":saved.device_id,"id":id,"message_id":item.message_id,"recipient":item.peer_id,"size":item.ciphertext.len()})).send().await.map_err(|_|"上传初始化失败，可重试原任务")?;
            if !response.status().is_success(){return Err(format!("上传初始化失败：{}",response.status()));}
        }
        let offset=item.offset as usize;
        if offset<item.ciphertext.len(){
            let end=(offset+CHUNK).min(item.ciphertext.len());
            let response=http.put(format!("{base}/attachments/{id}/{}",offset/CHUNK)).query(&[("device_id",&saved.device_id)]).bearer_auth(&saved.token).body(item.ciphertext[offset..end].to_vec()).send().await.map_err(|_|"分块上传失败，可重试原任务")?;
            if response.status()==reqwest::StatusCode::NOT_FOUND {item.offset=0;save(state,&item)?;return Err("远端暂存已过期，请继续原任务重新上传".into());}
            if !response.status().is_success(){return Err(format!("分块上传失败：{}",response.status()));}
            item.offset=end as i64;save(state,&item)?;
        }
    } else {
        let total=d.size+40;
        if item.ciphertext.len()<total {
            let part=item.ciphertext.len()/CHUNK;
            let mut response=http.get(format!("{base}/attachments/{id}/{part}")).query(&[("device_id",&saved.device_id)]).bearer_auth(&saved.token).send().await.map_err(|_|"下载中断，可继续原任务")?;
            if !response.status().is_success(){return Err(format!("附件不可下载（可能过期或无权限）：{}",response.status()));}
            let mut bytes=Vec::new();
            while let Some(chunk)=response.chunk().await.map_err(|_|"下载读取失败")? {
                if bytes.len()+chunk.len()>CHUNK {return Err("附件分块超过上限".into());}
                bytes.extend_from_slice(&chunk);
            }
            if bytes.len()!=(total-item.ciphertext.len()).min(CHUNK){return Err("附件分块长度不符".into());}
            if state.client.db.lock().map_err(|e|e.to_string())?.attachment_cache_bytes(&saved.user_id).map_err(|e|e.to_string())?+bytes.len() as i64>256*1024*1024{return Err("附件缓存已满，请清理后重试".into());}
            item.ciphertext.extend_from_slice(&bytes);item.offset=item.ciphertext.len() as i64;save(state,&item)?;
        }
    }
    view(state,&item)
}
pub async fn publish(state:&AppState,id:String)->Result<String,String> {
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    let saved=state.identity()?;let mut item=load(state,&id)?;
    if item.direction!="upload" || item.offset!=item.ciphertext.len() as i64 {return Err("请先完成上传".into());}
    let response=client()?.get(format!("{}/attachments/{}/{}",api::normalize_server_url(&saved.server_url)?,id,(item.ciphertext.len()-1)/CHUNK)).query(&[("device_id",&saved.device_id)]).bearer_auth(&saved.token).send().await.map_err(|_|"无法确认远端附件，保留原任务")?;
    if response.status()==reqwest::StatusCode::NOT_FOUND{item.offset=0;save(state,&item)?;return Err("远端暂存已过期，请继续原任务重新上传".into());}
    if !response.status().is_success(){return Err(format!("无法确认远端附件：{}",response.status()));}
    let existing=state.client.db.lock().map_err(|e|e.to_string())?.get_message(&item.message_id).map_err(|e|e.to_string())?.is_some();
    if existing {state.client.retry_message(item.message_id.clone()).await?;return Ok(item.message_id);}
    let d=descriptor(state,&item)?;
    let body=format!("{PREFIX}{}",serde_json::to_string(&d).map_err(|e|e.to_string())?);
    let peer=state.client.db.lock().map_err(|e|e.to_string())?.get_contact(&item.peer_id).map_err(|e|e.to_string())?.ok_or("联系人已删除")?;
    let devices=api::get_user_devices(saved.server_url.clone(),item.peer_id.clone(),saved.token.clone()).await?;
    let mut payloads=Vec::new();
    for device in devices.into_iter().filter(|d|!d.revoked){
        let encrypted=liteseal_core::chat::encrypt_message(body.as_bytes().to_vec(),device.public_key,saved.secret_key.clone())?;
        let signature=liteseal_core::chat::sign_message(encrypted.clone(),saved.ed25519_sk.clone())?;
        payloads.push(EncryptedPayload{recipient_user_id:item.peer_id.clone(),recipient_device_id:device.id,ciphertext:encrypted,signature});
    }
    let local=liteseal_core::chat::encrypt_message(body.into_bytes(),peer.public_key,saved.secret_key.clone())?;
    let signature=liteseal_core::chat::sign_message(local.clone(),saved.ed25519_sk.clone())?;
    super::chat::send_message(saved.user_id,local,signature,saved.device_id,payloads,Some(item.message_id.clone()),state).await?;
    Ok(item.message_id)
}
fn from_message(state:&AppState,message_id:&str)->Result<(Descriptor,String),String>{
    let saved=state.identity()?;
    let (row,peer)={let db=state.client.db.lock().map_err(|e|e.to_string())?;
        let row=db.get_message(message_id).map_err(|e|e.to_string())?.ok_or("消息不存在")?;
        if db.locally_deleted_ids(&saved.user_id,&row.conversation_id).map_err(|e|e.to_string())?.contains(&row.id)||row.local_state=="integrity_failed"{return Err("原文不可用".into());}
        let peer_id=if row.sender_id!=saved.user_id { row.sender_id.clone() } else { row.conversation_id.strip_prefix("dm:").ok_or("无效会话")?.split(':').find(|id|*id!=saved.user_id).ok_or("无效会话")?.to_string() };
        let peer=db.get_contact(&peer_id).map_err(|e|e.to_string())?.ok_or("请先恢复联系人")?;(row,peer)};
    let ops=super::message_operations::views(Some(row.conversation_id.clone()),state)?;
    if ops.iter().any(|op|op.target_id==message_id&&op.kind=="revoke"&&op.status=="accepted"){return Err("原文已撤回".into());}
    let plain=liteseal_core::chat::decrypt_message(row.ciphertext,peer.public_key,saved.secret_key)?;
    let text=String::from_utf8(plain).map_err(|_|"附件描述损坏")?;
    let d:Descriptor=serde_json::from_str(text.strip_prefix(PREFIX).ok_or("不是附件消息")?).map_err(|_|"附件描述损坏")?;
    if d.version!=1||d.size>LIMIT||d.key.len()!=32||uuid::Uuid::parse_str(&d.id).is_err(){return Err("附件版本或大小不支持".into());}
    Ok((d,peer.user_id))
}
pub async fn begin_download(state:&AppState,message_id:String)->Result<View,String>{
    let _guard=GATE.get_or_init(||tokio::sync::Mutex::new(())).lock().await;
    let saved=state.identity()?;let (d,peer_id)=from_message(state,&message_id)?;
    if let Ok(item)=load(state,&d.id){return view(state,&item);}
    if state.client.db.lock().map_err(|e|e.to_string())?.attachment_cache_bytes(&saved.user_id).map_err(|e|e.to_string())?+d.size as i64+40>256*1024*1024{return Err("附件缓存已满，请清理已下载缓存".into());}
    let metadata=liteseal_core::chat::encrypt_message(serde_json::to_vec(&d).map_err(|e|e.to_string())?,saved.public_key,saved.secret_key)?;
    let item=AttachmentTransfer{id:d.id,user_id:saved.user_id,peer_id,message_id,metadata,ciphertext:Vec::new(),offset:0,direction:"download".into()};save(state,&item)?;view(state,&item)
}
pub fn export(state:&AppState,message_id:String,path:String)->Result<(),String>{
    let (d,_)=from_message(state,&message_id)?;let item=load(state,&d.id)?;
    let bytes=crypto::decrypt_attachment(&item.ciphertext,&d.key).map_err(|_|"附件认证失败，文件未保存")?;
    if bytes.len()!=d.size{return Err("附件长度不符".into());}
    // Main process supplies a newly created private staging path. Never overwrite existing files here.
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|_|"无法创建保存文件，请检查权限和磁盘空间")?;
    if let Err(error)=file.write_all(&bytes).and_then(|_|file.sync_all()){drop(file);let _=std::fs::remove_file(&path);return Err(format!("保存失败，请检查磁盘空间：{error}"));}
    Ok(())
}
pub fn preview_chunk(state:&AppState,message_id:String,offset:usize)->Result<Vec<u8>,String>{
    let (d,_)=from_message(state,&message_id)?;let item=load(state,&d.id)?;
    let bytes=crypto::decrypt_attachment(&item.ciphertext,&d.key).map_err(|_|"附件认证失败")?;
    if bytes.len()!=d.size || !media(&bytes).starts_with("image/") || offset>bytes.len(){return Err("图片格式或大小不支持".into());}
    Ok(bytes[offset..(offset+CHUNK).min(bytes.len())].to_vec())
}
pub fn pending_preview_chunk(state:&AppState,id:String,offset:usize)->Result<Vec<u8>,String>{
    let item=load(state,&id)?;
    if item.direction!="upload"{return Err("不是待发任务".into());}
    let d=descriptor(state,&item)?;
    let bytes=crypto::decrypt_attachment(&item.ciphertext,&d.key).map_err(|_|"附件认证失败")?;
    if !media(&bytes).starts_with("image/")||offset>bytes.len(){return Err("图片格式不支持".into());}
    Ok(bytes[offset..(offset+CHUNK).min(bytes.len())].to_vec())
}
pub fn public_plaintext(bytes:Vec<u8>)->Result<Vec<u8>,String>{
    let Ok(text)=std::str::from_utf8(&bytes) else{return Ok(bytes)};
    if let Some(raw)=text.strip_prefix(PREFIX){
        let d:Descriptor=serde_json::from_str(raw).map_err(|_|"附件描述格式不支持")?;
        // Strip ALL decryption material before crossing the desktop bridge.
        return Ok(format!("{PREFIX}{}",serde_json::json!({"version":d.version,"id":d.id,"name":d.name,"size":d.size,"mime":d.mime})).into_bytes());
    }
    Ok(bytes)
}
