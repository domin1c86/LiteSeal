use crate::{commands, AppState};
use liteseal_core::keystore::KeystoreData;
use liteseal_shared::protocol::EncryptedPayload;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: u64,
    pub command: Command,
}

#[derive(Deserialize)]
#[serde(tag = "name", content = "args", deny_unknown_fields)]
pub enum Command {
    #[serde(rename = "submit_message_operation")]
    SubmitMessageOperation {
        #[serde(rename = "targetId")]
        target_id: String,
        kind: String,
        content: String,
        #[serde(rename = "baseRevision")]
        base_revision: i64,
    },
    #[serde(rename = "sync_message_operations")]
    SyncMessageOperations {},
    #[serde(rename = "get_message_operations")]
    GetMessageOperations {
        #[serde(rename = "conversationId", default)]
        conversation_id: Option<String>,
    },
    #[serde(rename = "delete_message_locally")]
    DeleteMessageLocally {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
    },
    #[serde(rename = "get_locally_deleted_ids")]
    GetLocallyDeletedIds {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },
    #[serde(rename = "get_conversation_preferences")]
    GetConversationPreferences {
        #[serde(rename = "userId")]
        user_id: String,
    },
    #[serde(rename = "save_conversation_preference")]
    SaveConversationPreference {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "peerId")]
        peer_id: String,
        pinned: Option<bool>,
        archived: Option<bool>,
        draft: Option<Vec<u8>>,
    },
    #[serde(rename = "get_conversation_summaries")]
    GetConversationSummaries {
        #[serde(rename = "userId")]
        user_id: String,
    },
    #[serde(rename = "mark_messages_read")]
    MarkMessagesRead {
        #[serde(rename = "userId")]
        user_id: String,
        ids: Vec<String>,
    },
    #[serde(rename = "send_message")]
    SendMessage {
        #[serde(rename = "messageId", default)]
        message_id: Option<String>,
        #[serde(rename = "senderId")]
        sender_id: String,
        #[serde(rename = "ciphertext")]
        ciphertext: Vec<u8>,
        #[serde(rename = "signature")]
        signature: Vec<u8>,
        #[serde(rename = "senderDeviceId")]
        sender_device_id: String,
        #[serde(rename = "payloads")]
        payloads: Vec<EncryptedPayload>,
    },
    #[serde(rename = "retry_message")]
    RetryMessage {
        #[serde(rename = "messageId")]
        message_id: String,
    },
    #[serde(rename = "poll_messages")]
    PollMessages {},
    #[serde(rename = "get_local_message_page")]
    GetLocalMessagePage {
        #[serde(rename = "userId", default)]
        user_id: String,
        #[serde(rename = "conversationId")]
        conversation_id: String,
        limit: i64,
        #[serde(rename = "beforeTimestamp", default)]
        before_timestamp: Option<i64>,
        #[serde(rename = "beforeId", default)]
        before_id: Option<String>,
    },
    #[serde(rename = "get_local_messages")]
    GetLocalMessages {
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "limit")]
        limit: i64,
        #[serde(rename = "offset")]
        offset: i64,
    },
    #[serde(rename = "encrypt_message")]
    EncryptMessage {
        #[serde(rename = "plaintext")]
        plaintext: Vec<u8>,
        #[serde(rename = "recipientPublicKey")]
        recipient_public_key: Vec<u8>,
        #[serde(rename = "senderSecretKey")]
        sender_secret_key: Vec<u8>,
    },
    #[serde(rename = "decrypt_message")]
    DecryptMessage {
        #[serde(rename = "ciphertext")]
        ciphertext: Vec<u8>,
        #[serde(rename = "senderPublicKey")]
        sender_public_key: Vec<u8>,
        #[serde(rename = "recipientSecretKey")]
        recipient_secret_key: Vec<u8>,
    },
    #[serde(rename = "sign_message")]
    SignMessage {
        #[serde(rename = "message")]
        message: Vec<u8>,
        #[serde(rename = "signingKey")]
        signing_key: Vec<u8>,
    },
    #[serde(rename = "verify_message")]
    VerifyMessage {
        #[serde(rename = "message")]
        message: Vec<u8>,
        #[serde(rename = "signature")]
        signature: Vec<u8>,
        #[serde(rename = "senderPublicKey")]
        sender_public_key: Vec<u8>,
    },
    #[serde(rename = "generate_keypair_cmd")]
    GenerateKeypairCmd {},
    #[serde(rename = "sign_out")]
    SignOut {},
    #[serde(rename = "save_keypair")]
    SaveKeypair {
        #[serde(rename = "data")]
        data: KeystoreData,
    },
    #[serde(rename = "load_keypair")]
    LoadKeypair {},
    #[serde(rename = "clear_keypair")]
    ClearKeypair {},
    #[serde(rename = "register")]
    Register {
        #[serde(rename = "inviteCode")]
        invite_code: String,
        #[serde(rename = "username")]
        username: String,
        #[serde(rename = "password")]
        password: String,
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "publicKey")]
        public_key: Vec<u8>,
        #[serde(rename = "ed25519Pk")]
        ed25519_pk: Vec<u8>,
    },
    #[serde(rename = "login")]
    Login {
        #[serde(rename = "username")]
        username: String,
        #[serde(rename = "password")]
        password: String,
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "publicKey")]
        public_key: Vec<u8>,
        #[serde(rename = "ed25519Pk")]
        ed25519_pk: Vec<u8>,
        #[serde(rename = "deviceId")]
        device_id: Option<String>,
    },
    #[serde(rename = "refresh_session")]
    RefreshSession {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "refreshToken")]
        refresh_token: String,
    },
    #[serde(rename = "connect_relay")]
    ConnectRelay {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "token")]
        token: String,
        #[serde(rename = "deviceId")]
        device_id: String,
    },
    #[serde(rename = "disconnect")]
    Disconnect {},
    #[serde(rename = "validate_invite")]
    ValidateInvite {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "inviteCode")]
        invite_code: String,
    },
    #[serde(rename = "add_contact")]
    AddContact {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "username")]
        username: String,
        #[serde(rename = "publicKey")]
        public_key: Vec<u8>,
        #[serde(rename = "ed25519Pk")]
        ed25519_pk: Option<Vec<u8>>,
    },
    #[serde(rename = "get_contacts")]
    GetContacts {},
    #[serde(rename = "remove_contact")]
    RemoveContact {
        #[serde(rename = "userId")]
        user_id: String,
    },
    #[serde(rename = "set_contact_trust")]
    SetContactTrust {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "trustState")]
        trust_state: String,
    },
    #[serde(rename = "get_user_devices")]
    GetUserDevices {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "accessToken")]
        access_token: String,
    },
    #[serde(rename = "search_users")]
    SearchUsers {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "query")]
        query: String,
        #[serde(rename = "accessToken")]
        access_token: String,
    },
    #[serde(rename = "get_storage_stats")]
    GetStorageStats {},
    #[serde(rename = "clear_expired_messages")]
    ClearExpiredMessages {},
    #[serde(rename = "clear_downloaded_attachments")]
    ClearDownloadedAttachments {},
}

#[derive(Serialize)]
pub struct Response {
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
impl Response {
    pub fn from_result(id: Option<u64>, result: Result<Value, String>) -> Self {
        match result {
            Ok(value) => Self {
                id,
                result: Some(value),
                error: None,
            },
            Err(error) => Self {
                id,
                result: None,
                error: Some(error),
            },
        }
    }
}

pub async fn dispatch(command: Command, state: &AppState) -> Result<Value, String> {
    let result = match command {
        Command::SubmitMessageOperation {
            target_id,
            kind,
            content,
            base_revision,
        } => serde_json::to_value(
            commands::message_operations::submit(target_id, kind, content, base_revision, state)
                .await?,
        ),
        Command::SyncMessageOperations {} => {
            serde_json::to_value(commands::message_operations::sync(state).await?)
        }
        Command::GetMessageOperations { conversation_id } => {
            serde_json::to_value(commands::message_operations::views(conversation_id, state)?)
        }
        Command::DeleteMessageLocally {
            user_id,
            conversation_id,
            message_id,
        } => {
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .delete_message_locally(&user_id, &conversation_id, &message_id)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
        Command::GetLocallyDeletedIds {
            user_id,
            conversation_id,
        } => serde_json::to_value(
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .locally_deleted_ids(&user_id, &conversation_id)
                .map_err(|e| e.to_string())?,
        ),
        Command::GetConversationPreferences { user_id } => serde_json::to_value(
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .conversation_preferences(&user_id)
                .map_err(|e| e.to_string())?,
        ),
        Command::SaveConversationPreference {
            user_id,
            peer_id,
            pinned,
            archived,
            draft,
        } => {
            if draft
                .as_ref()
                .is_some_and(|value| value.len() > 1024 * 1024)
            {
                return Err("Draft exceeds 1 MiB".into());
            }
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .save_conversation_preference(
                    &user_id,
                    &peer_id,
                    pinned,
                    archived,
                    draft.as_deref(),
                )
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
        Command::GetConversationSummaries { user_id } => serde_json::to_value(
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .conversation_summaries(&user_id)
                .map_err(|e| e.to_string())?,
        ),
        Command::MarkMessagesRead { user_id, ids } => {
            if ids.len() > 1000 {
                return Err("Too many message ids".into());
            }
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .mark_messages_read(&user_id, &ids)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
        Command::GetLocalMessagePage {
            user_id,
            conversation_id,
            limit,
            before_timestamp,
            before_id,
        } => serde_json::to_value(
            commands::chat::get_local_message_page(
                user_id,
                conversation_id,
                limit,
                before_timestamp,
                before_id,
                state,
            )
            .await?,
        ),
        Command::SignOut {} => serde_json::to_value(commands::keystore::sign_out().await?),
        Command::RetryMessage { message_id } => {
            serde_json::to_value(commands::chat::retry_message(message_id, state).await?)
        }
        Command::SendMessage {
            message_id,
            sender_id,
            ciphertext,
            signature,
            sender_device_id,
            payloads,
        } => serde_json::to_value(
            commands::chat::send_message(
                sender_id,
                ciphertext,
                signature,
                sender_device_id,
                payloads,
                message_id,
                state,
            )
            .await?,
        ),
        Command::PollMessages {} => {
            serde_json::to_value(commands::chat::poll_messages(state).await?)
        }
        Command::GetLocalMessages {
            conversation_id,
            limit,
            offset,
        } => serde_json::to_value(
            commands::chat::get_local_messages(conversation_id, limit, offset, state).await?,
        ),
        Command::EncryptMessage {
            plaintext,
            recipient_public_key,
            sender_secret_key,
        } => serde_json::to_value(
            commands::chat::encrypt_message(plaintext, recipient_public_key, sender_secret_key)
                .await?,
        ),
        Command::DecryptMessage {
            ciphertext,
            sender_public_key,
            recipient_secret_key,
        } => serde_json::to_value(
            commands::chat::decrypt_message(ciphertext, sender_public_key, recipient_secret_key)
                .await?,
        ),
        Command::SignMessage {
            message,
            signing_key,
        } => serde_json::to_value(commands::chat::sign_message(message, signing_key).await?),
        Command::VerifyMessage {
            message,
            signature,
            sender_public_key,
        } => serde_json::to_value(
            commands::chat::verify_message(message, signature, sender_public_key).await?,
        ),
        Command::GenerateKeypairCmd {} => {
            serde_json::to_value(commands::chat::generate_keypair_cmd().await?)
        }
        Command::SaveKeypair { data } => {
            serde_json::to_value(commands::keystore::save_keypair(data)?)
        }
        Command::LoadKeypair {} => serde_json::to_value(commands::keystore::load_keypair()?),
        Command::ClearKeypair {} => serde_json::to_value(commands::keystore::clear_keypair()?),
        Command::Register {
            invite_code,
            username,
            password,
            server_url,
            public_key,
            ed25519_pk,
        } => serde_json::to_value(
            commands::auth::register(
                invite_code,
                username,
                password,
                server_url,
                public_key,
                ed25519_pk,
            )
            .await?,
        ),
        Command::Login {
            username,
            password,
            server_url,
            public_key,
            ed25519_pk,
            device_id,
        } => serde_json::to_value(
            commands::auth::login(
                username, password, server_url, public_key, ed25519_pk, device_id,
            )
            .await?,
        ),
        Command::RefreshSession {
            server_url,
            refresh_token,
        } => {
            serde_json::to_value(commands::auth::refresh_session(server_url, refresh_token).await?)
        }
        Command::ConnectRelay {
            server_url,
            user_id,
            token,
            device_id,
        } => serde_json::to_value(
            commands::auth::connect_relay(server_url, user_id, token, device_id, state).await?,
        ),
        Command::Disconnect {} => serde_json::to_value(commands::auth::disconnect(state).await?),
        Command::ValidateInvite {
            server_url,
            invite_code,
        } => serde_json::to_value(commands::auth::validate_invite(server_url, invite_code).await?),
        Command::AddContact {
            user_id,
            username,
            public_key,
            ed25519_pk,
        } => serde_json::to_value(
            commands::contacts::add_contact(user_id, username, public_key, ed25519_pk, state)
                .await?,
        ),
        Command::GetContacts {} => {
            serde_json::to_value(commands::contacts::get_contacts(state).await?)
        }
        Command::RemoveContact { user_id } => {
            serde_json::to_value(commands::contacts::remove_contact(user_id, state).await?)
        }
        Command::SetContactTrust {
            user_id,
            trust_state,
        } => serde_json::to_value(
            commands::contacts::set_contact_trust(user_id, trust_state, state).await?,
        ),
        Command::GetUserDevices {
            server_url,
            user_id,
            access_token,
        } => serde_json::to_value(
            commands::contacts::get_user_devices(server_url, user_id, access_token).await?,
        ),
        Command::SearchUsers {
            server_url,
            query,
            access_token,
        } => serde_json::to_value(
            commands::contacts::search_users(server_url, query, access_token).await?,
        ),
        Command::GetStorageStats {} => {
            serde_json::to_value(commands::storage::get_storage_stats(state).await?)
        }
        Command::ClearExpiredMessages {} => {
            serde_json::to_value(commands::storage::clear_expired_messages(state).await?)
        }
        Command::ClearDownloadedAttachments {} => {
            serde_json::to_value(commands::storage::clear_downloaded_attachments(state).await?)
        }
    };
    result.map_err(|_| "Failed to serialize response".to_string())
}
