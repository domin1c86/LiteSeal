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
    },
    #[serde(rename = "search_users")]
    SearchUsers {
        #[serde(rename = "serverUrl")]
        server_url: String,
        #[serde(rename = "query")]
        query: String,
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
        } => serde_json::to_value(commands::contacts::get_user_devices(server_url, user_id).await?),
        Command::SearchUsers { server_url, query } => {
            serde_json::to_value(commands::contacts::search_users(server_url, query).await?)
        }
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
