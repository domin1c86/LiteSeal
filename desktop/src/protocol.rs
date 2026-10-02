use crate::{commands, AppState};
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
    #[serde(rename = "get_direct_chat")]
    GetDirectChat {},
    #[serde(rename = "get_direct_history")]
    GetDirectHistory { before: Option<i64> },
    #[serde(rename = "inspect_direct_peer")]
    InspectDirectPeer { account: String },
    #[serde(rename = "confirm_direct_peer")]
    ConfirmDirectPeer {
        account: String,
        fingerprint: String,
    },
    #[serde(rename = "prepare_direct_text")]
    PrepareDirectText { account: String, text: String },
    #[serde(rename = "direct_task_step")]
    DirectTaskStep { id: String },
    #[serde(rename = "cancel_direct_task")]
    CancelDirectTask { id: String },
    #[serde(rename = "forget_direct_task")]
    ForgetDirectTask { id: String },
    #[serde(rename = "hide_direct_message")]
    HideDirectMessage { id: String },
    #[serde(rename = "process_direct_chat")]
    ProcessDirectChat {},
    #[serde(rename = "get_normal_profile")]
    GetNormalProfile {},
    #[serde(rename = "select_normal_profile")]
    SelectNormalProfile {
        target: commands::normal_profile::Target,
        generation: u64,
        #[serde(rename = "scopeFingerprint")]
        scope_fingerprint: String,
    },
    #[serde(rename = "clear_normal_profile")]
    ClearNormalProfile { generation: u64 },
    #[serde(rename = "get_session_refresh")]
    GetSessionRefresh {
        target: commands::session_refresh::Target,
    },
    #[serde(rename = "prepare_session_refresh")]
    PrepareSessionRefresh {
        target: commands::session_refresh::Target,
    },
    #[serde(rename = "session_refresh_step")]
    SessionRefreshStep {
        target: commands::session_refresh::Target,
        id: String,
    },
    #[serde(rename = "cancel_session_refresh")]
    CancelSessionRefresh {
        target: commands::session_refresh::Target,
        id: String,
        #[serde(rename = "confirmedFamilyExit")]
        confirmed_family_exit: bool,
    },
    #[serde(rename = "forget_session_refresh")]
    ForgetSessionRefresh {
        target: commands::session_refresh::Target,
        id: String,
    },
    #[serde(rename = "process_session_refreshes")]
    ProcessSessionRefreshes {},
    #[serde(rename = "get_root_messaging")]
    GetRootMessaging {},
    #[serde(rename = "check_root_messaging")]
    CheckRootMessaging {},
    #[serde(rename = "prepare_root_messaging")]
    PrepareRootMessaging {
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "root_messaging_step")]
    RootMessagingStep { id: String },
    #[serde(rename = "cancel_root_messaging")]
    CancelRootMessaging { id: String },
    #[serde(rename = "forget_root_messaging")]
    ForgetRootMessaging { id: String },
    #[serde(rename = "get_root_session")]
    GetRootSession {},
    #[serde(rename = "prepare_root_session")]
    PrepareRootSession { username: String },
    #[serde(rename = "root_session_step")]
    RootSessionStep {
        id: String,
        password: Option<String>,
    },
    #[serde(rename = "inspect_root_session")]
    InspectRootSession { id: String },
    #[serde(rename = "cancel_root_session")]
    CancelRootSession { id: String },
    #[serde(rename = "forget_root_session")]
    ForgetRootSession { id: String },
    #[serde(rename = "save_root_session")]
    SaveRootSession { id: String },
    #[serde(rename = "get_join_activation")]
    GetJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "prepare_join_activation")]
    PrepareJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "join_activation_step")]
    JoinActivationStep {
        #[serde(rename = "profileId")]
        profile_id: String,
        id: String,
        password: Option<String>,
    },
    #[serde(rename = "inspect_join_activation")]
    InspectJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
        id: String,
    },
    #[serde(rename = "cancel_join_activation")]
    CancelJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
        id: String,
    },
    #[serde(rename = "forget_join_activation")]
    ForgetJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
        id: String,
    },
    #[serde(rename = "save_join_activation")]
    SaveJoinActivation {
        #[serde(rename = "profileId")]
        profile_id: String,
        id: String,
    },
    #[serde(rename = "clear_join_activation_session")]
    ClearJoinActivationSession {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "list_device_join_profiles")]
    ListDeviceJoinProfiles {},
    #[serde(rename = "create_device_join_profile")]
    CreateDeviceJoinProfile {
        origin: String,
        username: String,
        #[serde(rename = "deviceName")]
        device_name: String,
    },
    #[serde(rename = "get_device_join_profile")]
    GetDeviceJoinProfile {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "confirm_device_join_root")]
    ConfirmDeviceJoinRoot {
        #[serde(rename = "profileId")]
        profile_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "device_join_step")]
    DeviceJoinStep {
        #[serde(rename = "profileId")]
        profile_id: String,
        password: Option<String>,
    },
    #[serde(rename = "cancel_device_join")]
    CancelDeviceJoin {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "abandon_device_join")]
    AbandonDeviceJoin {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "forget_device_join_profile")]
    ForgetDeviceJoinProfile {
        #[serde(rename = "profileId")]
        profile_id: String,
    },
    #[serde(rename = "get_device_control")]
    GetDeviceControl {},
    #[serde(rename = "inspect_device_request")]
    InspectDeviceRequest {
        #[serde(rename = "requestId")]
        request_id: String,
    },
    #[serde(rename = "prepare_device_challenge")]
    PrepareDeviceChallenge {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "prepare_device_grant")]
    PrepareDeviceGrant {
        #[serde(rename = "requestId")]
        request_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "prepare_device_revoke")]
    PrepareDeviceRevoke {
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "device_task_step")]
    DeviceTaskStep { id: String },
    #[serde(rename = "cancel_device_task")]
    CancelDeviceTask { id: String },
    #[serde(rename = "discard_device_task")]
    DiscardDeviceTask { id: String },
    #[serde(rename = "suspend_device_control")]
    SuspendDeviceControl {},
    #[serde(rename = "resume_device_control")]
    ResumeDeviceControl {},
    #[serde(rename = "get_group_extensions")]
    GetGroupExtensions {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "messageIds")]
        message_ids: Vec<String>,
    },
    #[serde(rename = "sync_group_extensions")]
    SyncGroupExtensions {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "submit_group_extension")]
    SubmitGroupExtension {
        #[serde(rename = "groupId")]
        group_id: String,
        command: liteseal_core::groups::ExtensionCommand,
    },
    #[serde(rename = "retry_group_extension")]
    RetryGroupExtension {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "cancel_group_extension")]
    CancelGroupExtension {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "select_group_attachment")]
    SelectGroupAttachment {
        #[serde(rename = "groupId")]
        group_id: String,
        path: String,
    },
    #[serde(rename = "stage_group_recorded_audio")]
    StageGroupRecordedAudio {
        #[serde(rename = "groupId")]
        group_id: String,
        encoded: String,
        #[serde(rename = "durationMs")]
        duration_ms: u32,
    },
    #[serde(rename = "stage_group_clipboard_image")]
    StageGroupClipboardImage {
        #[serde(rename = "groupId")]
        group_id: String,
        encoded: String,
    },
    #[serde(rename = "group_attachment_tasks")]
    GroupAttachmentTasks {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "group_attachment_step")]
    GroupAttachmentStep {
        #[serde(rename = "groupId")]
        group_id: String,
        id: String,
    },
    #[serde(rename = "publish_group_attachment")]
    PublishGroupAttachment {
        #[serde(rename = "groupId")]
        group_id: String,
        id: String,
    },
    #[serde(rename = "cancel_group_attachment")]
    CancelGroupAttachment {
        #[serde(rename = "groupId")]
        group_id: String,
        id: String,
    },
    #[serde(rename = "begin_group_attachment_download")]
    BeginGroupAttachmentDownload {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
    },
    #[serde(rename = "export_group_attachment")]
    ExportGroupAttachment {
        #[serde(rename = "groupId")]
        group_id: String,
        id: String,
        path: String,
    },
    #[serde(rename = "clear_group_attachment_cache")]
    ClearGroupAttachmentCache {
        #[serde(rename = "groupId", default)]
        group_id: Option<String>,
    },
    #[serde(rename = "start_backup_export")]
    StartBackupExport {
        path: String,
        password: String,
        #[serde(rename = "includeAttachments")]
        include_attachments: bool,
    },
    #[serde(rename = "start_backup_restore")]
    StartBackupRestore {
        path: String,
        parent: String,
        password: String,
    },
    #[serde(rename = "get_backup_job")]
    GetBackupJob { id: String },
    #[serde(rename = "cancel_backup_job")]
    CancelBackupJob { id: String },
    #[serde(rename = "open_backup_archive")]
    OpenBackupArchive { id: String },
    #[serde(rename = "get_backup_archive_info")]
    GetBackupArchiveInfo { id: String },
    #[serde(rename = "get_backup_conversations")]
    GetBackupConversations {
        id: String,
        #[serde(default)]
        after: Option<String>,
    },
    #[serde(rename = "get_backup_history")]
    GetBackupHistory {
        id: String,
        kind: String,
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "beforeTime", default)]
        before_time: Option<i64>,
        #[serde(rename = "beforeId", default)]
        before_id: Option<String>,
        #[serde(rename = "beforeGroup", default)]
        before_group: Option<i64>,
    },
    #[serde(rename = "export_backup_attachment")]
    ExportBackupAttachment {
        id: String,
        #[serde(rename = "messageId")]
        message_id: String,
        path: String,
        #[serde(rename = "groupId", default)]
        group_id: Option<String>,
    },
    #[serde(rename = "close_backup_archive")]
    CloseBackupArchive {},
    #[serde(rename = "get_group_collaboration")]
    GetGroupCollaboration {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "messageIds", default)]
        message_ids: Option<Vec<String>>,
    },
    #[serde(rename = "sync_group_collaboration")]
    SyncGroupCollaboration {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "submit_group_collaboration")]
    SubmitGroupCollaboration {
        #[serde(rename = "groupId")]
        group_id: String,
        command: liteseal_core::groups::CollaborationCommand,
    },
    #[serde(rename = "retry_group_collaboration")]
    RetryGroupCollaboration {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "discard_group_collaboration_conflict")]
    DiscardGroupCollaborationConflict {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "get_group_storage_stats")]
    GetGroupStorageStats {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "clear_group_history")]
    ClearGroupHistory {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "get_sent_group_invites")]
    GetSentGroupInvites {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "afterId", default)]
        after_id: Option<String>,
    },
    #[serde(rename = "revoke_group_invite")]
    RevokeGroupInvite {
        #[serde(rename = "inviteId")]
        invite_id: String,
    },
    #[serde(rename = "set_group_muted")]
    SetGroupMuted {
        #[serde(rename = "groupId")]
        group_id: String,
        muted: bool,
    },
    #[serde(rename = "sync_group")]
    SyncGroup {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "get_groups")]
    GetGroups {
        #[serde(default)]
        refresh: bool,
        #[serde(rename = "afterId", default)]
        after_id: Option<String>,
    },
    #[serde(rename = "create_group")]
    CreateGroup { name: String },
    #[serde(rename = "inspect_group")]
    InspectGroup {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "inviteId", default)]
        invite_id: Option<String>,
    },
    #[serde(rename = "inspect_group_peer")]
    InspectGroupPeer {
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    #[serde(rename = "recover_group")]
    RecoverGroup {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "invite_group_member")]
    InviteGroupMember {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "peerId")]
        peer_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "accept_group_invite")]
    AcceptGroupInvite {
        #[serde(rename = "inviteId")]
        invite_id: String,
        #[serde(rename = "confirmedFingerprint")]
        confirmed_fingerprint: String,
    },
    #[serde(rename = "decline_group_invite")]
    DeclineGroupInvite {
        #[serde(rename = "inviteId")]
        invite_id: String,
    },
    #[serde(rename = "change_group_membership")]
    ChangeGroupMembership {
        #[serde(rename = "groupId")]
        group_id: String,
        action: String,
        #[serde(default)]
        value: Option<String>,
    },
    #[serde(rename = "get_group_history")]
    GetGroupHistory {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(default)]
        before: Option<i64>,
    },
    #[serde(rename = "group_draft")]
    GroupDraft {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(default)]
        text: Option<String>,
    },
    #[serde(rename = "mark_group_seen")]
    MarkGroupSeen {
        #[serde(rename = "groupId")]
        group_id: String,
        ids: Vec<String>,
    },
    #[serde(rename = "send_group_text")]
    SendGroupText {
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(default)]
        text: Option<String>,
    },
    #[serde(rename = "cancel_group_send")]
    CancelGroupSend {
        #[serde(rename = "groupId")]
        group_id: String,
    },
    #[serde(rename = "process_groups")]
    ProcessGroups {},
    #[serde(rename = "save_scheduled_message")]
    SaveScheduledMessage {
        id: Option<String>,
        #[serde(rename = "peerId")]
        peer_id: String,
        text: String,
        #[serde(rename = "dueAt")]
        due_at: i64,
    },
    #[serde(rename = "list_scheduled_messages")]
    ListScheduledMessages {},
    #[serde(rename = "cancel_scheduled_message")]
    CancelScheduledMessage {
        id: String,
        #[serde(rename = "removeSubmitted", default)]
        remove_submitted: bool,
    },
    #[serde(rename = "send_scheduled_now")]
    SendScheduledNow { id: String },
    #[serde(rename = "process_scheduled_messages")]
    ProcessScheduledMessages {},
    #[serde(rename = "suspend_scheduled_messages")]
    SuspendScheduledMessages {},
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
    #[serde(rename = "set_conversation_muted")]
    SetConversationMuted {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "peerId")]
        peer_id: String,
        muted: bool,
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
    #[serde(rename = "unlock_app")]
    UnlockApp { password: String },
    #[serde(rename = "submit_reaction")]
    SubmitReaction {
        #[serde(rename = "targetId")]
        target_id: String,
        #[serde(rename = "peerId")]
        peer_id: String,
        emoji: String,
    },
    #[serde(rename = "sync_reactions")]
    SyncReactions {},
    #[serde(rename = "get_read_receipt_enabled")]
    GetReadReceiptEnabled {},
    #[serde(rename = "set_read_receipt_enabled")]
    SetReadReceiptEnabled { enabled: bool },
    #[serde(rename = "sync_read_receipts")]
    SyncReadReceipts {},
    #[serde(rename = "get_read_receipts")]
    GetReadReceipts {
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },
    #[serde(rename = "mark_visible_messages")]
    MarkVisibleMessages {
        #[serde(rename = "userId")]
        user_id: String,
        ids: Vec<String>,
    },
    #[serde(rename = "get_typing_enabled")]
    GetTypingEnabled {},
    #[serde(rename = "set_typing_enabled")]
    SetTypingEnabled { enabled: bool },
    #[serde(rename = "send_typing")]
    SendTyping {
        #[serde(rename = "peerId")]
        peer_id: String,
        active: bool,
    },
    #[serde(rename = "get_reactions")]
    GetReactions {
        #[serde(rename = "conversationId")]
        conversation_id: String,
    },
    #[serde(rename = "list_contact_requests")]
    ListContactRequests {},
    #[serde(rename = "set_contact_policy")]
    SetContactPolicy {
        #[serde(rename = "peerId")]
        peer_id: String,
        status: String,
    },
    #[serde(rename = "list_account_sessions")]
    ListAccountSessions {},
    #[serde(rename = "get_public_profile")]
    GetPublicProfile {
        #[serde(rename = "userId")]
        user_id: String,
    },
    #[serde(rename = "update_public_profile")]
    UpdatePublicProfile {
        #[serde(rename = "displayName")]
        display_name: String,
        #[serde(rename = "avatarPng")]
        avatar_png: Option<String>,
    },
    #[serde(rename = "logout_all_sessions")]
    LogoutAllSessions {},
    #[serde(rename = "change_password")]
    ChangePassword {
        #[serde(rename = "currentPassword")]
        current_password: String,
        #[serde(rename = "newPassword")]
        new_password: String,
    },
    #[serde(rename = "select_attachment")]
    SelectAttachment {
        path: String,
        #[serde(rename = "peerId")]
        peer_id: String,
    },
    #[serde(rename = "stage_clipboard_image")]
    StageClipboardImage {
        #[serde(rename = "peerId")]
        peer_id: String,
        encoded: String,
    },
    #[serde(rename = "stage_recorded_audio")]
    StageRecordedAudio {
        #[serde(rename = "peerId")]
        peer_id: String,
        encoded: String,
        #[serde(rename = "durationMs")]
        duration_ms: u32,
    },
    #[serde(rename = "list_attachment_tasks")]
    ListAttachmentTasks {},
    #[serde(rename = "attachment_step")]
    AttachmentStep { id: String },
    #[serde(rename = "publish_attachment")]
    PublishAttachment { id: String },
    #[serde(rename = "begin_attachment_download")]
    BeginAttachmentDownload {
        #[serde(rename = "messageId")]
        message_id: String,
    },
    #[serde(rename = "export_attachment")]
    ExportAttachment {
        #[serde(rename = "messageId")]
        message_id: String,
        path: Option<String>,
        offset: Option<usize>,
        #[serde(rename = "taskId")]
        task_id: Option<String>,
    },
    #[serde(rename = "forget_attachment_task")]
    ForgetAttachmentTask { id: String },
    #[serde(rename = "attachment_cache_stats")]
    AttachmentCacheStats {},
    #[serde(rename = "clear_attachment_cache")]
    ClearAttachmentCache {
        #[serde(rename = "peerId")]
        peer_id: Option<String>,
    },
    #[serde(rename = "get_personal_organizer")]
    GetPersonalOrganizer {},
    #[serde(rename = "save_personal_organizer")]
    SavePersonalOrganizer { content: String },
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
    #[serde(rename = "get_message_context")]
    GetMessageContext {
        #[serde(rename = "userId")]
        user_id: String,
        #[serde(rename = "conversationId")]
        conversation_id: String,
        #[serde(rename = "messageId")]
        message_id: String,
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
    },
    #[serde(rename = "decrypt_message")]
    DecryptMessage {
        #[serde(rename = "ciphertext")]
        ciphertext: Vec<u8>,
        #[serde(rename = "senderPublicKey")]
        sender_public_key: Vec<u8>,
    },
    #[serde(rename = "sign_message")]
    SignMessage {
        #[serde(rename = "message")]
        message: Vec<u8>,
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
    #[serde(rename = "sign_out")]
    SignOut {},
    #[serde(rename = "prepare_identity")]
    PrepareIdentity {},
    #[serde(rename = "load_identity")]
    LoadIdentity {},
    #[serde(rename = "save_session")]
    SaveSession {
        #[serde(rename = "userId")]
        user_id: String,
        token: String,
        #[serde(rename = "refreshToken")]
        refresh_token: String,
        #[serde(rename = "deviceId")]
        device_id: String,
        #[serde(rename = "serverUrl")]
        server_url: String,
    },
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
    let identity_write = matches!(
        &command,
        Command::SaveSession { .. }
            | Command::ClearKeypair {}
            | Command::SignOut {}
            | Command::LogoutAllSessions {}
            | Command::ChangePassword { .. }
    );
    let transition = matches!(
        &command,
        Command::SelectNormalProfile { .. } | Command::ClearNormalProfile { .. }
    );
    let lifecycle = matches!(
        &command,
        Command::SuspendDeviceControl {} | Command::ResumeDeviceControl {}
    );
    let management = matches!(
        &command,
        Command::GetDirectChat {}
            | Command::GetDirectHistory { .. }
            | Command::InspectDirectPeer { .. }
            | Command::ConfirmDirectPeer { .. }
            | Command::PrepareDirectText { .. }
            | Command::DirectTaskStep { .. }
            | Command::CancelDirectTask { .. }
            | Command::ForgetDirectTask { .. }
            | Command::HideDirectMessage { .. }
            | Command::ProcessDirectChat {}
            | Command::UnlockApp { .. }
            | Command::SuspendScheduledMessages {}
            | Command::GetNormalProfile {}
            | Command::SelectNormalProfile { .. }
            | Command::ClearNormalProfile { .. }
            | Command::GetSessionRefresh { .. }
            | Command::PrepareSessionRefresh { .. }
            | Command::SessionRefreshStep { .. }
            | Command::CancelSessionRefresh { .. }
            | Command::ForgetSessionRefresh { .. }
            | Command::ProcessSessionRefreshes {}
            | Command::GetRootMessaging {}
            | Command::CheckRootMessaging {}
            | Command::PrepareRootMessaging { .. }
            | Command::RootMessagingStep { .. }
            | Command::CancelRootMessaging { .. }
            | Command::ForgetRootMessaging { .. }
            | Command::GetRootSession {}
            | Command::PrepareRootSession { .. }
            | Command::RootSessionStep { .. }
            | Command::InspectRootSession { .. }
            | Command::CancelRootSession { .. }
            | Command::ForgetRootSession { .. }
            | Command::SaveRootSession { .. }
            | Command::GetJoinActivation { .. }
            | Command::PrepareJoinActivation { .. }
            | Command::JoinActivationStep { .. }
            | Command::InspectJoinActivation { .. }
            | Command::CancelJoinActivation { .. }
            | Command::ForgetJoinActivation { .. }
            | Command::SaveJoinActivation { .. }
            | Command::ClearJoinActivationSession { .. }
            | Command::ListDeviceJoinProfiles {}
            | Command::CreateDeviceJoinProfile { .. }
            | Command::GetDeviceJoinProfile { .. }
            | Command::ConfirmDeviceJoinRoot { .. }
            | Command::DeviceJoinStep { .. }
            | Command::CancelDeviceJoin { .. }
            | Command::AbandonDeviceJoin { .. }
            | Command::ForgetDeviceJoinProfile { .. }
            | Command::GetDeviceControl {}
            | Command::InspectDeviceRequest { .. }
            | Command::PrepareDeviceChallenge { .. }
            | Command::PrepareDeviceGrant { .. }
            | Command::PrepareDeviceRevoke { .. }
            | Command::DeviceTaskStep { .. }
            | Command::CancelDeviceTask { .. }
            | Command::DiscardDeviceTask { .. }
            | Command::SuspendDeviceControl {}
            | Command::ResumeDeviceControl {}
            | Command::StartBackupRestore { .. }
            | Command::GetBackupJob { .. }
            | Command::CancelBackupJob { .. }
            | Command::OpenBackupArchive { .. }
            | Command::CloseBackupArchive { .. }
            | Command::GetBackupArchiveInfo { .. }
            | Command::GetBackupConversations { .. }
            | Command::GetBackupHistory { .. }
            | Command::ExportBackupAttachment { .. }
    );
    let _normal_guard = if transition || lifecycle {
        None
    } else {
        Some(state.normal_profile_gate.read().await)
    };
    let normal_epoch = if !management {
        if !commands::normal_profile::allows_legacy(state)? {
            return match &command {
                Command::ProcessScheduledMessages {} => Ok(serde_json::json!(0)),
                Command::ProcessGroups {} => Ok(
                    serde_json::json!({"changed":0,"errors":[],"notifications":[],"notification_identity":null}),
                ),
                _ => Err(
                    "当前选中的独立档案不能使用原设备接口；原身份和历史保留，请返回档案管理".into(),
                ),
            };
        }
        Some(commands::normal_profile::lease(state)?)
    } else {
        None
    };
    // A single async read gate covers the full legacy business operation. Root
    // preparation waits for these operations to finish before its atomic check.
    let legacy_write = matches!(
        &command,
        Command::SendMessage { .. }
            | Command::RetryMessage { .. }
            | Command::SelectAttachment { .. }
            | Command::StageClipboardImage { .. }
            | Command::StageRecordedAudio { .. }
            | Command::AttachmentStep { .. }
            | Command::PublishAttachment { .. }
            | Command::SaveScheduledMessage { .. }
            | Command::SendScheduledNow { .. }
            | Command::ProcessScheduledMessages {}
            | Command::SubmitMessageOperation { .. }
            | Command::SubmitReaction { .. }
            | Command::MarkVisibleMessages { .. }
            | Command::SendTyping { .. }
    );
    let _legacy_guard = if legacy_write {
        let guard = state.legacy_direct_gate.read().await;
        if commands::root_messaging::admission(state)?
            != liteseal_core::trusted_devices::activation::legacy::Admission::Legacy
        {
            match &command {
                Command::ProcessScheduledMessages {} => return Ok(serde_json::json!(0)),
                Command::MarkVisibleMessages { user_id, ids } => {
                    commands::root_messaging::local_seen(state, user_id, ids)?;
                    return Ok(Value::Null);
                }
                Command::AttachmentStep { id }
                    if commands::root_messaging::download(state, id)? => {}
                _ => {
                    return Err(
                        "原设备已准备或启用协议切换，旧单聊发送已暂停；原任务和历史保留".into(),
                    )
                }
            }
        }
        Some(guard)
    } else {
        None
    };
    let result = match command {
        Command::GetDirectChat {} => serde_json::to_value(commands::direct::snapshot(state)?),
        Command::GetDirectHistory { before } => {
            serde_json::to_value(commands::direct::history(state, before)?)
        }
        Command::InspectDirectPeer { account } => {
            serde_json::to_value(commands::direct::inspect_peer(state, account).await?)
        }
        Command::ConfirmDirectPeer {
            account,
            fingerprint,
        } => serde_json::to_value(commands::direct::confirm_peer(state, account, fingerprint)?),
        Command::PrepareDirectText { account, text } => {
            serde_json::to_value(commands::direct::prepare(state, account, text).await?)
        }
        Command::DirectTaskStep { id } => {
            serde_json::to_value(commands::direct::step(state, id).await?)
        }
        Command::CancelDirectTask { id } => {
            serde_json::to_value(commands::direct::cancel(state, id)?)
        }
        Command::ForgetDirectTask { id } => {
            serde_json::to_value(commands::direct::forget(state, id)?)
        }
        Command::HideDirectMessage { id } => {
            serde_json::to_value(commands::direct::hide(state, id)?)
        }
        Command::ProcessDirectChat {} => {
            serde_json::to_value(commands::direct::process(state).await?)
        }
        Command::GetNormalProfile {} => {
            serde_json::to_value(commands::normal_profile::snapshot(state)?)
        }
        Command::SelectNormalProfile {
            target,
            generation,
            scope_fingerprint,
        } => serde_json::to_value(
            commands::normal_profile::select(
                state,
                Some(target),
                generation,
                Some(scope_fingerprint),
            )
            .await?,
        ),
        Command::ClearNormalProfile { generation } => serde_json::to_value(
            commands::normal_profile::select(state, None, generation, None).await?,
        ),
        Command::GetSessionRefresh { target } => {
            serde_json::to_value(commands::session_refresh::snapshot(state, target)?)
        }
        Command::PrepareSessionRefresh { target } => {
            serde_json::to_value(commands::session_refresh::prepare(state, target)?)
        }
        Command::SessionRefreshStep { target, id } => {
            serde_json::to_value(commands::session_refresh::step(state, target, id).await?)
        }
        Command::CancelSessionRefresh {
            target,
            id,
            confirmed_family_exit,
        } => serde_json::to_value(commands::session_refresh::cancel(
            state,
            target,
            id,
            confirmed_family_exit,
        )?),
        Command::ForgetSessionRefresh { target, id } => {
            serde_json::to_value(commands::session_refresh::forget(state, target, id)?)
        }
        Command::ProcessSessionRefreshes {} => {
            serde_json::to_value(commands::session_refresh::process(state).await?)
        }
        Command::GetRootSession {} => {
            serde_json::to_value(commands::root_session::snapshot(state)?)
        }
        Command::PrepareRootSession { username } => {
            serde_json::to_value(commands::root_session::prepare(state, username).await?)
        }
        Command::RootSessionStep { id, password } => {
            serde_json::to_value(commands::root_session::step(state, id, password).await?)
        }
        Command::InspectRootSession { id } => {
            serde_json::to_value(commands::root_session::inspect(state, id).await?)
        }
        Command::CancelRootSession { id } => {
            serde_json::to_value(commands::root_session::cancel(state, id)?)
        }
        Command::ForgetRootSession { id } => {
            serde_json::to_value(commands::root_session::forget(state, id)?)
        }
        Command::SaveRootSession { id } => {
            serde_json::to_value(commands::root_session::save(state, id).await?)
        }
        Command::GetRootMessaging {} => {
            serde_json::to_value(commands::root_messaging::snapshot(state)?)
        }
        Command::CheckRootMessaging {} => {
            serde_json::to_value(commands::root_messaging::check(state).await?)
        }
        Command::PrepareRootMessaging {
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::root_messaging::prepare(state, confirmed_fingerprint).await?,
        ),
        Command::RootMessagingStep { id } => {
            serde_json::to_value(commands::root_messaging::step(state, id).await?)
        }
        Command::CancelRootMessaging { id } => {
            serde_json::to_value(commands::root_messaging::cancel(state, id)?)
        }
        Command::ForgetRootMessaging { id } => {
            serde_json::to_value(commands::root_messaging::forget(state, id)?)
        }
        Command::GetJoinActivation { profile_id } => {
            serde_json::to_value(commands::device_activation::snapshot(state, profile_id)?)
        }
        Command::PrepareJoinActivation { profile_id } => {
            serde_json::to_value(commands::device_activation::prepare(state, profile_id).await?)
        }
        Command::JoinActivationStep {
            profile_id,
            id,
            password,
        } => serde_json::to_value(
            commands::device_activation::step(state, profile_id, id, password).await?,
        ),
        Command::InspectJoinActivation { profile_id, id } => {
            serde_json::to_value(commands::device_activation::inspect(state, profile_id, id).await?)
        }
        Command::CancelJoinActivation { profile_id, id } => {
            serde_json::to_value(commands::device_activation::cancel(state, profile_id, id)?)
        }
        Command::ForgetJoinActivation { profile_id, id } => {
            serde_json::to_value(commands::device_activation::forget(state, profile_id, id)?)
        }
        Command::SaveJoinActivation { profile_id, id } => {
            serde_json::to_value(commands::device_activation::save(state, profile_id, id).await?)
        }
        Command::ClearJoinActivationSession { profile_id } => serde_json::to_value(
            commands::device_activation::clear_session(state, profile_id)?,
        ),
        Command::ListDeviceJoinProfiles {} => {
            serde_json::to_value(commands::device_join::list(state)?)
        }
        Command::CreateDeviceJoinProfile {
            origin,
            username,
            device_name,
        } => serde_json::to_value(commands::device_join::create(
            state,
            origin,
            username,
            device_name,
        )?),
        Command::GetDeviceJoinProfile { profile_id } => {
            serde_json::to_value(commands::device_join::snapshot(state, profile_id)?)
        }
        Command::ConfirmDeviceJoinRoot {
            profile_id,
            confirmed_fingerprint,
        } => serde_json::to_value(commands::device_join::confirm(
            state,
            profile_id,
            confirmed_fingerprint,
        )?),
        Command::DeviceJoinStep {
            profile_id,
            password,
        } => serde_json::to_value(commands::device_join::step(state, profile_id, password).await?),
        Command::CancelDeviceJoin { profile_id } => {
            serde_json::to_value(commands::device_join::cancel(state, profile_id)?)
        }
        Command::AbandonDeviceJoin { profile_id } => {
            serde_json::to_value(commands::device_join::abandon(state, profile_id)?)
        }
        Command::ForgetDeviceJoinProfile { profile_id } => {
            serde_json::to_value(commands::device_join::forget(state, profile_id)?)
        }
        Command::GetDeviceControl {} => {
            serde_json::to_value(commands::device_control::snapshot(state).await?)
        }
        Command::InspectDeviceRequest { request_id } => {
            serde_json::to_value(commands::device_control::inspect(state, request_id).await?)
        }
        Command::PrepareDeviceChallenge {
            request_id,
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::device_control::prepare(state, request_id, confirmed_fingerprint, false)
                .await?,
        ),
        Command::PrepareDeviceGrant {
            request_id,
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::device_control::prepare(state, request_id, confirmed_fingerprint, true)
                .await?,
        ),
        Command::PrepareDeviceRevoke {
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::device_control::revoke(state, confirmed_fingerprint).await?,
        ),
        Command::DeviceTaskStep { id } => {
            serde_json::to_value(commands::device_control::step(state, id).await?)
        }
        Command::CancelDeviceTask { id } => {
            serde_json::to_value(commands::device_control::cancel(state, id)?)
        }
        Command::DiscardDeviceTask { id } => {
            serde_json::to_value(commands::device_control::discard(state, id)?)
        }
        Command::SuspendDeviceControl {} => {
            serde_json::to_value(commands::device_control::suspend(state)?)
        }
        Command::ResumeDeviceControl {} => {
            serde_json::to_value(commands::device_control::resume(state)?)
        }
        Command::GetGroupExtensions {
            group_id,
            message_ids,
        } => serde_json::to_value(
            commands::groups_media::extensions(state, group_id, message_ids).await?,
        ),
        Command::SyncGroupExtensions { group_id } => {
            serde_json::to_value(commands::groups_media::sync(state, group_id).await?)
        }
        Command::SubmitGroupExtension { group_id, command } => {
            serde_json::to_value(commands::groups_media::submit(state, group_id, command).await?)
        }
        Command::RetryGroupExtension { group_id } => {
            serde_json::to_value(commands::groups_media::retry(state, group_id, false).await?)
        }
        Command::CancelGroupExtension { group_id } => {
            serde_json::to_value(commands::groups_media::retry(state, group_id, true).await?)
        }
        Command::SelectGroupAttachment { group_id, path } => {
            serde_json::to_value(commands::groups_media::stage(state, group_id, path).await?)
        }
        Command::StageGroupRecordedAudio {
            group_id,
            encoded,
            duration_ms,
        } => {
            use base64::Engine;
            if encoded.len() > 15 * 1024 * 1024 || !(1..=60000).contains(&duration_ms) {
                return Err("群语音大小或时长无效".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "群语音编码无效")?;
            serde_json::to_value(
                commands::groups_media::stage_bytes(
                    state,
                    group_id,
                    bytes,
                    "voice-message.webm".into(),
                    Some(duration_ms),
                )
                .await?,
            )
        }
        Command::StageGroupClipboardImage { group_id, encoded } => {
            use base64::Engine;
            if encoded.len() > 15 * 1024 * 1024 {
                return Err("图片过大".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "图片编码无效")?;
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err("剪贴板图片格式无效".into());
            }
            serde_json::to_value(
                commands::groups_media::stage_bytes(
                    state,
                    group_id,
                    bytes,
                    "clipboard.png".into(),
                    None,
                )
                .await?,
            )
        }
        Command::GroupAttachmentTasks { group_id } => {
            serde_json::to_value(commands::groups_media::tasks(state, group_id).await?)
        }
        Command::GroupAttachmentStep { group_id, id } => {
            serde_json::to_value(commands::groups_media::step(state, group_id, id).await?)
        }
        Command::PublishGroupAttachment { group_id, id } => {
            serde_json::to_value(commands::groups_media::publish(state, group_id, id).await?)
        }
        Command::CancelGroupAttachment { group_id, id } => {
            serde_json::to_value(commands::groups_media::cancel(state, group_id, id).await?)
        }
        Command::BeginGroupAttachmentDownload {
            group_id,
            message_id,
        } => serde_json::to_value(
            commands::groups_media::download(state, group_id, message_id).await?,
        ),
        Command::ExportGroupAttachment { group_id, id, path } => {
            serde_json::to_value(commands::groups_media::export(state, group_id, id, path).await?)
        }
        Command::ClearGroupAttachmentCache { group_id } => {
            serde_json::to_value(commands::groups_media::clear(state, group_id).await?)
        }
        Command::StartBackupExport {
            path,
            password,
            include_attachments,
        } => serde_json::to_value(commands::backup::start_export(
            state,
            path,
            password,
            include_attachments,
        )?),
        Command::StartBackupRestore {
            path,
            parent,
            password,
        } => serde_json::to_value(commands::backup::start_restore(
            state, path, parent, password,
        )?),
        Command::GetBackupJob { id } => serde_json::to_value(commands::backup::status(state, &id)?),
        Command::CancelBackupJob { id } => {
            serde_json::to_value(commands::backup::cancel(state, &id)?)
        }
        Command::OpenBackupArchive { id } => Ok(commands::backup::open(state, &id)?),
        Command::GetBackupArchiveInfo { id } => Ok(commands::backup::info(state, &id)?),
        Command::GetBackupConversations { id, after } => Ok(commands::backup::conversations(
            state,
            &id,
            after.as_deref(),
        )?),
        Command::GetBackupHistory {
            id,
            kind,
            conversation_id,
            before_time,
            before_id,
            before_group,
        } => Ok(commands::backup::page(
            state,
            &id,
            &kind,
            &conversation_id,
            before_time,
            before_id.as_deref(),
            before_group,
        )?),
        Command::ExportBackupAttachment {
            id,
            message_id,
            path,
            group_id,
        } => serde_json::to_value(if let Some(group) = group_id {
            commands::backup::export_group_attachment(state, &id, &group, &message_id, &path)?
        } else {
            commands::backup::export_attachment(state, &id, &message_id, &path)?
        }),
        Command::CloseBackupArchive {} => serde_json::to_value(commands::backup::reset(state)?),
        Command::GetGroupCollaboration {
            group_id,
            message_ids,
        } => serde_json::to_value(
            commands::groups::collaboration_view(state, group_id, message_ids).await?,
        ),
        Command::SyncGroupCollaboration { group_id } => {
            serde_json::to_value(commands::groups::collaboration_sync(state, group_id).await?)
        }
        Command::SubmitGroupCollaboration { group_id, command } => serde_json::to_value(
            commands::groups::collaboration_send(state, group_id, command).await?,
        ),
        Command::RetryGroupCollaboration { group_id } => {
            serde_json::to_value(commands::groups::collaboration_retry(state, group_id).await?)
        }
        Command::DiscardGroupCollaborationConflict { group_id } => {
            serde_json::to_value(commands::groups::collaboration_discard(state, group_id).await?)
        }
        Command::GetGroupStorageStats { group_id } => {
            serde_json::to_value(commands::groups::storage_stats(state, group_id).await?)
        }
        Command::ClearGroupHistory { group_id } => {
            serde_json::to_value(commands::groups::clear_history(state, group_id).await?)
        }
        Command::GetSentGroupInvites { group_id, after_id } => {
            serde_json::to_value(commands::groups::sent_invites(state, group_id, after_id).await?)
        }
        Command::RevokeGroupInvite { invite_id } => {
            serde_json::to_value(commands::groups::revoke_invite(state, invite_id).await?)
        }
        Command::SetGroupMuted { group_id, muted } => {
            serde_json::to_value(commands::groups::set_muted(state, group_id, muted).await?)
        }
        Command::SyncGroup { group_id } => {
            serde_json::to_value(commands::groups::sync(state, group_id).await?)
        }
        Command::GetGroups { refresh, after_id } => {
            serde_json::to_value(commands::groups::list(state, refresh, after_id).await?)
        }
        Command::CreateGroup { name } => {
            serde_json::to_value(commands::groups::create(state, name).await?)
        }
        Command::InspectGroup {
            group_id,
            invite_id,
        } => serde_json::to_value(commands::groups::inspect(state, group_id, invite_id).await?),
        Command::InspectGroupPeer { peer_id } => {
            serde_json::to_value(commands::groups::peer(state, peer_id).await?)
        }
        Command::RecoverGroup {
            group_id,
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::groups::recover(state, group_id, confirmed_fingerprint).await?,
        ),
        Command::InviteGroupMember {
            group_id,
            peer_id,
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::groups::invite(state, group_id, peer_id, confirmed_fingerprint).await?,
        ),
        Command::AcceptGroupInvite {
            invite_id,
            confirmed_fingerprint,
        } => serde_json::to_value(
            commands::groups::accept(state, invite_id, confirmed_fingerprint).await?,
        ),
        Command::DeclineGroupInvite { invite_id } => {
            serde_json::to_value(commands::groups::decline(state, invite_id).await?)
        }
        Command::ChangeGroupMembership {
            group_id,
            action,
            value,
        } => serde_json::to_value(
            commands::groups::membership(state, group_id, action, value).await?,
        ),
        Command::GetGroupHistory { group_id, before } => {
            serde_json::to_value(commands::groups::history(state, group_id, before).await?)
        }
        Command::GroupDraft { group_id, text } => {
            serde_json::to_value(commands::groups::draft(state, group_id, text).await?)
        }
        Command::MarkGroupSeen { group_id, ids } => {
            serde_json::to_value(commands::groups::seen(state, group_id, ids).await?)
        }
        Command::SendGroupText { group_id, text } => {
            serde_json::to_value(commands::groups::send(state, group_id, text).await?)
        }
        Command::CancelGroupSend { group_id } => {
            serde_json::to_value(commands::groups::cancel(state, group_id).await?)
        }
        Command::ProcessGroups {} => serde_json::to_value(commands::groups::process(state).await?),
        Command::SaveScheduledMessage {
            id,
            peer_id,
            text,
            due_at,
        } => {
            serde_json::to_value(commands::scheduled::save(state, id, peer_id, text, due_at).await?)
        }
        Command::ListScheduledMessages {} => {
            serde_json::to_value(commands::scheduled::list(state).await?)
        }
        Command::CancelScheduledMessage {
            id,
            remove_submitted,
        } => serde_json::to_value(commands::scheduled::cancel(state, id, remove_submitted).await?),
        Command::SendScheduledNow { id } => {
            serde_json::to_value(commands::scheduled::send_now(state, id).await?)
        }
        Command::ProcessScheduledMessages {} => {
            serde_json::to_value(commands::scheduled::process(state).await?)
        }
        Command::SuspendScheduledMessages {} => {
            serde_json::to_value(commands::scheduled::suspend(state).await?)
        }
        Command::UnlockApp { password } => {
            serde_json::to_value(commands::windows_lock::verify(password)?)
        }
        Command::SubmitReaction {
            target_id,
            peer_id,
            emoji,
        } => serde_json::to_value(
            commands::reactions::submit(state, target_id, peer_id, emoji).await?,
        ),
        Command::SyncReactions {} => serde_json::to_value(commands::reactions::sync(state).await?),
        Command::GetReadReceiptEnabled {} => {
            serde_json::to_value(commands::read_receipts::enabled(state)?)
        }
        Command::SetReadReceiptEnabled { enabled } => {
            serde_json::to_value(commands::read_receipts::set_enabled(state, enabled).await?)
        }
        Command::SyncReadReceipts {} => {
            serde_json::to_value(commands::read_receipts::sync(state).await?)
        }
        Command::GetReadReceipts { conversation_id } => {
            serde_json::to_value(commands::read_receipts::views(state, conversation_id)?)
        }
        Command::MarkVisibleMessages { user_id, ids } => {
            if ids.len() > 1000 {
                return Err("Too many message ids".into());
            }
            serde_json::to_value(commands::read_receipts::mark_visible(state, user_id, ids).await?)
        }
        Command::GetTypingEnabled {} => serde_json::to_value(commands::typing::enabled(state)?),
        Command::SetTypingEnabled { enabled } => {
            serde_json::to_value(commands::typing::set_enabled(state, enabled).await?)
        }
        Command::SendTyping { peer_id, active } => {
            serde_json::to_value(commands::typing::send(state, peer_id, active).await?)
        }
        Command::GetReactions { conversation_id } => {
            serde_json::to_value(commands::reactions::views(state, conversation_id)?)
        }
        Command::ListContactRequests {} => {
            serde_json::to_value(commands::account::policies(state).await?)
        }
        Command::SetContactPolicy { peer_id, status } => {
            serde_json::to_value(commands::account::policy(state, peer_id, status).await?)
        }
        Command::ListAccountSessions {} => {
            serde_json::to_value(commands::account::sessions(state).await?)
        }
        Command::GetPublicProfile { user_id } => {
            serde_json::to_value(commands::account::public_profile(state, user_id).await?)
        }
        Command::UpdatePublicProfile {
            display_name,
            avatar_png,
        } => serde_json::to_value(
            commands::account::update_public_profile(state, display_name, avatar_png).await?,
        ),
        Command::LogoutAllSessions {} => {
            serde_json::to_value(commands::account::logout_all(state).await?)
        }
        Command::ChangePassword {
            current_password,
            new_password,
        } => serde_json::to_value(
            commands::account::change_password(state, current_password, new_password).await?,
        ),
        Command::SelectAttachment { path, peer_id } => {
            serde_json::to_value(commands::attachments::stage(state, path, peer_id).await?)
        }
        Command::StageClipboardImage { peer_id, encoded } => {
            use base64::Engine;
            if encoded.len() > 15 * 1024 * 1024 {
                return Err("剪贴板图片过大".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "剪贴板图片编码无效")?;
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                return Err("剪贴板图片格式无效".into());
            }
            serde_json::to_value(
                commands::attachments::stage_bytes(
                    state,
                    bytes,
                    "clipboard-image.png".into(),
                    peer_id,
                )
                .await?,
            )
        }
        Command::StageRecordedAudio {
            peer_id,
            encoded,
            duration_ms,
        } => {
            use base64::Engine;
            if encoded.len() > 15 * 1024 * 1024 || !(1..=60_000).contains(&duration_ms) {
                return Err("语音长度或大小超出限制".into());
            }
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| "语音编码无效")?;
            serde_json::to_value(
                commands::attachments::stage_recorded_audio(state, bytes, peer_id, duration_ms)
                    .await?,
            )
        }
        Command::ListAttachmentTasks {} => {
            serde_json::to_value(commands::attachments::pending(state)?)
        }
        Command::AttachmentStep { id } => {
            serde_json::to_value(commands::attachments::step(state, id).await?)
        }
        Command::PublishAttachment { id } => {
            serde_json::to_value(commands::attachments::publish(state, id).await?)
        }
        Command::BeginAttachmentDownload { message_id } => {
            serde_json::to_value(commands::attachments::begin_download(state, message_id).await?)
        }
        Command::ExportAttachment {
            message_id,
            path,
            offset,
            task_id,
        } => {
            match (path, task_id) {
                (Some(path), None) => {
                    serde_json::to_value(commands::attachments::export(state, message_id, path)?)
                }
                (None, Some(id)) => serde_json::to_value(
                    commands::attachments::pending_preview_chunk(state, id, offset.unwrap_or(0))?,
                ),
                (None, None) => serde_json::to_value(commands::attachments::preview_chunk(
                    state,
                    message_id,
                    offset.unwrap_or(0),
                )?),
                _ => return Err("无效附件导出请求".into()),
            }
        }
        Command::ForgetAttachmentTask { id } => {
            let user = state.identity()?.user_id;
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .forget_attachment_transfer(&user, &id)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
        Command::AttachmentCacheStats {} => {
            let user = state.identity()?.user_id;
            let db = state.client.db.lock().map_err(|e| e.to_string())?;
            let (allocated, free) = db.database_disk_stats().map_err(|e| e.to_string())?;
            let disk_bytes: u64 = ["", "-wal", "-shm", "-journal"]
                .iter()
                .map(|suffix| {
                    let mut path = state.db_path.as_os_str().to_os_string();
                    path.push(suffix);
                    std::fs::metadata(std::path::PathBuf::from(path))
                        .map(|m| m.len())
                        .unwrap_or(0)
                })
                .sum();
            serde_json::to_value(
                serde_json::json!({"cache_bytes":db.attachment_cache_bytes(&user).map_err(|e|e.to_string())?,"database_allocated":allocated,"database_reusable":free,"disk_bytes":disk_bytes,"limit":256*1024*1024}),
            )
        }
        Command::ClearAttachmentCache { peer_id } => {
            let user = state.identity()?.user_id;
            serde_json::to_value(
                state
                    .client
                    .db
                    .lock()
                    .map_err(|e| e.to_string())?
                    .clear_attachment_cache(&user, peer_id.as_deref())
                    .map_err(|e| e.to_string())?,
            )
        }
        Command::GetPersonalOrganizer {} => {
            let saved = state.identity()?;
            let bytes = state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .personal_organizer(&saved.user_id)
                .map_err(|e| e.to_string())?;
            let content = if bytes.is_empty() {
                String::new()
            } else {
                String::from_utf8(liteseal_core::chat::decrypt_message(
                    bytes,
                    saved.public_key,
                    saved.secret_key,
                )?)
                .map_err(|_| "Invalid organizer encoding")?
            };
            serde_json::to_value(content)
        }
        Command::SavePersonalOrganizer { content } => {
            if content.len() > 1024 * 1024 {
                return Err("本机列表和便笺总量不能超过 1 MiB".into());
            }
            let saved = state.identity()?;
            let encrypted = liteseal_core::chat::encrypt_message(
                content.into_bytes(),
                saved.public_key,
                saved.secret_key,
            )?;
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .save_personal_organizer(&saved.user_id, &encrypted)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
        Command::GetMessageContext {
            user_id,
            conversation_id,
            message_id,
        } => {
            if state.identity()?.user_id != user_id {
                return Err("Account mismatch".into());
            }
            serde_json::to_value(
                state
                    .client
                    .db
                    .lock()
                    .map_err(|e| e.to_string())?
                    .message_context(&user_id, &conversation_id, &message_id)
                    .map_err(|e| e.to_string())?,
            )
        }
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
        Command::SetConversationMuted {
            user_id,
            peer_id,
            muted,
        } => {
            if state.identity()?.user_id != user_id {
                return Err("Account mismatch".into());
            }
            state
                .client
                .db
                .lock()
                .map_err(|e| e.to_string())?
                .set_conversation_muted(&user_id, &peer_id, muted)
                .map_err(|e| e.to_string())?;
            serde_json::to_value(())
        }
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
        Command::SignOut {} => serde_json::to_value(commands::keystore::sign_out(state).await?),
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
        } => serde_json::to_value(
            commands::chat::encrypt_message(plaintext, recipient_public_key, state).await?,
        ),
        Command::DecryptMessage {
            ciphertext,
            sender_public_key,
        } => serde_json::to_value(
            commands::chat::decrypt_message(ciphertext, sender_public_key, state).await?,
        ),
        Command::SignMessage { message } => {
            serde_json::to_value(commands::chat::sign_message(message, state).await?)
        }
        Command::VerifyMessage {
            message,
            signature,
            sender_public_key,
        } => serde_json::to_value(
            commands::chat::verify_message(message, signature, sender_public_key).await?,
        ),
        Command::PrepareIdentity {} => {
            serde_json::to_value(commands::keystore::prepare_identity(state)?)
        }
        Command::LoadIdentity {} => serde_json::to_value(commands::keystore::load_identity(state)?),
        Command::SaveSession {
            user_id,
            token,
            refresh_token,
            device_id,
            server_url,
        } => serde_json::to_value(commands::keystore::save_session(
            user_id,
            token,
            refresh_token,
            device_id,
            server_url,
            state,
        )?),
        Command::ClearKeypair {} => serde_json::to_value(commands::keystore::clear_keypair(state)?),
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
        } => {
            if state.identity().is_ok()
                && commands::root_messaging::admission(state)?
                    == liteseal_core::trusted_devices::activation::legacy::Admission::V3
            {
                return Err("原设备已启用单聊 v3，请使用原设备正式会话恢复".into());
            }
            serde_json::to_value(
                commands::auth::login(
                    username, password, server_url, public_key, ed25519_pk, device_id,
                )
                .await?,
            )
        }
        Command::RefreshSession {
            server_url,
            refresh_token,
        } => {
            if commands::root_messaging::admission(state)?
                == liteseal_core::trusted_devices::activation::legacy::Admission::V3
            {
                return Err("请使用原设备正式会话恢复；单聊 v3 自动续期尚未接入".into());
            }
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
    if let Some(epoch) = normal_epoch.filter(|_| !identity_write) {
        commands::normal_profile::check(state, epoch)?;
    }
    result.map_err(|_| "Failed to serialize response".to_string())
}
