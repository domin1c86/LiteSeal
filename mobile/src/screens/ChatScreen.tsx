import React, { useCallback, useEffect, useState } from 'react';
import {
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import {
  FfiRelayEvent_Tags,
  encryptMessage,
  getUserDevices,
  signMessage,
  decryptMessage,
  type FfiEncryptedPayload,
  type FfiIncomingMessage,
} from 'react-native-liteseal';
import Avatar from '../components/Avatar';
import TrustLabel from '../components/TrustLabel';
import { bytesToBuffer, utf8Decode, utf8Encode } from '../lib/bytes';
import { conversationIdFor, useApp } from '../lib/AppContext';
import { getCore } from '../lib/core';
import { fonts, radius, useTheme } from '../theme';
import type { RootStackParamList } from '../navigation';

interface DisplayMessage {
  id: string;
  senderId: string;
  text: string;
  timestamp: number;
  state: string;
}

type Props = NativeStackScreenProps<RootStackParamList, 'Chat'>;

export default function ChatScreen({ route, navigation }: Props) {
  const { peerId } = route.params;
  const { colors } = useTheme();
  const { session, contacts, relayBatch, clearUnread } = useApp();
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);

  const contact = contacts.find(c => c.userId === peerId);
  const convId = session ? conversationIdFor(session, peerId) : '';

  const decryptWithPeer = useCallback(
    (ciphertext: ArrayBuffer): string => {
      if (!session || !contact) {
        return '[encrypted]';
      }
      try {
        return utf8Decode(
          decryptMessage(ciphertext, contact.publicKey, bytesToBuffer(session.secretKey)),
        );
      } catch {
        return '[encrypted]';
      }
    },
    [session, contact],
  );

  // Initial history from the local store.
  useEffect(() => {
    if (!session || !convId) {
      return;
    }
    clearUnread(convId);
    try {
      const local = getCore().getLocalMessages(convId, 200n, 0n);
      setMessages(
        local.map(m => ({
          id: m.id,
          senderId: m.senderId,
          text:
            m.localState === 'integrity_failed'
              ? '[message withheld]'
              : decryptWithPeer(m.ciphertext),
          timestamp: Number(m.timestamp),
          state: m.localState,
        })),
      );
    } catch (err) {
      console.error('Failed to load messages:', err);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, convId, contact?.userId]);

  // Live batches from the app-level poll loop.
  useEffect(() => {
    if (!relayBatch || !session) {
      return;
    }
    clearUnread(convId);
    const { events, messages: incoming } = relayBatch.result;

    // Delivery-state updates for our own messages.
    const stateByMessage = new Map<string, string>();
    for (const event of events) {
      switch (event.tag) {
        case FfiRelayEvent_Tags.Delivered:
          stateByMessage.set(event.inner.messageId, 'delivered');
          break;
        case FfiRelayEvent_Tags.Offline:
          stateByMessage.set(event.inner.messageId, 'offline');
          break;
        case FfiRelayEvent_Tags.DeliveryUpdate:
          stateByMessage.set(event.inner.messageId, event.inner.status);
          break;
        case FfiRelayEvent_Tags.Error:
          setSendError(event.inner.message);
          break;
      }
    }
    if (stateByMessage.size > 0) {
      setMessages(prev =>
        prev.map(m =>
          stateByMessage.has(m.id) ? { ...m, state: stateByMessage.get(m.id)! } : m,
        ),
      );
    }

    const mine = incoming.filter(m => m.conversationId === convId);
    if (mine.length > 0) {
      const decoded = mine.map(m => toDisplay(m));
      setMessages(prev => {
        const seen = new Set(prev.map(m => m.id));
        return [...prev, ...decoded.filter(m => !seen.has(m.id))];
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [relayBatch]);

  function toDisplay(m: FfiIncomingMessage): DisplayMessage {
    const base = {
      id: m.messageId,
      senderId: m.fromUserId,
      timestamp: Number(m.timestamp),
      state: m.localState,
    };
    if (m.localState === 'integrity_failed') {
      return { ...base, text: '[message withheld]' };
    }
    if (!contact) {
      return { ...base, text: '[sender not in contacts]' };
    }
    // The Rust core verified the signed envelope before storing it.
    return { ...base, text: decryptWithPeer(m.ciphertext) };
  }

  async function handleSend() {
    const text = input.trim();
    if (!text || !session || sending) {
      return;
    }
    setInput('');
    setSendError(null);
    setSending(true);
    try {
      if (!contact) {
        throw new Error('Recipient not found in contacts');
      }
      const devices = (await getUserDevices(session.serverUrl, peerId, session.token)).filter(
        d => !d.revoked && d.publicKey.byteLength === 32,
      );
      if (devices.length === 0) {
        throw new Error('Recipient has no active devices');
      }

      const plaintext = utf8Encode(text);
      const secretKey = bytesToBuffer(session.secretKey);
      const signingKey = bytesToBuffer(session.ed25519Sk);

      // Local copy encrypted to the contact's stored key so history stays
      // readable; per-device copies for the relay fan-out.
      const ciphertext = encryptMessage(plaintext, contact.publicKey, secretKey);
      const signature = signMessage(ciphertext, signingKey);

      const payloads: FfiEncryptedPayload[] = devices.map(device => {
        const deviceCiphertext = encryptMessage(plaintext, device.publicKey, secretKey);
        return {
          recipientUserId: peerId,
          recipientDeviceId: device.id,
          ciphertext: deviceCiphertext,
          signature: signMessage(deviceCiphertext, signingKey),
        };
      });

      const messageId = await getCore().sendMessage(
        session.userId,
        ciphertext,
        signature,
        session.deviceId,
        payloads,
        signingKey,
      );

      setMessages(prev => [
        ...prev,
        {
          id: messageId,
          senderId: session.userId,
          text,
          timestamp: Date.now(),
          state: 'pending',
        },
      ]);
    } catch (err) {
      setSendError(String(err));
    } finally {
      setSending(false);
    }
  }

  const inverted = [...messages].reverse();

  return (
    <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
      <View style={[styles.appbar, { borderBottomColor: colors.border }]}>
        <Pressable onPress={() => navigation.goBack()} hitSlop={10}>
          <Text style={{ color: colors.textMuted, fontSize: 22, marginRight: 4 }}>
            ‹
          </Text>
        </Pressable>
        <Pressable
          style={styles.headerContact}
          onPress={() => navigation.navigate('ContactDetail', { userId: peerId })}
        >
          <Avatar name={contact?.username ?? peerId} size={32} />
          <View>
            <Text style={{ color: colors.text, fontSize: 13.5, fontWeight: '600' }}>
              {contact?.username ?? peerId}
            </Text>
            {contact ? (
              <TrustLabel contact={contact} />
            ) : (
              <Text
                style={{ fontFamily: fonts.mono, fontSize: 10.5, color: colors.textSubtle }}
              >
                not in contacts
              </Text>
            )}
          </View>
        </Pressable>
      </View>

      <FlatList
        inverted
        data={inverted}
        keyExtractor={m => m.id}
        contentContainerStyle={styles.messages}
        renderItem={({ item }) => {
          const isMine = item.senderId === session?.userId;
          const failed = item.state === 'integrity_failed';
          return (
            <View
              style={[styles.msgRow, { justifyContent: isMine ? 'flex-end' : 'flex-start' }]}
            >
              <View
                style={[
                  styles.bubble,
                  isMine
                    ? { backgroundColor: colors.accent, borderBottomRightRadius: 4 }
                    : {
                        backgroundColor: colors.surface,
                        borderWidth: 1,
                        borderColor: failed ? colors.danger : colors.border,
                        borderBottomLeftRadius: 4,
                      },
                ]}
              >
                <Text
                  style={{
                    color: failed
                      ? colors.textMuted
                      : isMine
                        ? colors.accentContrast
                        : colors.text,
                    fontSize: 14,
                  }}
                >
                  {item.text}
                </Text>
                <Text
                  style={{
                    fontFamily: fonts.mono,
                    fontSize: 9.5,
                    marginTop: 4,
                    alignSelf: 'flex-end',
                    color: failed
                      ? colors.danger
                      : isMine
                        ? colors.accentContrast
                        : colors.textSubtle,
                    opacity: failed ? 1 : 0.7,
                  }}
                >
                  {failed
                    ? 'integrity check failed 完整性校验失败'
                    : `${formatClock(item.timestamp)}${isMine ? ` ${stateGlyph(item.state)}` : ''}`}
                </Text>
              </View>
            </View>
          );
        }}
      />

      {sendError != null && (
        <Text
          style={{
            fontFamily: fonts.mono,
            fontSize: 11,
            color: colors.danger,
            paddingHorizontal: 16,
            paddingBottom: 4,
          }}
        >
          {sendError}
        </Text>
      )}

      <View style={styles.composerWrap}>
        <View
          style={[
            styles.composer,
            { borderColor: colors.borderStrong, backgroundColor: colors.surfaceMuted },
          ]}
        >
          <Text style={{ fontFamily: fonts.mono, color: colors.textSubtle, fontSize: 14 }}>
            ❯
          </Text>
          <TextInput
            style={[styles.input, { color: colors.text }]}
            placeholder={`message ${contact?.username ?? ''}…`}
            placeholderTextColor={colors.textSubtle}
            value={input}
            onChangeText={setInput}
            multiline
          />
          <Pressable
            onPress={handleSend}
            disabled={sending || !input.trim()}
            style={[
              styles.sendBtn,
              {
                backgroundColor: colors.accent,
                opacity: sending || !input.trim() ? 0.55 : 1,
              },
            ]}
          >
            <Text style={{ color: colors.accentContrast, fontSize: 15, fontWeight: '700' }}>
              ↑
            </Text>
          </Pressable>
        </View>
      </View>
    </View>
  );
}

function formatClock(timestamp: number): string {
  const d = new Date(timestamp);
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function stateGlyph(state: string): string {
  switch (state) {
    case 'delivered':
    case 'acked':
      return '✓✓';
    case 'sent':
      return '✓';
    case 'pending':
      return '…';
    case 'offline':
      return 'offline';
    case 'failed':
      return '✗';
    default:
      return state;
  }
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  appbar: {
    height: 52,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
  },
  headerContact: { flexDirection: 'row', alignItems: 'center', gap: 10, flex: 1 },
  messages: { paddingHorizontal: 14, paddingVertical: 12, gap: 10 },
  msgRow: { flexDirection: 'row', marginVertical: 2 },
  bubble: {
    maxWidth: '78%',
    paddingHorizontal: 12,
    paddingVertical: 9,
    borderRadius: radius.lg,
  },
  composerWrap: { paddingHorizontal: 12, paddingTop: 6, paddingBottom: 12 },
  composer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    borderWidth: 1,
    borderRadius: radius.lg,
    paddingLeft: 14,
    paddingRight: 8,
    paddingVertical: 6,
  },
  input: { flex: 1, fontSize: 14, maxHeight: 110, paddingVertical: 6 },
  sendBtn: {
    width: 34,
    height: 34,
    borderRadius: radius.md,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
