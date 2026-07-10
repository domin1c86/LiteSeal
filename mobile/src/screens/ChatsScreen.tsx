import React, { useEffect, useState } from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useNavigation } from '@react-navigation/native';
import { decryptMessage } from 'react-native-liteseal';
import Avatar from '../components/Avatar';
import { bytesToBuffer, utf8Decode } from '../lib/bytes';
import { conversationIdFor, useApp } from '../lib/AppContext';
import { getCore } from '../lib/core';
import { fonts, useTheme } from '../theme';
import type { RootStackParamList } from '../navigation';

interface Preview {
  text: string;
  timestamp: number;
}

export default function ChatsScreen() {
  const { colors } = useTheme();
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { session, contacts, unread, relayBatch, connected } = useApp();
  const [previews, setPreviews] = useState<Record<string, Preview>>({});

  // Rebuild previews from the local store; re-runs when new messages arrive
  // via the app-level poll loop.
  useEffect(() => {
    if (!session) {
      return;
    }
    const next: Record<string, Preview> = {};
    for (const contact of contacts) {
      const convId = conversationIdFor(session, contact.userId);
      try {
        const messages = getCore().getLocalMessages(convId, 1000n, 0n);
        const last = messages[messages.length - 1];
        if (!last) {
          continue;
        }
        let text = '[encrypted]';
        try {
          const plaintext = decryptMessage(
            last.ciphertext,
            contact.publicKey,
            bytesToBuffer(session.secretKey),
          );
          text = utf8Decode(plaintext);
        } catch {
          // key mismatch or integrity-failed placeholder; keep [encrypted]
        }
        next[convId] = { text, timestamp: Number(last.timestamp) };
      } catch {
        // ignore per-conversation load errors
      }
    }
    setPreviews(next);
  }, [session, contacts, relayBatch]);

  if (!session) {
    return null;
  }

  const rows = contacts
    .map(contact => {
      const convId = conversationIdFor(session, contact.userId);
      return { contact, convId, preview: previews[convId] };
    })
    .sort(
      (a, b) => (b.preview?.timestamp ?? 0) - (a.preview?.timestamp ?? 0),
    );

  return (
    <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
      <View style={[styles.appbar, { borderBottomColor: colors.border }]}>
        <Text style={[styles.wordmark, { color: colors.text }]}>
          liteseal
          <Text style={{ color: colors.textSubtle, fontWeight: '400' }}>▌</Text>
        </Text>
        <View
          style={[
            styles.connDot,
            { backgroundColor: connected ? colors.ok : colors.warn },
          ]}
        />
      </View>
      {!connected && (
        <View
          style={[
            styles.banner,
            { backgroundColor: colors.surfaceMuted, borderBottomColor: colors.border },
          ]}
        >
          <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.warn }}>
            offline — showing local history 离线，仅显示本地记录
          </Text>
        </View>
      )}
      <FlatList
        data={rows}
        keyExtractor={item => item.contact.userId}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={{ fontFamily: fonts.mono, fontSize: 13, color: colors.textSubtle }}>
              no conversations yet
            </Text>
            <Text
              style={{
                fontFamily: fonts.mono,
                fontSize: 11,
                color: colors.textSubtle,
                marginTop: 6,
              }}
            >
              add a contact to start messaging
            </Text>
          </View>
        }
        renderItem={({ item }) => {
          const count = unread[item.convId] ?? 0;
          return (
            <Pressable
              onPress={() =>
                navigation.navigate('Chat', { peerId: item.contact.userId })
              }
              style={[styles.row, { borderBottomColor: colors.border }]}
              android_ripple={{ color: colors.surfaceHover }}
            >
              <Avatar name={item.contact.username} />
              <View style={styles.rowBody}>
                <Text
                  style={{ color: colors.text, fontSize: 14.5, fontWeight: '600' }}
                  numberOfLines={1}
                >
                  {item.contact.username}
                </Text>
                <Text
                  style={{ color: colors.textMuted, fontSize: 12.5, marginTop: 3 }}
                  numberOfLines={1}
                >
                  {item.preview?.text ?? 'no messages yet'}
                </Text>
              </View>
              <View style={styles.rowMeta}>
                {item.preview && (
                  <Text
                    style={{
                      fontFamily: fonts.mono,
                      fontSize: 10.5,
                      color: colors.textSubtle,
                    }}
                  >
                    {formatTime(item.preview.timestamp)}
                  </Text>
                )}
                {count > 0 && (
                  <View style={[styles.unread, { backgroundColor: colors.accent }]}>
                    <Text
                      style={{
                        color: colors.accentContrast,
                        fontSize: 10,
                        fontWeight: '700',
                      }}
                    >
                      {count}
                    </Text>
                  </View>
                )}
              </View>
            </Pressable>
          );
        }}
      />
    </View>
  );
}

function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return `${String(date.getHours()).padStart(2, '0')}:${String(
      date.getMinutes(),
    ).padStart(2, '0')}`;
  }
  return `${String(date.getMonth() + 1).padStart(2, '0')}-${String(
    date.getDate(),
  ).padStart(2, '0')}`;
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  appbar: {
    height: 52,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    borderBottomWidth: 1,
  },
  wordmark: { fontFamily: fonts.mono, fontSize: 15, fontWeight: '600' },
  connDot: { width: 7, height: 7, borderRadius: 4 },
  banner: {
    paddingVertical: 7,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
  },
  empty: { alignItems: 'center', paddingTop: 80 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderBottomWidth: 1,
    minHeight: 66,
  },
  rowBody: { flex: 1, minWidth: 0 },
  rowMeta: { alignItems: 'flex-end', gap: 6 },
  unread: {
    minWidth: 17,
    height: 17,
    borderRadius: 9,
    paddingHorizontal: 5,
    alignItems: 'center',
    justifyContent: 'center',
  },
});
