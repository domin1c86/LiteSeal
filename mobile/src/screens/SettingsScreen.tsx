import React, { useEffect, useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { keyFingerprint, type FfiStorageStats } from 'react-native-liteseal';
import { bytesToBuffer, groupFingerprint } from '../lib/bytes';
import { useApp } from '../lib/AppContext';
import { getCore } from '../lib/core';
import { clearKeystore } from '../lib/keystore';
import { fonts, radius, useTheme } from '../theme';

export default function SettingsScreen() {
  const { colors } = useTheme();
  const { session, setSession, connected, setConnected, relayBatch } = useApp();
  const [stats, setStats] = useState<FfiStorageStats | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    try {
      setStats(getCore().getStorageStats());
    } catch {
      setStats(null);
    }
  }, [relayBatch, notice]);

  if (!session) {
    return null;
  }

  const fingerprint = groupFingerprint(
    keyFingerprint(bytesToBuffer(session.ed25519Pk)),
  );

  async function handleLogout() {
    try {
      await getCore().disconnect();
    } catch {}
    try {
      await clearKeystore();
    } catch {}
    setConnected(false);
    setSession(null);
  }

  function clearExpired() {
    try {
      const n = getCore().clearExpiredMessages();
      setNotice(`cleared ${n} expired messages`);
    } catch (err) {
      setNotice(String(err));
    }
  }

  function clearAttachments() {
    try {
      const n = getCore().clearUnpinnedAttachments();
      setNotice(`cleared ${n} cached attachments`);
    } catch (err) {
      setNotice(String(err));
    }
  }

  return (
    <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
      <View style={[styles.appbar, { borderBottomColor: colors.border }]}>
        <Text style={[styles.title, { color: colors.text }]}>settings</Text>
        <View
          style={[
            styles.connDot,
            { backgroundColor: connected ? colors.ok : colors.warn },
          ]}
        />
      </View>
      <ScrollView>
        <Text style={[styles.section, { color: colors.textSubtle }]}>ACCOUNT 账户</Text>
        <Row label="user id" value={session.userId} colors={colors} />
        <Row label="device" value={session.deviceId || '—'} colors={colors} />
        <Row label="my fingerprint" value={fingerprint} colors={colors} />

        <Text style={[styles.section, { color: colors.textSubtle }]}>SERVER 服务器</Text>
        <Row label="relay url" value={session.serverUrl} colors={colors} />
        <Row label="status" value={connected ? 'connected' : 'offline'} colors={colors} />

        <Text style={[styles.section, { color: colors.textSubtle }]}>STORAGE 存储</Text>
        <Row
          label="local messages"
          value={
            stats
              ? `${stats.messageCount} · ${formatBytes(Number(stats.totalBytes))}`
              : '—'
          }
          colors={colors}
        />
        <Row
          label="conversations"
          value={stats ? String(stats.conversationCount) : '—'}
          colors={colors}
        />

        {notice != null && (
          <Text
            style={{
              fontFamily: fonts.mono,
              fontSize: 11,
              color: colors.textMuted,
              paddingHorizontal: 16,
              paddingTop: 12,
            }}
          >
            {notice}
          </Text>
        )}

        <View style={styles.actions}>
          <Pressable
            style={[styles.outlineBtn, { borderColor: colors.borderStrong }]}
            onPress={clearExpired}
          >
            <Text style={{ color: colors.textMuted, fontSize: 13.5, fontWeight: '600' }}>
              clear expired messages
            </Text>
          </Pressable>
          <Pressable
            style={[styles.outlineBtn, { borderColor: colors.borderStrong }]}
            onPress={clearAttachments}
          >
            <Text style={{ color: colors.textMuted, fontSize: 13.5, fontWeight: '600' }}>
              clear cached attachments
            </Text>
          </Pressable>
          <Pressable
            style={[styles.outlineBtn, { borderColor: colors.danger }]}
            onPress={handleLogout}
          >
            <Text style={{ color: colors.danger, fontSize: 13.5, fontWeight: '600' }}>
              log out
            </Text>
          </Pressable>
        </View>
      </ScrollView>
    </View>
  );
}

function Row({
  label,
  value,
  colors,
}: {
  label: string;
  value: string;
  colors: ReturnType<typeof useTheme>['colors'];
}) {
  return (
    <View style={[styles.kv, { borderBottomColor: colors.border }]}>
      <Text style={{ color: colors.textMuted, fontSize: 13.5 }}>{label}</Text>
      <Text
        style={{
          fontFamily: fonts.mono,
          fontSize: 11.5,
          color: colors.textSubtle,
          maxWidth: '60%',
        }}
        numberOfLines={2}
      >
        {value}
      </Text>
    </View>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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
  title: { fontFamily: fonts.mono, fontSize: 14, fontWeight: '600' },
  connDot: { width: 7, height: 7, borderRadius: 4 },
  section: {
    fontFamily: fonts.mono,
    fontSize: 10,
    letterSpacing: 1,
    paddingHorizontal: 16,
    paddingTop: 18,
    paddingBottom: 8,
  },
  kv: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingVertical: 13,
    borderBottomWidth: 1,
  },
  actions: { padding: 16, gap: 10, marginTop: 8 },
  outlineBtn: {
    borderWidth: 1,
    borderRadius: radius.md,
    paddingVertical: 12,
    alignItems: 'center',
  },
});
