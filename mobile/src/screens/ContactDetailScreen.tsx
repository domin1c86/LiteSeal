import React, { useState } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import Avatar from '../components/Avatar';
import { trustInfo } from '../components/TrustLabel';
import { groupFingerprint } from '../lib/bytes';
import { useApp } from '../lib/AppContext';
import { getCore } from '../lib/core';
import { fonts, radius, useTheme } from '../theme';
import type { RootStackParamList } from '../navigation';

type Props = NativeStackScreenProps<RootStackParamList, 'ContactDetail'>;

export default function ContactDetailScreen({ route, navigation }: Props) {
  const { userId } = route.params;
  const { colors } = useTheme();
  const { contacts, refreshContacts } = useApp();
  const [error, setError] = useState<string | null>(null);

  const contact = contacts.find(c => c.userId === userId);

  if (!contact) {
    return (
      <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
        <Text
          style={{
            fontFamily: fonts.mono,
            color: colors.textSubtle,
            textAlign: 'center',
            marginTop: 80,
          }}
        >
          contact not found
        </Text>
      </View>
    );
  }

  const verified = contact.trustState === 'verified';
  const keyChanged = contact.keyChanged || contact.trustState === 'key_changed';
  const trust = trustInfo(contact, colors);

  function setTrust(state: string) {
    try {
      getCore().setContactTrust(userId, state);
      refreshContacts();
    } catch (err) {
      setError(String(err));
    }
  }

  function removeContact() {
    try {
      getCore().removeContact(userId);
      refreshContacts();
      navigation.goBack();
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
      <View style={[styles.appbar, { borderBottomColor: colors.border }]}>
        <Pressable onPress={() => navigation.goBack()} hitSlop={10}>
          <Text style={{ color: colors.textMuted, fontSize: 22 }}>‹</Text>
        </Pressable>
        <Text style={[styles.title, { color: colors.text }]}>contact</Text>
      </View>
      <ScrollView contentContainerStyle={styles.body}>
        <Avatar name={contact.username} size={72} />
        <Text style={[styles.name, { color: colors.text }]}>{contact.username}</Text>
        <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.textSubtle }}>
          {contact.userId}
        </Text>
        <Text
          style={{ fontFamily: fonts.mono, fontSize: 11, color: trust.color, marginTop: 6 }}
        >
          {trust.text}
        </Text>

        <View
          style={[
            styles.block,
            { borderColor: colors.border, backgroundColor: colors.surfaceMuted },
          ]}
        >
          <Text style={[styles.blockLabel, { color: colors.textSubtle }]}>
            KEY FINGERPRINT 密钥指纹
          </Text>
          <Text
            style={{
              fontFamily: fonts.mono,
              fontSize: 12,
              color: colors.textMuted,
              lineHeight: 20,
            }}
          >
            {groupFingerprint(contact.fingerprint)}
          </Text>
        </View>

        {keyChanged && (
          <View style={[styles.block, { borderColor: colors.danger }]}>
            <Text style={[styles.blockLabel, { color: colors.danger }]}>WARNING 警告</Text>
            <Text style={{ fontFamily: fonts.mono, fontSize: 12, color: colors.danger, lineHeight: 18 }}>
              public key changed since last verification — re-verify before
              messaging. 公钥自上次验证后已变更，请先重新核对再发送消息。
            </Text>
          </View>
        )}

        {error != null && (
          <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.danger, marginTop: 10 }}>
            {error}
          </Text>
        )}

        <View style={styles.actions}>
          <Pressable
            style={[styles.primaryBtn, { backgroundColor: colors.accent }]}
            onPress={() => navigation.navigate('Chat', { peerId: userId })}
          >
            <Text style={{ color: colors.accentContrast, fontSize: 14, fontWeight: '600' }}>
              message
            </Text>
          </Pressable>
          <Pressable
            style={[styles.outlineBtn, { borderColor: colors.borderStrong }]}
            onPress={() => setTrust(verified ? 'unverified' : 'verified')}
          >
            <Text style={{ color: colors.textMuted, fontSize: 13.5, fontWeight: '600' }}>
              {verified ? 'mark as unverified' : 'mark as verified'}
            </Text>
          </Pressable>
          <Pressable
            style={[styles.outlineBtn, { borderColor: colors.danger }]}
            onPress={removeContact}
          >
            <Text style={{ color: colors.danger, fontSize: 13.5, fontWeight: '600' }}>
              remove contact
            </Text>
          </Pressable>
        </View>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  appbar: {
    height: 52,
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingHorizontal: 16,
    borderBottomWidth: 1,
  },
  title: { fontFamily: fonts.mono, fontSize: 14, fontWeight: '600' },
  body: { alignItems: 'center', padding: 24 },
  name: { fontSize: 17, fontWeight: '600', marginTop: 12 },
  block: {
    width: '100%',
    borderWidth: 1,
    borderRadius: radius.md,
    padding: 14,
    marginTop: 16,
  },
  blockLabel: {
    fontFamily: fonts.mono,
    fontSize: 10,
    letterSpacing: 1,
    marginBottom: 8,
  },
  actions: { width: '100%', gap: 10, marginTop: 20 },
  primaryBtn: {
    borderRadius: radius.md,
    paddingVertical: 13,
    alignItems: 'center',
  },
  outlineBtn: {
    borderWidth: 1,
    borderRadius: radius.md,
    paddingVertical: 12,
    alignItems: 'center',
  },
});
