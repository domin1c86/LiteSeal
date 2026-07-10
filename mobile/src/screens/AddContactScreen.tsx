import React, { useState } from 'react';
import {
  FlatList,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import type { NativeStackScreenProps } from '@react-navigation/native-stack';
import { searchUsers, type FfiUserSearchResult } from 'react-native-liteseal';
import Avatar from '../components/Avatar';
import { bufferToBytes } from '../lib/bytes';
import { useApp } from '../lib/AppContext';
import { getCore } from '../lib/core';
import { fonts, radius, useTheme } from '../theme';
import type { RootStackParamList } from '../navigation';

type Props = NativeStackScreenProps<RootStackParamList, 'AddContact'>;

export default function AddContactScreen({ navigation }: Props) {
  const { colors } = useTheme();
  const { session, contacts, refreshContacts } = useApp();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<FfiUserSearchResult[]>([]);
  const [searching, setSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState<Set<string>>(new Set());

  async function handleSearch() {
    if (!query.trim() || !session) {
      return;
    }
    setSearching(true);
    setError(null);
    try {
      const found = await searchUsers(session.serverUrl, query.trim());
      setResults(found.filter(r => r.userId !== session.userId));
    } catch (err) {
      setError(String(err));
    } finally {
      setSearching(false);
    }
  }

  function handleAdd(result: FfiUserSearchResult) {
    try {
      getCore().addContact(
        result.userId,
        result.username,
        result.publicKey,
        result.ed25519Pk,
      );
      setAdded(prev => new Set(prev).add(result.userId));
      refreshContacts();
    } catch (err) {
      setError(String(err));
    }
  }

  const existing = new Set(contacts.map(c => c.userId));

  return (
    <View style={[styles.container, { backgroundColor: colors.sidebarBg }]}>
      <View style={[styles.grip, { backgroundColor: colors.borderStrong }]} />
      <Text style={[styles.title, { color: colors.text }]}>
        add contact 添加联系人
      </Text>
      <View style={styles.searchRow}>
        <TextInput
          style={[
            styles.input,
            {
              borderColor: colors.borderStrong,
              backgroundColor: colors.surfaceMuted,
              color: colors.text,
            },
          ]}
          placeholder="search username…"
          placeholderTextColor={colors.textSubtle}
          value={query}
          onChangeText={setQuery}
          autoCapitalize="none"
          autoCorrect={false}
          autoFocus
          onSubmitEditing={handleSearch}
          returnKeyType="search"
        />
        <Pressable
          onPress={handleSearch}
          disabled={searching || !query.trim()}
          style={[
            styles.searchBtn,
            {
              backgroundColor: colors.accent,
              opacity: searching || !query.trim() ? 0.55 : 1,
            },
          ]}
        >
          <Text style={{ color: colors.accentContrast, fontSize: 13, fontWeight: '600' }}>
            {searching ? '…' : 'search'}
          </Text>
        </Pressable>
      </View>

      {error != null && (
        <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.danger, marginTop: 10 }}>
          {error}
        </Text>
      )}

      <FlatList
        data={results}
        keyExtractor={r => r.userId}
        style={styles.results}
        renderItem={({ item }) => {
          const isAdded = added.has(item.userId) || existing.has(item.userId);
          return (
            <View style={[styles.row, { borderBottomColor: colors.border }]}>
              <Avatar name={item.username} />
              <View style={styles.rowBody}>
                <Text style={{ color: colors.text, fontSize: 14.5, fontWeight: '600' }}>
                  {item.username}
                </Text>
                <Text
                  style={{
                    fontFamily: fonts.mono,
                    fontSize: 10.5,
                    color: colors.textSubtle,
                    marginTop: 3,
                  }}
                  numberOfLines={1}
                >
                  {shortKey(item.publicKey)}
                </Text>
              </View>
              {isAdded ? (
                <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.ok }}>
                  added ✓
                </Text>
              ) : (
                <Pressable
                  onPress={() => handleAdd(item)}
                  style={[styles.addBtn, { borderColor: colors.borderStrong }]}
                >
                  <Text style={{ fontFamily: fonts.mono, fontSize: 11, color: colors.textMuted }}>
                    add
                  </Text>
                </Pressable>
              )}
            </View>
          );
        }}
      />

      <Pressable onPress={() => navigation.goBack()} style={styles.close} hitSlop={10}>
        <Text style={{ fontFamily: fonts.mono, fontSize: 12, color: colors.textSubtle }}>
          close
        </Text>
      </Pressable>
    </View>
  );
}

function shortKey(key: ArrayBuffer): string {
  return bufferToBytes(key)
    .slice(0, 8)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ');
}

const styles = StyleSheet.create({
  container: { flex: 1, paddingHorizontal: 16, paddingTop: 10 },
  grip: {
    alignSelf: 'center',
    width: 36,
    height: 4,
    borderRadius: 2,
    marginBottom: 14,
  },
  title: { fontFamily: fonts.mono, fontSize: 13, fontWeight: '600', marginBottom: 12 },
  searchRow: { flexDirection: 'row', gap: 8 },
  input: {
    flex: 1,
    borderWidth: 1,
    borderRadius: radius.md,
    paddingHorizontal: 14,
    paddingVertical: 11,
    fontSize: 14,
  },
  searchBtn: {
    borderRadius: radius.md,
    paddingHorizontal: 16,
    justifyContent: 'center',
  },
  results: { marginTop: 8 },
  row: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    paddingVertical: 12,
    borderBottomWidth: 1,
  },
  rowBody: { flex: 1, minWidth: 0 },
  addBtn: {
    borderWidth: 1,
    borderRadius: radius.sm,
    paddingHorizontal: 12,
    paddingVertical: 7,
  },
  close: { alignSelf: 'center', padding: 14 },
});
