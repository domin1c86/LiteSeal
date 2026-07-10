import React from 'react';
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';
import { useNavigation } from '@react-navigation/native';
import Avatar from '../components/Avatar';
import TrustLabel from '../components/TrustLabel';
import { groupFingerprint } from '../lib/bytes';
import { useApp } from '../lib/AppContext';
import { fonts, useTheme } from '../theme';
import type { RootStackParamList } from '../navigation';

export default function ContactsScreen() {
  const { colors } = useTheme();
  const navigation =
    useNavigation<NativeStackNavigationProp<RootStackParamList>>();
  const { contacts } = useApp();

  return (
    <View style={[styles.container, { backgroundColor: colors.workspaceBg }]}>
      <View style={[styles.appbar, { borderBottomColor: colors.border }]}>
        <Text style={[styles.title, { color: colors.text }]}>contacts</Text>
        <Pressable
          onPress={() => navigation.navigate('AddContact')}
          hitSlop={10}
          style={styles.addBtn}
        >
          <Text style={{ color: colors.textMuted, fontSize: 20 }}>＋</Text>
        </Pressable>
      </View>
      <FlatList
        data={contacts}
        keyExtractor={c => c.userId}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={{ fontFamily: fonts.mono, fontSize: 13, color: colors.textSubtle }}>
              no contacts yet
            </Text>
          </View>
        }
        renderItem={({ item }) => (
          <Pressable
            onPress={() => navigation.navigate('ContactDetail', { userId: item.userId })}
            style={[styles.row, { borderBottomColor: colors.border }]}
            android_ripple={{ color: colors.surfaceHover }}
          >
            <Avatar name={item.username} />
            <View style={styles.rowBody}>
              <Text
                style={{ color: colors.text, fontSize: 14.5, fontWeight: '600' }}
                numberOfLines={1}
              >
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
                {groupFingerprint(item.fingerprint.slice(0, 16))}
              </Text>
            </View>
            <TrustLabel contact={item} />
          </Pressable>
        )}
      />
    </View>
  );
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
  addBtn: { width: 34, height: 34, alignItems: 'center', justifyContent: 'center' },
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
});
