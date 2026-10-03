import React, { useEffect, useState } from 'react';
import {
  KeyboardAvoidingView,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { getCore } from '../lib/core';
import { publicSession } from '../lib/keystore';
import type {FfiPublicIdentity} from 'react-native-liteseal';
import { useApp } from '../lib/AppContext';
import { fonts, radius, useTheme } from '../theme';

export default function LoginScreen() {
  const { colors } = useTheme();
  const { setSession, setConnected } = useApp();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [serverUrl, setServerUrl] = useState('http://10.0.2.2:3000');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [inviteCode,setInviteCode]=useState('');
  const [loading, setLoading] = useState(false);
  const [offlineIdentity,setOfflineIdentity]=useState<FfiPublicIdentity|null>(null);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = username.trim().length > 0 && password.length >= 8 && !loading;
  useEffect(() => {
    let retired=false;
    void (async()=>{
      try {
        const identity=await getCore().restoreIdentity();
        if (retired || !identity) return;
        setOfflineIdentity(identity);
      } catch {if(!retired)setError('原生身份恢复失败；原数据已保留，不能创建替换密钥。');}
    })();
    return()=>{retired=true;};
  },[setConnected,setSession]);

  async function handleSubmit() {
    if (!canSubmit) return;
    setLoading(true); setError(null);
    try {
      const identity = mode === 'register'
        ? await getCore().nativeRegister(inviteCode.trim(),username.trim(),password,serverUrl)
        : await getCore().nativeLogin(username.trim(),password,serverUrl);
      let connected = false;
      try { await getCore().resumeNative(); connected = true; } catch { /* Saved identity remains usable offline. */ }
      setConnected(connected); setSession(publicSession(identity,connected));
    } catch { setError('登录或注册未确认；原身份已保留。请核对原账号、服务器和邀请码后重试。'); }
    finally { setPassword(''); setLoading(false); }
  }
  return (
    <KeyboardAvoidingView
      style={[styles.container, { backgroundColor: colors.workspaceBg }]}
      behavior="height"
    >
      <Text style={[styles.wordmark, { color: colors.text }]}>
        liteseal
        <Text style={{ color: colors.textSubtle, fontWeight: '400' }}>▌</Text>
      </Text>
      <Text style={[styles.subtitle, { color: colors.textSubtle }]}>
        end-to-end encrypted messaging
      </Text>

      <View
        style={[
          styles.segmented,
          { borderColor: colors.border, backgroundColor: colors.surfaceMuted },
        ]}
      >
        {(['login', 'register'] as const).map(m => (
          <Pressable
            key={m}
            onPress={() => setMode(m)}
            style={[
              styles.segment,
              mode === m && { backgroundColor: colors.surfaceActive },
            ]}
          >
            <Text
              style={{
                color: mode === m ? colors.text : colors.textMuted,
                fontSize: 13,
                fontWeight: '600',
              }}
            >
              {m === 'login' ? 'Login' : 'Register'}
            </Text>
          </Pressable>
        ))}
      </View>

      {(
        [
          ['Server URL', serverUrl, setServerUrl, false],
          ['Username', username, setUsername, false],
          ['Password', password, setPassword, true],
        ] as const
      ).map(([placeholder, value, setter, secure]) => (
        <TextInput
          key={placeholder}
          placeholder={placeholder}
          placeholderTextColor={colors.textSubtle}
          value={value}
          onChangeText={setter}
          secureTextEntry={secure}
          autoCapitalize="none"
          autoCorrect={false}
          style={[
            styles.input,
            {
              borderColor: colors.borderStrong,
              backgroundColor: colors.surfaceMuted,
              color: colors.text,
            },
          ]}
        />
      ))}

      {mode==='register' && <TextInput value={inviteCode} onChangeText={setInviteCode}
        placeholder="邀请码 invite code" placeholderTextColor={colors.textSubtle}
        autoCapitalize="none" autoCorrect={false}
        style={[styles.input,{borderColor:colors.borderStrong,backgroundColor:colors.surfaceMuted,color:colors.text}]}/>}
      <Pressable
        onPress={handleSubmit}
        disabled={!canSubmit}
        style={[
          styles.button,
          { backgroundColor: colors.accent, opacity: canSubmit ? 1 : 0.55 },
        ]}
      >
        <Text style={{ color: colors.accentContrast, fontSize: 14, fontWeight: '600' }}>
          {loading ? 'Connecting…' : mode === 'register' ? 'Register & Connect' : 'Login'}
        </Text>
      </Pressable>

      {error != null && (
        <Text style={[styles.error, { color: colors.danger }]}>{error}</Text>
      )}
      {offlineIdentity && <Pressable disabled={loading} onPress={()=>{
        setConnected(false);setSession(publicSession(offlineIdentity,false));
      }} style={styles.button}><Text style={{color:colors.textMuted}}>查看本机离线历史 · 不恢复在线会话</Text></Pressable>}
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    paddingHorizontal: 28,
    paddingBottom: 40,
  },
  wordmark: {
    fontFamily: fonts.mono,
    fontSize: 24,
    fontWeight: '600',
    textAlign: 'center',
  },
  subtitle: {
    fontFamily: fonts.mono,
    fontSize: 11.5,
    textAlign: 'center',
    marginTop: 6,
    marginBottom: 24,
  },
  segmented: {
    flexDirection: 'row',
    gap: 6,
    padding: 4,
    borderWidth: 1,
    borderRadius: radius.md,
    marginBottom: 14,
  },
  segment: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: radius.sm,
    alignItems: 'center',
  },
  input: {
    borderWidth: 1,
    borderRadius: radius.md,
    paddingHorizontal: 14,
    paddingVertical: 12,
    fontSize: 14,
    marginBottom: 12,
  },
  button: {
    borderRadius: radius.md,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 4,
  },
  error: {
    fontFamily: fonts.mono,
    fontSize: 12,
    marginTop: 12,
    textAlign: 'center',
  },
});
