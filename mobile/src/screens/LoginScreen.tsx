import React, { useState } from 'react';
import {
  KeyboardAvoidingView,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import {
  generateKeypair,
  login as apiLogin,
  register as apiRegister,
  type FfiAuthResult,
} from 'react-native-liteseal';
import { bufferToBytes, bytesToBuffer } from '../lib/bytes';
import { DEVICE_NAME, getCore } from '../lib/core';
import { loadKeystore, saveKeystore } from '../lib/keystore';
import { useApp } from '../lib/AppContext';
import { fonts, radius, useTheme } from '../theme';

interface Keys {
  publicKey: number[];
  secretKey: number[];
  ed25519Pk: number[];
  ed25519Sk: number[];
}

function freshKeys(): Keys {
  const kp = generateKeypair();
  return {
    publicKey: bufferToBytes(kp.publicKey),
    secretKey: bufferToBytes(kp.secretKey),
    ed25519Pk: bufferToBytes(kp.ed25519Pk),
    ed25519Sk: bufferToBytes(kp.ed25519Sk),
  };
}

export default function LoginScreen() {
  const { colors } = useTheme();
  const { setSession, setConnected } = useApp();
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [serverUrl, setServerUrl] = useState('http://10.0.2.2:3000');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = username.trim().length > 0 && password.length >= 8 && !loading;

  async function handleSubmit() {
    if (!canSubmit) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      // Reuse the saved keypair + device on login so contacts keep a stable
      // public key for us; fresh keys only for register or first login here.
      let keys: Keys | null = null;
      let savedDeviceId: string | undefined;
      if (mode === 'login') {
        const saved = await loadKeystore().catch(() => null);
        if (saved) {
          keys = {
            publicKey: saved.public_key,
            secretKey: saved.secret_key,
            ed25519Pk: saved.ed25519_pk,
            ed25519Sk: saved.ed25519_sk,
          };
          savedDeviceId = saved.device_id || undefined;
        }
      }
      if (!keys) {
        keys = freshKeys();
      }

      let result: FfiAuthResult;
      if (mode === 'register') {
        result = await apiRegister(
          username.trim(),
          password,
          serverUrl,
          DEVICE_NAME,
          bytesToBuffer(keys.publicKey),
          bytesToBuffer(keys.ed25519Pk),
        );
      } else {
        try {
          result = await apiLogin(
            username.trim(),
            password,
            serverUrl,
            DEVICE_NAME,
            bytesToBuffer(keys.publicKey),
            bytesToBuffer(keys.ed25519Pk),
            savedDeviceId,
          );
        } catch (err) {
          // Saved device belongs to another account or was revoked: retry
          // once with a fresh keypair and a new device registration.
          if (savedDeviceId && String(err).includes('403')) {
            keys = freshKeys();
            result = await apiLogin(
              username.trim(),
              password,
              serverUrl,
              DEVICE_NAME,
              bytesToBuffer(keys.publicKey),
              bytesToBuffer(keys.ed25519Pk),
              undefined,
            );
          } else {
            throw err;
          }
        }
      }

      const token = result.accessToken ?? result.token;
      const deviceId = result.deviceId ?? '';
      await getCore().connectRelay(serverUrl, result.userId, token, deviceId);
      await saveKeystore({
        user_id: result.userId,
        token,
        refresh_token: result.refreshToken ?? '',
        device_id: deviceId,
        server_url: serverUrl,
        public_key: keys.publicKey,
        secret_key: keys.secretKey,
        ed25519_pk: keys.ed25519Pk,
        ed25519_sk: keys.ed25519Sk,
      });
      setConnected(true);
      setSession({
        userId: result.userId,
        token,
        refreshToken: result.refreshToken ?? '',
        deviceId,
        serverUrl,
        publicKey: keys.publicKey,
        secretKey: keys.secretKey,
        ed25519Pk: keys.ed25519Pk,
        ed25519Sk: keys.ed25519Sk,
        connected: true,
      });
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
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
