import * as Keychain from 'react-native-keychain';

// Same shape as the desktop keystore JSON (core/src/keystore.rs), stored in
// the Android Keystore-backed credential storage instead of a DPAPI file.
export interface KeystoreData {
  user_id: string;
  token: string;
  refresh_token: string;
  device_id: string;
  server_url: string;
  public_key: number[];
  secret_key: number[];
  ed25519_pk: number[];
  ed25519_sk: number[];
}

const SERVICE = 'liteseal.keystore';

export async function saveKeystore(data: KeystoreData): Promise<void> {
  const ok = await Keychain.setGenericPassword('liteseal', JSON.stringify(data), {
    service: SERVICE,
  });
  if (!ok) {
    throw new Error('Failed to save keystore');
  }
}

export async function loadKeystore(): Promise<KeystoreData | null> {
  const credentials = await Keychain.getGenericPassword({ service: SERVICE });
  if (!credentials) {
    return null;
  }
  const data = JSON.parse(credentials.password) as KeystoreData;
  if (!data.user_id || data.public_key?.length !== 32 || data.ed25519_sk?.length !== 64) {
    return null;
  }
  return data;
}

export async function clearKeystore(): Promise<void> {
  await Keychain.resetGenericPassword({ service: SERVICE });
}
