import type {FfiPublicIdentity} from 'react-native-liteseal';
import {getCore} from './core';
import {bufferToBytes} from './bytes';
import type {Session} from './AppContext';

// Public metadata only. Legacy keychain JSON is migrated entirely in Kotlin /
// Rust; the keychain module and private-key crypto exports are unavailable to JS.
export function publicSession(value: FfiPublicIdentity, connected = false): Session {
  return {userId:value.userId,deviceId:value.deviceId,serverUrl:value.serverUrl,
    publicKey:bufferToBytes(value.publicKey),ed25519Pk:bufferToBytes(value.ed25519Pk),connected};
}
export async function loadKeystore(): Promise<Session | null> {
  const identity=await getCore().restoreIdentity();
  return identity ? publicSession(identity) : null;
}
export async function clearKeystore(): Promise<void> { await getCore().nativeSignOut(); }
