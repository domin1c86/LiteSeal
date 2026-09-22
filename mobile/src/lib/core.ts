import { NativeModules } from 'react-native';
import { LitesealCore } from 'react-native-liteseal';

export const DEVICE_NAME = 'Android phone';

function filesDir(): string {
  const paths = NativeModules.LitesealPaths;
  const dir: string | undefined =
    paths?.getConstants?.().filesDir ?? paths?.filesDir;
  if (!dir) {
    throw new Error('LitesealPaths native module unavailable');
  }
  return dir;
}

let instance: LitesealCore | null = null;

// One core per process: it owns the SQLite handle and the relay socket,
// mirroring AppState in the desktop shell.
export function getCore(): LitesealCore {
  if (!instance) {
    instance = new LitesealCore(`${filesDir()}/liteseal.db`);
  }
  return instance;
}
