import { Platform, useColorScheme } from 'react-native';

// Token-for-token port of ui/src/theme.css so both clients share the
// "codex look"; dark is the default, light follows the system scheme.
export const darkColors = {
  appBg: '#0f0f0f',
  workspaceBg: '#0f0f0f',
  sidebarBg: '#161616',
  surface: '#1c1c1c',
  surfaceMuted: '#191919',
  surfaceHover: '#222222',
  surfaceActive: '#262626',
  border: '#262626',
  borderStrong: '#363636',
  text: '#ececec',
  textMuted: '#a3a3a3',
  textSubtle: '#6f6f6f',
  accent: '#ececec',
  accentHover: '#ffffff',
  accentSoft: 'rgba(255, 255, 255, 0.07)',
  accentContrast: '#0f0f0f',
  ok: '#62b47a',
  warn: '#d4a054',
  danger: '#e5484d',
  overlay: 'rgba(0, 0, 0, 0.65)',
};

export const lightColors: ThemeColors = {
  appBg: '#ffffff',
  workspaceBg: '#ffffff',
  sidebarBg: '#f7f7f7',
  surface: '#ffffff',
  surfaceMuted: '#f2f2f2',
  surfaceHover: '#ededed',
  surfaceActive: '#e6e6e6',
  border: '#e5e5e5',
  borderStrong: '#d4d4d4',
  text: '#171717',
  textMuted: '#666666',
  textSubtle: '#999999',
  accent: '#171717',
  accentHover: '#000000',
  accentSoft: 'rgba(0, 0, 0, 0.05)',
  accentContrast: '#ffffff',
  ok: '#1e9e50',
  warn: '#b07c33',
  danger: '#d13438',
  overlay: 'rgba(0, 0, 0, 0.35)',
};

export type ThemeColors = typeof darkColors;

export const radius = { sm: 6, md: 8, lg: 12 };

export const fonts = {
  mono: Platform.select({ android: 'monospace', default: 'Menlo' }) as string,
  sans: undefined as string | undefined, // system default
};

export function useTheme(): { colors: ThemeColors; dark: boolean } {
  const scheme = useColorScheme();
  const dark = scheme !== 'light';
  return { colors: dark ? darkColors : lightColors, dark };
}
