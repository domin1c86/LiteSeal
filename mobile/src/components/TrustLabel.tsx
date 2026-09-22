import React from 'react';
import { Text } from 'react-native';
import type { FfiContact } from 'react-native-liteseal';
import { fonts, useTheme } from '../theme';
import type { ThemeColors } from '../theme';

export function trustInfo(
  contact: Pick<FfiContact, 'trustState' | 'keyChanged'>,
  colors: ThemeColors,
): { text: string; color: string } {
  if (contact.keyChanged || contact.trustState === 'key_changed') {
    return { text: 'key changed', color: colors.danger };
  }
  if (contact.trustState === 'verified') {
    return { text: 'verified', color: colors.ok };
  }
  return { text: 'unverified', color: colors.warn };
}

export default function TrustLabel({
  contact,
  size = 10.5,
}: {
  contact: Pick<FfiContact, 'trustState' | 'keyChanged'>;
  size?: number;
}) {
  const { colors } = useTheme();
  const info = trustInfo(contact, colors);
  return (
    <Text style={{ fontFamily: fonts.mono, fontSize: size, color: info.color }}>
      {info.text}
    </Text>
  );
}
